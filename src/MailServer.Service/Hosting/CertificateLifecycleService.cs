using System.Globalization;
using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Service.Hosting;

/// <summary>
/// Watches certificate expiry, publishes TLS health, and generates the bootstrap certificate
/// on a server that has none.
/// </summary>
/// <remarks>
/// <para>
/// From Milestone 4 it also renews. A certificate inside the renewal window whose source is
/// ACME is reissued automatically; every other source is monitored and warned about only,
/// because this server cannot obtain a replacement for a certificate it did not obtain.
/// </para>
/// <para>
/// <b>Renewal never makes things worse.</b> A failed attempt leaves the existing certificate
/// and its binding exactly as they were, records the reason, and backs off. There is no path
/// from here to a self-signed substitute — see
/// <see cref="CertificateRenewalPolicy.MayDowngradeToSelfSignedOnRenewalFailure"/>.
/// </para>
/// <para>
/// <b>This service never replaces a certificate.</b> It generates one only when the server has
/// none whatsoever, which is a bootstrap, not a fallback. See
/// <see cref="CertificateRenewalPolicy.MayDowngradeToSelfSignedOnRenewalFailure"/>.
/// </para>
/// </remarks>
public sealed class CertificateLifecycleService(
    IServiceScopeFactory scopeFactory,
    ITlsCertificateProvider tlsProvider,
    IServerIdentityProvider serverIdentity,
    IOptions<MailServerOptions> options,
    IClock clock,
    IHealthRegistry health,
    ILogger<CertificateLifecycleService> logger)
    : ResilientBackgroundService(health, logger)
{
    private static readonly CertificateRenewalPolicy Policy = new();

    public override string ComponentName => "Certificates";

    private CertificateOptions Options => options.Value.Certificates;

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        // Before anything else: without a certificate the server cannot complete a TLS
        // handshake at all, so a fresh installation needs one to be usable enough to configure
        // a real one.
        await EnsureBootstrapCertificateAsync(stoppingToken).ConfigureAwait(false);

        await tlsProvider.ReloadAsync(stoppingToken).ConfigureAwait(false);

        using PeriodicTimer timer = new(
            TimeSpan.FromHours(Options.LifecycleCheckIntervalHours));

        // Evaluated immediately, so an expired certificate is on the dashboard within seconds
        // of a restart rather than after the first interval.
        await EvaluateAsync(stoppingToken).ConfigureAwait(false);

        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await EvaluateAsync(stoppingToken).ConfigureAwait(false);
            await RenewExpiringCertificatesAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Reissues ACME certificates that have entered the renewal window.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Thirty days out, against a ninety-day Let's Encrypt lifetime, leaves three full weeks of
    /// retries before anything is at risk. That headroom is what turns a transient DNS or
    /// rate-limit failure into a non-event rather than an incident.
    /// </para>
    /// <para>
    /// Certificates are renewed one at a time, and a failure on one does not stop the others.
    /// A server with several certificates should not lose them all because the first in the
    /// list had a DNS problem.
    /// </para>
    /// </remarks>
    private async Task RenewExpiringCertificatesAsync(CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        ICertificateRepository repository =
            scope.ServiceProvider.GetRequiredService<ICertificateRepository>();

        IReadOnlyList<Certificate> certificates =
            await repository.GetAllAsync(cancellationToken).ConfigureAwait(false);

        IReadOnlyList<CertificateBinding> bindings =
            await repository.GetBindingsAsync(cancellationToken).ConfigureAwait(false);

        DateTimeOffset now = clock.UtcNow;

        foreach (Certificate certificate in certificates)
        {
            // Only what this server can actually reissue. The aggregate refuses AutoRenew for
            // every other source, so this is belt and braces on a rule already enforced.
            if (!certificate.AutoRenew || certificate.Source != CertificateSource.Acme)
            {
                continue;
            }

            if (Policy.GetAction(certificate.DaysRemaining(now)) == RenewalAction.None)
            {
                continue;
            }

            if (certificate.IsRenewing)
            {
                continue;
            }

            IReadOnlyList<DomainName> identifiers =
            [
                .. bindings
                    .Where(b => b.CertificateId == certificate.Id)
                    .Select(static b => b.Hostname),
            ];

            if (identifiers.Count == 0)
            {
                // Nothing is served by it, so renewing would spend a rate-limit slot on a
                // certificate no handshake will ever present.
                Logger.LogInformation(
                    "Certificate {Thumbprint} is inside the renewal window but is not bound to " +
                    "any hostname, so it was not renewed.",
                    certificate.Thumbprint);

                continue;
            }

            await RenewOneAsync(scope, repository, certificate, identifiers, now, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task RenewOneAsync(
        AsyncServiceScope scope,
        ICertificateRepository repository,
        Certificate certificate,
        IReadOnlyList<DomainName> identifiers,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        certificate.BeginRenewal(now);
        await repository.UpdateAsync(certificate, cancellationToken).ConfigureAwait(false);

        Logger.LogInformation(
            "Renewing certificate {Thumbprint}, {Days} day(s) from expiry.",
            certificate.Thumbprint,
            certificate.DaysRemaining(now));

        IssuanceResult result = await scope.ServiceProvider
            .GetRequiredService<IAcmeIssuanceService>()
            .IssueAsync(
                identifiers,
                scope.ServiceProvider.GetRequiredService<IAcmeSettings>().DefaultChallengeType,

                // The new certificate takes over the binding; that IS the renewal.
                bindOnSuccess: true,
                cancellationToken)
            .ConfigureAwait(false);

        if (result.Succeeded)
        {
            certificate.CompleteRenewal(clock.UtcNow);
            await repository.UpdateAsync(certificate, cancellationToken).ConfigureAwait(false);

            // Rebuild the snapshot so live listeners serve the new certificate. The old one
            // stays in the rollback window for connections already in flight.
            await tlsProvider.ReloadAsync(cancellationToken).ConfigureAwait(false);

            Logger.LogInformation(
                "Certificate for {Hostname} renewed; new certificate {Thumbprint} is now " +
                "being served. No restart was required.",
                identifiers[0],
                result.Certificate?.Thumbprint);

            return;
        }

        // The failure path, and the one that matters. The existing certificate is untouched:
        // still valid, still bound, still being served. Substituting a self-signed certificate
        // here would turn a warning affecting nobody into a simultaneous TLS failure against
        // every verifying remote MTA and every mail client.
        certificate.FailRenewal(
            result.Failure ?? "Renewal failed without a reported reason.",
            clock.UtcNow);

        await repository.UpdateAsync(certificate, cancellationToken).ConfigureAwait(false);

        Logger.LogCritical(
            "Renewal of the certificate for {Hostname} FAILED: {Reason}. The existing " +
            "certificate is still in use and expires in {Days} day(s). It will NOT be replaced " +
            "with a self-signed certificate; fix the cause before it expires.",
            identifiers[0],
            result.Failure,
            certificate.DaysRemaining(clock.UtcNow));
    }

    /// <summary>
    /// Generates a self-signed certificate if, and only if, the server has none.
    /// </summary>
    /// <remarks>
    /// The guard is "no certificates exist", not "no valid certificate exists". An expired
    /// certificate must not trigger generation: that would be the downgrade the fallback policy
    /// forbids, arriving through the back door of a bootstrap check.
    /// </remarks>
    private async Task EnsureBootstrapCertificateAsync(CancellationToken cancellationToken)
    {
        if (!Options.GenerateSelfSignedOnFirstStart)
        {
            return;
        }

        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        ICertificateRepository repository =
            scope.ServiceProvider.GetRequiredService<ICertificateRepository>();

        IReadOnlyList<Certificate> existing =
            await repository.GetAllAsync(cancellationToken).ConfigureAwait(false);

        if (existing.Count > 0)
        {
            return;
        }

        if (!DomainName.TryParse(serverIdentity.Hostname, out DomainName? hostname))
        {
            Logger.LogError(
                "The configured server hostname '{Hostname}' is not a valid domain name, so no " +
                "bootstrap certificate could be generated. TLS will be unavailable until a " +
                "certificate is configured.",
                serverIdentity.Hostname);

            return;
        }

        ICertificateManager manager =
            scope.ServiceProvider.GetRequiredService<ICertificateManager>();

        Certificate certificate = await manager.GenerateSelfSignedAsync(
            new SelfSignedCertificateRequest(
                [hostname],
                Options.SelfSignedKeySizeBits,
                Options.SelfSignedValidityYears),
            cancellationToken).ConfigureAwait(false);

        CertificateBinding binding = CertificateBinding.Create(
            hostname,
            certificate.Id,
            CertificatePurpose.All,
            isDefault: true,
            clock.UtcNow);

        await repository.AddBindingAsync(binding, cancellationToken).ConfigureAwait(false);

        Logger.LogWarning(
            "No certificate was configured, so a self-signed certificate was generated for " +
            "{Hostname} so that TLS is available. {Warning}",
            hostname,
            CertificateRenewalPolicy.SelfSignedWarning.Replace('\n', ' '));
    }

    private async Task EvaluateAsync(CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        ICertificateRepository repository =
            scope.ServiceProvider.GetRequiredService<ICertificateRepository>();

        IReadOnlyList<Certificate> certificates =
            await repository.GetAllAsync(cancellationToken).ConfigureAwait(false);

        IReadOnlyList<CertificateBinding> bindings =
            await repository.GetBindingsAsync(cancellationToken).ConfigureAwait(false);

        DateTimeOffset now = clock.UtcNow;

        if (certificates.Count == 0)
        {
            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Critical,
                "No TLS certificate is configured. The server cannot complete a TLS handshake, " +
                "so STARTTLS, implicit TLS and the HTTPS endpoint are all unavailable.",
                now));

            return;
        }

        HealthState worst = HealthState.Healthy;
        string message = $"{certificates.Count} certificate(s) configured.";
        int selfSigned = 0;

        foreach (Certificate certificate in certificates)
        {
            if (certificate.IsSelfSigned)
            {
                selfSigned++;
            }

            int daysRemaining = certificate.DaysRemaining(now);
            HealthState state = Policy.GetHealthState(daysRemaining);

            LogEscalation(certificate, daysRemaining);

            if (state > worst)
            {
                worst = state;
                message = DescribeExpiry(certificate, bindings, daysRemaining);
            }
        }

        // A self-signed certificate never expires soon enough to be Critical on its own, but
        // it is also never a correct production state — so it raises a Warning that survives
        // the expiry checks above finding nothing wrong.
        if (worst == HealthState.Healthy && selfSigned > 0)
        {
            worst = HealthState.Warning;
            message =
                $"{selfSigned} self-signed certificate(s) in use. " +
                CertificateRenewalPolicy.SelfSignedWarning.Replace('\n', ' ');
        }

        if (!bindings.Any(static b => b.IsDefault))
        {
            // Escalated above a self-signed warning, because its consequence is dropped mail
            // rather than a client warning dialog.
            worst = worst > HealthState.Warning ? worst : HealthState.Warning;
            message =
                "No certificate binding is marked as the default. A TLS handshake that offers " +
                "no SNI hostname — which older MTAs still send — has no certificate to be " +
                "answered with, and that mail will not be delivered.";
        }

        Health.Publish(new HealthReading(
            ComponentName,
            worst,
            message,
            now,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Certificates"] = certificates.Count.ToString(CultureInfo.InvariantCulture),
                ["SelfSigned"] = selfSigned.ToString(CultureInfo.InvariantCulture),
                ["Bindings"] = bindings.Count.ToString(CultureInfo.InvariantCulture),
                ["TlsReady"] = tlsProvider.IsReady.ToString(),
            }));
    }

    /// <summary>
    /// Logs at the severity the remaining time warrants.
    /// </summary>
    /// <remarks>
    /// The escalation exists because a single notice at 30 days is read once and forgotten,
    /// and a single notice at one day arrives too late to act on. Each threshold crossing gets
    /// its own line so that an operator watching the log sees the pressure increasing.
    /// </remarks>
    private void LogEscalation(Certificate certificate, int daysRemaining)
    {
        if (daysRemaining < 0)
        {
            Logger.LogCritical(
                "Certificate {Thumbprint} EXPIRED {DaysAgo} day(s) ago. Every client that " +
                "verifies certificates is now refusing this server.",
                certificate.Thumbprint,
                -daysRemaining);

            return;
        }

        int? threshold = Policy.GetEscalationThreshold(daysRemaining);

        if (threshold is null)
        {
            return;
        }

        if (daysRemaining <= Policy.UrgentThresholdDays)
        {
            Logger.LogCritical(
                "Certificate {Thumbprint} expires in {Days} day(s). Replace it now.",
                certificate.Thumbprint,
                daysRemaining);
        }
        else
        {
            Logger.LogWarning(
                "Certificate {Thumbprint} expires in {Days} day(s), inside the {Threshold}-day " +
                "escalation step.",
                certificate.Thumbprint,
                daysRemaining,
                threshold);
        }
    }

    private static string DescribeExpiry(
        Certificate certificate,
        IReadOnlyList<CertificateBinding> bindings,
        int daysRemaining)
    {
        string name = bindings
            .FirstOrDefault(b => b.CertificateId == certificate.Id)
            ?.Hostname.Value
            ?? certificate.SubjectAlternativeNames.FirstOrDefault()?.Value
            ?? certificate.Thumbprint.Value;

        return daysRemaining < 0
            ? $"The certificate for {name} expired {-daysRemaining} day(s) ago."
            : $"The certificate for {name} expires in {daysRemaining} day(s).";
    }
}
