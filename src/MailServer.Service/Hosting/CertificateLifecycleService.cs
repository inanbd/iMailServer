using System.Globalization;
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
/// Milestone 3 monitors and warns; it does not renew, because there is nothing yet to renew
/// with — ACME arrives in Milestone 4 and plugs into the same escalation thresholds. Stating
/// that plainly is better than a service that appears to handle renewal and silently cannot:
/// the aggregate refuses <c>AutoRenew</c> for every source this server cannot reissue, so no
/// certificate here is currently marked for automatic renewal at all.
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
        }
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
