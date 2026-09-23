using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Runs every probe once and judges everything they gathered.
/// </summary>
/// <remarks>
/// <para>
/// <b>The order matters in exactly two places, and both are data dependencies rather than
/// sequencing for its own sake.</b> The MX hosts come out of <see cref="DnsProbe"/> and are what
/// an MTA-STS policy's <c>mx</c> list is judged against; the STARTTLS answer comes out of the
/// relay test's EHLO, which is already on the wire. Everything else could run in any order, and
/// runs in this one because a reader following the report's six categories finds it here in the
/// same shape.
/// </para>
/// <para>
/// <b>A probe that throws does not take the report with it.</b> Each category is gathered inside
/// a boundary that turns a failure into no facts, which the checks already know how to report as
/// "not tested". The alternative is an operator with one unreachable nameserver getting an error
/// page instead of the ninety points that were measurable.
/// </para>
/// </remarks>
public sealed class DeliverabilityReportService(
    IOptions<MailServerOptions> options,
    IdentityProbe identity,
    AuthenticationProbe authentication,
    DnsProbe dns,
    TransportPolicyProbe transportPolicy,
    ReputationProbe reputation,
    OperationsProbe operations,
    ICertificateRepository certificates,
    ITlsCertificateProvider tlsCertificates,
    IDkimKeyRepository dkimKeys,
    IDomainRepository domains,
    IClock clock,
    ILogger<DeliverabilityReportService> logger,
    Func<string, int, string, CancellationToken, Task<OpenRelayResult>>? relayTest = null)
    : IDeliverabilityReportService
{
    /// <summary>
    /// How the relay self-test is run, defaulting to a real SMTP connection.
    /// </summary>
    /// <remarks>
    /// A seam rather than a dependency. The alternative is a test that can only assert the check
    /// came back "not tested" — which it does whether the connection was skipped deliberately or
    /// merely refused, so the two cases the run options exist to separate become
    /// indistinguishable.
    /// </remarks>
    private readonly Func<string, int, string, CancellationToken, Task<OpenRelayResult>> _relayTest =
        relayTest ?? OpenRelaySelfTest.RunAsync;

    /// <summary>
    /// The issuer domains this server's ACME directories belong to, for the CAA check.
    /// </summary>
    /// <remarks>
    /// A CAA <c>issue</c> value names the CA's own domain, which is not derivable from a
    /// directory URL in general — <c>acme-v02.api.letsencrypt.org</c> is authorised as
    /// <c>letsencrypt.org</c>. A custom directory maps to null and the check goes unjudged,
    /// because guessing an issuer would invent a finding.
    /// </remarks>
    /// <summary>
    /// How long a revocation lookup may take before the chain build gives up on it.
    /// </summary>
    /// <remarks>
    /// Short, because an unreachable endpoint is not a finding and waiting on one only delays
    /// the report — see <see cref="ChainStatus"/> for why the result is not treated as a broken
    /// chain either way.
    /// </remarks>
    public static readonly TimeSpan RevocationTimeout = TimeSpan.FromSeconds(5);

    public static string? IssuerDomainFor(AcmeDirectory directory) => directory switch
    {
        AcmeDirectory.LetsEncryptProduction or AcmeDirectory.LetsEncryptStaging => "letsencrypt.org",
        _ => null,
    };

    /// <inheritdoc />
    public async Task<DeliverabilityReport> RunAsync(
        DomainName domain,
        DeliverabilityRunOptions runOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(runOptions);

        MailServerOptions settings = options.Value;
        DomainName hostname = DomainName.Parse(settings.Server.Hostname);

        IpAddressValue? publicAddress =
            settings.Server.PublicIpAddress is { Length: > 0 } text &&
            IpAddressValue.TryParse(text, out IpAddressValue? parsed)
                ? parsed
                : null;

        List<DeliverabilityCheck> checks = [];

        // ---- Identity ---------------------------------------------------------------------
        if (await GatherAsync(
                "identity",
                ct => identity.GatherAsync(hostname, publicAddress, ct),
                cancellationToken).ConfigureAwait(false) is { } identityFacts)
        {
            checks.AddRange(IdentityChecks.Evaluate(identityFacts));
        }

        // ---- Authentication ---------------------------------------------------------------
        IReadOnlyList<DkimSelector> selectors = await SelectorsAsync(domain, cancellationToken)
            .ConfigureAwait(false);

        if (await GatherAsync(
                "authentication",
                ct => authentication.GatherAsync(domain, selectors, ct),
                cancellationToken).ConfigureAwait(false) is { } authFacts)
        {
            checks.AddRange(AuthenticationChecks.Evaluate(authFacts));
        }

        // ---- DNS ---------------------------------------------------------------------------
        DnsFacts? dnsFacts = await GatherAsync(
                "dns",
                ct => dns.GatherAsync(domain, hostname, IssuerDomainFor(settings.Acme.Directory), ct),
                cancellationToken)
            .ConfigureAwait(false);

        if (dnsFacts is not null)
        {
            checks.AddRange(DnsChecks.Evaluate(dnsFacts));
        }

        // ---- The SMTP conversation ---------------------------------------------------------
        //
        // One connection answers two checks: whether this server relays for strangers, and
        // whether it advertises STARTTLS. See OpenRelayResult - the EHLO answer is already on
        // the wire, so a second connection would learn nothing new.
        OpenRelayResult? relay = runOptions.RunRelayTest
            ? await RelayTestAsync(settings, hostname, cancellationToken).ConfigureAwait(false)
            : null;

        // ---- TLS ---------------------------------------------------------------------------
        checks.AddRange(TlsChecks.Evaluate(await TlsFactsAsync(
                hostname,
                relay,
                cancellationToken)
            .ConfigureAwait(false)));

        // ---- MTA-STS and TLS-RPT ------------------------------------------------------------
        //
        // The MX hosts come from the DNS facts above: a policy's mx list is judged against what
        // the domain actually publishes, and resolving them a second time here would let the two
        // halves of one report disagree about it.
        IReadOnlyList<string>? mxHosts = dnsFacts?.MxRecords
            ?.Where(mx => !mx.IsNull)
            .Select(mx => mx.Host)
            .ToList();

        if (runOptions.FetchMtaStsPolicy &&
            await GatherAsync(
                "transport-policy",
                ct => transportPolicy.GatherAsync(domain, mxHosts, ct),
                cancellationToken).ConfigureAwait(false) is { } transportFacts)
        {
            checks.AddRange(TransportPolicyChecks.Evaluate(transportFacts));
        }

        // ---- Reputation ---------------------------------------------------------------------
        if (runOptions.QueryReputationLists &&
            await GatherAsync(
                "reputation",
                ct => reputation.GatherAsync(domain, publicAddress, ct),
                cancellationToken).ConfigureAwait(false) is { } reputationFacts)
        {
            checks.AddRange(ReputationChecks.Evaluate(reputationFacts));
        }

        // ---- Operations -----------------------------------------------------------------------
        if (await GatherAsync(
                "operations",
                ct => operations.GatherAsync(relay, ct),
                cancellationToken).ConfigureAwait(false) is { } operationsFacts)
        {
            checks.AddRange(OperationsChecks.Evaluate(operationsFacts));
        }

        return DeliverabilityReport.From(checks, clock.UtcNow);
    }

    /// <summary>
    /// Runs one probe, turning a failure into no facts.
    /// </summary>
    /// <remarks>
    /// The checks a failed probe would have fed are simply absent from the report, which
    /// <see cref="DeliverabilityReport.From"/> already handles: the category scores zero judged
    /// weight and the summary says how many points could not be tested. An exception escaping
    /// here would replace ninety measurable points with an error page.
    /// </remarks>
    private async Task<T?> GatherAsync<T>(
        string category,
        Func<CancellationToken, Task<T>> gather,
        CancellationToken cancellationToken)
        where T : class
    {
        try
        {
            return await gather(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                ex,
                "The {Category} probe failed; its checks will report as not tested.",
                category);

            return null;
        }
    }

    /// <summary>The selectors this server signs this domain's mail with.</summary>
    /// <remarks>
    /// Active keys only. A retired key's selector may still be published — deliberately, so
    /// signatures made before the rotation still verify — and reporting it as one of this
    /// server's would make a completed rotation look like a configuration to fix.
    /// </remarks>
    private async Task<IReadOnlyList<DkimSelector>> SelectorsAsync(
        DomainName domain,
        CancellationToken cancellationToken)
    {
        try
        {
            MailDomain? record = await domains.GetByNameAsync(domain, cancellationToken)
                .ConfigureAwait(false);

            if (record is null)
            {
                return [];
            }

            IReadOnlyList<DkimKey> keys = await dkimKeys
                .GetForDomainAsync(record.Id, cancellationToken)
                .ConfigureAwait(false);

            return [.. keys.Where(k => k.Status == DkimKeyStatus.Active).Select(k => k.Selector)];
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "The configured DKIM selectors could not be read.");

            return [];
        }
    }

    /// <summary>What the TLS checks judge: the bound certificate, its chain, and STARTTLS.</summary>
    private async Task<TlsFacts> TlsFactsAsync(
        DomainName hostname,
        OpenRelayResult? relay,
        CancellationToken cancellationToken)
    {
        Certificate? certificate = null;
        CertificateChainStatus chain = CertificateChainStatus.NotBuilt;

        try
        {
            CertificateBinding? binding = await certificates
                .GetBindingByHostnameAsync(hostname, cancellationToken)
                .ConfigureAwait(false);

            if (binding is not null)
            {
                certificate = await certificates
                    .GetAsync(binding.CertificateId, cancellationToken)
                    .ConfigureAwait(false);
            }

            chain = ChainStatus(hostname);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "The bound certificate could not be read.");
        }

        return new TlsFacts(
            hostname,
            certificate,
            chain,
            relay?.StartTlsOffered,
            new CertificateRenewalPolicy(),
            clock.UtcNow);
    }

    /// <summary>
    /// What building the chain for the certificate this server would present establishes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Built against the certificate the provider would actually hand a listener, not against
    /// stored metadata, because the fault this catches is an intermediate the server does not
    /// send — which is invisible in the metadata and is what a chain build is for.
    /// </para>
    /// <para>
    /// <b>Revocation is checked, not skipped.</b> RFC 8461 §4.2 lets a sending MTA check the
    /// receiving one for revocation, so a revoked certificate is a real deliverability failure
    /// and one an operator would rather hear from their own report. The cost is a network round
    /// trip, which a diagnostic run on demand can afford where a handshake could not.
    /// </para>
    /// <para>
    /// <b>Revocation that could not be determined is not a chain failure.</b> An unreachable CRL
    /// or OCSP endpoint makes <see cref="X509Chain.Build"/> return false with nothing but
    /// <see cref="X509ChainStatusFlags.RevocationStatusUnknown"/> or
    /// <see cref="X509ChainStatusFlags.OfflineRevocation"/> to show for it, and reporting that as
    /// a broken chain would send an operator to reinstall intermediates that were never missing.
    /// The chain itself built; only its revocation state is unknown.
    /// </para>
    /// </remarks>
    private CertificateChainStatus ChainStatus(DomainName hostname)
    {
        try
        {
            // The provider's instance is the one every listener is presenting right now, and it is
            // shared rather than lent: disposing it takes TLS down on every port - SMTP, IMAP,
            // POP3, submission and the MTA-STS endpoint - until the next certificate reload. That
            // is exactly what this method once did, and one run of the report was enough. The
            // chain is built on a copy of the public certificate instead: the report needs the
            // chain, not the private key, and a copy is this method's own to dispose.
            X509Certificate2? served = tlsCertificates.Select(hostname.Value, CertificatePurpose.SmtpInbound);

            if (served is null)
            {
                return CertificateChainStatus.NotBuilt;
            }

            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(served.RawData);

            using X509Chain chain = new();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.UrlRetrievalTimeout = RevocationTimeout;
            chain.ChainPolicy.VerificationTime = clock.UtcNow.UtcDateTime;

            bool built = chain.Build(leaf);

            return Classify(
                built,
                chain.ChainStatus.Aggregate(
                    X509ChainStatusFlags.NoError,
                    (all, status) => all | status.Status));
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException)
        {
            logger.LogWarning(ex, "The certificate chain could not be built.");

            return CertificateChainStatus.NotBuilt;
        }
    }

    /// <summary>
    /// Turns a chain build's outcome into one of four states.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Separated from the build so it can be tested: constructing a certificate that a platform
    /// trust store genuinely revokes is not something a unit test can do, while every
    /// combination of flags it would produce is.
    /// </para>
    /// <para>
    /// <b>Revocation that could not be determined is not a chain failure.</b> An unreachable CRL
    /// or OCSP endpoint fails the build with nothing but
    /// <see cref="X509ChainStatusFlags.RevocationStatusUnknown"/> or
    /// <see cref="X509ChainStatusFlags.OfflineRevocation"/> to show for it. The chain itself
    /// built; only its revocation state is unknown, and reporting that as a broken chain would
    /// send an operator to reinstall intermediates that were never missing.
    /// </para>
    /// </remarks>
    public static CertificateChainStatus Classify(bool built, X509ChainStatusFlags flags)
    {
        if (built)
        {
            return CertificateChainStatus.Trusted;
        }

        // Checked before the others: a chain can be revoked and untrusted at once, and the
        // revocation is the finding that matters — there is no chain left to repair.
        if (flags.HasFlag(X509ChainStatusFlags.Revoked))
        {
            return CertificateChainStatus.Revoked;
        }

        const X509ChainStatusFlags RevocationUnknown =
            X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation;

        return (flags & ~RevocationUnknown) == X509ChainStatusFlags.NoError
            ? CertificateChainStatus.Trusted
            : CertificateChainStatus.Untrusted;
    }

    /// <summary>Asks this server whether it relays, on whichever port 25 listener is enabled.</summary>
    private async Task<OpenRelayResult?> RelayTestAsync(
        MailServerOptions settings,
        DomainName hostname,
        CancellationToken cancellationToken)
    {
        SmtpListenerOptions listener = settings.Smtp.InboundMta;

        if (!listener.Enabled)
        {
            return null;
        }

        return await _relayTest("127.0.0.1", listener.Port, hostname.Value, cancellationToken)
            .ConfigureAwait(false);
    }
}
