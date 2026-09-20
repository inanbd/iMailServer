using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>What the TLS probe observed.</summary>
/// <param name="Hostname">The name this server presents, which its certificate must cover.</param>
/// <param name="Certificate">The certificate bound to the SMTP listeners, or null if none is.</param>
/// <param name="Chain">
/// What building the chain established. Not something the Domain can decide — it needs the trust
/// store and the network, neither of which a model with no dependencies outside the BCL has.
/// </param>
/// <param name="StartTlsOffered">
/// Whether the server advertised STARTTLS on port 25, or null when no probe was made.
/// </param>
/// <param name="RenewalPolicy">The window the certificate checks judge expiry against.</param>
/// <param name="Now">The instant the report is being produced for.</param>
public sealed record TlsFacts(
    DomainName Hostname,
    Certificate? Certificate,
    CertificateChainStatus Chain,
    bool? StartTlsOffered,
    CertificateRenewalPolicy RenewalPolicy,
    DateTimeOffset Now);

/// <summary>
/// The TLS category: whether this server can prove who it is over an encrypted channel.
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing here is required to carry mail, and that is exactly why it scores twenty.</b> RFC
/// 3207 makes TLS between MTAs opportunistic — "A publicly-referenced SMTP server MUST NOT
/// require use of the STARTTLS extension in order to deliver mail locally" — so a server with no
/// certificate at all still exchanges mail with most of the internet. What it cannot do is
/// satisfy MTA-STS, DANE, or any mail client, and each of those failures is silent from this
/// side: the sender's report shows it, the receiver's does not.
/// </para>
/// <para>
/// So these checks judge against RFC 8461 §4.2's bar rather than RFC 3207's — "The certificate
/// presented by the receiving MTA MUST not be expired and MUST chain to a root CA that is
/// trusted by the Sending MTA. The certificate MUST have a subject alternative name (SAN)
/// [RFC5280] with a DNS-ID [RFC6125] matching the hostname" — because that is the bar the
/// senders who care are applying.
/// </para>
/// </remarks>
public static class TlsChecks
{
    /// <summary>The certificate-installed check's id.</summary>
    public const string CertificateInstalledId = "tls.certificate-installed";

    /// <summary>The certificate-covers-hostname check's id.</summary>
    public const string CertificateCoversHostnameId = "tls.certificate-covers-hostname";

    /// <summary>The certificate-trusted check's id.</summary>
    public const string CertificateTrustedId = "tls.certificate-trusted";

    /// <summary>The certificate-expiry check's id.</summary>
    public const string CertificateExpiryId = "tls.certificate-expiry";

    /// <summary>The renewal-health check's id.</summary>
    public const string RenewalHealthId = "tls.renewal-health";

    /// <summary>The STARTTLS-offered check's id.</summary>
    public const string StartTlsOfferedId = "tls.starttls-offered";

    /// <summary>Judges a set of observations. Pure.</summary>
    public static IReadOnlyList<DeliverabilityCheck> Evaluate(TlsFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(facts.RenewalPolicy);

        return
        [
            CertificateInstalled(facts),
            CertificateCoversHostname(facts),
            CertificateTrusted(facts),
            CertificateExpiry(facts),
            RenewalHealth(facts),
            StartTlsOffered(facts),
        ];
    }

    /// <summary>A certificate is bound to the SMTP listeners.</summary>
    private static DeliverabilityCheck CertificateInstalled(TlsFacts facts)
    {
        const string Id = CertificateInstalledId;
        const string Title = "A TLS certificate is installed";
        const int Weight = 3;

        if (facts.Certificate is not { } certificate)
        {
            return Fail(
                Id,
                Title,
                Weight,
                "No certificate is bound to the SMTP listeners, so this server cannot offer TLS " +
                "at all. Mail still flows in clear text to senders that allow it, and not at " +
                "all to any that require TLS.",
                DeliverabilityEvidence.Missing("A certificate covering " + facts.Hostname.Value),
                $"Obtain a certificate for {facts.Hostname.Value} — this server can request one " +
                "over ACME — and bind it to the SMTP listeners.");
        }

        return Pass(
            Id,
            Title,
            Weight,
            $"A certificate issued by {certificate.Issuer} is installed.",
            new DeliverabilityEvidence(
                $"A certificate covering {facts.Hostname.Value}",
                $"{certificate.Subject}, issued by {certificate.Issuer}"));
    }

    /// <summary>
    /// The certificate names the host this server calls itself.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §4.2: "The certificate MUST have a subject alternative name (SAN) [RFC5280] with
    /// a DNS-ID [RFC6125] matching the hostname, per the rules given in [RFC6125]." The matching
    /// itself lives on <see cref="Entities.Certificate.Covers"/>, which is where the wildcard
    /// rules are already tested.
    /// </remarks>
    private static DeliverabilityCheck CertificateCoversHostname(TlsFacts facts)
    {
        const string Id = CertificateCoversHostnameId;
        const string Title = "The certificate covers this server's hostname";
        const int Weight = 3;

        if (facts.Certificate is not { } certificate)
        {
            return Unmeasured(Id, Title, Weight, "There is no certificate to check the name of.");
        }

        string names = string.Join(", ", certificate.SubjectAlternativeNames.Select(n => n.Value));

        DeliverabilityEvidence evidence = new(
            $"A subjectAltName matching {facts.Hostname.Value}",
            names.Length == 0 ? null : names);

        return certificate.Covers(facts.Hostname)
            ? Pass(Id, Title, Weight, $"The certificate covers {facts.Hostname.Value}.", evidence)
            : Fail(
                Id,
                Title,
                Weight,
                $"The certificate does not name {facts.Hostname.Value}, which is the name this " +
                "server presents in EHLO. Senders enforcing MTA-STS will refuse to deliver, and " +
                "every mail client will warn.",
                evidence,
                $"Reissue the certificate with {facts.Hostname.Value} in its subjectAltName " +
                "list, or change this server's hostname to one the certificate covers.");
    }

    /// <summary>
    /// The chain builds to a trusted root.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A failure although nothing about plain SMTP requires it.</b> RFC 3207's opportunistic
    /// TLS means a self-signed certificate carries mail perfectly well to most of the internet,
    /// so an operator watching their queues sees no problem at all. What they do not see is RFC
    /// 8461 §4.2 — "MUST chain to a root CA that is trusted by the Sending MTA" — and §5's
    /// enforce mode, where "Sending MTAs MUST NOT deliver the message to hosts that fail MX
    /// matching or certificate validation". The mail that does not arrive leaves no trace here.
    /// </para>
    /// <para>
    /// Self-signed is named separately from merely untrusted because the remedy differs: one is
    /// a certificate to replace, the other is usually a missing intermediate in the chain the
    /// server serves.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck CertificateTrusted(TlsFacts facts)
    {
        const string Id = CertificateTrustedId;
        const string Title = "The certificate chains to a trusted root";
        const int Weight = 3;

        if (facts.Certificate is not { } certificate)
        {
            return Unmeasured(Id, Title, Weight, "There is no certificate to build a chain from.");
        }

        if (certificate.IsSelfSigned)
        {
            return Fail(
                Id,
                Title,
                Weight,
                "The certificate is self-signed. Mail still arrives from senders using " +
                "opportunistic TLS, so nothing looks wrong from here — but senders enforcing " +
                "MTA-STS must not deliver at all, and no mail client will connect without a " +
                "warning.",
                new DeliverabilityEvidence("A certificate from a public CA", "self-signed"),
                $"Obtain a certificate for {facts.Hostname.Value} from a public CA. This server " +
                "can request one over ACME at no cost.");
        }

        DeliverabilityEvidence evidence = new(
            "A chain to a trusted root",
            facts.Chain switch
            {
                CertificateChainStatus.Trusted => "chain builds",
                CertificateChainStatus.Revoked => "revoked by the issuer",
                CertificateChainStatus.Untrusted => "chain does not build",
                _ => null,
            });

        return facts.Chain switch
        {
            CertificateChainStatus.Trusted =>
                Pass(Id, Title, Weight, "The chain builds to a trusted root.", evidence),

            // Its own finding because the remedy shares nothing with the others: there is no
            // chain to repair and no certificate to keep. A revoked certificate is also the one
            // state here that gets worse on its own, as the revocation propagates.
            CertificateChainStatus.Revoked => Fail(
                Id,
                Title,
                Weight,
                "The issuer has revoked this certificate. Every client that checks will refuse " +
                "it, and more of them will as the revocation propagates.",
                evidence,
                "Reissue the certificate and install the new one. If you did not ask for the " +
                "revocation, treat the private key as compromised."),

            CertificateChainStatus.Untrusted => Fail(
                Id,
                Title,
                Weight,
                "The certificate's chain does not build to a trusted root, so senders enforcing " +
                "MTA-STS will refuse to deliver. The usual cause is an intermediate certificate " +
                "the server does not send, which the issuer's own tooling installs and a manual " +
                "copy does not.",
                evidence,
                "Install the issuer's intermediate certificates alongside the leaf, so the whole " +
                "chain is presented during the handshake."),

            _ => Unmeasured(Id, Title, Weight, "The chain was not built."),
        };
    }

    /// <summary>
    /// The certificate is valid now and not about to stop being so.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §4.2 opens with it: the certificate "MUST not be expired". Expiry is a failure
    /// and the renewal window a warning, because the window exists precisely so there is time to
    /// act — a warning that arrived only once the certificate had expired would be no use.
    /// </remarks>
    private static DeliverabilityCheck CertificateExpiry(TlsFacts facts)
    {
        const string Id = CertificateExpiryId;
        const string Title = "The certificate is valid and not near expiry";
        const int Weight = 3;

        if (facts.Certificate is not { } certificate)
        {
            return Unmeasured(Id, Title, Weight, "There is no certificate to date.");
        }

        int days = certificate.DaysRemaining(facts.Now);

        DeliverabilityEvidence evidence = new(
            $"More than {facts.RenewalPolicy.RenewalWindowDays} days remaining",
            $"expires {certificate.NotAfterUtc:yyyy-MM-dd}");

        if (facts.Now >= certificate.NotAfterUtc)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"The certificate expired on {certificate.NotAfterUtc:yyyy-MM-dd}. Every client " +
                "that checks will refuse it, and senders enforcing MTA-STS will not deliver.",
                evidence,
                "Renew the certificate now.");
        }

        if (facts.Now < certificate.NotBeforeUtc)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"The certificate is not valid until {certificate.NotBeforeUtc:yyyy-MM-dd}. " +
                "Until then it is refused exactly as an expired one is; if that date looks " +
                "wrong, this server's clock is the thing to check.",
                evidence with { Expected = "A certificate valid now" },
                "Check this server's clock, and install a certificate that is valid today.");
        }

        return days <= facts.RenewalPolicy.RenewalWindowDays
            ? Warn(
                Id,
                Title,
                Weight,
                $"The certificate expires in {days} day(s), inside the {facts.RenewalPolicy.RenewalWindowDays}-day " +
                "renewal window.",
                evidence,
                "Renew it now, or check why automatic renewal has not already run.")
            : Pass(Id, Title, Weight, $"The certificate is valid for {days} more day(s).", evidence);
    }

    /// <summary>
    /// Renewal will happen without anybody remembering to do it.
    /// </summary>
    /// <remarks>
    /// <b>Judged only for certificates this server can re-obtain.</b> A certificate installed by
    /// hand has no renewal process to be healthy or unhealthy, and inventing a finding about one
    /// would tell an operator to fix something that does not exist. The expiry check still
    /// watches the outcome for them.
    /// </remarks>
    private static DeliverabilityCheck RenewalHealth(TlsFacts facts)
    {
        const string Id = RenewalHealthId;
        const string Title = "Certificate renewal is automatic and healthy";
        const int Weight = 1;

        if (facts.Certificate is not { } certificate)
        {
            return Unmeasured(Id, Title, Weight, "There is no certificate to renew.");
        }

        if (certificate.Source is not CertificateSource.Acme)
        {
            return Unmeasured(
                Id,
                Title,
                Weight,
                "This certificate was not obtained over ACME, so this server cannot renew it and " +
                "there is no renewal process to judge.");
        }

        if (certificate.LastRenewalError is { Length: > 0 } error)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"The last renewal attempt failed: {error}. Left alone, the certificate expires " +
                "and TLS stops.",
                new DeliverabilityEvidence("A renewal that succeeded", error),
                "Resolve the cause and run a renewal, rather than waiting for the next scheduled " +
                "attempt to fail the same way.");
        }

        DeliverabilityEvidence evidence = new(
            "Automatic renewal enabled",
            certificate.AutoRenew ? "enabled" : "disabled");

        return certificate.AutoRenew
            ? Pass(Id, Title, Weight, "Automatic renewal is enabled and has not failed.", evidence)
            : Warn(
                Id,
                Title,
                Weight,
                "Automatic renewal is switched off for an ACME certificate, so it will expire " +
                "unless somebody renews it by hand.",
                evidence,
                "Switch automatic renewal back on, unless something else is renewing this " +
                "certificate.");
    }

    /// <summary>
    /// The server advertises STARTTLS.
    /// </summary>
    /// <remarks>
    /// RFC 3207 forbids <i>requiring</i> it — "A publicly-referenced SMTP server MUST NOT require
    /// use of the STARTTLS extension in order to deliver mail locally" — and says nothing against
    /// offering it. A server that does not offer it takes every message in clear text and fails
    /// MTA-STS §5's enforce mode outright: senders "MUST NOT deliver the message to hosts […]
    /// that do not support STARTTLS".
    /// </remarks>
    private static DeliverabilityCheck StartTlsOffered(TlsFacts facts)
    {
        const string Id = StartTlsOfferedId;
        const string Title = "STARTTLS is offered on port 25";
        const int Weight = 1;

        if (facts.StartTlsOffered is not { } offered)
        {
            return Unmeasured(Id, Title, Weight, "The SMTP listener was not probed.");
        }

        DeliverabilityEvidence evidence = new(
            "STARTTLS in the EHLO response",
            offered ? "advertised" : "not advertised");

        return offered
            ? Pass(Id, Title, Weight, "The server advertises STARTTLS.", evidence)
            : Fail(
                Id,
                Title,
                Weight,
                "The server does not advertise STARTTLS, so every message arrives in clear text " +
                "and senders enforcing MTA-STS will not deliver at all.",
                evidence,
                "Enable STARTTLS on the port 25 listener. Do not require it there — RFC 3207 " +
                "forbids that for a publicly-referenced server.");
    }

    // -------------------------------------------------------------------------------------------
    // Shared.
    // -------------------------------------------------------------------------------------------

    private static DeliverabilityCheck Pass(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence) =>
        new(id, DeliverabilityCategory.Tls, title, weight, DeliverabilityOutcome.Pass, detail, evidence);

    private static DeliverabilityCheck Warn(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Tls, title, weight, DeliverabilityOutcome.Warn, detail, evidence, remedy);

    private static DeliverabilityCheck Fail(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Tls, title, weight, DeliverabilityOutcome.Fail, detail, evidence, remedy);

    private static DeliverabilityCheck Unmeasured(string id, string title, int weight, string detail) =>
        new(id, DeliverabilityCategory.Tls, title, weight, DeliverabilityOutcome.Inconclusive, detail);
}
