using MailServer.Domain.Deliverability;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

public sealed class TlsCheckTests
{
    private static readonly DomainName Hostname = DomainName.Parse("mail.example.com");
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly CertificateRenewalPolicy Policy = new();

    private static Certificate Cert(
        CertificateSource source = CertificateSource.Acme,
        int validForDays = 90,
        int issuedDaysAgo = 10,
        params string[] sans) =>
        Certificate.Register(
            CertificateThumbprint.Parse(new string('A', 40)),
            "CN=mail.example.com",
            source == CertificateSource.SelfSigned ? "CN=mail.example.com" : "CN=Test CA",
            "01",
            (sans.Length == 0 ? ["mail.example.com"] : sans).Select(CertificateSubjectName.Parse),
            source,
            CertificateKeyLocation.InWindowsStore(CertificateThumbprint.Parse(new string('A', 40))),
            Now.AddDays(-issuedDaysAgo),
            Now.AddDays(validForDays - issuedDaysAgo),
            Now);

    /// <summary>
    /// A correct configuration, with one aspect replaced.
    /// </summary>
    /// <remarks>
    /// The <see cref="Certificate"/> parameter cannot express "no certificate installed", since
    /// null there means "leave this correct" as everywhere else in this project — so the two
    /// tests that need that build <see cref="TlsFacts"/> directly.
    /// </remarks>
    private static TlsFacts Facts(
        Certificate? certificate = null,
        CertificateChainStatus chain = CertificateChainStatus.Trusted,
        bool? startTls = true,
        DateTimeOffset? now = null) =>
        new(Hostname, certificate ?? Cert(), chain, startTls, Policy, now ?? Now);

    private static DeliverabilityCheck Check(TlsFacts facts, string id) =>
        TlsChecks.Evaluate(facts).Single(c => c.Id == id);

    // ---------------------------------------------------------------------------------------
    // Shape.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Every_tls_check_is_in_the_tls_category()
    {
        foreach (DeliverabilityCheck check in TlsChecks.Evaluate(Facts()))
        {
            check.Category.ShouldBe(DeliverabilityCategory.Tls);
        }
    }

    /// <summary>
    /// Fourteen of the category's twenty points.
    /// </summary>
    /// <remarks>
    /// The remaining six are MTA-STS and TLS-RPT, which judge published records rather than the
    /// certificate and land separately.
    /// </remarks>
    [Fact]
    public void The_certificate_and_starttls_weights_sum_to_fourteen()
    {
        TlsChecks.Evaluate(Facts()).Sum(c => c.Weight).ShouldBe(14);
    }

    [Fact]
    public void Tls_check_ids_are_unique()
    {
        IReadOnlyList<DeliverabilityCheck> checks = TlsChecks.Evaluate(Facts());

        checks.Select(c => c.Id).Distinct().Count().ShouldBe(checks.Count);
    }

    [Fact]
    public void A_correctly_configured_server_passes_every_tls_check()
    {
        foreach (DeliverabilityCheck check in TlsChecks.Evaluate(Facts()))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Pass, check.Id);
        }
    }

    /// <summary>Anything that is not a pass says what to do about it.</summary>
    [Fact]
    public void Every_tls_finding_carries_a_remedy()
    {
        TlsFacts[] broken =
        [
            new(Hostname, null, CertificateChainStatus.Trusted, true, Policy, Now),
            Facts(certificate: Cert(sans: "other.example.net")),
            Facts(certificate: Cert(source: CertificateSource.SelfSigned)),
            Facts(chain: CertificateChainStatus.Untrusted),
            Facts(now: Now.AddDays(100)),
            Facts(now: Now.AddDays(-20)),
            Facts(certificate: Cert(validForDays: 20)),
            Facts(startTls: false),
        ];

        foreach (TlsFacts facts in broken)
        {
            foreach (DeliverabilityCheck check in TlsChecks.Evaluate(facts))
            {
                if (check.Outcome is DeliverabilityOutcome.Warn or DeliverabilityOutcome.Fail)
                {
                    check.Remedy.ShouldNotBeNullOrWhiteSpace(check.Id);
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Installation.
    // ---------------------------------------------------------------------------------------

    /// <summary>No certificate fails, and leaves the checks about one unjudged.</summary>
    [Fact]
    public void No_certificate_fails_and_leaves_the_rest_unjudged()
    {
        TlsFacts facts = new(Hostname, null, CertificateChainStatus.Trusted, true, Policy, Now);

        Check(facts, TlsChecks.CertificateInstalledId).Outcome.ShouldBe(DeliverabilityOutcome.Fail);

        foreach (string id in new[]
                 {
                     TlsChecks.CertificateCoversHostnameId,
                     TlsChecks.CertificateTrustedId,
                     TlsChecks.CertificateExpiryId,
                     TlsChecks.RenewalHealthId,
                 })
        {
            Check(facts, id).Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, id);
        }
    }

    /// <summary>STARTTLS is probed on the wire, so it is still judged with no certificate.</summary>
    [Fact]
    public void Starttls_is_still_judged_without_a_certificate()
    {
        Check(new TlsFacts(Hostname, null, CertificateChainStatus.Trusted, false, Policy, Now), TlsChecks.StartTlsOfferedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    // ---------------------------------------------------------------------------------------
    // The name.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A certificate that does not name this host fails.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §4.2: "The certificate MUST have a subject alternative name (SAN) [RFC5280] with
    /// a DNS-ID [RFC6125] matching the hostname, per the rules given in [RFC6125]."
    /// </remarks>
    [Fact]
    public void A_certificate_that_does_not_name_this_host_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(certificate: Cert(sans: "webmail.example.com")),
            TlsChecks.CertificateCoversHostnameId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence.ShouldNotBeNull().Found.ShouldNotBeNull().ShouldContain("webmail.example.com");
    }

    /// <summary>Being one name among several is enough.</summary>
    [Fact]
    public void A_certificate_naming_this_host_among_others_passes()
    {
        Check(
                Facts(certificate: Cert(sans: ["webmail.example.com", "mail.example.com"])),
                TlsChecks.CertificateCoversHostnameId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>A wildcard covering this host passes, as RFC 6125's rules allow.</summary>
    [Fact]
    public void A_wildcard_certificate_covering_this_host_passes()
    {
        Check(Facts(certificate: Cert(sans: "*.example.com")), TlsChecks.CertificateCoversHostnameId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    // ---------------------------------------------------------------------------------------
    // Trust.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A self-signed certificate fails although plain SMTP accepts it.
    /// </summary>
    /// <remarks>
    /// The whole reason this category is weighted at twenty. RFC 3207's opportunistic TLS means
    /// mail keeps arriving, so nothing looks wrong from this side — while RFC 8461 §5's enforce
    /// mode says senders "MUST NOT deliver the message to hosts that fail MX matching or
    /// certificate validation". The mail that does not arrive leaves no trace here.
    /// </remarks>
    [Fact]
    public void A_self_signed_certificate_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(certificate: Cert(source: CertificateSource.SelfSigned)),
            TlsChecks.CertificateTrustedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("self-signed");
        check.Remedy.ShouldNotBeNull().ShouldContain("ACME");
    }

    /// <summary>
    /// A CA-issued certificate whose chain does not build gets a different remedy.
    /// </summary>
    /// <remarks>
    /// Same outcome, different fault: the near-universal cause is an intermediate the server
    /// does not send, which the issuer's tooling installs and a manual copy does not. Telling
    /// that operator to "get a certificate from a public CA" would be advice they have already
    /// followed.
    /// </remarks>
    [Fact]
    public void An_untrusted_chain_is_reported_separately_from_a_self_signed_certificate()
    {
        DeliverabilityCheck check = Check(Facts(chain: CertificateChainStatus.Untrusted), TlsChecks.CertificateTrustedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("intermediate");
        check.Remedy.ShouldNotBeNull().ShouldContain("intermediate");
    }

    /// <summary>
    /// A revoked certificate is its own finding, with its own remedy.
    /// </summary>
    /// <remarks>
    /// It shares nothing with the other two: there is no chain to repair and no certificate to
    /// keep. It is also the one state here that gets worse on its own, as the revocation
    /// propagates — and if the operator did not ask for it, the private key is the real news.
    /// </remarks>
    [Fact]
    public void A_revoked_certificate_is_reported_as_revoked()
    {
        DeliverabilityCheck check = Check(
            Facts(chain: CertificateChainStatus.Revoked),
            TlsChecks.CertificateTrustedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("revoked");
        check.Remedy.ShouldNotBeNull().ShouldContain("compromised");
        check.Detail.ShouldNotContain("intermediate");
    }

    /// <summary>
    /// A chain that was not built leaves the check unjudged.
    /// </summary>
    /// <remarks>
    /// Chain building needs the platform trust store and the network. A report that assumed
    /// either way would be inventing the answer.
    /// </remarks>
    [Fact]
    public void An_unbuilt_chain_leaves_trust_unjudged()
    {
        Check(Facts(chain: CertificateChainStatus.NotBuilt), TlsChecks.CertificateTrustedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// Self-signed is decided without the chain, since the answer cannot depend on it.
    /// </summary>
    /// <remarks>
    /// A self-signed certificate never chains to a public root, so waiting for a chain result to
    /// say so would leave the most common misconfiguration of all unjudged whenever the trust
    /// store was unavailable.
    /// </remarks>
    [Fact]
    public void A_self_signed_certificate_fails_even_with_no_chain_result()
    {
        Check(
                Facts(certificate: Cert(source: CertificateSource.SelfSigned), chain: CertificateChainStatus.NotBuilt),
                TlsChecks.CertificateTrustedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    // ---------------------------------------------------------------------------------------
    // Expiry.
    // ---------------------------------------------------------------------------------------

    /// <summary>An expired certificate fails. RFC 8461 §4.2: it "MUST not be expired".</summary>
    [Fact]
    public void An_expired_certificate_fails()
    {
        DeliverabilityCheck check = Check(Facts(now: Now.AddDays(100)), TlsChecks.CertificateExpiryId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("expired");
    }

    /// <summary>
    /// A certificate inside the renewal window warns.
    /// </summary>
    /// <remarks>
    /// The window exists so there is time to act. A warning that arrived only once the
    /// certificate had expired would be no use at all.
    /// </remarks>
    [Fact]
    public void A_certificate_inside_the_renewal_window_warns()
    {
        Check(Facts(certificate: Cert(validForDays: 35, issuedDaysAgo: 20)), TlsChecks.CertificateExpiryId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>
    /// A not-yet-valid certificate fails, and names the clock.
    /// </summary>
    /// <remarks>
    /// It is refused exactly as an expired one is, and the overwhelmingly likely cause is this
    /// server's clock rather than the certificate — so the finding says so, because an operator
    /// told only "not valid until" will go and reissue a perfectly good certificate.
    /// </remarks>
    [Fact]
    public void A_not_yet_valid_certificate_fails_and_names_the_clock()
    {
        DeliverabilityCheck check = Check(Facts(now: Now.AddDays(-20)), TlsChecks.CertificateExpiryId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("clock");
    }

    /// <summary>A certificate with plenty of life passes.</summary>
    [Fact]
    public void A_certificate_well_inside_its_validity_passes()
    {
        Check(Facts(certificate: Cert(validForDays: 90, issuedDaysAgo: 1)), TlsChecks.CertificateExpiryId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    // ---------------------------------------------------------------------------------------
    // Renewal.
    // ---------------------------------------------------------------------------------------

    /// <summary>An ACME certificate renewing automatically passes.</summary>
    [Fact]
    public void An_acme_certificate_with_automatic_renewal_passes()
    {
        Check(Facts(), TlsChecks.RenewalHealthId).Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// A certificate this server cannot renew has no renewal process to judge.
    /// </summary>
    /// <remarks>
    /// Inventing a finding about a process that does not exist would tell an operator to fix
    /// nothing. The expiry check still watches the outcome for them.
    /// </remarks>
    [Theory]
    [InlineData(CertificateSource.SelfSigned)]
    [InlineData(CertificateSource.ImportedPfx)]
    [InlineData(CertificateSource.WindowsStore)]
    public void A_certificate_this_server_cannot_renew_leaves_renewal_unjudged(CertificateSource source)
    {
        Check(Facts(certificate: Cert(source: source)), TlsChecks.RenewalHealthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>Renewal switched off for an ACME certificate warns.</summary>
    [Fact]
    public void Automatic_renewal_switched_off_warns()
    {
        Certificate certificate = Cert();

        certificate.SetAutoRenew(false, Now);

        Check(Facts(certificate: certificate), TlsChecks.RenewalHealthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>
    /// A failed renewal fails, and the finding carries the reason.
    /// </summary>
    /// <remarks>
    /// Left alone it ends in expiry, and the reason is the only part an operator can act on —
    /// "renewal failed" without it sends them to read logs this report has already read.
    /// </remarks>
    [Fact]
    public void A_failed_renewal_fails_and_carries_the_reason()
    {
        Certificate certificate = Cert();

        certificate.FailRenewal("the DNS-01 challenge was not answered", Now);

        DeliverabilityCheck check = Check(Facts(certificate: certificate), TlsChecks.RenewalHealthId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("DNS-01");
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A server that does not advertise STARTTLS fails.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §5's enforce mode: senders "MUST NOT deliver the message to hosts that fail MX
    /// matching or certificate validation or that do not support STARTTLS."
    /// </remarks>
    [Fact]
    public void Not_advertising_starttls_fails()
    {
        Check(Facts(startTls: false), TlsChecks.StartTlsOfferedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// The remedy does not tell an operator to require STARTTLS.
    /// </summary>
    /// <remarks>
    /// RFC 3207: "A publicly-referenced SMTP server MUST NOT require use of the STARTTLS
    /// extension in order to deliver mail locally. This rule prevents the STARTTLS extension
    /// from damaging the interoperability of the Internet's SMTP infrastructure." A remedy that
    /// said "require TLS" would be telling the operator to break inbound mail in the name of
    /// securing it.
    /// </remarks>
    [Fact]
    public void The_starttls_remedy_says_not_to_require_it()
    {
        Check(Facts(startTls: false), TlsChecks.StartTlsOfferedId)
            .Remedy.ShouldNotBeNull().ShouldContain("Do not require it");
    }

    /// <summary>An unprobed listener leaves the check unjudged.</summary>
    [Fact]
    public void An_unprobed_listener_leaves_starttls_unjudged()
    {
        Check(Facts(startTls: null), TlsChecks.StartTlsOfferedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    // ---------------------------------------------------------------------------------------
    // The category as a whole.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A server with no certificate is Not ready, whatever else it scores.
    /// </summary>
    /// <remarks>
    /// The readiness verdict is the worst outcome present, never arithmetic — a comfortable
    /// number beside a failing certificate is exactly the report that gets skimmed.
    /// </remarks>
    [Fact]
    public void A_server_with_no_certificate_is_not_ready()
    {
        DeliverabilityReport report = DeliverabilityReport.From(
            TlsChecks.Evaluate(new TlsFacts(Hostname, null, CertificateChainStatus.Trusted, true, Policy, Now)),
            Now);

        report.Readiness.ShouldBe(DeliverabilityReadiness.NotReady);
    }
}
