using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.Entities;

/// <summary>
/// The certificate aggregate: coverage matching, status derivation, and the rules about which
/// sources may renew themselves.
/// </summary>
public sealed class CertificateTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static readonly CertificateRenewalPolicy Policy = new();

    private static Certificate Create(
        string[] sans,
        CertificateSource source = CertificateSource.Acme,
        int validForDays = 90,
        int issuedDaysAgo = 0) =>
        Certificate.Register(
            CertificateThumbprint.Parse(new string('A', 40)),
            "CN=mail.example.com",
            source == CertificateSource.SelfSigned ? "CN=mail.example.com" : "CN=Test CA",
            "01",
            sans.Select(CertificateSubjectName.Parse),
            source,
            CertificateKeyLocation.InWindowsStore(CertificateThumbprint.Parse(new string('A', 40))),
            Now.AddDays(-issuedDaysAgo),
            Now.AddDays(validForDays - issuedDaysAgo),
            Now);

    // ---- Coverage -------------------------------------------------------------------------

    [Fact]
    public void An_exact_san_covers_the_hostname()
    {
        Certificate certificate = Create(["mail.example.com"]);

        certificate.Covers(DomainName.Parse("mail.example.com")).ShouldBeTrue();
    }

    [Fact]
    public void A_different_hostname_is_not_covered()
    {
        Certificate certificate = Create(["mail.example.com"]);

        certificate.Covers(DomainName.Parse("imap.example.com")).ShouldBeFalse();
    }

    [Fact]
    public void Every_san_is_consulted_not_only_the_first()
    {
        Certificate certificate = Create(
            ["mail.example.com", "imap.example.com", "smtp.example.com"]);

        certificate.Covers(DomainName.Parse("smtp.example.com")).ShouldBeTrue();
    }

    [Fact]
    public void A_wildcard_covers_one_label()
    {
        Certificate certificate = Create(["*.example.com"]);

        certificate.Covers(DomainName.Parse("mail.example.com")).ShouldBeTrue();
    }

    /// <summary>
    /// RFC 6125 §6.4.3: a wildcard matches exactly one label. Matching more would report
    /// coverage that no real client honours, so the dashboard would say Healthy while clients
    /// showed name-mismatch warnings.
    /// </summary>
    [Fact]
    public void A_wildcard_does_not_cover_two_labels()
    {
        Certificate certificate = Create(["*.example.com"]);

        certificate.Covers(DomainName.Parse("a.b.example.com")).ShouldBeFalse();
    }

    [Fact]
    public void A_wildcard_does_not_cover_the_bare_domain()
    {
        Certificate certificate = Create(["*.example.com"]);

        certificate.Covers(DomainName.Parse("example.com")).ShouldBeFalse();
    }

    [Fact]
    public void A_wildcard_does_not_cover_a_different_parent()
    {
        Certificate certificate = Create(["*.example.com"]);

        certificate.Covers(DomainName.Parse("mail.example.org")).ShouldBeFalse();
        certificate.Covers(DomainName.Parse("mail.notexample.com")).ShouldBeFalse();
    }

    /// <summary>
    /// A partial-label wildcard is refused at the value object rather than accepted and then
    /// quietly not matched. Support for it is inconsistent across clients, so a certificate
    /// relying on one covers nothing reliably.
    /// </summary>
    [Fact]
    public void A_partial_label_wildcard_is_refused()
    {
        Should.Throw<InvalidValueObjectException>(() => Create(["m*.example.com"]));
    }

    // ---- Status ---------------------------------------------------------------------------

    [Fact]
    public void A_fresh_certificate_is_healthy()
    {
        Certificate certificate = Create(["mail.example.com"]);

        certificate.GetStatus(Now, Policy).ShouldBe(CertificateStatus.Healthy);
    }

    [Fact]
    public void A_certificate_inside_the_renewal_window_is_expiring_soon()
    {
        Certificate certificate = Create(["mail.example.com"], validForDays: 20);

        certificate.GetStatus(Now, Policy).ShouldBe(CertificateStatus.ExpiringSoon);
    }

    [Fact]
    public void A_past_dated_certificate_is_expired()
    {
        Certificate certificate = Create(["mail.example.com"], validForDays: 90, issuedDaysAgo: 91);

        certificate.GetStatus(Now, Policy).ShouldBe(CertificateStatus.Expired);
    }

    [Fact]
    public void A_future_dated_certificate_is_invalid()
    {
        Certificate certificate = Certificate.Register(
            CertificateThumbprint.Parse(new string('B', 40)),
            "CN=mail.example.com",
            "CN=Test CA",
            "01",
            [CertificateSubjectName.Parse("mail.example.com")],
            CertificateSource.Acme,
            CertificateKeyLocation.InWindowsStore(CertificateThumbprint.Parse(new string('B', 40))),
            Now.AddDays(5),
            Now.AddDays(95),
            Now);

        certificate.GetStatus(Now, Policy).ShouldBe(CertificateStatus.Invalid);
    }

    [Fact]
    public void A_certificate_not_covering_its_binding_reports_a_hostname_mismatch()
    {
        Certificate certificate = Create(["mail.example.com"]);

        certificate
            .GetStatus(Now, Policy, [DomainName.Parse("imap.example.com")])
            .ShouldBe(CertificateStatus.HostnameMismatch);
    }

    [Fact]
    public void An_untrusted_chain_is_reported_as_untrusted()
    {
        Certificate certificate = Create(["mail.example.com"], CertificateSource.SelfSigned);

        certificate
            .GetStatus(Now, Policy, null, chainIsTrusted: false)
            .ShouldBe(CertificateStatus.Untrusted);
    }

    /// <summary>
    /// Worst-first ordering. An expired certificate that also fails to cover its hostname must
    /// report the expiry, because re-issuing with corrected SANs would not fix it.
    /// </summary>
    [Fact]
    public void Expiry_outranks_a_hostname_mismatch()
    {
        Certificate certificate = Create(
            ["mail.example.com"],
            validForDays: 90,
            issuedDaysAgo: 91);

        certificate
            .GetStatus(Now, Policy, [DomainName.Parse("imap.example.com")], chainIsTrusted: false)
            .ShouldBe(CertificateStatus.Expired);
    }

    [Fact]
    public void A_renewal_in_flight_is_reported_as_renewing()
    {
        Certificate certificate = Create(["mail.example.com"]);
        certificate.BeginRenewal(Now);

        certificate.GetStatus(Now, Policy).ShouldBe(CertificateStatus.Renewing);
    }

    // ---- Registration invariants ------------------------------------------------------------

    [Fact]
    public void A_certificate_with_no_sans_is_refused()
    {
        Should.Throw<DomainRuleViolationException>(() => Create([]))
            .Code.ShouldBe("certificate.no_subject_alternative_names");
    }

    [Fact]
    public void An_inverted_validity_window_is_refused()
    {
        Should.Throw<DomainRuleViolationException>(() => Certificate.Register(
            CertificateThumbprint.Parse(new string('C', 40)),
            "CN=mail.example.com",
            "CN=Test CA",
            "01",
            [CertificateSubjectName.Parse("mail.example.com")],
            CertificateSource.Acme,
            CertificateKeyLocation.InWindowsStore(CertificateThumbprint.Parse(new string('C', 40))),
            Now.AddDays(10),
            Now,
            Now)).Code.ShouldBe("certificate.validity_window_inverted");
    }

    // ---- Auto-renew -------------------------------------------------------------------------

    [Fact]
    public void An_acme_certificate_auto_renews_by_default()
    {
        Create(["mail.example.com"], CertificateSource.Acme).AutoRenew.ShouldBeTrue();
    }

    [Theory]
    [InlineData(CertificateSource.SelfSigned)]
    [InlineData(CertificateSource.ImportedPfx)]
    [InlineData(CertificateSource.WindowsStore)]
    public void A_source_this_server_cannot_reissue_does_not_auto_renew(CertificateSource source)
    {
        Create(["mail.example.com"], source).AutoRenew.ShouldBeFalse();
    }

    /// <summary>
    /// The switch must not merely default to off — it must be impossible to turn on, or it is
    /// a control that silently does nothing while the certificate expires.
    /// </summary>
    [Theory]
    [InlineData(CertificateSource.SelfSigned)]
    [InlineData(CertificateSource.ImportedPfx)]
    [InlineData(CertificateSource.WindowsStore)]
    public void Auto_renew_cannot_be_enabled_for_a_source_this_server_cannot_reissue(
        CertificateSource source)
    {
        Certificate certificate = Create(["mail.example.com"], source);

        Should.Throw<DomainRuleViolationException>(() => certificate.SetAutoRenew(true, Now))
            .Code.ShouldBe("certificate.auto_renew.unsupported_source");
    }

    // ---- Renewal outcome --------------------------------------------------------------------

    [Fact]
    public void A_failed_renewal_leaves_the_certificate_untouched()
    {
        Certificate certificate = Create(["mail.example.com"]);
        CertificateThumbprint before = certificate.Thumbprint;

        certificate.BeginRenewal(Now);
        certificate.FailRenewal("The ACME order was rejected.", Now);

        certificate.IsRenewing.ShouldBeFalse();
        certificate.LastRenewalError.ShouldBe("The ACME order was rejected.");

        // The point of the fallback policy: nothing about the serving certificate changed.
        certificate.Thumbprint.ShouldBe(before);
        certificate.NotAfterUtc.ShouldBe(Now.AddDays(90));
        certificate.Source.ShouldBe(CertificateSource.Acme);
    }

    [Fact]
    public void A_successful_renewal_clears_the_previous_error()
    {
        Certificate certificate = Create(["mail.example.com"]);

        certificate.FailRenewal("A transient DNS failure.", Now);
        certificate.CompleteRenewal(Now.AddHours(1));

        certificate.LastRenewalError.ShouldBeNull();
        certificate.LastRenewalUtc.ShouldBe(Now.AddHours(1));
    }

    [Fact]
    public void Days_remaining_is_negative_once_expired()
    {
        Certificate certificate = Create(["mail.example.com"], validForDays: 90, issuedDaysAgo: 100);

        certificate.DaysRemaining(Now).ShouldBe(-10);
        certificate.IsCurrentlyValid(Now).ShouldBeFalse();
    }
}
