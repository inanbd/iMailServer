using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Certificates;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Certificates.Tests;

/// <summary>
/// The self-signed generator, against real BCL certificate generation.
/// </summary>
/// <remarks>
/// <para>
/// Milestone 3's stated exit criterion is "generate a self-signed certificate with correct
/// SANs and EKU", so these tests read the extensions back out of the generated certificate
/// rather than trusting that the builder was called correctly.
/// </para>
/// <para>
/// Every extension asserted here is one whose absence produces a certificate that looks fine
/// in a viewer and fails in the field: no SANs means no client accepts it, no basic
/// constraints means some validators treat it as a CA, no key usage means some TLS stacks
/// refuse the handshake outright.
/// </para>
/// </remarks>
public sealed class SelfSignedGenerationTests
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static SelfSignedCertificateGenerator CreateGenerator() =>
        new(new FixedClock(Now), NullLogger<SelfSignedCertificateGenerator>.Instance);

    private static IssuedCertificate Generate(
        string[] hostnames,
        int keySize = 2048,
        int years = 1) =>
        CreateGenerator().Generate(new SelfSignedCertificateRequest(
            [.. hostnames.Select(DomainName.Parse)],
            keySize,
            years));

    // ---- Subject alternative names ----------------------------------------------------------

    [Fact]
    public void Every_hostname_appears_in_the_subject_alternative_name_extension()
    {
        using IssuedCertificate issued =
            Generate(["mail.example.com", "imap.example.com", "smtp.example.com"]);

        List<string> dnsNames = ReadDnsNames(issued.Certificate);

        dnsNames.ShouldBe(["mail.example.com", "imap.example.com", "smtp.example.com"], ignoreOrder: true);
    }

    /// <summary>
    /// RFC 6125 deprecated common-name matching and current clients ignore the CN entirely, so
    /// a certificate whose hostname appears only there covers nothing.
    /// </summary>
    [Fact]
    public void A_single_hostname_still_gets_a_subject_alternative_name()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        ReadDnsNames(issued.Certificate).ShouldHaveSingleItem().ShouldBe("mail.example.com");
    }

    [Fact]
    public void The_first_hostname_becomes_the_subject()
    {
        using IssuedCertificate issued = Generate(["mail.example.com", "imap.example.com"]);

        issued.Certificate.Subject.ShouldBe("CN=mail.example.com");
    }

    /// <summary>
    /// A SAN dNSName is an IA5String, so an internationalised name must be written in its
    /// A-label form. A U-label would be rejected by strict parsers and mis-compared by lenient
    /// ones.
    /// </summary>
    [Fact]
    public void An_internationalized_hostname_is_written_in_ascii_form()
    {
        using IssuedCertificate issued = Generate(["bücher.example"]);

        ReadDnsNames(issued.Certificate).ShouldHaveSingleItem().ShouldBe("xn--bcher-kva.example");
    }

    // ---- Extended key usage -----------------------------------------------------------------

    [Fact]
    public void The_extended_key_usage_is_server_authentication_only()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        X509EnhancedKeyUsageExtension eku = issued.Certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .ShouldHaveSingleItem();

        List<string> oids = [.. eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value!)];

        // Exactly one. A mail server's certificate has no reason to also be usable for client
        // authentication or code signing, and the narrowest grant that works is the right one.
        oids.ShouldHaveSingleItem().ShouldBe(ServerAuthenticationOid);
    }

    // ---- Basic constraints ------------------------------------------------------------------

    [Fact]
    public void The_certificate_is_marked_as_an_end_entity_and_the_marking_is_critical()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        X509BasicConstraintsExtension constraints = issued.Certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .ShouldHaveSingleItem();

        constraints.CertificateAuthority.ShouldBeFalse();

        // Critical, so a validator that does not understand the extension must reject the
        // certificate rather than ignore it. A self-signed certificate that could sign others
        // is a considerably worse thing to leave on disk.
        constraints.Critical.ShouldBeTrue();
    }

    // ---- Key usage --------------------------------------------------------------------------

    [Fact]
    public void The_key_usage_covers_both_key_exchange_modes_and_is_critical()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        X509KeyUsageExtension usage = issued.Certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .ShouldHaveSingleItem();

        // DigitalSignature for ECDHE, KeyEncipherment for RSA key transport. Omitting either
        // makes some TLS stacks refuse the handshake.
        usage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature).ShouldBeTrue();
        usage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment).ShouldBeTrue();
        usage.Critical.ShouldBeTrue();
    }

    [Fact]
    public void A_subject_key_identifier_is_present()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        issued.Certificate.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .ShouldHaveSingleItem();
    }

    // ---- Key and signature ------------------------------------------------------------------

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    public void The_requested_key_size_is_produced(int keySize)
    {
        using IssuedCertificate issued = Generate(["mail.example.com"], keySize);

        using RSA? key = issued.Certificate.GetRSAPublicKey();

        key.ShouldNotBeNull();
        key.KeySize.ShouldBe(keySize);
    }

    [Fact]
    public void The_certificate_has_a_usable_private_key()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        // Without this the certificate cannot terminate TLS at all, whatever else is correct.
        issued.Certificate.HasPrivateKey.ShouldBeTrue();
    }

    [Fact]
    public void The_signature_algorithm_is_sha256()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        issued.Certificate.SignatureAlgorithm.FriendlyName
            .ShouldNotBeNull()
            .ShouldContain("sha256", Case.Insensitive);
    }

    [Fact]
    public void It_is_self_signed()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        issued.Certificate.Issuer.ShouldBe(issued.Certificate.Subject);
    }

    // ---- Validity ---------------------------------------------------------------------------

    /// <summary>
    /// Backdated by an hour, so a client whose clock is a minute behind does not see a
    /// freshly generated certificate as "not yet valid" — a fault that appears intermittent
    /// and resolves itself, which is the hardest kind to diagnose.
    /// </summary>
    [Fact]
    public void The_validity_window_starts_before_now_to_absorb_clock_skew()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        issued.NotBeforeUtc.ShouldBeLessThan(Now);
        (Now - issued.NotBeforeUtc).ShouldBeGreaterThanOrEqualTo(TimeSpan.FromMinutes(30));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    public void The_requested_validity_period_is_produced(int years)
    {
        using IssuedCertificate issued = Generate(["mail.example.com"], 2048, years);

        issued.NotAfterUtc.ShouldBe(Now.AddYears(years));
    }

    // ---- Refusals ---------------------------------------------------------------------------

    [Fact]
    public void A_request_with_no_hostnames_is_refused()
    {
        Should.Throw<ArgumentException>(() =>
            CreateGenerator().Generate(new SelfSignedCertificateRequest([])));
    }

    [Theory]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(8192)]
    public void An_unsupported_key_size_is_refused(int keySize)
    {
        // 1024 and below are rejected outright by current clients; above 4096 the handshake
        // cost grows faster than the security benefit, and a mail server performs many.
        Should.Throw<ArgumentOutOfRangeException>(() =>
            Generate(["mail.example.com"], keySize));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(10)]
    public void An_unsupported_validity_period_is_refused(int years)
    {
        Should.Throw<ArgumentOutOfRangeException>(() =>
            Generate(["mail.example.com"], 2048, years));
    }

    // ---- Reported metadata ------------------------------------------------------------------

    [Fact]
    public void The_reported_thumbprint_matches_the_certificate()
    {
        using IssuedCertificate issued = Generate(["mail.example.com"]);

        issued.Thumbprint.Value.ShouldBe(issued.Certificate.Thumbprint);
    }

    [Fact]
    public void The_reported_subject_names_match_the_extension()
    {
        using IssuedCertificate issued = Generate(["mail.example.com", "imap.example.com"]);

        issued.SubjectAlternativeNames
            .Select(static n => n.Value)
            .ShouldBe(ReadDnsNames(issued.Certificate), ignoreOrder: true);
    }

    [Fact]
    public void Two_certificates_for_the_same_hostname_have_different_keys()
    {
        using IssuedCertificate first = Generate(["mail.example.com"]);
        using IssuedCertificate second = Generate(["mail.example.com"]);

        // A reissue must never reuse a key. If it did, compromising one certificate's key
        // would compromise every certificate that succeeded it.
        first.Thumbprint.ShouldNotBe(second.Thumbprint);
    }

    private static List<string> ReadDnsNames(X509Certificate2 certificate)
    {
        List<string> names = [];

        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is X509SubjectAlternativeNameExtension san)
            {
                names.AddRange(san.EnumerateDnsNames());
            }
        }

        return names;
    }
}

/// <summary>A clock frozen at a known instant.</summary>
internal sealed class FixedClock(DateTimeOffset now) : IClock
{
    public DateTimeOffset UtcNow { get; } = now;

    public long GetTimestamp() => 0;

    public TimeSpan GetElapsedTime(long startingTimestamp) => TimeSpan.Zero;
}
