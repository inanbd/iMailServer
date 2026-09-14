using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Certificates;

/// <summary>
/// Generates self-signed certificates using <see cref="CertificateRequest"/> and
/// <see cref="RSA"/> from the BCL.
/// </summary>
/// <remarks>
/// <para>
/// No external dependency. Certificate generation is well covered by the framework, and a
/// third-party library here would add a supply-chain dependency to the one component that
/// handles private keys.
/// </para>
/// <para>
/// The extensions written are not decorative. Each one is required by at least one class of
/// client, and omitting any of them produces a certificate that fails in a way that is
/// tedious to diagnose:
/// </para>
/// <list type="bullet">
///   <item><description><b>subjectAltName</b> — RFC 6125 deprecated common-name matching, and
///   current clients ignore the CN entirely. A certificate without SANs covers no hostname at
///   all, however correct its subject looks in a certificate viewer.</description></item>
///   <item><description><b>Basic constraints CA=false, critical</b> — marks this as an end-entity
///   certificate. Without it some validators treat it as a potential CA, and a self-signed
///   certificate that could sign others is a considerably worse thing to have on disk.</description></item>
///   <item><description><b>Key usage, critical</b> — <c>DigitalSignature</c> for ECDHE key exchange
///   and <c>KeyEncipherment</c> for RSA key transport. A missing key usage makes some TLS stacks
///   refuse the handshake outright.</description></item>
///   <item><description><b>Extended key usage: server authentication only</b> — narrowest grant
///   that works. There is no reason for a mail server's certificate to also be usable for
///   client authentication or code signing.</description></item>
///   <item><description><b>Subject key identifier</b> — makes chain building deterministic and
///   makes the certificate legible to operators comparing it against a store entry.</description></item>
/// </list>
/// </remarks>
internal sealed class SelfSignedCertificateGenerator(
    IClock clock,
    ILogger<SelfSignedCertificateGenerator> logger)
{
    /// <summary>OID for TLS server authentication.</summary>
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>
    /// Backdated by this much, so a small clock difference between this server and a client
    /// does not make a certificate "not yet valid" for its first few minutes.
    /// </summary>
    /// <remarks>
    /// An hour is the conventional allowance. Without it, generating a certificate and
    /// immediately restarting the listener can fail on a client whose clock is a minute
    /// behind — a fault that appears intermittent and resolves itself, which is the hardest
    /// kind to diagnose.
    /// </remarks>
    private static readonly TimeSpan ClockSkewAllowance = TimeSpan.FromHours(1);

    public IssuedCertificate Generate(SelfSignedCertificateRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Hostnames.Count == 0)
        {
            throw new ArgumentException(
                "A certificate must cover at least one hostname; one with no subjectAltName " +
                "entries is not usable for TLS by any current client.",
                nameof(request));
        }

        if (!SelfSignedCertificateRequest.SupportedKeySizes.Contains(request.KeySizeBits))
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                request.KeySizeBits,
                "Supported RSA key sizes are " +
                string.Join(", ", SelfSignedCertificateRequest.SupportedKeySizes) + ".");
        }

        if (!SelfSignedCertificateRequest.SupportedValidityYears.Contains(request.ValidityYears))
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                request.ValidityYears,
                "Supported validity periods are " +
                string.Join(", ", SelfSignedCertificateRequest.SupportedValidityYears) +
                " years.");
        }

        DomainName primary = request.Hostnames[0];

        // Disposed after the certificate is created: CopyWithPrivateKey-style export below
        // takes its own copy of the key material.
        using RSA key = RSA.Create(request.KeySizeBits);

        CertificateRequest certificateRequest = new(
            new X500DistinguishedName($"CN={primary.Value}"),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        certificateRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        certificateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));

        certificateRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                [new Oid(ServerAuthenticationOid, "Server Authentication")],
                critical: false));

        SubjectAlternativeNameBuilder sanBuilder = new();
        List<CertificateSubjectName> sans = [];

        foreach (DomainName hostname in request.Hostnames)
        {
            // The A-label form, because a SAN dNSName is IA5String: a U-label would be
            // rejected by strict parsers and silently mis-compared by lenient ones.
            sanBuilder.AddDnsName(hostname.Value);
            sans.Add(CertificateSubjectName.FromHostname(hostname));
        }

        certificateRequest.CertificateExtensions.Add(sanBuilder.Build());

        certificateRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, critical: false));

        DateTimeOffset notBefore = clock.UtcNow - ClockSkewAllowance;
        DateTimeOffset notAfter = clock.UtcNow.AddYears(request.ValidityYears);

        X509Certificate2 certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);

        // Thumbprint and hostnames only. The key size and validity are safe to log; nothing
        // about the key itself ever is.
        logger.LogInformation(
            "Generated a self-signed certificate {Thumbprint} for {HostnameCount} hostname(s), " +
            "RSA {KeySize}, valid until {NotAfter:u}. This certificate is NOT publicly trusted.",
            certificate.Thumbprint,
            request.Hostnames.Count,
            request.KeySizeBits,
            notAfter);

        return new IssuedCertificate(
            certificate,
            CertificateThumbprint.Parse(certificate.Thumbprint),
            sans,
            notBefore,
            notAfter);
    }
}
