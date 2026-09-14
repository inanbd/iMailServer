using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Certificates;

/// <summary>
/// Reads certificates from the Windows certificate store at <c>LocalMachine\My</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Read-only, always.</b> The store is opened with <see cref="OpenFlags.ReadOnly"/> and
/// nothing here writes or deletes. Installing into the machine store is an elevated,
/// separately audited operation performed by the installer, not something a background service
/// does on its own.
/// </para>
/// <para>
/// That restraint matters because the store is shared. A certificate in
/// <c>LocalMachine\My</c> may belong to IIS, to a line-of-business application, or to nothing
/// at all; this server can adopt one, but deleting an operator's certificate because a row was
/// removed from our database would be destroying something we do not own.
/// </para>
/// <para>
/// <b>The private key is never exported.</b> The certificate is used in place, and the service
/// account is granted read access to the key container by the installer — the narrowest grant
/// that allows a handshake to succeed.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class WindowsCertificateStoreReader(
    ILogger<WindowsCertificateStoreReader> logger)
{
    /// <summary>Finds a certificate by thumbprint, or null when it is not present.</summary>
    /// <remarks>
    /// <paramref name="validOnly"/> is false, deliberately. Passing true would silently hide an
    /// expired certificate, and "the certificate has vanished" is a far worse diagnostic than
    /// "the certificate expired" when an operator is trying to work out why TLS stopped.
    /// </remarks>
    public X509Certificate2? Find(CertificateThumbprint thumbprint)
    {
        if (thumbprint.IsEmpty)
        {
            return null;
        }

        using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        X509Certificate2Collection matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            thumbprint.Value,
            validOnly: false);

        if (matches.Count == 0)
        {
            logger.LogWarning(
                "Certificate {Thumbprint} was not found in LocalMachine\\My.",
                thumbprint);

            return null;
        }

        X509Certificate2 certificate = matches[0];

        if (!certificate.HasPrivateKey)
        {
            logger.LogError(
                "Certificate {Thumbprint} is present in LocalMachine\\My but its private key " +
                "is not accessible to this service. Grant the service account read access to " +
                "the key container; the certificate cannot terminate TLS without it.",
                thumbprint);
        }

        return certificate;
    }

    /// <summary>Enumerates certificates in the store that could serve TLS.</summary>
    /// <remarks>
    /// Filtered to those with a private key, because the admin UI uses this to offer a choice
    /// and a certificate without its key is not a choice — selecting it would produce a
    /// handshake failure at the first connection.
    /// </remarks>
    public IReadOnlyList<X509Certificate2> ListUsable()
    {
        using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        List<X509Certificate2> usable = [];

        foreach (X509Certificate2 certificate in store.Certificates)
        {
            if (certificate.HasPrivateKey)
            {
                usable.Add(certificate);
            }
            else
            {
                certificate.Dispose();
            }
        }

        return usable;
    }
}

/// <summary>
/// Builds and validates certificate chains.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no bypass here and there is none anywhere else in this product.</b> No
/// <c>RemoteCertificateValidationCallback</c> returning a constant true, no
/// <c>TrustServerCertificate</c> on the database connection, no "ignore errors in
/// development" switch. A security test asserts it, because the single most common way a
/// product ends up with no transport security at all is a validation bypass added during
/// development and never removed.
/// </para>
/// <para>
/// Revocation is checked online with an offline fallback: <see cref="X509RevocationMode.Online"/>
/// with <see cref="X509RevocationFlag.ExcludeRoot"/>. A network failure reaching an OCSP
/// responder must not be reported as an untrusted certificate — that would turn an outage at
/// the CA into an outage here.
/// </para>
/// </remarks>
internal sealed class CertificateChainValidator(ILogger<CertificateChainValidator> logger)
{
    public CertificateChainResult Validate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        using X509Chain chain = new();

        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

        bool built = chain.Build(certificate);

        if (built)
        {
            return CertificateChainResult.Trusted;
        }

        List<string> reasons = [];
        bool onlyRevocationUnavailable = chain.ChainStatus.Length > 0;

        foreach (X509ChainStatus status in chain.ChainStatus)
        {
            reasons.Add(status.StatusInformation.Trim());

            // "Could not reach the revocation server" is a network problem, not a statement
            // about this certificate. Treating it as untrusted would mean a CA's OCSP outage
            // showed up here as every certificate suddenly becoming invalid.
            if (status.Status is not (X509ChainStatusFlags.RevocationStatusUnknown
                                      or X509ChainStatusFlags.OfflineRevocation))
            {
                onlyRevocationUnavailable = false;
            }
        }

        string summary = reasons.Count > 0
            ? string.Join("; ", reasons)
            : "The chain could not be built, and the platform gave no reason.";

        if (onlyRevocationUnavailable)
        {
            logger.LogWarning(
                "Revocation status could not be determined for certificate {Thumbprint}: " +
                "{Summary}. Treating the chain as trusted; a revocation responder being " +
                "unreachable is a network fault, not evidence against the certificate.",
                certificate.Thumbprint,
                summary);

            return new CertificateChainResult(
                true,
                "The chain builds, but revocation status could not be checked: " + summary);
        }

        logger.LogWarning(
            "The chain for certificate {Thumbprint} does not build to a trusted root: {Summary}",
            certificate.Thumbprint,
            summary);

        return new CertificateChainResult(false, summary);
    }
}
