using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Certificates;

/// <summary>
/// The single implementation of <see cref="ICertificateManager"/>, routing each source to the
/// right generator or store.
/// </summary>
/// <remarks>
/// <para>
/// Where a certificate is stored is decided here rather than by the caller. On Windows, with
/// the store available and preferred, an adopted certificate stays in
/// <c>LocalMachine\My</c> and is used in place; everything else becomes a DPAPI-protected
/// PFX. A handler asking for a self-signed certificate does not need to know which, and should
/// not, because the answer changes with the platform.
/// </para>
/// <para>
/// <b>Storage happens before the database row is written, every time.</b> If the process dies
/// between the two, the result is an orphaned file — which the next write of the same
/// thumbprint replaces, and which a maintenance sweep can find. The other order would leave a
/// row pointing at a certificate that does not exist, and the first thing to discover that
/// would be a failed TLS handshake.
/// </para>
/// </remarks>
internal sealed class CertificateManager(
    SelfSignedCertificateGenerator generator,
    ProtectedPfxCertificateStore pfxStore,
    CertificateChainValidator chainValidator,
    ICertificateRepository repository,
    IOptions<MailServerOptions> options,
    IClock clock,
    ILogger<CertificateManager> logger) : ICertificateManager
{
    private CertificateOptions Options => options.Value.Certificates;

    /// <summary>
    /// True when this process can read the Windows certificate store.
    /// </summary>
    /// <remarks>
    /// Checked at every use rather than cached in a field, so the platform guard sits directly
    /// next to the platform-specific call and the analyzer can see it.
    /// </remarks>
    private bool UseWindowsStore =>
        OperatingSystem.IsWindows() && Options.PreferWindowsCertificateStore;

    public async Task<Certificate> GenerateSelfSignedAsync(
        SelfSignedCertificateRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        using IssuedCertificate issued = generator.Generate(request);

        // Always a protected file, even on Windows. Writing a generated certificate into
        // LocalMachine\My would need elevation the service does not hold at runtime, and
        // installing into the machine store is deliberately an installer-time, audited
        // operation rather than something a background process does.
        CertificateKeyLocation location = await pfxStore
            .StoreAsync(issued.Certificate, cancellationToken)
            .ConfigureAwait(false);

        Certificate certificate = Certificate.Register(
            issued.Thumbprint,
            issued.Certificate.Subject,
            issued.Certificate.Issuer,
            issued.Certificate.SerialNumber,
            issued.SubjectAlternativeNames,
            CertificateSource.SelfSigned,
            location,
            issued.NotBeforeUtc,
            issued.NotAfterUtc,
            clock.UtcNow);

        await repository.AddAsync(certificate, cancellationToken).ConfigureAwait(false);

        // Logged at Warning, not Information. A self-signed certificate on a mail server is a
        // condition an operator should be prompted to resolve, not a routine event.
        logger.LogWarning(
            "A self-signed certificate {Thumbprint} was generated. SELF-SIGNED CERTIFICATES " +
            "ARE NOT PUBLICLY TRUSTED; mail clients and remote systems may display " +
            "certificate warnings. Obtain a certificate from Let's Encrypt or another public " +
            "CA before this server handles production mail.",
            issued.Thumbprint);

        return certificate;
    }

    public async Task<Certificate> ImportPfxAsync(
        byte[] pfxBytes,
        string? passphrase,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);

        X509Certificate2 imported;
        CertificateKeyLocation location;

        try
        {
            (imported, location) = await pfxStore
                .ImportAsync(pfxBytes, passphrase, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            // The caller's buffer holds an encrypted private key. Clear it here rather than
            // trusting every caller to remember; this is the one place every import passes
            // through.
            CryptographicOperations.ZeroMemory(pfxBytes);
        }

        using (imported)
        {
            Certificate certificate = Certificate.Register(
                CertificateThumbprint.Parse(imported.Thumbprint),
                imported.Subject,
                imported.Issuer,
                imported.SerialNumber,
                ReadSubjectAlternativeNames(imported),
                CertificateSource.ImportedPfx,
                location,
                imported.NotBefore,
                imported.NotAfter,
                clock.UtcNow);

            await repository.AddAsync(certificate, cancellationToken).ConfigureAwait(false);

            logger.LogInformation(
                "Imported certificate {Thumbprint}, issued by {Issuer}, valid until {NotAfter:u}.",
                certificate.Thumbprint,
                certificate.Issuer,
                certificate.NotAfterUtc);

            return certificate;
        }
    }

    public async Task<Certificate> AdoptFromWindowsStoreAsync(
        CertificateThumbprint thumbprint,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The Windows certificate store is only available on Windows. On other " +
                "platforms, import the certificate as a PKCS#12 file instead.");
        }

        using X509Certificate2? found = FindInWindowsStore(thumbprint);

        if (found is null)
        {
            throw new InvalidOperationException(
                $"Certificate {thumbprint} is not present in LocalMachine\\My, or this service " +
                "cannot read it.");
        }

        Certificate certificate = Certificate.Register(
            CertificateThumbprint.Parse(found.Thumbprint),
            found.Subject,
            found.Issuer,
            found.SerialNumber,
            ReadSubjectAlternativeNames(found),
            CertificateSource.WindowsStore,
            CertificateKeyLocation.InWindowsStore(thumbprint),
            found.NotBefore,
            found.NotAfter,
            clock.UtcNow);

        await repository.AddAsync(certificate, cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "Adopted certificate {Thumbprint} from LocalMachine\\My. Its private key remains " +
            "in the store and is not exported.",
            thumbprint);

        return certificate;
    }

    public Task<X509Certificate2?> LoadAsync(
        CertificateKeyLocation location,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(location);

        if (location.Storage == CertificateKeyStorage.WindowsCertificateStore)
        {
            if (!OperatingSystem.IsWindows())
            {
                logger.LogError(
                    "Certificate {Thumbprint} is recorded as living in the Windows certificate " +
                    "store, but this is not Windows. The certificate cannot be loaded.",
                    location.Thumbprint);

                return Task.FromResult<X509Certificate2?>(null);
            }

            return Task.FromResult(FindInWindowsStore(location.Thumbprint));
        }

        return pfxStore.LoadAsync(location, cancellationToken);
    }

    public async Task<CertificateChainResult> ValidateChainAsync(
        CertificateKeyLocation location,
        CancellationToken cancellationToken)
    {
        using X509Certificate2? certificate = await LoadAsync(location, cancellationToken)
            .ConfigureAwait(false);

        return certificate is null
            ? new CertificateChainResult(false, "The certificate could not be loaded.")
            : chainValidator.Validate(certificate);
    }

    public Task RemoveAsync(CertificateKeyLocation location, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(location);

        if (location.Storage == CertificateKeyStorage.WindowsCertificateStore)
        {
            // Adoption is not ownership. The certificate may be in use by IIS or by an
            // unrelated application, and removing our database row is not consent to delete
            // something we did not install.
            logger.LogInformation(
                "Certificate {Thumbprint} was adopted from the Windows certificate store and " +
                "is left there untouched; only this server's reference to it is removed.",
                location.Thumbprint);

            return Task.CompletedTask;
        }

        return pfxStore.RemoveAsync(location, cancellationToken);
    }

    /// <remarks>
    /// Separated so the <c>SupportedOSPlatform</c> reader is only ever reached from a guarded
    /// call site. Constructing it inline in a method the analyzer cannot prove is Windows-only
    /// produces a CA1416 the team would be tempted to suppress.
    /// </remarks>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private X509Certificate2? FindInWindowsStore(CertificateThumbprint thumbprint)
    {
        using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        X509Certificate2Collection matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            thumbprint.Value,
            validOnly: false);

        return matches.Count == 0 ? null : matches[0];
    }

    /// <summary>
    /// Reads the dNSName entries from the subjectAltName extension.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Entries that are not usable hostnames — IP addresses, email addresses, a wildcard this
    /// product will not honour — are skipped rather than causing the import to fail. A
    /// perfectly good certificate that happens to carry an IP SAN should still be importable;
    /// it simply does not cover that entry as far as this server is concerned.
    /// </para>
    /// <para>
    /// If nothing usable is found the aggregate refuses the registration, which is the correct
    /// outcome: such a certificate covers no hostname any current client will accept.
    /// </para>
    /// </remarks>
    private IReadOnlyList<CertificateSubjectName> ReadSubjectAlternativeNames(
        X509Certificate2 certificate)
    {
        List<CertificateSubjectName> names = [];

        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is not X509SubjectAlternativeNameExtension san)
            {
                continue;
            }

            foreach (string dnsName in san.EnumerateDnsNames())
            {
                if (CertificateSubjectName.TryParse(dnsName, out CertificateSubjectName? parsed))
                {
                    names.Add(parsed);
                }
                else
                {
                    logger.LogWarning(
                        "Certificate {Thumbprint} carries the subjectAltName entry '{Entry}', " +
                        "which this server does not treat as covering any hostname.",
                        certificate.Thumbprint,
                        dnsName);
                }
            }
        }

        return names;
    }
}
