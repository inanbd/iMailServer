using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Security;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Certificates;

/// <summary>
/// Stores certificates as PKCS#12 files whose passphrases live in the DPAPI-protected secret
/// store.
/// </summary>
/// <remarks>
/// <para>
/// Used where the Windows certificate store is unavailable — non-Windows development, and the
/// bootstrap window before the store has been configured. On Windows in production the store
/// is preferred, because there the private key never becomes a file at all.
/// </para>
/// <para>
/// <b>Two layers of protection, not one.</b> The PFX is encrypted under a randomly generated
/// 256-bit passphrase, and that passphrase is held in <see cref="ISecretStore"/>, which
/// encrypts it under DPAPI. Someone who copies the file gets ciphertext; someone who copies
/// the database gets the passphrase only as DPAPI ciphertext bound to the original machine.
/// Neither alone is sufficient.
/// </para>
/// <para>
/// <b>The passphrase is never returned, logged, or audited.</b> It is fetched at the moment of
/// use, passed to the PKCS#12 loader, and dropped. It does not appear in
/// <see cref="CertificateKeyLocation"/>, which carries only the secret's <i>name</i>.
/// </para>
/// </remarks>
internal sealed class ProtectedPfxCertificateStore(
    IServerPaths paths,
    ISecretStore secrets,
    ILogger<ProtectedPfxCertificateStore> logger)
{
    /// <summary>Prefix for the secret holding a certificate's PFX passphrase.</summary>
    private const string PassphraseSecretPrefix = "Certificates.Pfx.Passphrase.";

    /// <summary>256 bits, base64-encoded. The file's encryption is only as good as this.</summary>
    private const int PassphraseBytes = 32;

    /// <summary>
    /// Writes a certificate and its private key to a protected file.
    /// </summary>
    /// <remarks>
    /// The secret is written <b>before</b> the file. If the process dies between the two, the
    /// result is an unreferenced secret — harmless, and cleaned up on the next write of the
    /// same name. The other order would leave a file nothing can ever decrypt, which is
    /// indistinguishable from data loss.
    /// </remarks>
    public async Task<CertificateKeyLocation> StoreAsync(
        X509Certificate2 certificate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        CertificateThumbprint thumbprint = CertificateThumbprint.Parse(certificate.Thumbprint);

        // Named after the thumbprint, which is server-derived and hexadecimal, so no part of
        // the path comes from operator input.
        string relativePath = $"{thumbprint.Value}.pfx";
        string secretName = PassphraseSecretPrefix + thumbprint.Value;

        string passphrase = Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(PassphraseBytes));

        await secrets.SetAsync(
            secretName,
            passphrase,
            $"PKCS#12 passphrase for certificate {thumbprint}.",
            cancellationToken).ConfigureAwait(false);

        string fullPath = paths.ResolveContained(paths.CertificatesRoot, relativePath);

        byte[] pfx = certificate.Export(X509ContentType.Pkcs12, passphrase);

        try
        {
            await File.WriteAllBytesAsync(fullPath, pfx, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // The exported blob contains the private key. Clear it as soon as it has been
            // written rather than leaving it for the garbage collector, which makes no promise
            // about when — or whether — the bytes stop being readable in the process's memory.
            CryptographicOperations.ZeroMemory(pfx);
        }

        logger.LogInformation(
            "Stored certificate {Thumbprint} as a protected PKCS#12 file.",
            thumbprint);

        return CertificateKeyLocation.InProtectedFile(relativePath, secretName, thumbprint);
    }

    /// <summary>
    /// Loads a certificate, or null when the file or its passphrase is missing.
    /// </summary>
    /// <remarks>
    /// Null rather than an exception: the caller is ultimately a TLS handshake callback, and
    /// an exception thrown into the TLS stack aborts the connection with an opaque error
    /// instead of letting the server fall back to its default binding.
    /// </remarks>
    public async Task<X509Certificate2?> LoadAsync(
        CertificateKeyLocation location,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(location);

        if (location.RelativeFilePath is null || location.PassphraseSecretName is null)
        {
            logger.LogError(
                "Certificate location {Location} is not a protected file location.",
                location);

            return null;
        }

        string fullPath = paths.ResolveContained(paths.CertificatesRoot, location.RelativeFilePath);

        if (!File.Exists(fullPath))
        {
            logger.LogError(
                "The certificate file for {Thumbprint} is missing from the certificate " +
                "directory. The certificate cannot be presented until it is restored or " +
                "reissued.",
                location.Thumbprint);

            return null;
        }

        string? passphrase = await secrets
            .GetAsync(location.PassphraseSecretName, cancellationToken)
            .ConfigureAwait(false);

        if (passphrase is null)
        {
            // Names the secret, never a value. This is the shape a DPAPI failure after a
            // machine migration takes, so the message says what to do about it.
            logger.LogError(
                "The passphrase secret '{SecretName}' for certificate {Thumbprint} could not " +
                "be read. If this database was restored onto a different machine, " +
                "DPAPI-protected secrets do not travel with it and the certificate must be " +
                "re-imported.",
                location.PassphraseSecretName,
                location.Thumbprint);

            return null;
        }

        byte[] pfx = await File.ReadAllBytesAsync(fullPath, cancellationToken).ConfigureAwait(false);

        try
        {
            return X509CertificateLoader.LoadPkcs12(
                pfx,
                passphrase,
                X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (CryptographicException ex)
        {
            // The exception message is safe (it describes a format or passphrase failure, not
            // key material), but the passphrase itself is never in scope for logging.
            logger.LogError(
                ex,
                "The certificate file for {Thumbprint} could not be opened. It may be corrupt " +
                "or protected with a different passphrase.",
                location.Thumbprint);

            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfx);
        }
    }

    /// <summary>Deletes the file and its passphrase secret.</summary>
    public async Task RemoveAsync(
        CertificateKeyLocation location,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(location);

        if (location.RelativeFilePath is not null)
        {
            string fullPath = paths.ResolveContained(
                paths.CertificatesRoot,
                location.RelativeFilePath);

            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
            }
        }

        if (location.PassphraseSecretName is not null)
        {
            await secrets
                .RemoveAsync(location.PassphraseSecretName, cancellationToken)
                .ConfigureAwait(false);
        }

        logger.LogInformation("Removed stored certificate {Thumbprint}.", location.Thumbprint);
    }

    /// <summary>
    /// Imports an operator-supplied PKCS#12 blob and re-protects it under a server-generated
    /// passphrase.
    /// </summary>
    /// <remarks>
    /// Deliberately re-wrapped rather than stored as supplied. The operator's passphrase may be
    /// weak, may be shared with other systems, and would have to be persisted somewhere to be
    /// usable at startup. Generating our own means the stored passphrase is 256 random bits and
    /// the operator's is discarded at the end of this method.
    /// </remarks>
    public async Task<(X509Certificate2 Certificate, CertificateKeyLocation Location)> ImportAsync(
        byte[] pfxBytes,
        string? passphrase,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);

        X509Certificate2 imported = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            passphrase,
            X509KeyStorageFlags.EphemeralKeySet);

        if (!imported.HasPrivateKey)
        {
            imported.Dispose();

            throw new InvalidOperationException(
                "The supplied PKCS#12 file contains no private key. A certificate without its " +
                "private key cannot be used to terminate TLS.");
        }

        CertificateKeyLocation location = await StoreAsync(imported, cancellationToken)
            .ConfigureAwait(false);

        return (imported, location);
    }
}
