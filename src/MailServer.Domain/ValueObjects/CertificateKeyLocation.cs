using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;

namespace MailServer.Domain.ValueObjects;

/// <summary>How the server finds a certificate's bytes and private key when a handshake needs them.</summary>
public enum CertificateKeyStorage
{
    /// <summary>
    /// The Windows certificate store at <c>LocalMachine\My</c>, located by thumbprint. The
    /// private key never leaves the store.
    /// </summary>
    WindowsCertificateStore = 0,

    /// <summary>
    /// A PKCS#12 file on disk whose passphrase is held in the DPAPI-protected secret store.
    /// Used where the Windows store is unavailable or not yet configured.
    /// </summary>
    ProtectedPfxFile = 1,
}

/// <summary>
/// A pointer to where a certificate physically lives — never the certificate itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>This type never carries key material, a passphrase, or a file's contents.</b> It carries
/// a thumbprint or a relative path plus the <i>name</i> of a secret. The passphrase is fetched
/// from <c>ISecretStore</c> at the moment of use and is not retained.
/// </para>
/// <para>
/// That indirection is what lets certificate metadata be logged, audited, serialised over IPC
/// and rendered in the admin UI without any of those paths ever touching a private key. A
/// value object holding the PFX password would put it into every one of them.
/// </para>
/// <para>
/// The file path is stored <b>relative to the configured certificate directory</b>, never
/// absolute. An absolute path from the database would be an arbitrary-file-read primitive the
/// moment anything could write to that column, and a relative path resolved through the
/// existing path-containment check cannot escape the directory.
/// </para>
/// </remarks>
public sealed class CertificateKeyLocation : ValueObject
{
    private CertificateKeyLocation(
        CertificateKeyStorage storage,
        CertificateThumbprint thumbprint,
        string? relativeFilePath,
        string? passphraseSecretName)
    {
        Storage = storage;
        Thumbprint = thumbprint;
        RelativeFilePath = relativeFilePath;
        PassphraseSecretName = passphraseSecretName;
    }

    public CertificateKeyStorage Storage { get; }

    /// <summary>The thumbprint used to locate the certificate in the Windows store.</summary>
    public CertificateThumbprint Thumbprint { get; }

    /// <summary>Path relative to the configured certificate directory. Null for store-held certificates.</summary>
    public string? RelativeFilePath { get; }

    /// <summary>
    /// The name under which the PFX passphrase is held in <c>ISecretStore</c> — not the
    /// passphrase.
    /// </summary>
    public string? PassphraseSecretName { get; }

    /// <summary>Points at a certificate in <c>LocalMachine\My</c>.</summary>
    public static CertificateKeyLocation InWindowsStore(CertificateThumbprint thumbprint)
    {
        if (thumbprint.IsEmpty)
        {
            throw new InvalidValueObjectException(
                nameof(CertificateKeyLocation),
                "a Windows store location needs a thumbprint to locate the certificate by.");
        }

        return new CertificateKeyLocation(
            CertificateKeyStorage.WindowsCertificateStore,
            thumbprint,
            relativeFilePath: null,
            passphraseSecretName: null);
    }

    /// <summary>Points at a protected PFX file inside the certificate directory.</summary>
    public static CertificateKeyLocation InProtectedFile(
        string relativeFilePath,
        string passphraseSecretName,
        CertificateThumbprint thumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativeFilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(passphraseSecretName);

        // Rejected here as well as at the filesystem boundary. Defence in depth costs one
        // comparison, and a traversal sequence reaching the value object at all means
        // something upstream is already wrong.
        if (Path.IsPathRooted(relativeFilePath) ||
            relativeFilePath.Contains("..", StringComparison.Ordinal))
        {
            throw new InvalidValueObjectException(
                nameof(CertificateKeyLocation),
                "the certificate file path must be relative and must not contain '..'. An " +
                "absolute or traversing path would let a database row address any file on " +
                "the machine.");
        }

        return new CertificateKeyLocation(
            CertificateKeyStorage.ProtectedPfxFile,
            thumbprint,
            relativeFilePath,
            passphraseSecretName);
    }

    /// <summary>Rebuilds a location from persisted columns, without re-validating.</summary>
    public static CertificateKeyLocation Rehydrate(
        CertificateKeyStorage storage,
        CertificateThumbprint thumbprint,
        string? relativeFilePath,
        string? passphraseSecretName) =>
        new(storage, thumbprint, relativeFilePath, passphraseSecretName);

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Storage;
        yield return Thumbprint;
        yield return RelativeFilePath;
        yield return PassphraseSecretName;
    }

    /// <summary>
    /// A description safe to log.
    /// </summary>
    /// <remarks>
    /// Names the secret, never its value, and is written so that an accidental interpolation
    /// of this object into a log line cannot leak anything.
    /// </remarks>
    public override string ToString() => Storage switch
    {
        CertificateKeyStorage.WindowsCertificateStore =>
            $"LocalMachine\\My:{Thumbprint}",
        CertificateKeyStorage.ProtectedPfxFile =>
            $"file:{RelativeFilePath} (passphrase in secret '{PassphraseSecretName}')",
        _ => Storage.ToString(),
    };
}
