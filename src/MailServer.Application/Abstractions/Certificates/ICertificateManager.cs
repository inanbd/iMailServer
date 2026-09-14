using System.Security.Cryptography.X509Certificates;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Certificates;

/// <summary>
/// Settings for generating a self-signed certificate.
/// </summary>
/// <param name="Hostnames">
/// Every hostname the certificate must cover, written into the subjectAltName extension.
/// </param>
/// <param name="KeySizeBits">RSA modulus size. 3072 by default.</param>
/// <param name="ValidityYears">Validity in years. 1 by default.</param>
public sealed record SelfSignedCertificateRequest(
    IReadOnlyList<DomainName> Hostnames,
    int KeySizeBits = 3072,
    int ValidityYears = 1)
{
    /// <summary>Key sizes the generator will produce.</summary>
    /// <remarks>
    /// 2048 is the floor because anything smaller is rejected outright by current clients and
    /// by the CA/Browser Forum baseline requirements. 4096 is the ceiling because the handshake
    /// cost grows faster than the security benefit, and a mail server performs a great many
    /// handshakes.
    /// </remarks>
    public static IReadOnlyList<int> SupportedKeySizes { get; } = [2048, 3072, 4096];

    /// <summary>Validity periods the generator will produce.</summary>
    public static IReadOnlyList<int> SupportedValidityYears { get; } = [1, 2, 5];
}

/// <summary>
/// The result of obtaining a certificate: metadata for the domain model, plus the certificate
/// itself for immediate installation.
/// </summary>
/// <remarks>
/// The <see cref="X509Certificate2"/> is owned by the caller and must be disposed. It carries a
/// private key, so it is deliberately not something the domain aggregate holds — see
/// <see cref="Certificate"/>.
/// </remarks>
public sealed record IssuedCertificate(
    X509Certificate2 Certificate,
    CertificateThumbprint Thumbprint,
    IReadOnlyList<CertificateSubjectName> SubjectAlternativeNames,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc) : IDisposable
{
    public void Dispose() => Certificate.Dispose();
}

/// <summary>
/// Obtains and installs certificates, whatever their source.
/// </summary>
/// <remarks>
/// <para>
/// The single port through which the application layer acquires certificates. ACME
/// (Milestone 4) plugs in behind this interface without any handler changing, which is the
/// whole point of stating it now rather than after the ACME work has shaped it.
/// </para>
/// <para>
/// <b>No method on this interface returns a private key to the application layer.</b>
/// Generation and import produce an installed certificate and its metadata; the key stays in
/// the store or in a protected file. A port that handed back key bytes would make every
/// handler a place a private key could be logged.
/// </para>
/// </remarks>
public interface ICertificateManager
{
    /// <summary>Generates a self-signed certificate and installs it.</summary>
    /// <remarks>
    /// The result is not publicly trusted. Callers must surface
    /// <c>CertificateRenewalPolicy.SelfSignedWarning</c> verbatim wherever the outcome is
    /// shown.
    /// </remarks>
    Task<Certificate> GenerateSelfSignedAsync(
        SelfSignedCertificateRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Imports a PKCS#12 certificate supplied by the operator.
    /// </summary>
    /// <param name="pfxBytes">The PKCS#12 blob. Overwritten by the implementation once consumed.</param>
    /// <param name="passphrase">
    /// The file's passphrase. Held only for the duration of the call, never persisted as given,
    /// never logged, and never audited.
    /// </param>
    Task<Certificate> ImportPfxAsync(
        byte[] pfxBytes,
        string? passphrase,
        CancellationToken cancellationToken);

    /// <summary>
    /// Stores a certificate this server obtained from a certificate authority.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Distinct from <see cref="ImportPfxAsync"/> even though the storage is identical, because
    /// the <b>source</b> differs and the source is what decides whether the certificate can be
    /// renewed automatically. A certificate recorded as an operator's import is one this server
    /// cannot reissue, so it is never renewed — routing ACME issuance through the import path
    /// produced exactly that: certificates that were obtained automatically and would then have
    /// expired without a single renewal attempt.
    /// </para>
    /// <para>
    /// The caller owns <paramref name="certificate"/> and disposes it.
    /// </para>
    /// </remarks>
    Task<Certificate> StoreIssuedAsync(
        X509Certificate2 certificate,
        CertificateSource source,
        CancellationToken cancellationToken);

    /// <summary>
    /// Adopts a certificate that already exists in the Windows certificate store.
    /// </summary>
    /// <remarks>
    /// Records metadata only. The private key is not exported, and the certificate is read
    /// with <c>OpenFlags.ReadOnly</c>.
    /// </remarks>
    Task<Certificate> AdoptFromWindowsStoreAsync(
        CertificateThumbprint thumbprint,
        CancellationToken cancellationToken);

    /// <summary>
    /// Loads a certificate for use in a handshake.
    /// </summary>
    /// <remarks>
    /// Returns null rather than throwing when the certificate is missing, because a handshake
    /// callback must not propagate exceptions into the TLS stack. The caller logs and falls
    /// back to the default binding.
    /// </remarks>
    Task<X509Certificate2?> LoadAsync(
        CertificateKeyLocation location,
        CancellationToken cancellationToken);

    /// <summary>
    /// Builds and validates the chain, reporting whether it reaches a trusted root.
    /// </summary>
    /// <remarks>
    /// Revocation is checked online with an offline fallback. There is no bypass and no
    /// callback returning a constant true anywhere behind this method — a security test
    /// asserts it.
    /// </remarks>
    Task<CertificateChainResult> ValidateChainAsync(
        CertificateKeyLocation location,
        CancellationToken cancellationToken);

    /// <summary>Removes a certificate this server installed.</summary>
    /// <remarks>
    /// Never removes anything from the Windows certificate store: this server may have adopted
    /// a certificate it did not install, and deleting an operator's certificate because a row
    /// was removed from our database would be destroying something we do not own.
    /// </remarks>
    Task RemoveAsync(CertificateKeyLocation location, CancellationToken cancellationToken);
}

/// <summary>The outcome of building a certificate chain.</summary>
/// <param name="IsTrusted">True when the chain reaches a trusted root.</param>
/// <param name="StatusSummary">
/// A human-readable summary of why not, safe to show an operator and safe to log.
/// </param>
public sealed record CertificateChainResult(bool IsTrusted, string StatusSummary)
{
    public static CertificateChainResult Trusted { get; } =
        new(true, "The chain builds to a trusted root.");
}
