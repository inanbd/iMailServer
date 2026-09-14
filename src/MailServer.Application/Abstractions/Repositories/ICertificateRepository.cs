using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>Persists certificate metadata and the bindings that point hostnames at it.</summary>
/// <remarks>
/// Certificates and bindings are loaded together far more often than separately — the TLS
/// provider needs both to build its snapshot, and the admin UI shows them joined — so they
/// share a repository rather than splitting a single read into two round trips.
/// </remarks>
public interface ICertificateRepository
{
    Task<Certificate?> GetAsync(CertificateId id, CancellationToken cancellationToken);

    Task<Certificate?> GetByThumbprintAsync(
        CertificateThumbprint thumbprint,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<Certificate>> GetAllAsync(CancellationToken cancellationToken);

    Task AddAsync(Certificate certificate, CancellationToken cancellationToken);

    Task UpdateAsync(Certificate certificate, CancellationToken cancellationToken);

    Task RemoveAsync(CertificateId id, CancellationToken cancellationToken);

    // ---- Bindings ---------------------------------------------------------------------------

    Task<IReadOnlyList<CertificateBinding>> GetBindingsAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<CertificateBinding>> GetBindingsForCertificateAsync(
        CertificateId certificateId,
        CancellationToken cancellationToken);

    Task<CertificateBinding?> GetBindingAsync(
        CertificateBindingId id,
        CancellationToken cancellationToken);

    Task<CertificateBinding?> GetBindingByHostnameAsync(
        DomainName hostname,
        CancellationToken cancellationToken);

    Task AddBindingAsync(CertificateBinding binding, CancellationToken cancellationToken);

    Task UpdateBindingAsync(CertificateBinding binding, CancellationToken cancellationToken);

    Task RemoveBindingAsync(CertificateBindingId id, CancellationToken cancellationToken);

    /// <summary>
    /// Clears the default flag on every binding except <paramref name="keep"/>.
    /// </summary>
    /// <remarks>
    /// A set operation rather than a read-modify-write loop, because "exactly one default"
    /// is an invariant across rows and enforcing it one aggregate at a time leaves a window
    /// in which there are two — or none, which is worse, since a handshake without SNI would
    /// then have no certificate to offer.
    /// </remarks>
    Task ClearOtherDefaultsAsync(CertificateBindingId keep, CancellationToken cancellationToken);
}
