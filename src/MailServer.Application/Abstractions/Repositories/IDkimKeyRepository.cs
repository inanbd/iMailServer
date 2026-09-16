using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>Persists <see cref="DkimKey"/> metadata together with its private key.</summary>
/// <remarks>
/// <para>
/// One repository over two tables, the same shape as <c>ICertificateRepository</c> over
/// Certificates and CertificateBindings: metadata and the thing it points at are written and
/// read together far more often than separately, so splitting them into two abstractions would
/// buy nothing and would risk the two halves of one key being written in separate transactions.
/// </para>
/// <para>
/// Private key material never appears on <see cref="DkimKey"/> itself — see that aggregate's own
/// remarks — so every method that returns a <see cref="DkimKey"/> reads only the metadata table.
/// <see cref="GetPrivateKeyAsync"/> is the one deliberately separate, narrow path to the key
/// itself, exactly mirroring how <c>ISecretStore</c> hides <c>ISecretProtector</c>'s encryption
/// behind a plaintext-in, plaintext-out API: callers here deal in plaintext PKCS#8 bytes, and
/// this repository is responsible for protecting them at rest.
/// </para>
/// </remarks>
public interface IDkimKeyRepository
{
    Task<DkimKey?> GetAsync(DkimKeyId id, CancellationToken cancellationToken);

    Task<IReadOnlyList<DkimKey>> GetForDomainAsync(DomainId domainId, CancellationToken cancellationToken);

    /// <summary>The key currently signing for a domain, or null if none is active.</summary>
    Task<DkimKey?> GetActiveForDomainAsync(DomainId domainId, CancellationToken cancellationToken);

    Task<IReadOnlyList<DkimKey>> GetAllAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Adds a newly generated key's metadata together with its private key, atomically. The key
    /// is protected at rest before this call returns; <paramref name="pkcs8PrivateKey"/> itself
    /// is plaintext PKCS#8, exactly as <c>RSA.ExportPkcs8PrivateKey</c> produces it.
    /// </summary>
    Task AddAsync(DkimKey key, byte[] pkcs8PrivateKey, CancellationToken cancellationToken);

    /// <summary>
    /// Persists a status transition. The selector, algorithm, public key and key length are
    /// immutable once generated, exactly like a certificate's identity fields — a rotation
    /// creates a new <see cref="DkimKey"/> row rather than mutating this one, and never touches
    /// the private key row either.
    /// </summary>
    Task UpdateAsync(DkimKey key, CancellationToken cancellationToken);

    /// <summary>Removes a key's metadata and its private key together.</summary>
    Task RemoveAsync(DkimKeyId id, CancellationToken cancellationToken);

    /// <summary>
    /// Reads and decrypts a key's PKCS#8 private key, for the signer's use. Null only if
    /// <paramref name="id"/> does not name a key this repository has ever stored.
    /// </summary>
    Task<byte[]?> GetPrivateKeyAsync(DkimKeyId id, CancellationToken cancellationToken);
}
