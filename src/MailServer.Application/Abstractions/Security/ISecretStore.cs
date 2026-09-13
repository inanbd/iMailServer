namespace MailServer.Application.Abstractions.Security;

/// <summary>Metadata about a stored secret, safe to display. Never includes the value.</summary>
/// <param name="Name">The lookup name.</param>
/// <param name="Description">What it is for.</param>
/// <param name="CreatedUtc">When it was first stored.</param>
/// <param name="ModifiedUtc">When it was last replaced.</param>
/// <param name="ProtectionScheme">Which protector encrypted it.</param>
public sealed record SecretDescriptor(
    string Name,
    string? Description,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? ModifiedUtc,
    string ProtectionScheme);

/// <summary>
/// Durable storage for secrets the server must be able to read back.
/// </summary>
/// <remarks>
/// <para>
/// Distinct from <see cref="ISecretProtector"/> on purpose, and the distinction is not
/// cosmetic. The protector <i>encrypts and decrypts</i>; the store decides <i>where protected
/// bytes live and who may read them</i>. Keeping them apart means the protection scheme can
/// change — DPAPI today, a hardware-backed key later — without touching storage, and storage
/// can change without touching cryptography.
/// </para>
/// <para>
/// Holds: SQL Server connection strings, smarthost credentials, certificate passphrases, the
/// SRS and unsubscribe HMAC keys, and from Milestone 4 the ACME account key. DKIM private keys
/// get their own typed storage in Milestone 9 because they are per-domain and rotate.
/// </para>
/// <para>
/// <b>Values are never logged, never returned by a listing, and never audited.</b> The listing
/// returns <see cref="SecretDescriptor"/>, which deliberately has no value property — there is
/// no method on this interface that hands the UI a plaintext secret in bulk.
/// </para>
/// </remarks>
public interface ISecretStore
{
    /// <summary>Reads and decrypts a secret, or returns null when it is not present.</summary>
    Task<string?> GetAsync(string name, CancellationToken cancellationToken);

    /// <summary>Encrypts and stores a secret, replacing any existing value of the same name.</summary>
    Task SetAsync(
        string name,
        string value,
        string? description,
        CancellationToken cancellationToken);

    /// <summary>Removes a secret. Returns false when it was not present.</summary>
    Task<bool> RemoveAsync(string name, CancellationToken cancellationToken);

    /// <summary>True when a secret of this name exists, without decrypting it.</summary>
    Task<bool> ExistsAsync(string name, CancellationToken cancellationToken);

    /// <summary>Lists stored secrets as metadata only.</summary>
    Task<IReadOnlyList<SecretDescriptor>> ListAsync(CancellationToken cancellationToken);
}

/// <summary>
/// The secret names this product uses.
/// </summary>
/// <remarks>
/// Constants rather than scattered string literals, so that a typo is a compile error rather
/// than a silent "secret not found" at three in the morning.
/// </remarks>
public static class WellKnownSecrets
{
    /// <summary>SQL Server connection string, when not supplied inline for development.</summary>
    public const string SqlServerConnectionString = "Database.SqlServer.ConnectionString";

    /// <summary>Password for an outbound smarthost relay (Milestone 8).</summary>
    public const string SmartHostPassword = "Delivery.SmartHost.Password";

    /// <summary>ACME account private key (Milestone 4).</summary>
    public const string AcmeAccountKey = "Acme.AccountKey";

    /// <summary>HMAC key for Sender Rewriting Scheme addresses (Milestone 9).</summary>
    public const string SrsSigningKey = "Mail.Srs.SigningKey";

    /// <summary>HMAC key for one-click unsubscribe tokens (Milestone 11).</summary>
    public const string UnsubscribeSigningKey = "Mail.Unsubscribe.SigningKey";
}
