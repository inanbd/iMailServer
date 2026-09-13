using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// Stores protected secrets in the database.
/// </summary>
/// <remarks>
/// <para>
/// The store decides <i>where protected bytes live</i>; <see cref="ISecretProtector"/> decides
/// <i>how they are protected</i>. Keeping the two apart means the protection scheme can change
/// without touching storage and vice versa.
/// </para>
/// <para>
/// <b>Values are encrypted before they reach SQL.</b> A database backup, a replica, or a
/// support engineer with read access sees only ciphertext. Under DPAPI that ciphertext is also
/// machine-bound, so a database copied to another machine yields nothing — which is precisely
/// why backups re-wrap secrets under a passphrase-derived key.
/// </para>
/// <para>
/// <b>No method returns secrets in bulk.</b> <see cref="ListAsync"/> returns metadata only.
/// There is deliberately no "export all secrets" path for a UI to call, because the moment one
/// exists somebody will render it.
/// </para>
/// </remarks>
public sealed class DatabaseSecretStore(
    IDbConnectionFactory connectionFactory,
    ISecretProtector protector,
    IClock clock,
    ILogger<DatabaseSecretStore> logger) : ISecretStore
{
    /// <summary>Bound on a stored value, to keep a mistake from filling the table.</summary>
    public const int MaxValueLength = 64 * 1024;

    public async Task<string?> GetAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        await using System.Data.Common.DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        string? protectedValue = await connection.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT ProtectedValue FROM ProtectedSecrets WHERE SecretName = @Name",
            new { Name = name },
            cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (protectedValue is null)
        {
            return null;
        }

        try
        {
            return protector.UnprotectString(protectedValue);
        }
        catch (Exception ex)
        {
            // Almost always means the database was restored onto a different machine, because
            // DPAPI is machine-scoped. The message says so, because the alternative is an
            // operator staring at "Bad Data" during a disaster recovery.
            logger.LogCritical(
                ex,
                "Secret '{SecretName}' could not be decrypted. If this database was restored " +
                "onto a different machine, DPAPI-protected secrets cannot be recovered without " +
                "the backup passphrase - see docs/BackupRestore.md.",
                name);

            throw;
        }
    }

    public async Task SetAsync(
        string name,
        string value,
        string? description,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length > MaxValueLength)
        {
            throw new ArgumentException(
                $"A secret may be at most {MaxValueLength} characters.",
                nameof(value));
        }

        string protectedValue = protector.ProtectString(value);
        DateTimeOffset now = clock.UtcNow;

        await using System.Data.Common.DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        // UPDATE then INSERT rather than a provider-specific upsert: two short portable
        // statements, and this runs a handful of times per server lifetime.
        int updated = await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE ProtectedSecrets
            SET    ProtectedValue = @Value,
                   Description = @Description,
                   ProtectionScheme = @Scheme,
                   ModifiedUtc = @Now
            WHERE  SecretName = @Name
            """,
            new
            {
                Name = name,
                Value = protectedValue,
                Description = description,
                Scheme = protector.SchemeName,
                Now = now,
            },
            cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (updated == 0)
        {
            await connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO ProtectedSecrets
                    (SecretName, ProtectedValue, Description, ProtectionScheme, CreatedUtc, ModifiedUtc)
                VALUES
                    (@Name, @Value, @Description, @Scheme, @Now, NULL)
                """,
                new
                {
                    Name = name,
                    Value = protectedValue,
                    Description = description,
                    Scheme = protector.SchemeName,
                    Now = now,
                },
                cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        // The NAME is logged, never the value, and never a prefix or length of the value.
        logger.LogInformation(
            "Secret '{SecretName}' was stored using the {Scheme} protection scheme.",
            name,
            protector.SchemeName);
    }

    public async Task<bool> RemoveAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        await using System.Data.Common.DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        int removed = await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM ProtectedSecrets WHERE SecretName = @Name",
            new { Name = name },
            cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (removed > 0)
        {
            logger.LogWarning("Secret '{SecretName}' was removed.", name);
        }

        return removed > 0;
    }

    public async Task<bool> ExistsAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        await using System.Data.Common.DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        // COUNT rather than selecting the value: an existence check must never decrypt.
        int count = await connection.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT COUNT(1) FROM ProtectedSecrets WHERE SecretName = @Name",
            new { Name = name },
            cancellationToken: cancellationToken)).ConfigureAwait(false);

        return count > 0;
    }

    public async Task<IReadOnlyList<SecretDescriptor>> ListAsync(CancellationToken cancellationToken)
    {
        await using System.Data.Common.DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        // ProtectedValue is deliberately absent from the projection.
        IEnumerable<SecretRow> rows = await connection.QueryAsync<SecretRow>(new CommandDefinition(
            """
            SELECT SecretName, Description, ProtectionScheme, CreatedUtc, ModifiedUtc
            FROM   ProtectedSecrets
            ORDER  BY SecretName
            """,
            cancellationToken: cancellationToken)).ConfigureAwait(false);

        return
        [
            .. rows.Select(r => new SecretDescriptor(
                r.SecretName,
                r.Description,
                r.CreatedUtc,
                r.ModifiedUtc,
                r.ProtectionScheme))
        ];
    }

    private sealed class SecretRow
    {
        public string SecretName { get; set; } = string.Empty;

        public string? Description { get; set; }

        public string ProtectionScheme { get; set; } = string.Empty;

        public DateTimeOffset CreatedUtc { get; set; }

        public DateTimeOffset? ModifiedUtc { get; set; }
    }
}
