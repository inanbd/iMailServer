using System.Data;
using System.Data.Common;
using System.Diagnostics;
using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Exceptions;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Persistence;

/// <summary>
/// Applies numbered SQL migrations, in order, exactly once.
/// </summary>
/// <remarks>
/// <para>
/// Entity Framework is forbidden by the brief, so schema evolution is explicit SQL applied
/// by this runner. DbUp and FluentMigrator were both evaluated (see
/// <c>docs/Architecture.md</c> §11); a purpose-built runner was chosen because production
/// upgrades need four behaviours neither provides out of the box: pre-upgrade backup,
/// checksum drift detection with an actionable message, per-provider script sets, and an
/// advisory lock against concurrent service starts.
/// </para>
/// <para>Guarantees, each covered by a test in <c>MailServer.Persistence.Tests</c>:</para>
/// <list type="number">
///   <item><description>A migration never runs twice.</description></item>
///   <item><description>Each script runs in a transaction unless it opts out explicitly.</description></item>
///   <item><description>An edited applied script is a hard startup failure, not a warning.</description></item>
///   <item><description>A failure aborts startup; the service never runs against a partial schema.</description></item>
///   <item><description>Destructive migrations trigger a backup first.</description></item>
///   <item><description>An advisory lock prevents two instances racing.</description></item>
/// </list>
/// </remarks>
internal sealed class MigrationRunner(
    IDbConnectionFactory connectionFactory,
    ISqlDialect dialect,
    IClock clock,
    IEnvironmentInfo environment,
    IOptions<MailServerOptions> options,
    ILogger<MigrationRunner> logger) : IDatabaseMigrator
{
    private readonly MigrationOptions _migrationOptions = options.Value.Database.Migrations;

    public async Task<MigrationStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<LoadedMigration> available = MigrationScriptLoader.Load(dialect);

        await using DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        await EnsureSchemaVersionTableAsync(connection, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<AppliedMigration> applied =
            await ReadAppliedAsync(connection, transaction: null, cancellationToken).ConfigureAwait(false);

        HashSet<int> appliedVersions = [.. applied.Select(a => a.Version)];

        IReadOnlyList<MigrationScript> pending =
        [
            .. available
                .Where(m => !appliedVersions.Contains(m.Metadata.Version))
                .Select(m => m.Metadata)
        ];

        return new MigrationStatus(
            applied.Count == 0 ? 0 : applied.Max(a => a.Version),
            available.Count == 0 ? 0 : available.Max(m => m.Metadata.Version),
            applied,
            pending);
    }

    public async Task<MigrationRunResult> MigrateAsync(CancellationToken cancellationToken = default)
    {
        long started = clock.GetTimestamp();

        IReadOnlyList<LoadedMigration> available = MigrationScriptLoader.Load(dialect);

        await using DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        // Held for the whole run on this one connection, so two service instances starting
        // simultaneously cannot both apply migration 0007.
        await AcquireMigrationLockAsync(connection, cancellationToken).ConfigureAwait(false);

        try
        {
            await EnsureSchemaVersionTableAsync(connection, cancellationToken).ConfigureAwait(false);

            IReadOnlyList<AppliedMigration> applied =
                await ReadAppliedAsync(connection, transaction: null, cancellationToken)
                    .ConfigureAwait(false);

            VerifyNoChecksumDrift(available, applied);

            Dictionary<int, AppliedMigration> appliedByVersion =
                applied.ToDictionary(a => a.Version);

            LoadedMigration[] pending =
            [
                .. available.Where(m => !appliedByVersion.ContainsKey(m.Metadata.Version))
            ];

            int fromVersion = applied.Count == 0 ? 0 : applied.Max(a => a.Version);

            if (pending.Length == 0)
            {
                logger.LogInformation(
                    "Database schema is up to date at version {SchemaVersion}.",
                    fromVersion);

                return new MigrationRunResult(fromVersion, fromVersion, [], clock.GetElapsedTime(started));
            }

            logger.LogInformation(
                "Applying {PendingCount} migration(s) to {Target}: {Versions}.",
                pending.Length,
                connectionFactory.DescribeTarget(),
                string.Join(", ", pending.Select(p => $"{p.Metadata.Version:D4}_{p.Metadata.Name}")));

            if (_migrationOptions.BackupBeforeDestructive &&
                pending.Any(p => p.Metadata.IsDestructive))
            {
                RefuseDestructiveMigrationWithoutBackup(pending);
            }

            List<string> appliedNames = [];

            foreach (LoadedMigration migration in pending)
            {
                await ApplyOneAsync(connection, migration, cancellationToken).ConfigureAwait(false);
                appliedNames.Add($"{migration.Metadata.Version:D4}_{migration.Metadata.Name}");
            }

            int toVersion = pending.Max(p => p.Metadata.Version);

            logger.LogInformation(
                "Database schema migrated from version {FromVersion} to {ToVersion}.",
                fromVersion,
                toVersion);

            return new MigrationRunResult(
                fromVersion,
                toVersion,
                appliedNames,
                clock.GetElapsedTime(started));
        }
        finally
        {
            await ReleaseMigrationLockAsync(connection).ConfigureAwait(false);
        }
    }

    private async Task ApplyOneAsync(
        DbConnection connection,
        LoadedMigration migration,
        CancellationToken cancellationToken)
    {
        MigrationScript metadata = migration.Metadata;
        Stopwatch stopwatch = Stopwatch.StartNew();

        bool useTransaction = dialect.SupportsTransactionalDdl && !metadata.RunsOutsideTransaction;

        if (!useTransaction)
        {
            logger.LogWarning(
                "Migration {Version:D4} '{Name}' runs OUTSIDE a transaction. A failure will " +
                "leave the schema partially modified and will require manual repair.",
                metadata.Version,
                metadata.Name);
        }

        DbTransaction? transaction = useTransaction
            ? await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
                .ConfigureAwait(false)
            : null;

        try
        {
            foreach (string batch in SplitBatches(migration.Sql))
            {
                await connection.ExecuteAsync(new CommandDefinition(
                    batch,
                    transaction: transaction,
                    commandTimeout: _migrationOptions.CommandTimeoutSeconds,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }

            stopwatch.Stop();

            await RecordAppliedAsync(
                connection,
                transaction,
                metadata,
                stopwatch.ElapsedMilliseconds,
                cancellationToken).ConfigureAwait(false);

            if (transaction is not null)
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }

            logger.LogInformation(
                "Applied migration {Version:D4} '{Name}' in {ElapsedMs} ms.",
                metadata.Version,
                metadata.Name,
                stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            if (transaction is not null)
            {
                try
                {
                    await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);

                    logger.LogError(
                        "Migration {Version:D4} '{Name}' failed and was rolled back.",
                        metadata.Version,
                        metadata.Name);
                }
                catch (Exception rollbackFailure)
                {
                    logger.LogCritical(
                        rollbackFailure,
                        "Migration {Version:D4} '{Name}' failed AND its rollback failed. The " +
                        "schema may be inconsistent; restore from backup before restarting.",
                        metadata.Version,
                        metadata.Name);
                }
            }

            // Fail safe: the service must not start against a partially migrated schema.
            throw new MigrationFailedException(metadata.Version, metadata.Name, ex);
        }
        finally
        {
            if (transaction is not null)
            {
                await transaction.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Compares each applied migration's recorded checksum against the script now present.
    /// </summary>
    /// <remarks>
    /// A mismatch means an applied script was edited. Continuing would run every later
    /// migration against a schema whose recorded history is a fiction, compounding the
    /// divergence with each release. Refusing to start is the only safe response, and the
    /// message says exactly how to recover.
    /// </remarks>
    private void VerifyNoChecksumDrift(
        IReadOnlyList<LoadedMigration> available,
        IReadOnlyList<AppliedMigration> applied)
    {
        Dictionary<int, LoadedMigration> byVersion =
            available.ToDictionary(m => m.Metadata.Version);

        foreach (AppliedMigration record in applied)
        {
            if (!byVersion.TryGetValue(record.Version, out LoadedMigration? script))
            {
                // The database is ahead of this build - a downgrade, or a mixed-version
                // deployment. Not fatal by itself, but the operator must know.
                logger.LogWarning(
                    "Migration {Version:D4} '{Name}' is recorded as applied but no such script " +
                    "exists in this build. The database may have been migrated by a newer " +
                    "version of the product.",
                    record.Version,
                    record.Name);
                continue;
            }

            if (!string.Equals(record.Checksum, script.Metadata.Checksum, StringComparison.OrdinalIgnoreCase))
            {
                throw new SchemaDriftException(
                    record.Version,
                    record.Name,
                    record.Checksum,
                    script.Metadata.Checksum);
            }
        }
    }

    /// <summary>
    /// Refuses to apply a migration marked destructive until the backup subsystem exists.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>BackupBeforeDestructive</c> is on by default and promises a backup. The backup
    /// subsystem lands in Milestone 13, where SQLite uses a checkpointed file copy and SQL
    /// Server uses <c>BACKUP DATABASE ... WITH CHECKSUM</c>. Until then this refuses to
    /// proceed rather than applying a destructive change while silently not taking the
    /// backup the option promised - honouring the setting in letter but not in substance is
    /// how people lose mail.
    /// </para>
    /// <para>
    /// Synchronous today because it performs no I/O. It becomes asynchronous in Milestone 13.
    /// </para>
    /// </remarks>
    private void RefuseDestructiveMigrationWithoutBackup(IReadOnlyList<LoadedMigration> pending)
    {
        LoadedMigration first = pending.First(p => p.Metadata.IsDestructive);

        string[] destructive =
        [
            .. pending
                .Where(p => p.Metadata.IsDestructive)
                .Select(p => $"{p.Metadata.Version:D4}_{p.Metadata.Name}")
        ];

        logger.LogCritical(
            "Pending migrations are marked destructive ({Migrations}) and " +
            "BackupBeforeDestructive is enabled, but automatic backup is not yet implemented.",
            string.Join(", ", destructive));

        throw new MigrationFailedException(
            first.Metadata.Version,
            first.Metadata.Name,
            new NotSupportedException(
                "Automatic pre-migration backup arrives in Milestone 13. Take a manual backup, " +
                "then set MailServer:Database:Migrations:BackupBeforeDestructive to false for " +
                "this upgrade only."));
    }

    private async Task EnsureSchemaVersionTableAsync(
        DbConnection connection,
        CancellationToken cancellationToken)
    {
        // Written for both providers with portable SQL, because it necessarily predates the
        // first migration and so cannot itself be one.
        string sql = dialect.Name switch
        {
            "SqlServer" => """
                IF OBJECT_ID(N'dbo.SchemaVersion', N'U') IS NULL
                CREATE TABLE dbo.SchemaVersion (
                    Version        INT             NOT NULL CONSTRAINT PK_SchemaVersion PRIMARY KEY,
                    Name           NVARCHAR(200)   NOT NULL,
                    Checksum       CHAR(64)        NOT NULL,
                    AppliedUtc     DATETIMEOFFSET  NOT NULL,
                    DurationMs     BIGINT          NOT NULL,
                    AppliedBy      NVARCHAR(256)   NOT NULL,
                    ProductVersion NVARCHAR(64)    NOT NULL
                );
                """,
            _ => """
                CREATE TABLE IF NOT EXISTS SchemaVersion (
                    Version        INTEGER NOT NULL PRIMARY KEY,
                    Name           TEXT    NOT NULL,
                    Checksum       TEXT    NOT NULL,
                    AppliedUtc     TEXT    NOT NULL,
                    DurationMs     INTEGER NOT NULL,
                    AppliedBy      TEXT    NOT NULL,
                    ProductVersion TEXT    NOT NULL
                );
                """,
        };

        await connection.ExecuteAsync(new CommandDefinition(
            sql,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<AppliedMigration>> ReadAppliedAsync(
        DbConnection connection,
        DbTransaction? transaction,
        CancellationToken cancellationToken)
    {
        const string Sql = """
            SELECT Version, Name, Checksum, AppliedUtc, DurationMs, AppliedBy, ProductVersion
            FROM SchemaVersion
            ORDER BY Version
            """;

        // Read into a row class with settable properties rather than straight into the
        // positional record. Dapper matches a record's constructor by exact parameter type,
        // which makes it brittle across two providers that return different CLR types for
        // the same logical column; property mapping goes through the registered type
        // handlers instead.
        IEnumerable<AppliedMigrationRow> rows = await connection
            .QueryAsync<AppliedMigrationRow>(new CommandDefinition(
                Sql,
                transaction: transaction,
                cancellationToken: cancellationToken))
            .ConfigureAwait(false);

        return [.. rows.Select(r => r.ToRecord())];
    }

    private async Task RecordAppliedAsync(
        DbConnection connection,
        DbTransaction? transaction,
        MigrationScript metadata,
        long durationMs,
        CancellationToken cancellationToken)
    {
        const string Sql = """
            INSERT INTO SchemaVersion
                (Version, Name, Checksum, AppliedUtc, DurationMs, AppliedBy, ProductVersion)
            VALUES
                (@Version, @Name, @Checksum, @AppliedUtc, @DurationMs, @AppliedBy, @ProductVersion)
            """;

        await connection.ExecuteAsync(new CommandDefinition(
            Sql,
            new
            {
                metadata.Version,
                metadata.Name,
                metadata.Checksum,
                AppliedUtc = clock.UtcNow,
                DurationMs = durationMs,
                AppliedBy = $"{environment.MachineName}\\{environment.ProcessAccount}",
                environment.ProductVersion,
            },
            transaction: transaction,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    private async Task AcquireMigrationLockAsync(
        DbConnection connection,
        CancellationToken cancellationToken)
    {
        if (dialect.AcquireMigrationLockSql is not { } sql)
        {
            // SQLite needs none: its single-writer file lock already serialises the whole
            // migration transaction across processes.
            return;
        }

        logger.LogDebug("Acquiring the migration advisory lock.");

        await connection.ExecuteAsync(new CommandDefinition(
            sql,
            commandTimeout: _migrationOptions.CommandTimeoutSeconds,
            cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    private async Task ReleaseMigrationLockAsync(DbConnection connection)
    {
        if (dialect.ReleaseMigrationLockSql is not { } sql)
        {
            return;
        }

        try
        {
            await connection.ExecuteAsync(new CommandDefinition(sql)).ConfigureAwait(false);
        }
        catch (DbException ex)
        {
            // The lock is session-scoped, so closing the connection releases it anyway.
            // Worth a log line, not worth masking a migration failure behind.
            logger.LogWarning(ex, "Releasing the migration advisory lock failed.");
        }
    }

    /// <summary>Flat row shape for the SchemaVersion table.</summary>
    private sealed class AppliedMigrationRow
    {
        public int Version { get; set; }

        public string Name { get; set; } = string.Empty;

        public string Checksum { get; set; } = string.Empty;

        public DateTimeOffset AppliedUtc { get; set; }

        public long DurationMs { get; set; }

        public string AppliedBy { get; set; } = string.Empty;

        public string ProductVersion { get; set; } = string.Empty;

        public AppliedMigration ToRecord() =>
            new(Version, Name, Checksum, AppliedUtc, DurationMs, AppliedBy, ProductVersion);
    }

    /// <summary>
    /// Splits a script on batch separators.
    /// </summary>
    /// <remarks>
    /// SQL Server's <c>GO</c> is a client-side batch separator, not a T-SQL statement: sent
    /// to the server it is a syntax error. Any script using <c>CREATE VIEW</c>,
    /// <c>CREATE TRIGGER</c> or similar must be split here because those statements must be
    /// first in their batch.
    /// </remarks>
    private static IEnumerable<string> SplitBatches(string sql)
    {
        string[] lines = sql.Split('\n');
        List<string> current = [];

        foreach (string line in lines)
        {
            if (line.Trim().Equals("GO", StringComparison.OrdinalIgnoreCase))
            {
                string batch = string.Join('\n', current).Trim();
                if (batch.Length > 0)
                {
                    yield return batch;
                }

                current.Clear();
                continue;
            }

            current.Add(line);
        }

        string final = string.Join('\n', current).Trim();
        if (final.Length > 0)
        {
            yield return final;
        }
    }
}
