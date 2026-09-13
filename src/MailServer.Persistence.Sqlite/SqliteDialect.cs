using System.Data.Common;
using System.Globalization;
using System.Reflection;
using MailServer.Application.Abstractions.Persistence;
using Microsoft.Data.Sqlite;

namespace MailServer.Persistence.Sqlite;

/// <summary>SQLite's answers to the provider-specific questions in <see cref="ISqlDialect"/>.</summary>
public sealed class SqliteDialect : ISqlDialect
{
    public string Name => "Sqlite";

    /// <summary>
    /// True: SQLite permits exactly one writer.
    /// </summary>
    /// <remarks>
    /// This flag is what switches on <c>SqlWriteGate</c>. Without it, several queue workers
    /// plus the IMAP APPEND path plus the admin console all contend for one writer slot,
    /// each burning its busy-timeout budget before failing with SQLITE_BUSY. Serialising
    /// them in-process turns that into an orderly queue and actually raises throughput,
    /// because no work is wasted on retries.
    /// </remarks>
    public bool RequiresSerializedWrites => true;

    /// <summary>True: SQLite fully supports DDL inside a transaction.</summary>
    public bool SupportsTransactionalDdl => true;

    public string QuoteIdentifier(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        // Doubling embedded quotes is the standard escape. Identifiers in this codebase are
        // compile-time constants, so this is belt-and-braces rather than input handling.
        return $"\"{identifier.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    }

    public string PagingClause(int take, int skip)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(take);
        ArgumentOutOfRangeException.ThrowIfNegative(skip);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"LIMIT {take} OFFSET {skip}");
    }

    public string UtcNowExpression => "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

    /// <summary>
    /// Classifies SQLite errors that are worth retrying.
    /// </summary>
    /// <remarks>
    /// Only genuine contention errors qualify. <c>SQLITE_BUSY</c> (5) means another
    /// connection holds the write lock, and <c>SQLITE_LOCKED</c> (6) means a table lock
    /// within the same connection - both clear on their own. Everything else, in particular
    /// a constraint violation, is permanent: retrying it would loop forever while looking
    /// like a hang.
    /// </remarks>
    public bool IsTransient(DbException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception is SqliteException sqlite &&
               sqlite.SqliteErrorCode is SqliteErrorCodes.Busy or SqliteErrorCodes.Locked;
    }

    public bool IsUniqueConstraintViolation(DbException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        // 19 is SQLITE_CONSTRAINT; the extended code distinguishes which constraint failed.
        // 2067 is SQLITE_CONSTRAINT_UNIQUE and 1555 is SQLITE_CONSTRAINT_PRIMARYKEY.
        return exception is SqliteException sqlite &&
               sqlite.SqliteErrorCode == SqliteErrorCodes.Constraint &&
               sqlite.SqliteExtendedErrorCode is SqliteErrorCodes.ConstraintUnique
                                              or SqliteErrorCodes.ConstraintPrimaryKey;
    }

    /// <summary>
    /// Null: SQLite needs no advisory lock.
    /// </summary>
    /// <remarks>
    /// Its single-writer file lock already serialises the whole migration transaction across
    /// processes, so a second instance starting simultaneously simply waits.
    /// </remarks>
    public string? AcquireMigrationLockSql => null;

    public string? ReleaseMigrationLockSql => null;

    public string MigrationsResourcePrefix => "MailServer.Persistence.Sqlite.Migrations.";

    public Assembly MigrationsAssembly => typeof(SqliteDialect).Assembly;
}

/// <summary>
/// The SQLite result codes this product reacts to.
/// </summary>
/// <remarks>
/// Named constants rather than bare integers scattered through the dialect, because a
/// mis-typed error code silently changes retry behaviour in a way no test would obviously
/// catch.
/// </remarks>
internal static class SqliteErrorCodes
{
    public const int Busy = 5;
    public const int Locked = 6;
    public const int Constraint = 19;
    public const int ConstraintPrimaryKey = 1555;
    public const int ConstraintUnique = 2067;
}
