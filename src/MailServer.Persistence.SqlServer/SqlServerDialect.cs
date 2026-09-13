using System.Data.Common;
using System.Globalization;
using System.Reflection;
using MailServer.Application.Abstractions.Persistence;
using Microsoft.Data.SqlClient;

namespace MailServer.Persistence.SqlServer;

/// <summary>SQL Server's answers to the provider-specific questions in <see cref="ISqlDialect"/>.</summary>
public sealed class SqlServerDialect : ISqlDialect
{
    public string Name => "SqlServer";

    /// <summary>
    /// False: SQL Server handles concurrent writers properly.
    /// </summary>
    /// <remarks>
    /// Serialising writes in-process here would discard most of the engine's throughput for
    /// no benefit. The write gate exists for SQLite's single-writer model and is a no-op
    /// under this provider.
    /// </remarks>
    public bool RequiresSerializedWrites => false;

    public bool SupportsTransactionalDdl => true;

    public string QuoteIdentifier(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        return $"[{identifier.Replace("]", "]]", StringComparison.Ordinal)}]";
    }

    /// <summary>
    /// SQL Server's paging form. Requires an ORDER BY, which every paged query here supplies.
    /// </summary>
    public string PagingClause(int take, int skip)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(take);
        ArgumentOutOfRangeException.ThrowIfNegative(skip);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"OFFSET {skip} ROWS FETCH NEXT {take} ROWS ONLY");
    }

    public string UtcNowExpression => "SYSUTCDATETIME()";

    /// <summary>
    /// Classifies SQL Server errors worth retrying.
    /// </summary>
    /// <remarks>
    /// The list is the documented set of transient conditions: deadlock victim, lock request
    /// timeout, Azure SQL throttling and connection-establishment failures. Getting this
    /// wrong costs in both directions - retrying a constraint violation loops forever, and
    /// failing a deadlock victim aborts work that would have succeeded on a second attempt.
    /// </remarks>
    public bool IsTransient(DbException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        if (exception is not SqlException sql)
        {
            return false;
        }

        foreach (SqlError error in sql.Errors)
        {
            if (TransientErrorNumbers.Contains(error.Number))
            {
                return true;
            }
        }

        return false;
    }

    public bool IsUniqueConstraintViolation(DbException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        if (exception is not SqlException sql)
        {
            return false;
        }

        foreach (SqlError error in sql.Errors)
        {
            // 2601 duplicate key in a unique index; 2627 unique constraint violation.
            if (error.Number is 2601 or 2627)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Takes an exclusive application lock for the duration of the migration session.
    /// </summary>
    /// <remarks>
    /// <c>@LockOwner = 'Session'</c> rather than 'Transaction', because the runner applies
    /// several migrations in several transactions and the lock must span all of them.
    /// A ten-minute timeout, then failure: waiting forever would turn a stuck peer into a
    /// service that never starts and never says why.
    /// </remarks>
    public string? AcquireMigrationLockSql => """
        DECLARE @result INT;
        EXEC @result = sp_getapplock
            @Resource = 'AetherMail.SchemaMigration',
            @LockMode = 'Exclusive',
            @LockOwner = 'Session',
            @LockTimeout = 600000;
        IF @result < 0
            THROW 50001,
                'Could not acquire the AetherMail schema migration lock within 10 minutes. Another instance may be migrating.',
                1;
        """;

    public string? ReleaseMigrationLockSql => """
        IF APPLOCK_MODE('public', 'AetherMail.SchemaMigration', 'Session') <> 'NoLock'
            EXEC sp_releaseapplock
                @Resource = 'AetherMail.SchemaMigration',
                @LockOwner = 'Session';
        """;

    public string MigrationsResourcePrefix => "MailServer.Persistence.SqlServer.Migrations.";

    public Assembly MigrationsAssembly => typeof(SqlServerDialect).Assembly;

    /// <summary>
    /// SQL Server error numbers treated as transient.
    /// </summary>
    private static readonly HashSet<int> TransientErrorNumbers =
    [
        -2,     // Client-side command timeout
        20,     // Encryption-capable instance not found
        64,     // Connection failed during login
        233,    // No process on the other end of the pipe
        4060,   // Cannot open database (may be coming online)
        4221,   // Login to a replica in a transitional state
        10053,  // Transport-level error on receive
        10054,  // Existing connection forcibly closed
        10060,  // Network or instance-specific error during connect
        10928,  // Azure SQL: resource limit reached
        10929,  // Azure SQL: minimum guarantee not met
        40197,  // Azure SQL: service error during processing
        40501,  // Azure SQL: service busy
        40613,  // Azure SQL: database not currently available
        41301,  // Dependency failure in a concurrent transaction
        41302,  // Attempted update of a row updated since this transaction started
        41305,  // Repeatable-read validation failure
        41325,  // Serializable validation failure
        49918,  // Cannot process request: not enough resources
        49919,  // Cannot process create/update request
        49920,  // Cannot process request: too many operations
        1204,   // Lock manager out of lock resources
        1205,   // Deadlock victim
        1222,   // Lock request timeout
    ];
}
