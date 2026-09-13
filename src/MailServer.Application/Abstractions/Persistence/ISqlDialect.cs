using System.Data.Common;
using System.Reflection;

namespace MailServer.Application.Abstractions.Persistence;

/// <summary>
/// The provider-specific SQL fragments and behaviours that the shared repository
/// implementations need.
/// </summary>
/// <remarks>
/// <para>
/// Repositories are written <b>once</b> against this interface rather than duplicated per
/// provider. Two hand-maintained copies of the same SQL is where drift breeds, and drift in
/// a mail store means data-corruption bugs that appear on only one provider and are
/// therefore found in production.
/// </para>
/// <para>
/// Only genuinely divergent SQL is written twice, and this interface enumerates exactly
/// which parts those are - which makes the divergence auditable.
/// </para>
/// </remarks>
public interface ISqlDialect
{
    /// <summary>Provider name for logs and diagnostics, e.g. <c>Sqlite</c>.</summary>
    string Name { get; }

    /// <summary>
    /// True when the provider permits only one writer at a time, so write transactions must
    /// be serialised in-process. True for SQLite; false for SQL Server.
    /// </summary>
    bool RequiresSerializedWrites { get; }

    /// <summary>True when the provider supports DDL inside a transaction.</summary>
    bool SupportsTransactionalDdl { get; }

    /// <summary>Quotes an identifier: <c>[Name]</c> on SQL Server, <c>"Name"</c> on SQLite.</summary>
    string QuoteIdentifier(string identifier);

    /// <summary>
    /// Paging clause: <c>LIMIT n OFFSET m</c> on SQLite,
    /// <c>OFFSET m ROWS FETCH NEXT n ROWS ONLY</c> on SQL Server. Requires an ORDER BY.
    /// </summary>
    string PagingClause(int take, int skip);

    /// <summary>Expression yielding the current UTC time in the database's own dialect.</summary>
    string UtcNowExpression { get; }

    /// <summary>
    /// Classifies an exception as transient and therefore worth retrying: SQLITE_BUSY for
    /// SQLite, deadlock/lock-timeout/throttling error numbers for SQL Server. Getting this
    /// wrong in either direction is costly - retrying a constraint violation forever, or
    /// failing a request that would have succeeded a millisecond later.
    /// </summary>
    bool IsTransient(DbException exception);

    /// <summary>
    /// True when the exception is a unique-constraint violation, which the Application layer
    /// maps to <see cref="Domain.Exceptions.DuplicateEntityException"/>.
    /// </summary>
    bool IsUniqueConstraintViolation(DbException exception);

    /// <summary>
    /// Statement that acquires an exclusive, session-scoped advisory lock before migrations
    /// run, or null when the provider needs none.
    /// </summary>
    /// <remarks>
    /// Two service instances starting simultaneously must not both apply migration 0007.
    /// SQL Server uses <c>sp_getapplock</c>. SQLite returns null: its single-writer file
    /// lock already serialises the whole migration transaction across processes.
    /// </remarks>
    string? AcquireMigrationLockSql { get; }

    /// <summary>Statement releasing the lock taken by <see cref="AcquireMigrationLockSql"/>.</summary>
    string? ReleaseMigrationLockSql { get; }

    /// <summary>
    /// Assembly-qualified prefix under which this provider's embedded migration scripts live.
    /// </summary>
    string MigrationsResourcePrefix { get; }

    /// <summary>The assembly carrying this provider's embedded migration scripts.</summary>
    Assembly MigrationsAssembly { get; }
}
