using System.Data.Common;

namespace MailServer.Application.Abstractions.Persistence;

/// <summary>
/// Establishes explicit transaction boundaries.
/// </summary>
/// <remarks>
/// <para>
/// <b>No <see cref="System.Transactions.TransactionScope"/>, ever.</b> It can silently
/// promote to a distributed transaction and pull in MSDTC. A mail server must not acquire
/// a distributed-transaction dependency by accident, and a promotion failure at 3am is a
/// diagnosis nobody enjoys.
/// </para>
/// <para>
/// <b>Nested calls join the ambient transaction</b> rather than opening a second connection.
/// Under SQLite, where exactly one writer is permitted, a second write connection inside an
/// open write transaction is a guaranteed self-deadlock.
/// </para>
/// <para>
/// <b>No network I/O inside a transaction.</b> An SMTP conversation held inside a database
/// transaction holds the SQLite writer for the duration of a remote server's response time.
/// The delivery happens outside; the outcome is recorded in a second short transaction.
/// </para>
/// </remarks>
public interface ITransactionManager
{
    /// <summary>
    /// Runs <paramref name="action"/> inside a transaction, committing on success and
    /// rolling back on any exception. Joins the ambient transaction if one exists.
    /// </summary>
    Task<T> ExecuteAsync<T>(
        Func<DbConnection, DbTransaction, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default);

    /// <summary>Transaction-scoped work with no return value.</summary>
    Task ExecuteAsync(
        Func<DbConnection, DbTransaction, CancellationToken, Task> action,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs <paramref name="action"/> inside a transaction that is published as the ambient
    /// session, so repositories resolved within it enlist automatically. This is the overload
    /// the transaction pipeline behavior uses.
    /// </summary>
    Task<T> ExecuteScopedAsync<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default);
}
