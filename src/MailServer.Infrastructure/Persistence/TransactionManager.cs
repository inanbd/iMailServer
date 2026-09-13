using System.Data;
using System.Data.Common;
using MailServer.Application.Abstractions.Persistence;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Persistence;

/// <summary>
/// Provider-neutral transaction boundaries with join semantics, write serialisation and
/// bounded retry of transient failures.
/// </summary>
/// <remarks>
/// <para>
/// <b>Retry safety.</b> A transaction body is retried only when it failed with a transient
/// error <i>and</i> was rolled back, so the database is back at its starting state. This is
/// safe precisely because the codebase forbids network I/O inside a transaction: if a handler
/// could send an SMTP message inside its transaction, a retry would send it twice. That rule
/// is what makes this retry loop correct, which is why it is stated on
/// <see cref="ITransactionManager"/> as well as here.
/// </para>
/// </remarks>
internal sealed class TransactionManager(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect,
    SqlWriteGate writeGate,
    ILogger<TransactionManager> logger) : ITransactionManager
{
    private const int MaxTransientRetries = 3;

    public Task<T> ExecuteAsync<T>(
        Func<DbConnection, DbTransaction, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(action);

        return RunAsync(
            (session, ct) => action(session.Connection, session.Transaction!, ct),
            cancellationToken);
    }

    public async Task ExecuteAsync(
        Func<DbConnection, DbTransaction, CancellationToken, Task> action,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(action);

        await RunAsync(
            async (session, ct) =>
            {
                await action(session.Connection, session.Transaction!, ct).ConfigureAwait(false);
                return true;
            },
            cancellationToken).ConfigureAwait(false);
    }

    public Task<T> ExecuteScopedAsync<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        return RunAsync((_, ct) => action(ct), cancellationToken);
    }

    private async Task<T> RunAsync<T>(
        Func<IDbSession, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        // Join an existing transaction rather than opening a second connection. Under SQLite
        // a second write connection inside an open write transaction deadlocks against it.
        if (ambientSession.Current is { IsTransactional: true } existing)
        {
            logger.LogDebug("Joining the ambient transaction.");
            return await action(existing, cancellationToken).ConfigureAwait(false);
        }

        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return await ExecuteOnceAsync(action, cancellationToken).ConfigureAwait(false);
            }
            catch (DbException ex) when (dialect.IsTransient(ex) && attempt < MaxTransientRetries)
            {
                // Safe: the transaction rolled back, so the database is back where it started,
                // and no external side effect can have occurred inside it.
                TimeSpan delay = TimeSpan.FromMilliseconds(50 * Math.Pow(2, attempt - 1));

                logger.LogWarning(
                    ex,
                    "Transient database failure on attempt {Attempt} of {MaxAttempts}; " +
                    "retrying in {DelayMs} ms.",
                    attempt,
                    MaxTransientRetries,
                    (int)delay.TotalMilliseconds);

                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task<T> ExecuteOnceAsync<T>(
        Func<IDbSession, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        // The gate is taken BEFORE the connection is opened. Acquiring it afterwards would
        // hold an idle connection open for the whole wait, which under SQLite is exactly the
        // resource the waiter is queuing for.
        using IDisposable writeSlot = await writeGate
            .AcquireAsync(cancellationToken)
            .ConfigureAwait(false);

        await using DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        await using DbTransaction transaction = await connection
            .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
            .ConfigureAwait(false);

        DbSession session = new(connection, transaction, ownsConnection: false);

        IDisposable? enlistment = ambientSession is AmbientDbSession ambient
            ? ambient.Enlist(session)
            : null;

        try
        {
            T result = await action(session, cancellationToken).ConfigureAwait(false);

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

            return result;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction).ConfigureAwait(false);
            throw;
        }
        finally
        {
            enlistment?.Dispose();
        }
    }

    private async Task RollbackQuietlyAsync(DbTransaction transaction)
    {
        try
        {
            // CancellationToken.None: a rollback must complete even when the request was
            // cancelled. Abandoning it would leave the transaction open until the connection
            // is reclaimed, and under SQLite that blocks every other writer in the meantime.
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception rollbackFailure)
        {
            // Logged, never swallowed silently, and never rethrown: rethrowing here would
            // replace the original exception - the one that says what actually went wrong -
            // with a secondary failure.
            logger.LogError(
                rollbackFailure,
                "Rollback failed after a transaction error. The original error is being " +
                "propagated.");
        }
    }
}
