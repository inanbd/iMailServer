using System.Data.Common;
using MailServer.Application.Abstractions.Persistence;

namespace MailServer.Infrastructure.Persistence;

/// <summary>A connection, and the transaction enlisted on it if there is one.</summary>
internal sealed class DbSession : IDbSession
{
    private readonly bool _ownsConnection;
    private bool _disposed;

    public DbSession(DbConnection connection, DbTransaction? transaction, bool ownsConnection)
    {
        Connection = connection;
        Transaction = transaction;
        _ownsConnection = ownsConnection;
    }

    public DbConnection Connection { get; }

    public DbTransaction? Transaction { get; }

    public bool IsTransactional => Transaction is not null;

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Only the creator disposes. A repository that joined an ambient transaction must
        // never close the connection the transaction manager is still using.
        if (_ownsConnection)
        {
            await Connection.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Scoped holder for the ambient session established by the transaction manager.
/// </summary>
internal sealed class AmbientDbSession : IAmbientDbSession
{
    public IDbSession? Current { get; private set; }

    /// <summary>Publishes a session as ambient. Returns a handle that clears it on dispose.</summary>
    public IDisposable Enlist(IDbSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (Current is not null)
        {
            throw new InvalidOperationException(
                "A transaction is already in progress in this scope. Nested transactions must " +
                "join the ambient one rather than opening a second connection; opening a " +
                "second write connection under SQLite deadlocks against the first.");
        }

        Current = session;
        return new Enlistment(this);
    }

    private void Clear() => Current = null;

    private sealed class Enlistment(AmbientDbSession owner) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            owner.Clear();
        }
    }
}
