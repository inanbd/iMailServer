using MailServer.Application.Abstractions.Persistence;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Persistence;

/// <summary>
/// Serialises write transactions in-process when the provider permits only one writer.
/// </summary>
/// <remarks>
/// <para>
/// SQLite allows exactly one writer at a time. Several queue workers, the IMAP APPEND path
/// and the admin console all competing for that one slot produce <c>SQLITE_BUSY</c> storms
/// and long tail latencies, because each contender burns its busy-timeout budget before
/// failing.
/// </para>
/// <para>
/// A single in-process gate converts that contention into an orderly queue: waiters are
/// admitted one at a time, nobody times out, and throughput actually improves because no
/// work is wasted on retries. Reads are untouched and run fully concurrently thanks to WAL.
/// </para>
/// <para>
/// Under SQL Server the gate is a no-op, because the engine handles concurrent writers
/// properly and serialising them in-process would throw away most of its throughput.
/// </para>
/// </remarks>
public sealed class SqlWriteGate : IDisposable
{
    private readonly SemaphoreSlim? _semaphore;
    private readonly ILogger<SqlWriteGate> _logger;

    public SqlWriteGate(ISqlDialect dialect, ILogger<SqlWriteGate> logger)
    {
        ArgumentNullException.ThrowIfNull(dialect);

        _logger = logger;
        IsEnabled = dialect.RequiresSerializedWrites;
        _semaphore = IsEnabled ? new SemaphoreSlim(1, 1) : null;

        if (IsEnabled)
        {
            logger.LogInformation(
                "Write serialisation is enabled for the {Provider} provider: write " +
                "transactions are admitted one at a time. Reads are unaffected.",
                dialect.Name);
        }
    }

    /// <summary>True when writes are being serialised.</summary>
    public bool IsEnabled { get; }

    /// <summary>Waits for the write slot. Returns a handle that releases it on dispose.</summary>
    public async ValueTask<IDisposable> AcquireAsync(CancellationToken cancellationToken)
    {
        if (_semaphore is null)
        {
            return NullRelease.Instance;
        }

        await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new Release(_semaphore, _logger);
    }

    public void Dispose() => _semaphore?.Dispose();

    private sealed class Release(SemaphoreSlim semaphore, ILogger logger) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            try
            {
                semaphore.Release();
            }
            catch (ObjectDisposedException)
            {
                // The gate was disposed during shutdown while a writer was still finishing.
                // Harmless: the process is going away and nothing else is waiting.
                logger.LogDebug("Write gate was disposed before its holder released it.");
            }
        }
    }

    private sealed class NullRelease : IDisposable
    {
        public static readonly NullRelease Instance = new();

        public void Dispose()
        {
        }
    }
}
