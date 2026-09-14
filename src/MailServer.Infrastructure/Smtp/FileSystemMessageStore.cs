using System.Globalization;
using System.Security.Cryptography;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Smtp;

/// <summary>
/// Stores message content as files under the data root.
/// </summary>
/// <remarks>
/// <para>
/// Layout is <c>Messages/yyyy/MM/dd/{id}.eml</c>. Date sharding keeps any one directory to a
/// day's mail instead of every message the server has ever received, which matters on NTFS long
/// before it becomes a correctness problem: directory enumeration and even a single open slow
/// down badly once a folder holds millions of entries, and a backup tool walking it may simply
/// stop.
/// </para>
/// <para>
/// <b>Write to a temporary name, then rename.</b> A rename within a volume is atomic, so a reader
/// — or a crash — never sees a message that is half-written. Everything that fails before the
/// rename leaves only a temporary file, which a sweep removes.
/// </para>
/// </remarks>
public sealed class FileSystemMessageStore : IMessageStore
{
    private const string MessagesFolder = "Messages";
    private const string IncomingFolder = "Incoming";
    private const string Extension = ".eml";

    private readonly string _root;
    private readonly string _incoming;
    private readonly IClock _clock;
    private readonly ILogger<FileSystemMessageStore> _logger;

    public FileSystemMessageStore(
        IOptions<MailServerOptions> options,
        IClock clock,
        ILogger<FileSystemMessageStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(logger);

        _root = Path.Combine(options.Value.Storage.DataRoot, MessagesFolder);
        _incoming = Path.Combine(_root, IncomingFolder);
        _clock = clock;
        _logger = logger;

        Directory.CreateDirectory(_incoming);
    }

    /// <summary>Creates a store rooted at an explicit directory. For tests and tooling.</summary>
    public FileSystemMessageStore(string messagesRoot, IClock clock, ILogger<FileSystemMessageStore> logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messagesRoot);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(logger);

        _root = messagesRoot;
        _incoming = Path.Combine(_root, IncomingFolder);
        _clock = clock;
        _logger = logger;

        Directory.CreateDirectory(_incoming);
    }

    /// <inheritdoc />
    public ValueTask<IMessageWriter> BeginWriteAsync(long maxSizeBytes, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxSizeBytes);
        cancellationToken.ThrowIfCancellationRequested();

        StoredMessageId id = new(Guid.NewGuid());
        DateTimeOffset now = _clock.UtcNow;

        string temporaryPath = Path.Combine(_incoming, FormatFileName(id) + ".tmp");
        string finalPath = ResolvePath(id, now);

        Directory.CreateDirectory(Path.GetDirectoryName(finalPath)!);

        // Asynchronous and sequential: the whole access pattern is append-only, and saying so
        // lets the filesystem read ahead and flush behind instead of guessing.
        FileStream stream = new(
            temporaryPath,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                BufferSize = 64 * 1024,
            });

        return ValueTask.FromResult<IMessageWriter>(
            new FileMessageWriter(id, stream, temporaryPath, finalPath, maxSizeBytes, now, _logger));
    }

    /// <inheritdoc />
    public ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string? path = FindExisting(id);

        if (path is null)
        {
            throw new FileNotFoundException($"No stored message with id {id.Value}.");
        }

        Stream stream = new FileStream(
            path,
            new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,

                // Readers do not exclude one another: IMAP may be fetching a message while the
                // retention sweep is looking at it, and neither is writing.
                Share = FileShare.Read | FileShare.Delete,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                BufferSize = 64 * 1024,
            });

        return ValueTask.FromResult(stream);
    }

    /// <inheritdoc />
    public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(FindExisting(id) is not null);
    }

    /// <inheritdoc />
    public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string? path = FindExisting(id);

        if (path is null)
        {
            return ValueTask.FromResult(false);
        }

        File.Delete(path);

        return ValueTask.FromResult(true);
    }

    /// <summary>Removes temporary files left by writes that never committed.</summary>
    /// <remarks>
    /// The other half of write-then-rename: abandoning a write leaves a temporary file, and a
    /// crash mid-write leaves one nothing will ever dispose. Sweeping them is maintenance, not
    /// error recovery — no message is lost by removing one, because nothing ever referred to it.
    /// </remarks>
    public int SweepAbandonedWrites(TimeSpan olderThan)
    {
        DateTimeOffset cutoff = _clock.UtcNow - olderThan;
        int removed = 0;

        foreach (string path in Directory.EnumerateFiles(_incoming, "*.tmp"))
        {
            try
            {
                if (File.GetLastWriteTimeUtc(path) >= cutoff.UtcDateTime)
                {
                    continue;
                }

                File.Delete(path);
                removed++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Very likely a write still in progress that took longer than the cutoff. Leave
                // it; the next sweep will find it if it really was abandoned.
                _logger.LogDebug(ex, "Could not remove abandoned message file {Path}.", path);
            }
        }

        return removed;
    }

    /// <summary>
    /// Finds a stored message without knowing which day it was stored on.
    /// </summary>
    /// <remarks>
    /// The identifier does not carry its own date, so a lookup that had only the id would have to
    /// walk the tree. It does not: the caller almost always knows the date from the database row,
    /// and the fallback search exists for the rare case — a repair tool, an orphan sweep — where
    /// it does not. Callers on the delivery path never reach it.
    /// </remarks>
    private string? FindExisting(StoredMessageId id)
    {
        string fileName = FormatFileName(id) + Extension;

        // Today and yesterday first: a message being read is overwhelmingly a message just
        // delivered, and this avoids walking the tree for the common case.
        DateTimeOffset now = _clock.UtcNow;

        foreach (DateTimeOffset day in (DateTimeOffset[])[now, now.AddDays(-1)])
        {
            string candidate = Path.Combine(DirectoryFor(day), fileName);

            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        if (!Directory.Exists(_root))
        {
            return null;
        }

        return Directory
            .EnumerateFiles(_root, fileName, SearchOption.AllDirectories)
            .FirstOrDefault();
    }

    private string ResolvePath(StoredMessageId id, DateTimeOffset now) =>
        Path.Combine(DirectoryFor(now), FormatFileName(id) + Extension);

    private string DirectoryFor(DateTimeOffset day) => Path.Combine(
        _root,
        day.UtcDateTime.ToString("yyyy", CultureInfo.InvariantCulture),
        day.UtcDateTime.ToString("MM", CultureInfo.InvariantCulture),
        day.UtcDateTime.ToString("dd", CultureInfo.InvariantCulture));

    /// <summary>
    /// The file name for an identifier.
    /// </summary>
    /// <remarks>
    /// "N" format: 32 hex digits, no braces and no hyphens, so the name contains nothing that
    /// could be a path separator, a drive letter or a relative segment. Rule 105's "no path
    /// traversal" is met by the name being generated rather than by sanitising one that was not.
    /// </remarks>
    private static string FormatFileName(StoredMessageId id) => id.Value.ToString("N", CultureInfo.InvariantCulture);

    private sealed class FileMessageWriter(
        StoredMessageId id,
        FileStream stream,
        string temporaryPath,
        string finalPath,
        long maxSizeBytes,
        DateTimeOffset startedAt,
        ILogger logger) : IMessageWriter
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        private bool _committed;
        private bool _disposed;

        public StoredMessageId Id => id;

        public long BytesWritten { get; private set; }

        public async ValueTask WriteAsync(ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_committed)
            {
                throw new InvalidOperationException("The message has already been committed.");
            }

            if (chunk.IsEmpty)
            {
                return;
            }

            // Checked before the write, so the limit bounds what reaches the disk rather than
            // what is discovered afterwards.
            if (BytesWritten + chunk.Length > maxSizeBytes)
            {
                throw new MessageTooLargeException(maxSizeBytes, BytesWritten + chunk.Length);
            }

            await stream.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);

            _hash.AppendData(chunk.Span);
            BytesWritten += chunk.Length;
        }

        public async ValueTask<StoredMessage> CommitAsync(CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_committed)
            {
                throw new InvalidOperationException("The message has already been committed.");
            }

            // Flush through to the device before the rename. Without it the rename can become
            // visible while the content behind it is still in the write-back cache, and a power
            // loss leaves a named, referenced, empty message.
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
            await stream.DisposeAsync().ConfigureAwait(false);

            File.Move(temporaryPath, finalPath, overwrite: false);

            _committed = true;

            return new StoredMessage(
                id,
                BytesWritten,
                Sha256Hash.FromBytes(_hash.GetHashAndReset()),
                startedAt);
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _hash.Dispose();

            if (_committed)
            {
                return;
            }

            // Abandoned: a refused or interrupted DATA. Leave nothing behind.
            await stream.DisposeAsync().ConfigureAwait(false);

            try
            {
                File.Delete(temporaryPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The sweep will get it. Failing to delete a temporary file must not turn an
                // already-failed delivery into an exception on the session loop.
                logger.LogWarning(ex, "Could not remove abandoned message file {Path}.", temporaryPath);
            }
        }
    }
}
