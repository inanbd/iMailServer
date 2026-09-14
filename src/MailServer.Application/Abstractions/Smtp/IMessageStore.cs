using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Smtp;

/// <summary>A message that has been written and committed.</summary>
/// <param name="Id">The identifier the message was stored under.</param>
/// <param name="SizeBytes">Size of the stored content.</param>
/// <param name="ContentHash">SHA-256 of the stored content, computed while it was written.</param>
/// <param name="StoredAt">When the commit happened.</param>
public sealed record StoredMessage(
    StoredMessageId Id,
    long SizeBytes,
    Sha256Hash ContentHash,
    DateTimeOffset StoredAt);

/// <summary>
/// Writes one message, in chunks, and either commits it or leaves nothing behind.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no method that takes a whole message.</b> Not an overload, not a convenience, not
/// one marked "for small messages only". The largest message this server accepts is tens of
/// megabytes and it arrives from a stranger; an API that allowed a single array would eventually
/// be called with one, and the limit would be enforced only by whoever remembered to check.
/// </para>
/// <para>
/// Disposing without committing abandons the message and removes anything already written. That
/// is the normal path for a refused or interrupted <c>DATA</c>, so it must leave no trace.
/// </para>
/// </remarks>
public interface IMessageWriter : IAsyncDisposable
{
    /// <summary>The identifier this message will be committed under.</summary>
    StoredMessageId Id { get; }

    /// <summary>Octets written so far.</summary>
    long BytesWritten { get; }

    /// <summary>Appends a chunk.</summary>
    /// <exception cref="MessageTooLargeException">
    /// The message exceeded the size limit. Thrown rather than truncating: a truncated message
    /// delivered as though complete is worse than a refused one.
    /// </exception>
    ValueTask WriteAsync(ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken);

    /// <summary>
    /// Makes the message durable and visible, and returns what was stored.
    /// </summary>
    /// <remarks>
    /// Commit happens <b>before</b> any database row refers to the message. A crash between the
    /// two leaves a file nobody references — which a sweep can find and remove — rather than a
    /// row pointing at a file that does not exist, which is a mailbox the owner cannot open.
    /// </remarks>
    ValueTask<StoredMessage> CommitAsync(CancellationToken cancellationToken);
}

/// <summary>Raised when a message exceeds the size limit mid-write.</summary>
public sealed class MessageTooLargeException(long limitBytes, long attemptedBytes)
    : Exception($"The message exceeded the {limitBytes}-byte limit at {attemptedBytes} bytes.")
{
    /// <summary>The limit that was exceeded.</summary>
    public long LimitBytes { get; } = limitBytes;

    /// <summary>How far the write had got.</summary>
    public long AttemptedBytes { get; } = attemptedBytes;
}

/// <summary>
/// Where message content lives.
/// </summary>
/// <remarks>
/// <para>
/// Content is stored outside the database. A mail store is mostly large opaque blobs that are
/// written once and read whole, which is the one workload a relational database is worst at, and
/// keeping them out means a backup, a restore or a migration of the metadata does not have to
/// move gigabytes with it.
/// </para>
/// <para>
/// <b>The read side returns a <see cref="Stream"/> and nothing else.</b> There is deliberately no
/// method returning <c>byte[]</c>: IMAP fetches ranges, delivery copies to a socket, and the
/// virus scanner reads sequentially. None of them needs the whole message resident, and offering
/// it would mean a mailbox of large messages could be turned into memory pressure by anyone who
/// can send mail.
/// </para>
/// </remarks>
public interface IMessageStore
{
    /// <summary>Begins writing a new message.</summary>
    /// <param name="maxSizeBytes">
    /// Hard limit for this message. The writer enforces it as well as the caller — a limit
    /// checked in only one place is a limit that stops being checked when a second caller
    /// appears.
    /// </param>
    ValueTask<IMessageWriter> BeginWriteAsync(long maxSizeBytes, CancellationToken cancellationToken);

    /// <summary>Opens a committed message for reading.</summary>
    /// <returns>A readable, seekable stream. The caller disposes it.</returns>
    ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken);

    /// <summary>Whether a committed message exists.</summary>
    ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken);

    /// <summary>Removes a committed message. Returns false if it was not there.</summary>
    ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken);
}
