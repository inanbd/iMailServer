using MailServer.Domain.Filtering;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>Which held messages a listing asks for.</summary>
public enum QuarantineFilter
{
    /// <summary>Only what is still waiting for somebody to decide. The default view.</summary>
    Held = 0,

    /// <summary>Everything, including what has already been released or discarded.</summary>
    All = 1,
}

/// <summary>Stores what the filter held.</summary>
public interface IQuarantineRepository
{
    /// <summary>Holds a message.</summary>
    Task AddAsync(QuarantinedMessage message, CancellationToken cancellationToken);

    /// <summary>Reads one held message, signals and all.</summary>
    Task<QuarantinedMessage?> GetAsync(QuarantinedMessageId id, CancellationToken cancellationToken);

    /// <summary>The most recently held messages, newest first.</summary>
    Task<IReadOnlyList<QuarantinedMessage>> ListAsync(
        QuarantineFilter filter,
        int limit,
        CancellationToken cancellationToken);

    /// <summary>How many messages are still held.</summary>
    Task<int> CountHeldAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Writes a resolution, and reports whether it was this call that made it.
    /// </summary>
    /// <returns>
    /// False when the row was no longer held — another administrator resolved it first, or a
    /// retention sweep removed it. The caller must not deliver a message it did not win the
    /// right to release: two operators clicking at once would otherwise deliver it twice.
    /// </returns>
    Task<bool> TryResolveAsync(QuarantinedMessage message, CancellationToken cancellationToken);

    /// <summary>
    /// Removes held rows whose retention has run out, and reports which messages they named.
    /// </summary>
    /// <remarks>
    /// The message ids come back so the caller can remove the content too. Deleting the row and
    /// leaving the file would grow the store by one message per expiry for the life of the
    /// installation, with nothing left pointing at it.
    /// </remarks>
    Task<IReadOnlyList<StoredMessageId>> PurgeExpiredAsync(
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken);
}
