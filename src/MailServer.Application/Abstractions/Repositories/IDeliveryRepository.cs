using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>Persists accepted messages and where they were delivered.</summary>
/// <remarks>
/// The write side of local delivery. Reads for IMAP arrive in Milestone 10 and are deliberately
/// not speculated about here: an interface designed for a consumer that does not exist yet is an
/// interface designed wrongly.
/// </remarks>
public interface IDeliveryRepository
{
    /// <summary>Records a message that has already been committed to the store.</summary>
    /// <remarks>
    /// Called after the content file exists, never before. A row naming a file that is not there
    /// is a mailbox its owner cannot open; a file that no row names is an orphan a sweep removes.
    /// </remarks>
    Task AddMessageAsync(MessageRecord message, CancellationToken cancellationToken);

    /// <summary>Records one envelope recipient.</summary>
    Task AddRecipientAsync(MessageRecipient recipient, CancellationToken cancellationToken);

    /// <summary>
    /// Takes the next UID for a folder and advances the folder's counter.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One statement, not a read followed by a write. Two concurrent deliveries to the same
    /// folder that each read <c>NextUid</c> and then wrote back <c>NextUid + 1</c> would both get
    /// the same UID, and the unique index would reject the second — turning an ordinary
    /// concurrent delivery into a failed one.
    /// </para>
    /// <para>
    /// UIDs are never reused, even when the delivery that took one goes on to fail. A gap in the
    /// sequence is explicitly legal in IMAP; a repeated UID is not.
    /// </para>
    /// </remarks>
    Task<long> AllocateUidAsync(MailboxFolderId folderId, CancellationToken cancellationToken);

    /// <summary>Records a delivery into a folder.</summary>
    Task AddDeliveryAsync(Delivery delivery, CancellationToken cancellationToken);

    /// <summary>Adds to a mailbox's used storage.</summary>
    /// <remarks>
    /// A relative update rather than a read, add and write. Two deliveries landing at once would
    /// otherwise each read the same figure and one increment would vanish, which is how a quota
    /// drifts below the truth until a mailbox that is full reports that it is not.
    /// </remarks>
    Task AddStorageUsedAsync(MailboxId mailboxId, long bytes, CancellationToken cancellationToken);

    /// <summary>Finds the folder a delivery should land in, creating nothing.</summary>
    /// <returns>The folder, or null when the mailbox has no such folder.</returns>
    Task<MailboxFolder?> GetFolderAsync(
        MailboxId mailboxId,
        Domain.Enums.FolderSpecialUse specialUse,
        CancellationToken cancellationToken);
}
