using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>
/// The write side of a mailbox, for IMAP.
/// </summary>
/// <remarks>
/// <para>
/// A third interface rather than methods on <see cref="IImapMailboxReader"/>, whose name would
/// then be a lie, and rather than on <see cref="IDeliveryRepository"/>, which is local
/// delivery's write side and has a different caller. The reader's own remarks set this up: "an
/// IMAP session reads constantly and writes only when a client changes a flag". This is that
/// rare write, and keeping it behind its own interface is what stops a reading code path from
/// acquiring the ability to change a mailbox by accident.
/// </para>
/// <para>
/// <b>Every method takes the mailbox identity as well as the folder.</b> The same argument the
/// reader makes: a folder id is a value an authenticated session hands back from its own
/// earlier <c>SELECT</c>, so the authorisation belongs in the <c>WHERE</c> clause. It matters
/// more here — a read of the wrong folder shows a user somebody else's mail, and a write to the
/// wrong folder changes it.
/// </para>
/// </remarks>
public interface IImapMailboxWriter
{
    /// <summary>
    /// Applies a <c>STORE</c> to the messages a sequence set names, and reports what they became.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The new values are returned rather than left to the caller to predict.</b> RFC 3501
    /// §6.4.6: "The new value of the flags is returned as if a FETCH of those flags was done."
    /// A caller that computed the result itself would be reporting what it asked for rather than
    /// what happened — and those differ whenever a flag was already set, was concurrently
    /// changed, or could not be stored at all.
    /// </para>
    /// <para>
    /// <b>The read-back and the write are one transaction.</b> Otherwise the untagged
    /// <c>FETCH</c> could report a value that a concurrent session had already replaced, which is
    /// precisely the race §6.4.6's note exists to close: "The intent is that the status of the
    /// flags is determinate without a race condition."
    /// </para>
    /// <para>
    /// A message the set names but the folder does not hold is skipped, not reported — RFC 3501
    /// §6.4.8's "A non-existent unique identifier is ignored without any error message
    /// generated", which applies to <c>UID STORE</c> as much as to <c>UID FETCH</c>.
    /// </para>
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the write; never optional.</param>
    /// <param name="folderId">The selected folder.</param>
    /// <param name="set">The sequence set, with any <c>*</c> still unresolved.</param>
    /// <param name="byUid">Whether the numbers are UIDs — <c>UID STORE</c>.</param>
    /// <param name="request">What to do to the flags.</param>
    /// <returns>
    /// The affected messages carrying their <b>new</b> flags, in ascending sequence order. Empty
    /// when the set named nothing that exists.
    /// </returns>
    Task<IReadOnlyList<ImapMessageSummary>> StoreFlagsAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        ImapStoreRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Permanently removes every message carrying <c>\Deleted</c>, and says which they were.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The sequence numbers come back descending, and that is what makes the caller's job
    /// arithmetic-free.</b> RFC 3501 §7.4.1: "The message sequence number for each successive
    /// message in the mailbox is immediately decremented by 1, and this decrement is reflected in
    /// message sequence numbers in subsequent responses (including other untagged EXPUNGE
    /// responses)." The RFC permits either direction and spells both out — "a 'lower to higher'
    /// server will send five untagged EXPUNGE responses for message sequence number 5, whereas a
    /// 'higher to lower server' will send successive untagged EXPUNGE responses for message
    /// sequence numbers 9, 8, 7, 6, and 5". Descending is the half where no number ever moves
    /// before it is sent, because only higher positions have gone — so these are simply the
    /// positions as they were before anything was removed, and nothing has to track a running
    /// decrement. In the one response where an off-by-one deletes the wrong mail on the client,
    /// having no arithmetic at all is worth more than the symmetry.
    /// </para>
    /// <para>
    /// <b>The positions are read and the rows removed in one transaction.</b> A number computed
    /// against one state of the folder and applied to another is exactly the desynchronisation
    /// §7.4.1's "MUST NOT be sent" rule exists to prevent elsewhere.
    /// </para>
    /// <para>
    /// <b>The messages' stored content is not touched.</b> Only the <c>Deliveries</c> rows go.
    /// The <c>Messages</c> row and its file outlive them by design — the schema's own comment on
    /// <c>ContentRemovedUtc</c> says "The row outlives the file so that delivery history survives
    /// retention, which is what an abuse investigation actually needs months later" — so
    /// reclaiming a file once no delivery references it is a retention sweep's job, and there is
    /// no such sweep yet. Deleting the content here would destroy evidence the schema exists to
    /// keep.
    /// </para>
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the removal; never optional.</param>
    /// <param name="folderId">The selected folder.</param>
    /// <returns>
    /// The removed messages' sequence numbers, as they were before the removal, in descending
    /// order. Empty when nothing carried <c>\Deleted</c>.
    /// </returns>
    Task<IReadOnlyList<long>> ExpungeAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        CancellationToken cancellationToken);
}
