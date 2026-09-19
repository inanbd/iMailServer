using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
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

    /// <summary>
    /// Creates a folder, and every superior level it needs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 3501 §6.3.3: "If the server's hierarchy separator character appears elsewhere in the
    /// name, the server SHOULD create any superior hierarchical names that are needed for the
    /// CREATE command to be successfully completed. In other words, an attempt to create
    /// "foo/bar/zap" […] SHOULD create foo/ and foo/bar/ if they do not already exist."
    /// </para>
    /// <para>
    /// <b>A recreated name gets a fresh UIDVALIDITY, which is what licenses reusing UIDs from
    /// 1.</b> §6.3.3 requires that a new mailbox with a deleted mailbox's name uses identifiers
    /// "greater than any unique identifiers used in the previous incarnation […] <i>UNLESS the
    /// new incarnation has a different unique identifier validity value</i>". Taking the
    /// exception is cheaper and safer than preserving a high-water mark per deleted name, and it
    /// is the branch that tells every client to discard its cache — which is correct, because
    /// the mailbox genuinely is a different one.
    /// </para>
    /// </remarks>
    Task<ImapFolderMutation> CreateFolderAsync(
        MailboxId mailboxId,
        string path,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes a folder and its messages, leaving anything nested beneath it alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>§6.3.4's MUST: "The DELETE command MUST NOT remove inferior hierarchical names."</b>
    /// Deleting <c>foo</c> leaves <c>foo/bar</c> exactly where it was. The RFC then describes what
    /// the surviving name becomes: "It is permitted to delete a name that has inferior
    /// hierarchical names and does not have the <c>\Noselect</c> mailbox name attribute. In this
    /// case, all messages in that mailbox are removed, and the name will acquire the
    /// <c>\Noselect</c> mailbox name attribute." That acquisition needs no code here: with the
    /// row gone the name exists only as a hierarchy level, and a hierarchy level is precisely
    /// what this server reports <c>\Noselect</c>.
    /// </para>
    /// <para>
    /// <b>The subscription is not touched</b>, per §6.3.6's MUST NOT — see
    /// <see cref="IImapMailboxReader.ListSubscriptionsAsync"/>.
    /// </para>
    /// </remarks>
    Task<ImapFolderMutation> DeleteFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken);

    /// <summary>
    /// Renames a folder and everything nested beneath it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>§6.3.5's MUST: "If the name has inferior hierarchical names, then the inferior
    /// hierarchical names MUST also be renamed. For example, a rename of "foo" to "zap" will
    /// rename "foo/bar" […] to "zap/bar"."</b> So this is a subtree operation, not a row update,
    /// and it happens in one transaction: a half-renamed subtree is a mailbox whose folders have
    /// two different parents.
    /// </para>
    /// <para>
    /// <b>Renaming the inbox is a different operation entirely.</b> §6.3.5: "Renaming INBOX is
    /// permitted, and has special behavior. It moves all messages in INBOX to a new mailbox with
    /// the given name, leaving INBOX empty. If the server implementation supports inferior
    /// hierarchical names of INBOX, these are unaffected by a rename of INBOX." So the inbox
    /// survives under its own reserved name, its messages move out, and its children stay put —
    /// three departures from the ordinary case, and the reason the inbox is handled separately
    /// rather than as a special path prefix.
    /// </para>
    /// </remarks>
    Task<ImapFolderMutation> RenameFolderAsync(
        MailboxId mailboxId,
        string from,
        string to,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Adds or removes a name from the subscription list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Subscribing validates that the name exists; unsubscribing does not.</b> §6.3.6 permits
    /// the check — "A server MAY validate the mailbox argument to SUBSCRIBE to verify that it
    /// exists" — and this server takes it, because a typo that silently succeeds leaves a user
    /// with a folder list that never populates. Unsubscribing must not validate, because the
    /// whole point of the list is that it can name something gone.
    /// </para>
    /// <para>
    /// Both are idempotent. §6.3.6 and §6.3.7 ask only that the tagged <c>OK</c> mean the list is
    /// in the requested state, not that it changed.
    /// </para>
    /// </remarks>
    /// <summary>
    /// Copies messages into another folder, optionally removing them from this one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One method for <c>COPY</c> and <c>MOVE</c>, because RFC 6851 defines the second in
    /// terms of the first.</b> §3.3: a move "has the same effect for each message as this
    /// sequence: 1. [UID] COPY 2. [UID] STORE +FLAGS.SILENT \DELETED 3. UID EXPUNGE" — and then
    /// rules out the middle step's visible traces: "response codes for a STORE MUST NOT be
    /// generated and the <c>\DELETED</c> flag MUST NOT be set for any message." So the removal
    /// here is a deletion, never a flag.
    /// </para>
    /// <para>
    /// <b>The copy gets a new UID and keeps everything else.</b> RFC 3501 §6.4.7: messages go
    /// "to the end of the specified destination mailbox. The flags and internal date of the
    /// message(s) SHOULD be preserved, and the Recent flag SHOULD be set, in the copy." The flags
    /// and date are preserved; <c>\Recent</c> is not set, because this server never sets it
    /// anywhere and a copy is no place to start.
    /// </para>
    /// <para>
    /// <b>All of it in one transaction, which both RFCs demand in their own words.</b> §6.4.7:
    /// "If the COPY command is unsuccessful for any reason, server implementations MUST restore
    /// the destination mailbox to its state before the COPY attempt." RFC 6851 §3.3 is stricter
    /// still for a move: "The server MUST leave each message in a state where it is in at least
    /// one of the source or target mailboxes (no message can be lost or orphaned)." A half-done
    /// move is the one outcome that loses mail.
    /// </para>
    /// <para>
    /// The message content is not duplicated. A copy is another <c>Deliveries</c> row against the
    /// same <c>Messages</c> row, which is what makes copying a large message cheap and what the
    /// stored-once-delivered-many schema was shaped for.
    /// </para>
    /// </remarks>
    /// <param name="removeFromSource">True for <c>MOVE</c>, false for <c>COPY</c>.</param>
    /// <returns>
    /// The outcome, and — for a move — the source sequence numbers that were removed, descending,
    /// ready to be reported as untagged <c>EXPUNGE</c> responses.
    /// </returns>
    Task<ImapCopyResult> CopyAsync(
        MailboxId mailboxId,
        MailboxFolderId sourceFolderId,
        ImapSequenceSet set,
        bool byUid,
        string targetPath,
        bool removeFromSource,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Records an already-stored message as a new delivery at the end of a folder.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The octets are committed to the message store before this is called</b>, which is the
    /// order the storage schema insists on: its comment on <c>Messages</c> says the row "is
    /// written AFTER the file is committed. A crash between the two leaves a file nobody
    /// references, which the sweep removes - never a row naming a file that does not exist, which
    /// is a mailbox the owner cannot open."
    /// </para>
    /// <para>
    /// <b>A missing destination is reported, never created.</b> RFC 3501 §6.3.11: "If the
    /// destination mailbox does not exist, a server MUST return an error, and MUST NOT
    /// automatically create the mailbox." The handler turns that into the <c>[TRYCREATE]</c> the
    /// same section also makes a MUST.
    /// </para>
    /// <para>
    /// One transaction, per §6.3.11: "If the append is unsuccessful for any reason, the mailbox
    /// MUST be restored to its state before the APPEND attempt; no partial appending is
    /// permitted."
    /// </para>
    /// </remarks>
    /// <param name="stored">
    /// What the message store committed — its identity, size and content hash. The hash is
    /// carried rather than recomputed or stubbed: the schema keeps it so that a file truncated
    /// or altered underneath the row that names it can be noticed rather than served, and a row
    /// written with a placeholder would defeat that for every appended message.
    /// </param>
    /// <returns>The outcome, and the folder's message count afterwards.</returns>
    Task<ImapAppendResult> AppendAsync(
        MailboxId mailboxId,
        string path,
        StoredMessage stored,
        MessageFlags flags,
        DateTimeOffset internalDate,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    Task<ImapFolderMutation> SetSubscriptionAsync(
        MailboxId mailboxId,
        string path,
        bool subscribed,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes named messages from a folder, whatever their flags.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>POP3's UPDATE state is why this exists alongside
    /// <see cref="ExpungeAsync"/>.</b> RFC 1939 §6: "The POP3 server removes all messages marked
    /// as deleted from the maildrop […] In no case may the server remove any messages not marked
    /// as deleted." A POP3 session's marks live in that session and nowhere else, so the removal
    /// has to name the messages. Reaching for <c>ExpungeAsync</c> instead would remove every
    /// message in the folder carrying <c>\Deleted</c> — including ones an IMAP client marked and
    /// deliberately has not expunged, which is mail the user did not ask anybody to destroy.
    /// </para>
    /// <para>
    /// <b>The messages' stored content is not touched</b>, for the reason
    /// <see cref="ExpungeAsync"/> gives at length: only the <c>Deliveries</c> rows go, and
    /// reclaiming a file no delivery references is a retention sweep's job.
    /// </para>
    /// <para>
    /// A UID that is not there is passed over rather than reported. Another session may have
    /// removed it since this one listed the folder, and a POP3 client that is told its
    /// <c>QUIT</c> failed will simply send the same deletions again.
    /// </para>
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the removal; never optional.</param>
    /// <param name="folderId">The folder the messages are in.</param>
    /// <param name="uids">The messages to remove. An empty list does nothing.</param>
    /// <returns>How many rows were removed.</returns>
    Task<long> DeleteMessagesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        IReadOnlyList<long> uids,
        CancellationToken cancellationToken);
}

/// <summary>What an <c>APPEND</c> did.</summary>
/// <param name="Outcome">Whether it ran, and why not if it did not.</param>
/// <param name="FolderId">The destination folder, when there was one.</param>
/// <param name="ExistsCount">
/// How many messages the folder holds afterwards — what an untagged <c>EXISTS</c> would carry
/// if the client has that mailbox selected. §6.3.11: "If the mailbox is currently selected, the
/// normal new message actions SHOULD occur. Specifically, the server SHOULD notify the client
/// immediately via an untagged EXISTS response."
/// </param>
public sealed record ImapAppendResult(
    ImapFolderMutation Outcome,
    MailboxFolderId? FolderId,
    long ExistsCount);

/// <summary>
/// What a <c>COPY</c> or <c>MOVE</c> did.
/// </summary>
/// <param name="Outcome">Whether it ran, and why not if it did not.</param>
/// <param name="RemovedSequenceNumbers">
/// For a move, the source positions that went, highest first — the order RFC 3501 §7.4.1 permits
/// and the one that needs no renumbering arithmetic. Always empty for a copy.
/// </param>
/// <param name="CopiedCount">How many messages were copied.</param>
public sealed record ImapCopyResult(
    ImapFolderMutation Outcome,
    IReadOnlyList<long> RemovedSequenceNumbers,
    int CopiedCount);

/// <summary>
/// What a folder-shaped command did, or why it did nothing.
/// </summary>
/// <remarks>
/// An enum rather than an exception, because none of these is exceptional: RFC 3501 §6.3.3 and
/// §6.3.4 both describe their failures as ordinary outcomes answered with "a tagged NO response",
/// and a client creating a folder that already exists is a client doing something reasonable
/// with stale information.
/// </remarks>
public enum ImapFolderMutation
{
    /// <summary>The mailbox is now in the requested state.</summary>
    Done = 0,

    /// <summary>
    /// The name is already taken — §6.3.3: "It is an error to attempt to create INBOX or a
    /// mailbox with a name that refers to an extant mailbox."
    /// </summary>
    AlreadyExists = 1,

    /// <summary>
    /// No mailbox of that name — §6.3.4: "It is an error to attempt to delete INBOX or a mailbox
    /// name that does not exist."
    /// </summary>
    NotFound = 2,

    /// <summary>
    /// The name is reserved. <c>INBOX</c> may be neither created nor deleted, per §6.3.3 and
    /// §6.3.4; it may be renamed, which is a different operation — see
    /// <see cref="IImapMailboxWriter.RenameFolderAsync"/>.
    /// </summary>
    Reserved = 3,

    /// <summary>The name is not one this server can store — too long, too deep, or malformed.</summary>
    Invalid = 4,
}
