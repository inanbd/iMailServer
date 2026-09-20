using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>
/// The read side of a mailbox, for IMAP.
/// </summary>
/// <remarks>
/// <para>
/// Separate from <see cref="IDeliveryRepository"/>, which is the write side and says in its own
/// remarks that "reads for IMAP arrive in Milestone 10 and are deliberately not speculated about
/// here: an interface designed for a consumer that does not exist yet is an interface designed
/// wrongly". This is that interface, now that the consumer exists — and it is a second interface
/// rather than more methods on the first because the two have genuinely different callers. Local
/// delivery writes and never reads; an IMAP session reads constantly and writes only when a
/// client changes a flag.
/// </para>
/// <para>
/// <b>It grows one command at a time, and that is the point.</b> Only <c>SELECT</c> and
/// <c>EXAMINE</c> exist so far, so only what they need is here. Adding <c>LIST</c>'s and
/// <c>FETCH</c>'s reads now would be guessing at their shape before anything makes them prove
/// it, which is exactly the mistake the write side's remarks warn about.
/// </para>
/// <para>
/// <b>Every method takes the mailbox identity, and none of them trusts a folder id alone.</b>
/// A folder id is a value an authenticated session hands back from its own earlier
/// <c>SELECT</c> — but a session that had somehow acquired another mailbox's folder id must not
/// be able to read that folder, and the cheapest way to make that impossible is to never offer
/// a query that could. Authorisation belongs in the <c>WHERE</c> clause, not in a check a caller
/// might forget.
/// </para>
/// </remarks>
public interface IImapMailboxReader
{
    /// <summary>
    /// Finds a folder by the name a client asked for and reads what opening it requires.
    /// </summary>
    /// <remarks>
    /// One call and one query, because the count and the first-unseen position must be read at
    /// the same instant — see <see cref="ImapFolderSnapshot"/>'s remarks on why two reads that
    /// disagreed would be worse than either alone.
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the search; never optional.</param>
    /// <param name="path">
    /// The mailbox name from the command, already decoded from modified UTF-7. Matched exactly,
    /// except for the inbox — see <see cref="ImapMailboxPath"/>.
    /// </param>
    /// <returns>The snapshot, or null when this mailbox has no such folder.</returns>
    Task<ImapFolderSnapshot?> OpenFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken);

    /// <summary>
    /// Every folder in a mailbox, with enough about each to answer <c>LIST</c> and <c>LSUB</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>All of them, unfiltered, with the pattern applied afterwards in memory — and that is
    /// not laziness.</b> RFC 3501 §6.3.8's wildcards do not translate into <c>LIKE</c>: <c>%</c>
    /// must not cross the hierarchy delimiter, which <c>LIKE</c>'s <c>%</c> cheerfully does, and
    /// a folder path may itself contain <c>%</c> or <c>_</c>, which are <c>LIKE</c>
    /// metacharacters needing an <c>ESCAPE</c> clause whose syntax differs between providers.
    /// A pattern pushed into SQL would therefore be a second, subtly different matcher living in
    /// two dialects, against the one in
    /// <see cref="ImapMailboxPattern"/> that has tests. One matcher, in one place.
    /// </para>
    /// <para>
    /// <b><c>HasChildren</c> is computed here rather than per folder.</b> It is a question about
    /// the set — "is any other path nested beneath this one" — so answering it once for the
    /// whole set is one pass, while answering it per folder is a query per folder, which is the
    /// shape RFC 3501 §6.3.8 warns about: "if each name requires 1 second of processing, then a
    /// list of 1200 names would take 20 minutes!"
    /// </para>
    /// <para>
    /// The result is bounded by what the mailbox's own owner created, and the command is
    /// available only to an authenticated session, so there is no cap here — a cap would
    /// silently truncate a user's folder list, which is a worse failure than a large response to
    /// a request only its owner can make.
    /// </para>
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the enumeration; never optional.</param>
    /// <returns>The folders, ordered by path.</returns>
    Task<IReadOnlyList<ImapFolderListing>> ListFoldersAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken);

    /// <summary>
    /// The counts <c>STATUS</c> reports about a folder, without selecting it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A separate read from <see cref="OpenFolderAsync"/>, not a reuse of it, because the number
    /// both commands call <c>UNSEEN</c> is not the same number: <c>SELECT</c> reports the first
    /// unseen message's position and <c>STATUS</c> reports how many are unseen. See
    /// <see cref="ImapStatusItem.Unseen"/> for what reusing one as the other would get wrong.
    /// </para>
    /// <para>
    /// <b>Nothing about the session changes.</b> RFC 3501 §6.3.10: <c>STATUS</c> "does not change
    /// the currently selected mailbox, nor does it affect the state of any messages in the
    /// queried mailbox". A read method that returns a value and touches nothing is how that is
    /// made true rather than remembered.
    /// </para>
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the search; never optional.</param>
    /// <param name="path">The mailbox name from the command, already decoded.</param>
    /// <returns>The counts, or null when this mailbox has no such folder.</returns>
    Task<ImapFolderStatus?> ReadStatusAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken);

    /// <summary>
    /// The stored facts about the messages a <c>FETCH</c> names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The set is passed in unresolved, because only a reader can resolve it.</b> RFC 3501
    /// §9's <c>*</c> is "the largest in use", and which largest depends on the command: a
    /// <c>FETCH</c> resolves it against the message count and a <c>UID FETCH</c> against the
    /// largest UID. Both are facts about the folder at the instant of the read, so resolving
    /// them anywhere else would mean resolving them against a folder that may since have
    /// changed.
    /// </para>
    /// <para>
    /// <b>A non-existent message is not an error.</b> §6.4.8: "A non-existent unique identifier
    /// is ignored without any error message generated. Thus, it is possible for a UID FETCH
    /// command to return an OK without any data." The same is true of a sequence number past the
    /// end, so this returns what exists and never reports what did not.
    /// </para>
    /// <para>
    /// <b>Both ids are required, and the mailbox one is not redundant.</b> A folder id is a value
    /// an authenticated session hands back from its own earlier <c>SELECT</c>; putting the
    /// mailbox in the <c>WHERE</c> clause beside it is what makes a session that had somehow
    /// acquired another mailbox's folder id unable to read that folder's mail.
    /// </para>
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the read; never optional.</param>
    /// <param name="folderId">The selected folder.</param>
    /// <param name="set">The sequence set from the command, with any <c>*</c> still unresolved.</param>
    /// <param name="byUid">
    /// Whether the numbers are UIDs. True for <c>UID FETCH</c> — §6.4.8: "the numbers in the
    /// sequence set argument are unique identifiers instead of message sequence numbers".
    /// </param>
    /// <returns>The matching messages, in ascending sequence order.</returns>
    /// <summary>
    /// Every name a mailbox's owner has subscribed to, whether or not it still names a folder.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read from the subscription list rather than from the folders, and that is the whole
    /// reason the list exists.</b> RFC 3501 §6.3.6: a server "MUST NOT unilaterally remove an
    /// existing mailbox name from the subscription list even if a mailbox by that name no longer
    /// exists", with the RFC's own note explaining the case — "a server site can choose to
    /// routinely remove a mailbox with a well-known name (e.g., "system-alerts") after its
    /// contents expire, with the intention of recreating it when new contents are appropriate."
    /// A subscription derived from a folder row could not survive that, so <c>LSUB</c> would
    /// quietly stop reporting a name the user never unsubscribed from.
    /// </para>
    /// <para>
    /// Consequently <c>LSUB</c>'s name set is this, not <see cref="ListFoldersAsync"/>'s — and a
    /// subscribed name with no folder behind it is reported <c>\Noselect</c>, which is exactly
    /// what §7.2.2 defines the attribute to mean: "It is not possible to use this name as a
    /// selectable mailbox."
    /// </para>
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the read; never optional.</param>
    /// <returns>The subscribed names, ordered.</returns>
    Task<IReadOnlyList<string>> ListSubscriptionsAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken);

    /// <summary>
    /// How many messages a folder holds and whether any of their flags have changed, and nothing
    /// else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For <c>IDLE</c>, which asks this repeatedly while a client waits. Reading the summaries
    /// and counting them would work and would read every row of the folder on every poll; these
    /// are two aggregates over indexes the folder is already keyed by.
    /// </para>
    /// <para>
    /// <b>The counter is what keeps <see cref="ReadFlagsAsync"/> off the poll timer.</b> RFC 3501
    /// §6.4.6 asks a server to report a flag change "from an external source", which cannot be
    /// noticed without comparing the folder against what the client was last told — an O(folder)
    /// read. Asking this first turns that into work proportional to what actually happened: on a
    /// folder nothing has touched, an idling connection costs one row per poll however much mail
    /// it holds.
    /// </para>
    /// </remarks>
    Task<ImapFolderPoll> PollFolderAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Every message in a folder as a UID and its flags, ascending by UID.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The whole folder rather than a sequence set, because the caller is looking for what it
    /// does not already know about — including messages that have arrived and, by their absence,
    /// messages that have gone. A range cannot express either.
    /// </para>
    /// <para>
    /// <b>Two columns, and no join.</b> <see cref="ReadSummariesAsync"/> reaches into
    /// <c>Messages</c> for the size and would be the obvious thing to reuse; it is not reused
    /// because this read exists to be cheap enough to run whenever a folder changes, and
    /// <c>INTERNALDATE</c> and <c>RFC822.SIZE</c> are values no flag comparison looks at.
    /// </para>
    /// <para>
    /// Ascending by UID, which RFC 3501 §2.3.1.2 makes the same order as ascending by message
    /// sequence number: "Messages in a mailbox are also assigned a unique identifier … and
    /// ascending order of unique identifier corresponds to ascending order of message sequence
    /// number." The caller depends on that to read positions off the list.
    /// </para>
    /// </remarks>
    Task<IReadOnlyList<ImapFlagState>> ReadFlagsAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Which stored message each of these UIDs is a delivery of.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Separate from <see cref="ReadSummariesAsync"/> because most fetches never need it. A
    /// client's synchronisation pass asks for flags and sizes across a whole folder; only a
    /// fetch that actually wants content needs to know where the content is, and carrying the
    /// identity on every summary would invite a caller to open a message it was not asked for.
    /// </para>
    /// <para>
    /// The identity, not the content. Reading the octets is the message store's job, and keeping
    /// that out of the repository is what stops a database round trip turning into file I/O
    /// inside a transaction.
    /// </para>
    /// </remarks>
    /// <param name="uids">The UIDs to resolve. Scoped to the folder and the mailbox.</param>
    Task<IReadOnlyDictionary<long, StoredMessageId>> ReadMessageIdsAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        IReadOnlyList<long> uids,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ImapMessageSummary>> ReadSummariesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        CancellationToken cancellationToken);
}
