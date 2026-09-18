using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Imap;

/// <summary>
/// How a client's mailbox name maps onto a stored folder path.
/// </summary>
/// <remarks>
/// <para>
/// One name is special and the rest are this server's own choice. RFC 3501 §5.1: "The
/// case-insensitive mailbox name INBOX is a special name reserved to mean 'the primary mailbox
/// for this user on this server'. The interpretation of all other names is
/// implementation-dependent."
/// </para>
/// <para>
/// <b>The RFC declines to settle the rest, and says so.</b> §5.1 continues: "In particular, this
/// specification takes no position on case sensitivity in non-INBOX mailbox names. Some server
/// implementations are fully case-sensitive; others preserve case of a newly-created name but
/// otherwise are case-insensitive; and yet others coerce names to a particular case. Client
/// implementations MUST interact with any of these." This server takes the first of the three:
/// names are matched exactly. That is a decision rather than a requirement, and it is made this
/// way because a folder name is the user's own text — folding it would merge <c>Receipts</c> and
/// <c>receipts</c> into one folder on the user's behalf and without being asked. The inbox is
/// still folded, because there the RFC does require it, and because a client asking for
/// <c>inbox</c> in lower case must reach the primary mailbox.
/// </para>
/// <para>
/// The one case-sensitivity rule §5.1 does impose is narrower and lives in §5.1.3: "server
/// implementations MUST preserve the exact form of the modified BASE64 portion of a modified
/// UTF-7 name and treat that text as case-sensitive, even if names are otherwise case-insensitive
/// or case-folded." That binds <c>ImapMailboxName</c>'s encoded runs, not folder names at large.
/// </para>
/// </remarks>
public static class ImapMailboxPath
{
    /// <summary>The one name RFC 3501 reserves, in the spelling this server stores it under.</summary>
    /// <remarks>
    /// Upper case because that is how <see cref="MailboxFolder.StandardFolders"/> provisions it
    /// and how every example in RFC 3501 writes it, and because a client that has cached the
    /// name will send it back.
    /// </remarks>
    public const string Inbox = "INBOX";

    /// <summary>Whether <paramref name="path"/> names the primary mailbox.</summary>
    public static bool IsInbox(string? path) =>
        string.Equals(path, Inbox, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The stored path a client's mailbox name refers to.
    /// </summary>
    /// <remarks>
    /// Only ever changes the inbox, and only its case. Everything else is returned exactly as it
    /// arrived, because a folder name is the user's own text and this server has no business
    /// deciding that two spellings of it are the same folder.
    /// </remarks>
    public static string Canonical(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        return IsInbox(path) ? Inbox : path;
    }
}

/// <summary>
/// What <c>SELECT</c> and <c>EXAMINE</c> need to know about a folder, read at one instant.
/// </summary>
/// <remarks>
/// <para>
/// A snapshot rather than a live view, deliberately. RFC 3501 §6.3.1 has the server report a
/// message count and a first-unseen position as part of opening the mailbox, and those are true
/// as of the moment they were read — a delivery arriving a millisecond later does not make the
/// <c>EXISTS</c> that was already sent wrong, it makes a later untagged <c>EXISTS</c> due. Naming
/// the type for that avoids the mistake of treating the numbers as something to keep in step.
/// </para>
/// <para>
/// <b>Everything here is read in one query.</b> The count and the first-unseen position are two
/// aggregates over the same index — <c>IX_Deliveries_Folder_Uid</c>, whose own schema comment
/// calls it "the query IMAP runs constantly" — and splitting them would mean a client's
/// <c>SELECT</c> could be answered with a count from before a delivery and an unseen position
/// from after it. Those two numbers disagreeing is how a client ends up asking to fetch a
/// message that is not where it was told.
/// </para>
/// </remarks>
/// <param name="Folder">The folder itself, carrying UIDVALIDITY and UIDNEXT.</param>
/// <param name="ExistsCount">
/// How many messages the folder holds — RFC 3501 §7.3.1's <c>EXISTS</c>. Zero for an empty
/// folder, which is grammatical and true.
/// </param>
/// <param name="FirstUnseenSequenceNumber">
/// The message sequence number of the first message without <c>\Seen</c>, or null when every
/// message has been read.
/// </param>
public sealed record ImapFolderSnapshot(
    MailboxFolder Folder,
    long ExistsCount,
    long? FirstUnseenSequenceNumber)
{
    /// <summary>The folder's identity.</summary>
    public MailboxFolderId FolderId => Folder.Id;

    /// <summary>
    /// The UID a message delivered next would probably get — RFC 3501 §7.1's <c>UIDNEXT</c>.
    /// </summary>
    /// <remarks>
    /// "Probably" is the RFC's own word for it: the value is a prediction a client may use to
    /// size its cache, not a promise. A delivery that fails after taking a UID leaves a gap, and
    /// a gap is explicitly legal.
    /// </remarks>
    public long UidNext => Folder.NextUid;

    /// <summary>The folder's UIDVALIDITY, assigned once at creation and never changed.</summary>
    public long UidValidity => Folder.UidValidity;

    /// <summary>
    /// Whether an <c>* OK [UNSEEN n]</c> line should be sent at all.
    /// </summary>
    /// <remarks>
    /// RFC 3501 §9 types the code's argument as an <c>nz-number</c>, so there is no way to say
    /// "none": a folder with nothing unseen omits the whole line rather than sending
    /// <c>[UNSEEN 0]</c>, which is ungrammatical. Asking through a named property rather than a
    /// null check at the call site is what keeps that from being rediscovered per caller.
    /// </remarks>
    public bool HasUnseen => FirstUnseenSequenceNumber is > 0;
}

/// <summary>
/// One folder as <c>LIST</c> and <c>LSUB</c> see it.
/// </summary>
/// <remarks>
/// Deliberately not <see cref="MailboxFolder"/>. A listing needs a name, a role, whether it is
/// subscribed and whether it has children — and nothing else. Handing the whole entity over
/// would carry <c>UidValidity</c> and <c>NextUid</c> into a code path that must never report
/// them, since RFC 3501 §7.2.2's <c>LIST</c> response has nowhere to put them and a client
/// reading them from the wrong command would cache them against the wrong moment.
/// </remarks>
/// <param name="Path">The folder's full path, as stored. Never encoded; the writer does that.</param>
/// <param name="SpecialUse">The RFC 6154 role, which decides the special-use attribute.</param>
/// <param name="IsSubscribed">Whether it appears in <c>LSUB</c>.</param>
/// <param name="HasChildren">
/// Whether another folder in this mailbox is nested beneath it — RFC 3348's
/// <c>\HasChildren</c>.
/// </param>
public sealed record ImapFolderListing(
    string Path,
    FolderSpecialUse SpecialUse,
    bool IsSubscribed,
    bool HasChildren)
{
    /// <summary>
    /// The attributes this folder's <c>LIST</c> response carries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>\Noselect</c> never appears here, because every folder with a row is selectable. It is
    /// not that <c>\Noselect</c> never appears in a listing at all: a trailing <c>%</c> conjures
    /// up bare hierarchy levels that carry it, and <c>LSUB</c> puts it on an unsubscribed
    /// ancestor that may be a perfectly selectable mailbox — RFC 3501 §6.3.9 makes that a MUST,
    /// and the <c>LIST</c>/<c>LSUB</c> handler is where both of those are decided. Neither name
    /// has an <see cref="ImapFolderListing"/>, which is why neither reaches this property.
    /// </para>
    /// <para>
    /// RFC 3348's pair is always one or the other, never neither and never both. Never neither,
    /// because a server advertising <c>CHILDREN</c> has undertaken to answer the question — see
    /// <see cref="ImapMailboxAttribute.HasNoChildren"/>. Never both, because §3 says plainly:
    /// "It is an error for the server to return both a <c>\HasChildren</c> and a
    /// <c>\HasNoChildren</c> attribute in a LIST response." A conditional rather than two
    /// independent flags is what makes that unexpressible.
    /// </para>
    /// </remarks>
    public ImapMailboxAttribute Attributes =>
        (HasChildren ? ImapMailboxAttribute.HasChildren : ImapMailboxAttribute.HasNoChildren) |
        ImapMailboxAttributes.ForSpecialUse(SpecialUse);
}
