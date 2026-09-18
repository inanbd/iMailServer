using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Imap;

/// <summary>
/// How a client's mailbox name maps onto a stored folder path.
/// </summary>
/// <remarks>
/// RFC 3501 §5.1: "The case-insensitive mailbox name INBOX is a special name reserved to mean
/// the primary mailbox for this user on this server. […] Other mailbox names are
/// case-sensitive." One exception to one rule, and both halves matter — a server that folded
/// every name would merge <c>Receipts</c> and <c>receipts</c> into one folder, and a server that
/// folded none would fail to open <c>inbox</c> for the many clients that ask for it in lower
/// case.
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
