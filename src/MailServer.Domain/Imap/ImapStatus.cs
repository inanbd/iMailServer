using MailServer.Domain.Entities;

namespace MailServer.Domain.Imap;

/// <summary>
/// One of the data items <c>STATUS</c> can be asked for.
/// </summary>
/// <remarks>
/// RFC 3501 §6.3.10 defines exactly five and §9's <c>status-att</c> production closes the list:
/// <c>"MESSAGES" / "RECENT" / "UIDNEXT" / "UIDVALIDITY" / "UNSEEN"</c>. An extension may add
/// more — RFC 4551's <c>HIGHESTMODSEQ</c>, say — but only behind a capability, so a name not
/// here is a name this server has not undertaken to understand and answers <c>BAD</c>.
/// </remarks>
public enum ImapStatusItem
{
    /// <summary><c>MESSAGES</c> — "the number of messages in the mailbox".</summary>
    Messages = 0,

    /// <summary><c>RECENT</c> — "the number of messages with the <c>\Recent</c> flag set".</summary>
    Recent = 1,

    /// <summary><c>UIDNEXT</c> — "the next unique identifier value of the mailbox".</summary>
    UidNext = 2,

    /// <summary><c>UIDVALIDITY</c> — "the unique identifier validity value of the mailbox".</summary>
    UidValidity = 3,

    /// <summary>
    /// <c>UNSEEN</c> — "the number of messages which do not have the <c>\Seen</c> flag set".
    /// </summary>
    /// <remarks>
    /// <b>A count here, and a message sequence number in <c>SELECT</c>.</b> §6.3.10 defines this
    /// one as a number of messages; §6.3.1's <c>* OK [UNSEEN 12]</c> is "the message sequence
    /// number of the first unseen message". Same word, two quantities, and a server that reused
    /// one for the other would be wrong by however many read messages precede the first unread
    /// one — a mailbox whose first eleven messages are read and whose twelfth is not has
    /// <c>[UNSEEN 12]</c> on <c>SELECT</c> and could have <c>UNSEEN 1</c> on <c>STATUS</c>.
    /// The two are read by separate queries for that reason; see
    /// <see cref="ImapFolderStatus"/> and <see cref="ImapFolderSnapshot"/>.
    /// </remarks>
    Unseen = 4,
}

/// <summary>Reading and writing the <c>STATUS</c> data item names.</summary>
public static class ImapStatusItems
{
    /// <summary>Every item, for exhaustiveness tests and for <c>STATUS mailbox (ALL)</c>-style callers.</summary>
    public static IReadOnlyList<ImapStatusItem> All { get; } = Enum.GetValues<ImapStatusItem>();

    /// <summary>The longest item list accepted.</summary>
    /// <remarks>
    /// There are five items and repeats are grammatical, so a conformant client's list is at most
    /// five long once duplicates are dropped — but a client may send the same name a thousand
    /// times, and each one would be split and looked up. Bounding the count before any of that
    /// keeps a legal command from being an amplifier; the limit is generous enough that no
    /// sensible client can reach it.
    /// </remarks>
    public const int MaxItemCount = 32;

    /// <summary>The wire name of one item.</summary>
    public static string NameOf(ImapStatusItem item) => item switch
    {
        ImapStatusItem.Messages => "MESSAGES",
        ImapStatusItem.Recent => "RECENT",
        ImapStatusItem.UidNext => "UIDNEXT",
        ImapStatusItem.UidValidity => "UIDVALIDITY",
        ImapStatusItem.Unseen => "UNSEEN",
        _ => throw new ArgumentOutOfRangeException(nameof(item), item, "Not a STATUS data item."),
    };

    /// <summary>Recognises one item name.</summary>
    /// <remarks>
    /// Case-insensitively, as RFC 3501 §9 requires of every token: "Except as noted otherwise,
    /// all alphabetic characters are case-insensitive. The use of upper or lower case characters
    /// to define token strings is for editorial clarity only. Implementations MUST accept these
    /// strings in a case-insensitive fashion."
    /// </remarks>
    public static bool TryParse(string name, out ImapStatusItem item)
    {
        ArgumentNullException.ThrowIfNull(name);

        foreach (ImapStatusItem candidate in All)
        {
            if (name.Equals(NameOf(candidate), StringComparison.OrdinalIgnoreCase))
            {
                item = candidate;
                return true;
            }
        }

        item = default;
        return false;
    }

    /// <summary>
    /// Parses the parenthesised item list that follows a <c>STATUS</c> command's mailbox name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An empty list is refused.</b> §9: <c>status = "STATUS" SP mailbox SP "(" status-att
    /// *(SP status-att) ")"</c> — one item and then any number more, so <c>STATUS INBOX ()</c> is
    /// a syntax error rather than a request for nothing. Answering it with an empty
    /// <c>* STATUS</c> line would be inventing a response for a command that was never sent.
    /// </para>
    /// <para>
    /// <b>Extra spaces between names are tolerated, and nothing else is.</b> §9's note (2) tells
    /// a sender that "SP refers to exactly one space", but that binds the sender; a receiver
    /// rejecting <c>(MESSAGES  UNSEEN)</c> would be refusing a command whose meaning is not in
    /// any doubt, because the items are an unordered set and no amount of whitespace between
    /// them can make it ambiguous. Anything that could change the meaning — a missing
    /// parenthesis, a name not in the list, text after the closing bracket — is still refused.
    /// </para>
    /// <para>
    /// <b>Repeats are dropped and the requested order is kept.</b> The grammar permits
    /// <c>(MESSAGES MESSAGES)</c> and the response grammar has no way to say a number twice
    /// about the same item, so a repeat is answered once. Order is preserved because §9's
    /// <c>status-att-list</c> imposes none, and echoing the order asked makes a packet capture
    /// legible next to the command that prompted it.
    /// </para>
    /// </remarks>
    /// <param name="text">The list including its brackets, and nothing after them.</param>
    public static bool TryParseList(string text, out IReadOnlyList<ImapStatusItem> items)
    {
        ArgumentNullException.ThrowIfNull(text);

        items = [];

        string trimmed = text.Trim();

        if (trimmed.Length < 2 || trimmed[0] != '(' || trimmed[^1] != ')')
        {
            return false;
        }

        string body = trimmed[1..^1];

        // A nested bracket is not a syntax error the grammar has anywhere in this production, and
        // admitting one would mean guessing at a structure status-att-list does not have.
        if (body.Contains('(') || body.Contains(')'))
        {
            return false;
        }

        string[] names = body.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (names.Length is 0 or > MaxItemCount)
        {
            return false;
        }

        List<ImapStatusItem> parsed = [];

        foreach (string name in names)
        {
            if (!TryParse(name, out ImapStatusItem item))
            {
                return false;
            }

            if (!parsed.Contains(item))
            {
                parsed.Add(item);
            }
        }

        items = parsed;
        return true;
    }
}

/// <summary>
/// What <c>STATUS</c> reports about a folder, read at one instant.
/// </summary>
/// <remarks>
/// <para>
/// A sibling of <see cref="ImapFolderSnapshot"/> rather than the same type, because the two
/// answer different questions about the same folder. <c>SELECT</c> needs a position — where the
/// first unread message sits — and <c>STATUS</c> needs a population — how many are unread. The
/// two numbers are both called <c>UNSEEN</c> by RFC 3501 and are not the same number; see
/// <see cref="ImapStatusItem.Unseen"/>. Keeping them in separate types means no caller can reach
/// for the wrong one.
/// </para>
/// <para>
/// One query, for the reason <see cref="ImapFolderSnapshot"/> gives: a count and a total that
/// described different instants would let a client compute an unread tally larger than the
/// mailbox.
/// </para>
/// </remarks>
/// <param name="Folder">The folder, carrying UIDNEXT and UIDVALIDITY.</param>
/// <param name="MessageCount">How many messages it holds.</param>
/// <param name="UnseenCount">How many of them lack <c>\Seen</c>.</param>
public sealed record ImapFolderStatus(
    MailboxFolder Folder,
    long MessageCount,
    long UnseenCount)
{
    /// <summary>
    /// How many messages carry <c>\Recent</c> — always none.
    /// </summary>
    /// <remarks>
    /// Truthfully zero rather than unimplemented. <c>\Recent</c> is reserved and never set by
    /// this server — see <see cref="ImapResponses.Recent"/> for why — so the count of messages
    /// carrying it is zero, and a client asking for it is entitled to that answer rather than to
    /// a <c>NO</c>.
    /// </remarks>
    public long RecentCount => 0;

    /// <summary>The folder's UIDNEXT.</summary>
    public long UidNext => Folder.NextUid;

    /// <summary>The folder's UIDVALIDITY.</summary>
    public long UidValidity => Folder.UidValidity;

    /// <summary>The number to report for one requested item.</summary>
    /// <remarks>
    /// Every item has an answer, which is what makes <c>STATUS</c> total: §9 closes the list of
    /// names, so a name that parsed is a name this can answer, and there is no partial-response
    /// case to design for.
    /// </remarks>
    public long ValueOf(ImapStatusItem item) => item switch
    {
        ImapStatusItem.Messages => MessageCount,
        ImapStatusItem.Recent => RecentCount,
        ImapStatusItem.UidNext => UidNext,
        ImapStatusItem.UidValidity => UidValidity,
        ImapStatusItem.Unseen => UnseenCount,
        _ => throw new ArgumentOutOfRangeException(nameof(item), item, "Not a STATUS data item."),
    };
}
