using MailServer.Domain.Enums;

namespace MailServer.Domain.Imap;

/// <summary>
/// The name attributes a <c>LIST</c> or <c>LSUB</c> response may carry.
/// </summary>
/// <remarks>
/// <para>
/// Three RFCs contribute to one list, and they do not agree about whether using their attributes
/// needs a capability — which is the detail worth getting straight before any of them is sent.
/// </para>
/// <para>
/// <b>RFC 3501 §7.2.2's four are part of IMAP4rev1</b> and need nothing announced.
/// </para>
/// <para>
/// <b>RFC 6154's special-use attributes need no capability either</b>, and the RFC says so in as
/// many words: "There is no capability string related to the support of special-use attributes
/// on the non-extended LIST command." The <c>SPECIAL-USE</c> capability string belongs to RFC
/// 5258's extended <c>LIST</c>, which this server does not implement.
/// </para>
/// <para>
/// <b>RFC 3348's two do need one.</b> §3: "IMAP4 servers that support this extension MUST list
/// the keyword CHILDREN in their CAPABILITY response." So <see cref="HasChildren"/> and
/// <see cref="HasNoChildren"/> may only be sent by a server that advertises <c>CHILDREN</c> —
/// the opposite of the special-use case, and the reason the two are not treated alike here.
/// </para>
/// </remarks>
[Flags]
public enum ImapMailboxAttribute
{
    None = 0,

    /// <summary>
    /// <c>\Noinferiors</c> — RFC 3501 §7.2.2: "It is not possible for any child levels of
    /// hierarchy to exist under this name; no child levels exist now and none can be created in
    /// the future."
    /// </summary>
    /// <remarks>
    /// Never sent by this server. The claim is about the future as well as the present, and
    /// nothing here forbids creating a child of any folder — so asserting it would be a promise
    /// this server has no way to keep, and a client that believed it would refuse to offer the
    /// user a "new subfolder" action that would in fact have worked.
    /// </remarks>
    NoInferiors = 1,

    /// <summary>
    /// <c>\Noselect</c> — RFC 3501 §7.2.2: "It is not possible to use this name as a selectable
    /// mailbox."
    /// </summary>
    /// <remarks>
    /// Sent for the hierarchy levels a trailing <c>%</c> obliges <c>LIST</c> to report which are
    /// not themselves mailboxes — see <see cref="ImapMailboxPattern.EndsWithHierarchyWildcard"/>.
    /// §7.2.2 also ties it to the name's usability: "Unless <c>\Noselect</c> is indicated, the
    /// name MUST also be valid as an argument for commands, such as <c>SELECT</c>", which is
    /// exactly the promise a bare hierarchy level cannot honour.
    /// </remarks>
    NoSelect = 2,

    /// <summary>
    /// <c>\Marked</c> — the mailbox "probably contains messages that have been added since the
    /// last time the mailbox was selected".
    /// </summary>
    /// <remarks>
    /// Never sent, and the RFC sanctions the omission twice over. §7.2.2: "If it is not feasible
    /// for the server to determine whether or not the mailbox is 'interesting' […] the server
    /// SHOULD NOT send either <c>\Marked</c> or <c>\Unmarked</c>." §6.3.8 goes further and asks
    /// a server not to try: "It SHOULD NOT go to excess trouble to calculate the <c>\Marked</c>
    /// or <c>\Unmarked</c> status […] if each name requires 1 second of processing, then a list
    /// of 1200 names would take 20 minutes!" Answering "interesting" needs a per-folder record of
    /// when each was last selected, which nothing here keeps. The bit is reserved so that a
    /// future implementation has somewhere to live.
    /// </remarks>
    Marked = 4,

    /// <summary><c>\Unmarked</c> — the counterpart, and never sent for the same reason.</summary>
    Unmarked = 8,

    /// <summary>
    /// <c>\HasChildren</c> — RFC 3348 §3: "The presence of this attribute indicates that the
    /// mailbox has child mailboxes."
    /// </summary>
    /// <remarks>
    /// Computable here, unlike <see cref="Marked"/>: folder paths are <c>/</c>-separated in one
    /// table, so "has a child" is a prefix question the database can answer in the same pass
    /// that enumerates the folders. It is worth answering because a client uses it to decide
    /// whether to draw an expand arrow — and a client that has to probe every folder with
    /// another <c>LIST</c> to find out is the slow folder tree users notice.
    /// </remarks>
    HasChildren = 16,

    /// <summary>
    /// <c>\HasNoChildren</c> — RFC 3348 §3's counterpart.
    /// </summary>
    /// <remarks>
    /// Sent rather than left implicit, because RFC 3348's whole point is that the absence of
    /// <c>\HasChildren</c> is ambiguous on a server that does not implement the extension: it
    /// could mean "no children" or "this server does not say". A server advertising
    /// <c>CHILDREN</c> answers the question either way.
    /// </remarks>
    HasNoChildren = 32,

    /// <summary><c>\Sent</c> — RFC 6154 §2.</summary>
    Sent = 64,

    /// <summary><c>\Drafts</c> — RFC 6154 §2.</summary>
    Drafts = 128,

    /// <summary><c>\Trash</c> — RFC 6154 §2.</summary>
    Trash = 256,

    /// <summary><c>\Junk</c> — RFC 6154 §2.</summary>
    Junk = 512,

    /// <summary><c>\Archive</c> — RFC 6154 §2.</summary>
    Archive = 1024,
}

/// <summary>The wire names of the mailbox attributes, and what this server will actually send.</summary>
public static class ImapMailboxAttributes
{
    /// <summary>
    /// The attributes this server is willing to emit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="ImapMailboxAttribute.Marked"/>, <see cref="ImapMailboxAttribute.Unmarked"/> and
    /// <see cref="ImapMailboxAttribute.NoInferiors"/> are deliberately absent — see each one's
    /// own remarks. Filtering here rather than trusting every caller means a future handler
    /// cannot start asserting one of them by accident; it would have to change this list, and
    /// changing this list fails a test.
    /// </para>
    /// <para>
    /// Ordered structural-first, then special-use, so a packet capture of two <c>LIST</c>
    /// responses for the same folder reads the same way twice. RFC 3501 §9's
    /// <c>mbx-list-flags</c> production imposes no order, so this is a consistency choice rather
    /// than a conformance one.
    /// </para>
    /// <para>
    /// <b>Withholding <c>\Marked</c> and <c>\Unmarked</c> also keeps a grammatical rule
    /// unbreakable.</b> §9: <c>mbx-list-sflag = "\Noselect" / "\Marked" / "\Unmarked"</c>,
    /// annotated "; Selectability flags; only one per LIST response". Three flags, at most one of
    /// them per response — and since two of the three are never emitted, this server cannot send
    /// two however its caller combines them. RFC 3348 §3 adds the matching rule for its own pair:
    /// "It is an error for the server to return both a <c>\HasChildren</c> and a
    /// <c>\HasNoChildren</c> attribute in a LIST response", which
    /// <see cref="ImapFolderListing.Attributes"/> makes unexpressible by choosing between them
    /// rather than setting them independently.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<ImapMailboxAttribute> Emittable { get; } =
    [
        ImapMailboxAttribute.NoSelect,
        ImapMailboxAttribute.HasChildren,
        ImapMailboxAttribute.HasNoChildren,
        ImapMailboxAttribute.Sent,
        ImapMailboxAttribute.Drafts,
        ImapMailboxAttribute.Trash,
        ImapMailboxAttribute.Junk,
        ImapMailboxAttribute.Archive,
    ];

    /// <summary>The wire name of one attribute.</summary>
    public static string NameOf(ImapMailboxAttribute attribute) => attribute switch
    {
        ImapMailboxAttribute.NoInferiors => @"\Noinferiors",
        ImapMailboxAttribute.NoSelect => @"\Noselect",
        ImapMailboxAttribute.Marked => @"\Marked",
        ImapMailboxAttribute.Unmarked => @"\Unmarked",
        ImapMailboxAttribute.HasChildren => @"\HasChildren",
        ImapMailboxAttribute.HasNoChildren => @"\HasNoChildren",
        ImapMailboxAttribute.Sent => @"\Sent",
        ImapMailboxAttribute.Drafts => @"\Drafts",
        ImapMailboxAttribute.Trash => @"\Trash",
        ImapMailboxAttribute.Junk => @"\Junk",
        ImapMailboxAttribute.Archive => @"\Archive",
        _ => throw new ArgumentOutOfRangeException(
            nameof(attribute),
            attribute,
            "Not a single mailbox attribute."),
    };

    /// <summary>
    /// The RFC 6154 special-use attribute for a folder's role, if it has one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>There is no <c>\Inbox</c> attribute, and its absence is not an omission.</b> RFC 6154
    /// §2 defines <c>\All</c>, <c>\Archive</c>, <c>\Drafts</c>, <c>\Flagged</c>, <c>\Junk</c>,
    /// <c>\Sent</c> and <c>\Trash</c>, and the primary mailbox is not among them because RFC
    /// 3501 §5.1 already identifies it by name: <c>INBOX</c> is reserved, so a client needs no
    /// attribute to recognise it. <see cref="FolderSpecialUse.Inbox"/> therefore maps to nothing.
    /// </para>
    /// <para>
    /// <c>\All</c> and <c>\Flagged</c> go the other way — RFC 6154 defines them and this server
    /// has no folder that could honestly carry either. Both describe virtual folders whose
    /// contents are a view over other folders ("all messages" and "flagged messages"), and this
    /// product stores folders as real containers with real deliveries in them. There is no enum
    /// value for either because there is nothing for one to name.
    /// </para>
    /// </remarks>
    public static ImapMailboxAttribute ForSpecialUse(FolderSpecialUse specialUse) => specialUse switch
    {
        FolderSpecialUse.Sent => ImapMailboxAttribute.Sent,
        FolderSpecialUse.Drafts => ImapMailboxAttribute.Drafts,
        FolderSpecialUse.Trash => ImapMailboxAttribute.Trash,
        FolderSpecialUse.Junk => ImapMailboxAttribute.Junk,
        FolderSpecialUse.Archive => ImapMailboxAttribute.Archive,

        // Inbox is identified by its reserved name; None has no role to advertise.
        _ => ImapMailboxAttribute.None,
    };

    /// <summary>
    /// Formats a set of attributes as the space-separated body of a parenthesised list.
    /// </summary>
    /// <remarks>
    /// Without the parentheses, matching <see cref="ImapFlagNames.Format"/>, because the
    /// surrounding syntax belongs to the response. An empty result is legitimate: RFC 3501 §9's
    /// <c>mailbox-list</c> permits <c>()</c>, and a folder with no children and no special use
    /// genuinely has nothing to say about itself.
    /// </remarks>
    public static string Format(ImapMailboxAttribute attributes)
    {
        List<string> names = [];

        foreach (ImapMailboxAttribute attribute in Emittable)
        {
            if (attributes.HasFlag(attribute))
            {
                names.Add(NameOf(attribute));
            }
        }

        return string.Join(' ', names);
    }
}
