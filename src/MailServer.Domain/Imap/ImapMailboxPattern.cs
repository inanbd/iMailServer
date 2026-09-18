using System.Diagnostics.CodeAnalysis;
using MailServer.Domain.Entities;

namespace MailServer.Domain.Imap;

/// <summary>
/// RFC 3501 §6.3.8's mailbox-name pattern, as used by <c>LIST</c> and <c>LSUB</c>.
/// </summary>
/// <remarks>
/// <para>
/// Two wildcards, and the difference between them is the whole of the hierarchy semantics.
/// §6.3.8, verbatim: "The character <c>*</c> is a wildcard, and matches zero or more characters
/// at this position. The character <c>%</c> is similar to <c>*</c>, but it does not match a
/// hierarchy delimiter."
/// </para>
/// <para>
/// <b>Matched by dynamic programming rather than by a regular expression, and that is a security
/// decision rather than a stylistic one.</b> A pattern is text an authenticated client chose,
/// and translating it into a regex is how a server acquires a denial-of-service vector it never
/// wrote: a pattern of repeated wildcards becomes a regex whose backtracking is exponential in
/// its length, and the client gets to pick the length. The table below is
/// <c>O(pattern × name)</c> in time and <c>O(pattern)</c> in space with no backtracking at all,
/// so the worst case is arithmetic rather than a cliff — and it is the same worst case for every
/// pattern of a given size, which means it can be bounded by bounding the size.
/// </para>
/// <para>
/// <b>Matching is case-sensitive, including for the inbox, and that is not an oversight.</b> RFC
/// 3501 §5.1 takes no position on the case sensitivity of non-inbox names — this server chooses
/// to match them exactly, for the reasons <see cref="ImapMailboxPath"/> gives — and §6.3.8 is
/// specific about how the inbox, which §5.1 does settle, behaves here: "The special name INBOX is included in the
/// output from LIST […] if the <i>uppercase string</i> <c>INBOX</c> matches the interpreted
/// reference and mailbox name arguments". So the pattern is matched against <c>INBOX</c> as
/// spelled, and a client asking for <c>inb*</c> is told about no inbox — which is the RFC's
/// answer, however surprising, because the alternative is a matcher whose case-sensitivity
/// depends on what it happens to be matching.
/// </para>
/// </remarks>
public sealed class ImapMailboxPattern
{
    /// <summary>
    /// The longest pattern accepted.
    /// </summary>
    /// <remarks>
    /// Twice <see cref="MailboxFolder.MaxPathLength"/>, which is the longest name any pattern
    /// could usefully match: past that a pattern can only match by wildcards, and a client with
    /// a legitimate need has already been served. The cap exists because the matcher's cost is
    /// the product of the pattern's length and the name's, multiplied again by how many folders
    /// a mailbox has — so the one input a client controls freely is the one that has to be
    /// bounded. The same argument <see cref="ImapSequenceSet.MaxSegments"/> makes for itself.
    /// </remarks>
    public const int MaxPatternLength = MailboxFolder.MaxPathLength * 2;

    private readonly string _pattern;

    private ImapMailboxPattern(string pattern) => _pattern = pattern;

    /// <summary>The combined pattern, as it will be matched.</summary>
    public string Value => _pattern;

    /// <summary>Whether the pattern ends in <c>%</c>, which changes what <c>LIST</c> returns.</summary>
    /// <remarks>
    /// §6.3.8: "If the <c>%</c> wildcard is the last character of a mailbox name argument,
    /// matching levels of hierarchy are also returned. If these levels of hierarchy are not also
    /// selectable mailboxes, they are returned with the <c>\Noselect</c> mailbox name
    /// attribute." So a trailing <c>%</c> asks about the shape of the tree and not only about
    /// what is in it: a mailbox holding only <c>Projects/2026</c> must answer
    /// <c>LIST "" "%"</c> with <c>Projects</c>, marked <c>\Noselect</c> because no such mailbox
    /// exists to select. A server that omitted it would show a client a folder tree with the
    /// branch missing and the leaf unreachable.
    /// </remarks>
    public bool EndsWithHierarchyWildcard => _pattern.EndsWith('%');

    /// <summary>Whether the pattern contains no wildcard at all.</summary>
    public bool IsLiteral => !_pattern.Contains('*') && !_pattern.Contains('%');

    /// <summary>
    /// Combines a reference and a pattern into the form that will be matched.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §6.3.8 leaves this deliberately open — "The interpretation of the reference argument is
    /// implementation-defined" — and then describes the interpretation a server without
    /// break-out characters should use: "If a server implementation has no concept of break out
    /// characters, the canonical form is normally the reference name appended with the mailbox
    /// name." This server has no such concept, no current working directory and no namespace
    /// prefixes, so concatenation is the whole of it.
    /// </para>
    /// <para>
    /// The RFC's own worked example is the reason the returned names must be full names rather
    /// than names relative to the reference: "Any part of the reference argument that is
    /// included in the interpreted form SHOULD prefix the interpreted form […] This rule permits
    /// the client to determine if the returned mailbox name is in the context of the reference
    /// argument". A client that received relative names could not tell one case from the other,
    /// and would build the wrong tree.
    /// </para>
    /// </remarks>
    /// <param name="reference">The reference name. Empty is the ordinary case.</param>
    /// <param name="pattern">The mailbox-name pattern, possibly with wildcards.</param>
    public static bool TryCombine(
        string reference,
        string pattern,
        [NotNullWhen(true)] out ImapMailboxPattern? result)
    {
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(pattern);

        result = null;

        if (reference.Length + pattern.Length > MaxPatternLength)
        {
            return false;
        }

        result = new ImapMailboxPattern(reference + pattern);
        return true;
    }

    /// <summary>Whether this pattern matches a mailbox name.</summary>
    /// <remarks>
    /// The name is matched whole: RFC 3501 has no notion of a partial match, so a pattern with
    /// no trailing wildcard names exactly one mailbox.
    /// </remarks>
    public bool Matches(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return Matches(_pattern, name);
    }

    /// <summary>
    /// The glob match, as a table.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>reachable[j]</c> answers "could the first <c>j</c> characters of the pattern have
    /// consumed everything of the name seen so far". One row per character of the name, each
    /// computed from the last — so every cell is visited once, nothing is ever revisited, and
    /// there is no recursion to bound. Whatever the pattern, the cost is the product of the two
    /// lengths and the answer arrives.
    /// </para>
    /// <para>
    /// The two wildcards differ in exactly one clause. <c>*</c> may consume any character;
    /// <c>%</c> may consume any character that is not the hierarchy delimiter. Both may consume
    /// none, which is what the propagation along each row expresses.
    /// </para>
    /// </remarks>
    private static bool Matches(string pattern, string name)
    {
        // reachable[j] == true once the pattern's first j characters can account for the part of
        // the name already consumed. Starting state: the empty pattern accounts for the empty
        // name, and a leading run of wildcards accounts for it too, each matching nothing.
        bool[] reachable = new bool[pattern.Length + 1];

        reachable[0] = true;

        for (int j = 0; j < pattern.Length && reachable[j]; j++)
        {
            reachable[j + 1] = IsWildcard(pattern[j]);
        }

        foreach (char c in name)
        {
            bool[] next = new bool[pattern.Length + 1];

            // No pattern at all cannot account for a character, so the row always starts false.
            for (int j = 0; j < pattern.Length; j++)
            {
                if (!next[j] && !reachable[j] && !reachable[j + 1])
                {
                    continue;
                }

                next[j + 1] = pattern[j] switch
                {
                    // Consume this character and stay on the wildcard, or let the wildcard have
                    // matched nothing and carry the row forward.
                    '*' => reachable[j + 1] || next[j],

                    // The same, minus the one character a '%' may not cross.
                    '%' => (reachable[j + 1] && c != MailboxFolder.PathSeparator) || next[j],

                    // An ordinary character consumes exactly itself.
                    _ => reachable[j] && pattern[j] == c,
                };
            }

            reachable = next;
        }

        return reachable[pattern.Length];
    }

    private static bool IsWildcard(char c) => c is '*' or '%';

    /// <summary>
    /// The hierarchy levels above a name, from the outermost inwards.
    /// </summary>
    /// <remarks>
    /// The parents a trailing <c>%</c> obliges <c>LIST</c> to report — see
    /// <see cref="EndsWithHierarchyWildcard"/>. <c>Projects/2026/Q1</c> yields
    /// <c>Projects</c> and <c>Projects/2026</c>, and whichever of those is not itself a mailbox
    /// is reported <c>\Noselect</c>. Returned outermost first so a caller building a tree sees a
    /// parent before its child.
    /// </remarks>
    public static IReadOnlyList<string> HierarchyLevelsOf(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        List<string> levels = [];

        for (int i = 0; i < name.Length; i++)
        {
            if (name[i] == MailboxFolder.PathSeparator && i > 0)
            {
                levels.Add(name[..i]);
            }
        }

        return levels;
    }

    /// <summary>
    /// Which of a set of folder names have another name nested beneath them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The set of every name's parents, which is the same question asked from the other end:
    /// <c>Work</c> has children exactly when some name's parent list contains <c>Work</c>. Built
    /// once for the whole set and then consulted per folder, so the cost is linear in the total
    /// length of the names rather than quadratic in how many there are — the difference RFC 3501
    /// §6.3.8 has in mind when it warns that "if each name requires 1 second of processing, then
    /// a list of 1200 names would take 20 minutes!".
    /// </para>
    /// <para>
    /// <b>Sorting the names and comparing neighbours would be faster and would also be wrong.</b>
    /// It is tempting because descendants of a name are contiguous with it under an ordinal sort,
    /// so one neighbour looks like enough — but contiguous is not adjacent. The separator is
    /// <c>/</c> at 0x2F, and <see cref="MailboxFolder"/> refuses only control characters in a
    /// folder name, so <c>.</c>, <c>-</c> and <c>!</c> are all legal and all sort below it: a
    /// mailbox holding <c>Work</c>, <c>Work.old</c> and <c>Work/Q1</c> sorts <c>Work.old</c>
    /// between the parent and its child, and the neighbour check reports <c>Work</c> childless.
    /// Deriving the parents instead needs no ordering at all, and cannot confuse a child with a
    /// sibling whose name merely starts the same way — <c>Workshop</c> is nobody's child, because
    /// a parent is only ever a prefix ending at a separator.
    /// </para>
    /// </remarks>
    /// <param name="names">The folder names in one mailbox. Order is irrelevant.</param>
    /// <returns>
    /// The subset that are parents. Compared with <see cref="StringComparer.Ordinal"/>, because
    /// this server matches folder names exactly — see <see cref="ImapMailboxPath"/> on why that
    /// is a choice RFC 3501 §5.1 leaves open — so <c>Work/Q1</c> makes <c>Work</c> a parent and
    /// leaves <c>work</c> alone.
    /// </returns>
    public static IReadOnlySet<string> ParentsAmong(IEnumerable<string> names)
    {
        ArgumentNullException.ThrowIfNull(names);

        HashSet<string> parents = new(StringComparer.Ordinal);

        foreach (string name in names)
        {
            foreach (string level in HierarchyLevelsOf(name))
            {
                parents.Add(level);
            }
        }

        return parents;
    }
}
