using System.Diagnostics;
using MailServer.Domain.Entities;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapMailboxPatternTests
{
    private static ImapMailboxPattern Pattern(string pattern, string reference = "")
    {
        ImapMailboxPattern.TryCombine(reference, pattern, out ImapMailboxPattern? result)
            .ShouldBeTrue($"could not combine [{reference}] + [{pattern}]");

        return result!;
    }

    // ---------------------------------------------------------------------------------------
    // Literal names.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("INBOX", "INBOX", true)]
    [InlineData("INBOX", "INBOXX", false)]
    [InlineData("INBOX", "INBO", false)]
    [InlineData("INBOX", "", false)]
    [InlineData("", "", true)]
    [InlineData("", "INBOX", false)]
    [InlineData("Projects/2026", "Projects/2026", true)]
    [InlineData("Projects/2026", "Projects/2027", false)]
    public void A_pattern_with_no_wildcard_names_exactly_one_mailbox(
        string pattern,
        string name,
        bool expected) =>
        Pattern(pattern).Matches(name).ShouldBe(expected);

    [Theory]
    [InlineData("inbox", "INBOX")]
    [InlineData("inb*", "INBOX")]
    [InlineData("INBOX", "inbox")]
    [InlineData("receipts", "Receipts")]
    public void Matching_is_case_sensitive_even_for_the_inbox(string pattern, string name)
    {
        // RFC 3501 section 6.3.8 is specific about how section 5.1's INBOX exception applies
        // here: "The special name INBOX is included in the output from LIST ... if the uppercase
        // string INBOX matches the interpreted reference and mailbox name arguments". So the
        // pattern is matched against INBOX as spelled, and "inb*" is told about no inbox - which
        // is the RFC's answer, however surprising.
        Pattern(pattern).Matches(name).ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // '*' matches across the hierarchy delimiter.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("*", "INBOX", true)]
    [InlineData("*", "", true)]
    [InlineData("*", "Projects/2026/Q1", true)]
    [InlineData("Projects/*", "Projects/2026", true)]
    [InlineData("Projects/*", "Projects/2026/Q1", true)]
    [InlineData("Projects/*", "Projects/", true)]
    [InlineData("Projects/*", "Projects", false)]
    [InlineData("Projects*", "Projects", true)]
    [InlineData("*2026", "Projects/2026", true)]
    [InlineData("*/Q1", "Projects/2026/Q1", true)]
    [InlineData("P*s", "Projects", true)]
    [InlineData("P*s", "Project", false)]
    public void Star_matches_zero_or_more_characters_including_the_delimiter(
        string pattern,
        string name,
        bool expected)
    {
        // RFC 3501 section 6.3.8: "The character '*' is a wildcard, and matches zero or more
        // characters at this position."
        Pattern(pattern).Matches(name).ShouldBe(expected);
    }

    // ---------------------------------------------------------------------------------------
    // '%' stops at the hierarchy delimiter. This is the whole of the hierarchy semantics.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("%", "INBOX", true)]
    [InlineData("%", "", true)]
    [InlineData("%", "Projects", true)]
    [InlineData("%", "Projects/2026", false)]
    [InlineData("%", "Projects/2026/Q1", false)]
    [InlineData("Projects/%", "Projects/2026", true)]
    [InlineData("Projects/%", "Projects/2026/Q1", false)]
    [InlineData("Projects/%/Q1", "Projects/2026/Q1", true)]
    [InlineData("Projects/%/Q1", "Projects/2026/H1/Q1", false)]
    [InlineData("%/%", "Projects/2026", true)]
    [InlineData("%/%", "Projects/2026/Q1", false)]
    [InlineData("P%s", "Projects", true)]
    [InlineData("P%s", "P/s", false)]
    public void Percent_matches_zero_or_more_characters_but_not_the_delimiter(
        string pattern,
        string name,
        bool expected)
    {
        // RFC 3501 section 6.3.8: "The character '%' is similar to '*', but it does not match a
        // hierarchy delimiter."
        Pattern(pattern).Matches(name).ShouldBe(expected);
    }

    [Fact]
    public void The_delimiter_this_server_uses_is_the_one_percent_will_not_cross()
    {
        // A forward slash, not a dot - MailboxFolder.PathSeparator, chosen because a dot
        // collides with folder names containing one. A matcher hard-coding the other character
        // would silently treat every level as one name.
        MailboxFolder.PathSeparator.ShouldBe('/');

        Pattern("%").Matches("a.b").ShouldBeTrue("a dot is an ordinary character in a name.");
        Pattern("%").Matches("a/b").ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // Several wildcards, and patterns made only of them.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("**", "Projects/2026", true)]
    [InlineData("%%", "Projects", true)]
    [InlineData("%%", "Projects/2026", false)]
    [InlineData("*%", "Projects/2026", true)]
    [InlineData("%*", "Projects/2026", true)]
    [InlineData("*/*", "Projects/2026", true)]
    [InlineData("*/*", "Projects", false)]
    [InlineData("*a*b*", "xaybz", true)]
    [InlineData("*a*b*", "xbya", false)]
    [InlineData("%a%b%", "xaybz", true)]
    [InlineData("%a%b%", "xa/ybz", false)]
    public void Several_wildcards_compose(string pattern, string name, bool expected) =>
        Pattern(pattern).Matches(name).ShouldBe(expected);

    // ---------------------------------------------------------------------------------------
    // The reference argument.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("Projects/", "%", "Projects/2026", true)]
    [InlineData("Projects/", "%", "Projects/2026/Q1", false)]
    [InlineData("Projects/", "*", "Projects/2026/Q1", true)]
    [InlineData("Projects/", "2026", "Projects/2026", true)]
    [InlineData("Projects/", "2026", "Projects/2027", false)]
    [InlineData("", "*", "anything", true)]
    public void The_reference_is_prepended_to_the_pattern(
        string reference,
        string pattern,
        string name,
        bool expected)
    {
        // RFC 3501 section 6.3.8: "If a server implementation has no concept of break out
        // characters, the canonical form is normally the reference name appended with the
        // mailbox name." This server has no such concept - no working directory, no namespace
        // prefixes - so concatenation is the whole of it.
        Pattern(pattern, reference).Matches(name).ShouldBe(expected);
    }

    [Fact]
    public void The_combined_pattern_is_what_gets_matched()
    {
        Pattern("%", "Projects/").Value.ShouldBe("Projects/%");
    }

    // ---------------------------------------------------------------------------------------
    // The trailing '%' rule, which changes what LIST must return.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("%", true)]
    [InlineData("Projects/%", true)]
    [InlineData("*", false)]
    [InlineData("%/Q1", false)]
    [InlineData("INBOX", false)]
    [InlineData("", false)]
    public void A_trailing_percent_is_recognised(string pattern, bool expected)
    {
        // RFC 3501 section 6.3.8: "If the '%' wildcard is the last character of a mailbox name
        // argument, matching levels of hierarchy are also returned. If these levels of hierarchy
        // are not also selectable mailboxes, they are returned with the \Noselect mailbox name
        // attribute." A server that ignored this shows a client a tree with the branch missing
        // and the leaf unreachable.
        Pattern(pattern).EndsWithHierarchyWildcard.ShouldBe(expected);
    }

    [Theory]
    [InlineData("Projects/2026/Q1", new[] { "Projects", "Projects/2026" })]
    [InlineData("Projects/2026", new[] { "Projects" })]
    [InlineData("Projects", new string[0])]
    [InlineData("INBOX", new string[0])]
    [InlineData("", new string[0])]
    public void The_hierarchy_levels_above_a_name_are_listed_outermost_first(
        string name,
        string[] expected)
    {
        // Outermost first so a caller building a tree sees a parent before its child.
        ImapMailboxPattern.HierarchyLevelsOf(name).ShouldBe(expected);
    }

    [Fact]
    public void A_leading_delimiter_is_not_a_hierarchy_level()
    {
        // "/foo" has no parent: the empty string is not a mailbox name and reporting it would
        // put a nameless node in the client's tree.
        ImapMailboxPattern.HierarchyLevelsOf("/foo").ShouldBeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // Bounds. A pattern is text an authenticated but untrusted client chose.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_pattern_longer_than_the_cap_is_refused()
    {
        ImapMailboxPattern.TryCombine(
            string.Empty,
            new string('*', ImapMailboxPattern.MaxPatternLength + 1),
            out ImapMailboxPattern? result).ShouldBeFalse();

        result.ShouldBeNull();
    }

    [Fact]
    public void The_reference_counts_towards_the_cap()
    {
        // Otherwise the cap is bypassed by moving the bytes from one argument into the other.
        int half = ImapMailboxPattern.MaxPatternLength;

        ImapMailboxPattern.TryCombine(new string('a', half), new string('*', half), out _)
            .ShouldBeFalse();
    }

    [Fact]
    public void A_pattern_at_exactly_the_cap_is_accepted()
    {
        ImapMailboxPattern.TryCombine(
            string.Empty,
            new string('*', ImapMailboxPattern.MaxPatternLength),
            out ImapMailboxPattern? result).ShouldBeTrue();

        result.ShouldNotBeNull();
    }

    [Fact]
    public void A_pattern_built_to_make_a_regex_engine_backtrack_completes_promptly()
    {
        // The reason this matcher is a table rather than a regular expression. Translated to a
        // regex, a pattern of many wildcards against a non-matching name is the classic
        // catastrophic-backtracking shape, and the client picks the length. The table is
        // O(pattern x name) with no backtracking, so this is arithmetic rather than a cliff.
        string hostile = string.Concat(Enumerable.Repeat("a*", 200)) + "b";
        string name = new('a', 400);

        ImapMailboxPattern.TryCombine(string.Empty, hostile, out ImapMailboxPattern? pattern)
            .ShouldBeTrue();

        Stopwatch stopwatch = Stopwatch.StartNew();

        pattern!.Matches(name).ShouldBeFalse();

        stopwatch.Stop();

        // Generous by orders of magnitude against the real cost, and still far below what a
        // backtracking engine would take on this input.
        stopwatch.Elapsed.ShouldBeLessThan(
            TimeSpan.FromSeconds(2),
            $"matching took {stopwatch.ElapsedMilliseconds} ms.");
    }

    [Fact]
    public void The_same_hostile_shape_completes_promptly_with_percent_too()
    {
        string hostile = string.Concat(Enumerable.Repeat("a%", 200)) + "b";
        string name = new('a', 400);

        ImapMailboxPattern.TryCombine(string.Empty, hostile, out ImapMailboxPattern? pattern)
            .ShouldBeTrue();

        Stopwatch stopwatch = Stopwatch.StartNew();

        pattern!.Matches(name).ShouldBeFalse();

        stopwatch.Stop();

        stopwatch.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(2));
    }

    // ---------------------------------------------------------------------------------------
    // Shape.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("INBOX", true)]
    [InlineData("Projects/2026", true)]
    [InlineData("*", false)]
    [InlineData("%", false)]
    [InlineData("Projects/*", false)]
    public void A_literal_pattern_is_recognised(string pattern, bool expected) =>
        Pattern(pattern).IsLiteral.ShouldBe(expected);

    [Fact]
    public void Null_arguments_are_refused()
    {
        Should.Throw<ArgumentNullException>(
            () => ImapMailboxPattern.TryCombine(null!, "*", out _));

        Should.Throw<ArgumentNullException>(
            () => ImapMailboxPattern.TryCombine(string.Empty, null!, out _));

        Should.Throw<ArgumentNullException>(() => Pattern("*").Matches(null!));
        Should.Throw<ArgumentNullException>(() => ImapMailboxPattern.HierarchyLevelsOf(null!));
    }
    // ---------------------------------------------------------------------------------------
    // Which names are parents.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_mailbox_with_no_nesting_has_no_parents() =>
        ImapMailboxPattern.ParentsAmong(["INBOX", "Sent", "Trash"]).ShouldBeEmpty();

    [Fact]
    public void A_name_with_something_beneath_it_is_a_parent() =>
        ImapMailboxPattern.ParentsAmong(["Projects", "Projects/2026"])
            .ShouldBe(new HashSet<string> { "Projects" });

    /// <summary>
    /// Every level, not only the one immediately above the leaf: a client drawing the tree needs
    /// to know that Projects has children as well as that Projects/2026 does.
    /// </summary>
    [Fact]
    public void Every_level_above_a_name_is_a_parent() =>
        ImapMailboxPattern.ParentsAmong(["Projects/2026/Q1"])
            .ShouldBe(new HashSet<string> { "Projects", "Projects/2026" });

    /// <summary>
    /// A parent is a prefix ending at the delimiter, so a sibling whose name merely starts the
    /// same way is nobody's child.
    /// </summary>
    [Fact]
    public void A_name_that_is_only_a_prefix_is_not_a_parent() =>
        ImapMailboxPattern.ParentsAmong(["Work", "Workshop"]).ShouldBeEmpty();

    /// <summary>
    /// The case that rules out sorting the names and comparing neighbours, which would be
    /// faster and wrong. The separator is '/' at 0x2F and MailboxFolder refuses only control
    /// characters, so '.' at 0x2E is a legal folder-name character that sorts below it: ordered
    /// ordinally these three are Work, Work.old, Work/Q1, and the child is not adjacent to its
    /// parent. See ParentsAmong's own remarks.
    /// </summary>
    [Fact]
    public void A_sibling_sorting_between_a_parent_and_its_child_does_not_hide_the_child()
    {
        string[] names = ["Work", "Work.old", "Work/Q1"];

        // The trap, stated as an assertion so that the ordering this test relies on is shown
        // rather than asserted about in prose.
        List<string> sorted = [.. names];
        sorted.Sort(string.CompareOrdinal);
        sorted.ShouldBe(["Work", "Work.old", "Work/Q1"]);

        ImapMailboxPattern.ParentsAmong(names).ShouldBe(new HashSet<string> { "Work" });
    }

    [Theory]
    [InlineData('!')]
    [InlineData('#')]
    [InlineData('$')]
    [InlineData('-')]
    [InlineData('.')]
    [InlineData('+')]
    [InlineData(',')]
    public void A_sibling_named_with_any_character_below_the_delimiter_hides_nothing(char c)
    {
        ((int)c).ShouldBeLessThan(MailboxFolder.PathSeparator);

        string[] names = ["Work", $"Work{c}other", "Work/Q1"];

        ImapMailboxPattern.ParentsAmong(names).ShouldContain("Work");
    }

    /// <summary>
    /// This server matches folder names exactly — RFC 3501 §5.1 leaves that open for every name
    /// but INBOX — so Work/Q1 says nothing
    /// about a folder called work.
    /// </summary>
    [Fact]
    public void Parenthood_is_case_sensitive()
    {
        IReadOnlySet<string> parents = ImapMailboxPattern.ParentsAmong(["Work/Q1", "work"]);

        parents.ShouldContain("Work");
        parents.ShouldNotContain("work");
    }

    [Fact]
    public void A_level_named_by_two_children_is_reported_once() =>
        ImapMailboxPattern.ParentsAmong(["Projects/2026", "Projects/2025"])
            .ShouldBe(new HashSet<string> { "Projects" });

    [Fact]
    public void An_empty_mailbox_has_no_parents() =>
        ImapMailboxPattern.ParentsAmong([]).ShouldBeEmpty();

    /// <summary>
    /// The order names arrive in is the database's, which is not guaranteed — so the answer must
    /// not depend on it.
    /// </summary>
    [Fact]
    public void The_answer_does_not_depend_on_the_order_the_names_arrive_in()
    {
        string[] forwards = ["A", "A/B", "A/B/C", "A.x"];
        string[] backwards = ["A.x", "A/B/C", "A/B", "A"];

        ImapMailboxPattern.ParentsAmong(forwards)
            .ShouldBe(ImapMailboxPattern.ParentsAmong(backwards));
    }
}
