using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Imap.Tests;

public sealed class ImapStatusTests
{
    private static ImapFolderStatus Status(
        long messageCount = 0,
        long unseenCount = 0,
        long uidValidity = 3_857_529_045,
        long nextUid = 1)
    {
        MailboxFolder folder = new(
            new MailboxFolderId(Guid.NewGuid()),
            new MailboxId(Guid.NewGuid()),
            "INBOX",
            FolderSpecialUse.Inbox,
            uidValidity,
            nextUid,
            isSubscribed: true,
            DateTimeOffset.UnixEpoch,
            null);

        return new ImapFolderStatus(folder, messageCount, unseenCount);
    }

    // ---------------------------------------------------------------------------------------
    // Item names.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapStatusItem.Messages, "MESSAGES")]
    [InlineData(ImapStatusItem.Recent, "RECENT")]
    [InlineData(ImapStatusItem.UidNext, "UIDNEXT")]
    [InlineData(ImapStatusItem.UidValidity, "UIDVALIDITY")]
    [InlineData(ImapStatusItem.Unseen, "UNSEEN")]
    public void Every_item_has_the_name_RFC_3501_gives_it(ImapStatusItem item, string expected) =>
        ImapStatusItems.NameOf(item).ShouldBe(expected);

    /// <summary>
    /// RFC 3501 §9's status-att closes the list at five, so an addition here would be an
    /// extension needing a capability — and a silent one is what this catches.
    /// </summary>
    [Fact]
    public void There_are_exactly_the_five_items_the_RFC_defines() =>
        ImapStatusItems.All.Select(ImapStatusItems.NameOf)
            .ShouldBe(["MESSAGES", "RECENT", "UIDNEXT", "UIDVALIDITY", "UNSEEN"]);

    /// <summary>
    /// RFC 3501 §9 note (1): "all alphabetic characters are case-insensitive […]
    /// Implementations MUST accept these strings in a case-insensitive fashion."
    /// </summary>
    [Theory]
    [InlineData("MESSAGES", ImapStatusItem.Messages)]
    [InlineData("messages", ImapStatusItem.Messages)]
    [InlineData("MeSsAgEs", ImapStatusItem.Messages)]
    [InlineData("uidnext", ImapStatusItem.UidNext)]
    [InlineData("UidValidity", ImapStatusItem.UidValidity)]
    [InlineData("unseen", ImapStatusItem.Unseen)]
    [InlineData("recent", ImapStatusItem.Recent)]
    public void An_item_name_is_recognised_in_any_case(string name, ImapStatusItem expected)
    {
        ImapStatusItems.TryParse(name, out ImapStatusItem item).ShouldBeTrue();
        item.ShouldBe(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("MESSAGE")]
    [InlineData("MESSAGESS")]
    [InlineData("HIGHESTMODSEQ")]
    [InlineData("APPENDLIMIT")]
    [InlineData("SIZE")]
    [InlineData(" MESSAGES")]
    public void A_name_this_server_has_not_undertaken_to_answer_is_refused(string name) =>
        ImapStatusItems.TryParse(name, out _).ShouldBeFalse();

    // ---------------------------------------------------------------------------------------
    // The item list.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void One_item_is_a_list()
    {
        ImapStatusItems.TryParseList("(MESSAGES)", out IReadOnlyList<ImapStatusItem> items)
            .ShouldBeTrue();

        items.ShouldBe([ImapStatusItem.Messages]);
    }

    /// <summary>
    /// The order asked, rather than the order the enum happens to declare. §9's status-att-list
    /// imposes no order and §6.3.10's own example in fact reorders, so this is a legibility
    /// choice this server makes and not a conformance requirement.
    /// </summary>
    [Fact]
    public void The_requested_order_is_kept()
    {
        ImapStatusItems.TryParseList("(UIDNEXT MESSAGES)", out IReadOnlyList<ImapStatusItem> items)
            .ShouldBeTrue();

        items.ShouldBe([ImapStatusItem.UidNext, ImapStatusItem.Messages]);
    }

    [Fact]
    public void All_five_items_may_be_asked_for_at_once()
    {
        ImapStatusItems
            .TryParseList(
                "(MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)",
                out IReadOnlyList<ImapStatusItem> items)
            .ShouldBeTrue();

        items.ShouldBe(ImapStatusItems.All);
    }

    /// <summary>
    /// The grammar permits a repeat and the response has no way to answer one twice, so it is
    /// answered once — and at the position it was first asked for.
    /// </summary>
    [Fact]
    public void A_repeated_item_is_reported_once()
    {
        ImapStatusItems
            .TryParseList("(UNSEEN MESSAGES UNSEEN)", out IReadOnlyList<ImapStatusItem> items)
            .ShouldBeTrue();

        items.ShouldBe([ImapStatusItem.Unseen, ImapStatusItem.Messages]);
    }

    /// <summary>
    /// RFC 3501 §9: status = "STATUS" SP mailbox SP "(" status-att *(SP status-att) ")" — one
    /// item at minimum, so an empty list is a syntax error and not a request for nothing.
    /// </summary>
    [Fact]
    public void An_empty_list_is_refused() =>
        ImapStatusItems.TryParseList("()", out _).ShouldBeFalse();

    [Theory]
    [InlineData("")]
    [InlineData("(")]
    [InlineData(")")]
    [InlineData("MESSAGES")]
    [InlineData("(MESSAGES")]
    [InlineData("MESSAGES)")]
    [InlineData("[MESSAGES]")]
    public void A_list_without_its_brackets_is_refused(string text) =>
        ImapStatusItems.TryParseList(text, out _).ShouldBeFalse();

    [Theory]
    [InlineData("(MESSAGES) extra")]
    [InlineData("(MESSAGES) (UNSEEN)")]
    public void Text_after_the_closing_bracket_is_refused(string text) =>
        ImapStatusItems.TryParseList(text, out _).ShouldBeFalse();

    [Theory]
    [InlineData("((MESSAGES))")]
    [InlineData("(MESSAGES (UNSEEN))")]
    public void A_nested_bracket_is_refused(string text) =>
        ImapStatusItems.TryParseList(text, out _).ShouldBeFalse();

    [Theory]
    [InlineData("(MESSAGES UNSEEN NONSENSE)")]
    [InlineData("(NONSENSE)")]
    [InlineData("(MESSAGES HIGHESTMODSEQ)")]
    public void One_unknown_item_refuses_the_whole_list(string text) =>
        ImapStatusItems.TryParseList(text, out _).ShouldBeFalse();

    /// <summary>
    /// Leniency with a bounded argument: the items are an unordered set, so no amount of
    /// whitespace between them can make the request ambiguous. See TryParseList's remarks.
    /// </summary>
    [Theory]
    [InlineData("(MESSAGES  UNSEEN)")]
    [InlineData("( MESSAGES UNSEEN )")]
    [InlineData("  (MESSAGES UNSEEN)  ")]
    public void Extra_space_around_the_names_is_tolerated(string text)
    {
        ImapStatusItems.TryParseList(text, out IReadOnlyList<ImapStatusItem> items)
            .ShouldBeTrue();

        items.ShouldBe([ImapStatusItem.Messages, ImapStatusItem.Unseen]);
    }

    /// <summary>
    /// A legal command must not be an amplifier: the grammar permits a repeat, so a client could
    /// send one name a thousand times and have each one split and looked up.
    /// </summary>
    [Fact]
    public void A_list_longer_than_the_cap_is_refused()
    {
        string tooMany = "(" +
            string.Join(' ', Enumerable.Repeat("MESSAGES", ImapStatusItems.MaxItemCount + 1)) +
            ")";

        ImapStatusItems.TryParseList(tooMany, out _).ShouldBeFalse();
    }

    [Fact]
    public void A_list_at_the_cap_is_accepted()
    {
        string atCap = "(" +
            string.Join(' ', Enumerable.Repeat("MESSAGES", ImapStatusItems.MaxItemCount)) +
            ")";

        ImapStatusItems.TryParseList(atCap, out IReadOnlyList<ImapStatusItem> items)
            .ShouldBeTrue();

        items.ShouldBe([ImapStatusItem.Messages]);
    }

    // ---------------------------------------------------------------------------------------
    // The values.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Each_item_reports_its_own_number()
    {
        ImapFolderStatus status = Status(
            messageCount: 231,
            unseenCount: 7,
            uidValidity: 3_857_529_045,
            nextUid: 44_292);

        status.ValueOf(ImapStatusItem.Messages).ShouldBe(231);
        status.ValueOf(ImapStatusItem.Unseen).ShouldBe(7);
        status.ValueOf(ImapStatusItem.UidNext).ShouldBe(44_292);
        status.ValueOf(ImapStatusItem.UidValidity).ShouldBe(3_857_529_045);
    }

    /// <summary>
    /// \Recent is reserved and never set by this server, so the count of messages carrying it is
    /// zero — a true answer rather than an unimplemented one.
    /// </summary>
    [Fact]
    public void Recent_is_truthfully_zero() =>
        Status(messageCount: 231).ValueOf(ImapStatusItem.Recent).ShouldBe(0);

    /// <summary>
    /// The distinction RFC 3501 buries in two sections: §6.3.10's UNSEEN is a count and
    /// §6.3.1's [UNSEEN n] is a sequence number. A mailbox whose first eleven messages are read
    /// and whose twelfth is not has [UNSEEN 12] on SELECT and UNSEEN 1 on STATUS. Asserting both
    /// from one folder is what keeps the two from being conflated later.
    /// </summary>
    [Fact]
    public void Status_unseen_counts_while_select_unseen_points()
    {
        MailboxFolder folder = new(
            new MailboxFolderId(Guid.NewGuid()),
            new MailboxId(Guid.NewGuid()),
            "INBOX",
            FolderSpecialUse.Inbox,
            uidValidity: 1,
            nextUid: 13,
            isSubscribed: true,
            DateTimeOffset.UnixEpoch,
            null);

        ImapFolderStatus status = new(folder, MessageCount: 12, UnseenCount: 1);
        ImapFolderSnapshot snapshot = new(folder, ExistsCount: 12, FirstUnseenSequenceNumber: 12);

        status.ValueOf(ImapStatusItem.Unseen).ShouldBe(1);
        snapshot.FirstUnseenSequenceNumber.ShouldBe(12);

        status.ValueOf(ImapStatusItem.Unseen)
            .ShouldNotBe(snapshot.FirstUnseenSequenceNumber!.Value);
    }

    [Fact]
    public void An_empty_folder_reports_zeroes_and_its_own_uids()
    {
        ImapFolderStatus status = Status(uidValidity: 42, nextUid: 1);

        status.ValueOf(ImapStatusItem.Messages).ShouldBe(0);
        status.ValueOf(ImapStatusItem.Unseen).ShouldBe(0);
        status.ValueOf(ImapStatusItem.Recent).ShouldBe(0);
        status.ValueOf(ImapStatusItem.UidNext).ShouldBe(1);
        status.ValueOf(ImapStatusItem.UidValidity).ShouldBe(42);
    }

    /// <summary>
    /// Total, so a new item cannot be parseable and unanswerable at the same time.
    /// </summary>
    [Fact]
    public void Every_item_has_a_value()
    {
        ImapFolderStatus status = Status(messageCount: 3, unseenCount: 2);

        foreach (ImapStatusItem item in ImapStatusItems.All)
        {
            status.ValueOf(item).ShouldBeGreaterThanOrEqualTo(0);
        }
    }

    [Fact]
    public void An_undefined_item_has_no_value_and_no_name()
    {
        Should.Throw<ArgumentOutOfRangeException>(
            () => ImapStatusItems.NameOf((ImapStatusItem)99));

        Should.Throw<ArgumentOutOfRangeException>(
            () => Status().ValueOf((ImapStatusItem)99));
    }
}
