using MailServer.Domain.Enums;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

/// <summary>
/// The comparison behind RFC 3501 §6.4.6's untagged <c>FETCH</c>: "the server SHOULD send an
/// untagged FETCH response if a change to a message's flags from an external source is observed.
/// The intent is that the status of the flags is determinate without a race condition."
/// </summary>
/// <remarks>
/// Every position asserted here is a position in the <i>client's</i> numbering. That is the
/// distinction the whole type exists to keep, and most of these tests are about a case where it
/// differs from the folder's.
/// </remarks>
public sealed class ImapFlagWatchTests
{
    private static ImapFlagState[] Folder(params (long Uid, MessageFlags Flags)[] messages) =>
        [.. messages.Select(m => new ImapFlagState(m.Uid, m.Flags))];

    private static ImapFlagState[] Unread(params long[] uids) =>
        [.. uids.Select(uid => new ImapFlagState(uid, MessageFlags.None))];

    // ---------------------------------------------------------------------------------------
    // What is and is not a change.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The case the SHOULD is written for: a phone marks a message read and the desktop, sitting
    /// in <c>IDLE</c>, is told.
    /// </summary>
    [Fact]
    public void A_flag_set_by_somebody_else_is_reported_at_the_clients_position()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11, 12), flagsModSeq: 4);

        IReadOnlyList<ImapFlagChange> changes = watch.Observe(
            Folder((10, MessageFlags.None), (11, MessageFlags.Seen), (12, MessageFlags.None)),
            flagsModSeq: 5,
            reportedExists: 3);

        changes.ShouldHaveSingleItem();
        changes[0].SequenceNumber.ShouldBe(2);
        changes[0].Uid.ShouldBe(11);
        changes[0].Flags.ShouldBe(MessageFlags.Seen);
    }

    /// <summary>
    /// §6.4.6 asks for "the new value of the flags", not for what changed — so a message that
    /// gains one flag while keeping another is reported carrying both.
    /// </summary>
    [Fact]
    public void The_whole_new_value_is_reported_rather_than_the_difference()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(
            Folder((10, MessageFlags.Seen)),
            flagsModSeq: 1);

        IReadOnlyList<ImapFlagChange> changes = watch.Observe(
            Folder((10, MessageFlags.Seen | MessageFlags.Answered)),
            flagsModSeq: 2,
            reportedExists: 1);

        changes.ShouldHaveSingleItem();
        changes[0].Flags.ShouldBe(MessageFlags.Seen | MessageFlags.Answered);
    }

    /// <summary>
    /// The starting point is the folder as it stands, because a change is only news if it
    /// happened after the client last had the truth. A watch seeded empty would announce every
    /// message in the folder as changed on its first look.
    /// </summary>
    [Fact]
    public void Starting_a_watch_reports_nothing_about_the_folder_it_started_from()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(
            Folder((10, MessageFlags.Seen), (11, MessageFlags.Flagged)),
            flagsModSeq: 7);

        watch.Observe(
            Folder((10, MessageFlags.Seen), (11, MessageFlags.Flagged)),
            flagsModSeq: 7,
            reportedExists: 2).ShouldBeEmpty();
    }

    /// <summary>
    /// Reported once, not on every poll afterwards. A watch that compared against its starting
    /// point for ever would re-send the same untagged <c>FETCH</c> every five seconds until the
    /// client gave up and reconnected.
    /// </summary>
    [Fact]
    public void A_change_already_reported_is_not_reported_again()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10), flagsModSeq: 1);

        watch.Observe(Folder((10, MessageFlags.Seen)), 2, reportedExists: 1)
            .ShouldHaveSingleItem();

        watch.Observe(Folder((10, MessageFlags.Seen)), 2, reportedExists: 1)
            .ShouldBeEmpty();
    }

    /// <summary>
    /// Flags going away is as much a change as flags arriving — a message unmarked on another
    /// client must stop showing as read here.
    /// </summary>
    [Fact]
    public void A_flag_cleared_by_somebody_else_is_reported()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(
            Folder((10, MessageFlags.Seen)),
            flagsModSeq: 1);

        IReadOnlyList<ImapFlagChange> changes = watch.Observe(
            Folder((10, MessageFlags.None)),
            flagsModSeq: 2,
            reportedExists: 1);

        changes.ShouldHaveSingleItem();
        changes[0].Flags.ShouldBe(MessageFlags.None);
    }

    /// <summary>Several at once come back in ascending position order, which the wire needs.</summary>
    [Fact]
    public void Changes_come_back_in_position_order()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11, 12, 13), flagsModSeq: 1);

        IReadOnlyList<ImapFlagChange> changes = watch.Observe(
            Folder(
                (10, MessageFlags.None),
                (11, MessageFlags.Seen),
                (12, MessageFlags.None),
                (13, MessageFlags.Deleted)),
            flagsModSeq: 2,
            reportedExists: 4);

        changes.Select(c => c.SequenceNumber).ShouldBe([2, 4]);
    }

    // ---------------------------------------------------------------------------------------
    // What the client has been told about.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A <c>FETCH</c> for a position the client does not believe exists is a response about a
    /// message it cannot identify. A folder that grew between <c>SELECT</c> and <c>IDLE</c> is
    /// watched from its true size, so this really happens.
    /// </summary>
    [Fact]
    public void Nothing_is_reported_at_a_position_the_client_has_not_been_told_about()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11), flagsModSeq: 1);

        watch.Observe(
            Folder((10, MessageFlags.None), (11, MessageFlags.Seen)),
            flagsModSeq: 2,
            reportedExists: 1).ShouldBeEmpty();
    }

    /// <summary>
    /// Held back, not thrown away. Once an <c>EXISTS</c> has covered the position, the client is
    /// owed the flags it has never been told — but it is owed them once, from the value the
    /// folder holds, rather than one report per poll it waited.
    /// </summary>
    [Fact]
    public void A_change_held_back_is_reported_once_the_client_has_been_told_the_position()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11), flagsModSeq: 1);

        watch.Observe(
            Folder((10, MessageFlags.None), (11, MessageFlags.Seen)),
            flagsModSeq: 2,
            reportedExists: 1).ShouldBeEmpty();

        IReadOnlyList<ImapFlagChange> changes = watch.Observe(
            Folder((10, MessageFlags.None), (11, MessageFlags.Seen | MessageFlags.Flagged)),
            flagsModSeq: 3,
            reportedExists: 2);

        changes.ShouldHaveSingleItem();
        changes[0].SequenceNumber.ShouldBe(2);
        changes[0].Flags.ShouldBe(MessageFlags.Seen | MessageFlags.Flagged);
    }

    // ---------------------------------------------------------------------------------------
    // Arrivals.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A message that arrives while the client idles joins the list, so a later change to it is
    /// reported at the position the client now has for it.
    /// </summary>
    [Fact]
    public void A_message_that_arrives_is_adopted_and_watched()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10), flagsModSeq: 1);

        watch.Observe(Folder((10, MessageFlags.None), (11, MessageFlags.None)), 1, 2)
            .ShouldBeEmpty();

        IReadOnlyList<ImapFlagChange> changes = watch.Observe(
            Folder((10, MessageFlags.None), (11, MessageFlags.Seen)),
            flagsModSeq: 2,
            reportedExists: 2);

        changes.ShouldHaveSingleItem();
        changes[0].SequenceNumber.ShouldBe(2);
        changes[0].Uid.ShouldBe(11);
    }

    /// <summary>
    /// An arrival is not itself a flag change. The <c>EXISTS</c> says it arrived and the client
    /// fetches what it wants; an untagged <c>FETCH</c> as well would report flags the client has
    /// never had a stale value for.
    /// </summary>
    [Fact]
    public void An_arrival_is_not_reported_as_a_flag_change()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10), flagsModSeq: 1);

        watch.Observe(
            Folder((10, MessageFlags.None), (11, MessageFlags.Seen | MessageFlags.Flagged)),
            flagsModSeq: 1,
            reportedExists: 2).ShouldBeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // Expunges by another session, which is where positions part company.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <b>The case this design exists for.</b> Another session expunges the folder's second
    /// message. This session does not send <c>EXPUNGE</c> from a poll, so RFC 3501 §7.4.1
    /// forbids the client renumbering — its third message is still its third. The folder's third
    /// message is now its second. Reporting the folder's position would move the client's flag
    /// onto the wrong message.
    /// </summary>
    [Fact]
    public void After_an_expunge_elsewhere_positions_stay_the_clients_own()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11, 12), flagsModSeq: 1);

        IReadOnlyList<ImapFlagChange> changes = watch.Observe(
            Folder((10, MessageFlags.None), (12, MessageFlags.Seen)),
            flagsModSeq: 2,
            reportedExists: 3);

        changes.ShouldHaveSingleItem();
        changes[0].Uid.ShouldBe(12);

        // Three, not two: the client still counts the message that went.
        changes[0].SequenceNumber.ShouldBe(3);
    }

    /// <summary>
    /// The expunged message is simply never mentioned again. There is nothing to report about
    /// it — its flags are not "cleared", it is gone — and §7.4.1 reserves saying so for an
    /// <c>EXPUNGE</c> this poll does not send.
    /// </summary>
    [Fact]
    public void A_message_expunged_elsewhere_is_never_reported()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(
            Folder((10, MessageFlags.Seen), (11, MessageFlags.Seen)),
            flagsModSeq: 1);

        watch.Observe(Folder((10, MessageFlags.Seen)), flagsModSeq: 2, reportedExists: 2)
            .ShouldBeEmpty();
    }

    /// <summary>
    /// <b>Once the two numberings have parted, the list stops growing.</b> After an expunge
    /// nobody told the client about, there is no way to know which message the client would put
    /// at a new position — so a message arriving afterwards is watched by nobody rather than
    /// watched under a number that might name something else.
    /// </summary>
    [Fact]
    public void After_an_expunge_elsewhere_a_later_arrival_is_not_adopted()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11, 12), flagsModSeq: 1);

        // Seen once, so the watch knows the numberings have parted.
        watch.Observe(Folder((10, MessageFlags.None), (12, MessageFlags.None)), 1, 3)
            .ShouldBeEmpty();

        // Two arrive, taking the folder past what the client was told.
        watch.Observe(Unread(10, 12, 13, 14), flagsModSeq: 1, reportedExists: 4).ShouldBeEmpty();

        // One of them is then read elsewhere. A watch that had adopted it would report it under
        // a position that names a different message in the client's own numbering.
        watch.Observe(
            Folder(
                (10, MessageFlags.None),
                (12, MessageFlags.None),
                (13, MessageFlags.None),
                (14, MessageFlags.Seen)),
            flagsModSeq: 2,
            reportedExists: 4).ShouldBeEmpty();
    }

    /// <summary>
    /// Not a full stop, though: every message the client already had keeps its position and
    /// keeps being watched. Giving up on those too would lose the reports this feature exists
    /// for over an event that does not affect them.
    /// </summary>
    [Fact]
    public void After_an_expunge_elsewhere_the_messages_the_client_had_are_still_watched()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11, 12), flagsModSeq: 1);

        watch.Observe(Folder((10, MessageFlags.None), (12, MessageFlags.None)), 1, 3)
            .ShouldBeEmpty();

        IReadOnlyList<ImapFlagChange> changes = watch.Observe(
            Folder((10, MessageFlags.Flagged), (12, MessageFlags.None)),
            flagsModSeq: 2,
            reportedExists: 3);

        changes.ShouldHaveSingleItem();
        changes[0].SequenceNumber.ShouldBe(1);
        changes[0].Uid.ShouldBe(10);
    }

    /// <summary>
    /// A UID appearing below the folder's high-water mark violates the schema's "never reused,
    /// never reordered" — and the watch stops growing rather than trusting positions derived
    /// from a folder that is not what it is documented to be.
    /// </summary>
    [Fact]
    public void A_uid_appearing_out_of_order_stops_the_list_growing()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 12), flagsModSeq: 1);

        // 11 has appeared between two UIDs the watch already holds.
        watch.Observe(Unread(10, 11, 12), flagsModSeq: 1, reportedExists: 3).ShouldBeEmpty();

        // 13 arrives, and is then read elsewhere. It was never adopted, so nothing is reported
        // for it at a position derived from a folder that broke its own ordering rule.
        watch.Observe(Unread(10, 11, 12, 13), flagsModSeq: 1, reportedExists: 4).ShouldBeEmpty();

        watch.Observe(
            Folder(
                (10, MessageFlags.None),
                (11, MessageFlags.None),
                (12, MessageFlags.None),
                (13, MessageFlags.Seen)),
            flagsModSeq: 2,
            reportedExists: 4).ShouldBeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // Deciding whether to look at all.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The reason the counter exists. A folder nothing has happened to must cost one aggregate
    /// query per poll rather than every row it holds.
    /// </summary>
    [Fact]
    public void A_folder_nothing_happened_to_needs_no_look()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11), flagsModSeq: 9);

        watch.NeedsLook(messageCount: 2, flagsModSeq: 9).ShouldBeFalse();
    }

    /// <summary>A flag change moves the counter, and that is what a poll notices.</summary>
    [Fact]
    public void A_moved_counter_needs_a_look()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11), flagsModSeq: 9);

        watch.NeedsLook(messageCount: 2, flagsModSeq: 10).ShouldBeTrue();
    }

    /// <summary>
    /// The count is watched too, and an <b>expunge</b> is why — not only an arrival. An expunge
    /// moves no flag and so moves no counter, and a watch that did not look would go on
    /// extending its list past a message that is no longer there.
    /// </summary>
    [Theory]
    [InlineData(3)]
    [InlineData(1)]
    public void A_moved_count_needs_a_look(long count)
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10, 11), flagsModSeq: 9);

        watch.NeedsLook(count, flagsModSeq: 9).ShouldBeTrue();
    }

    /// <summary>Having looked, the watch stops asking to look again for the same reason.</summary>
    [Fact]
    public void Looking_records_what_was_seen()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10), flagsModSeq: 1);

        watch.Observe(Folder((10, MessageFlags.Seen), (11, MessageFlags.None)), 2, 2);

        watch.ObservedModSeq.ShouldBe(2);
        watch.ObservedCount.ShouldBe(2);
        watch.NeedsLook(2, 2).ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // Arguments.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_watch_refuses_a_null_folder()
    {
        Should.Throw<ArgumentNullException>(() => ImapFlagWatch.Start(null!, 0));

        ImapFlagWatch watch = ImapFlagWatch.Start([], 0);

        Should.Throw<ArgumentNullException>(() => watch.Observe(null!, 0, 0));
    }

    /// <summary>
    /// A negative count of what the client has been told is not a smaller number, it is a
    /// caller that has lost track — and silently clamping it would let every position through.
    /// </summary>
    [Fact]
    public void The_watch_refuses_a_negative_reported_count()
    {
        ImapFlagWatch watch = ImapFlagWatch.Start(Unread(10), 0);

        Should.Throw<ArgumentOutOfRangeException>(() => watch.Observe([], 0, -1));
    }
}
