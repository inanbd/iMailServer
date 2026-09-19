using MailServer.Domain.Pop3;

namespace MailServer.Pop3.Tests;

public sealed class Pop3MaildropTests
{
    private static Pop3Maildrop Drop(params (long Uid, long Size)[] messages) =>
        new(3_857_529_045, messages);

    /// <summary>
    /// RFC 1939 §4: "The first message in the maildrop is assigned a message-number of "1", the
    /// second is assigned "2", and so on, so that the nth message in a maildrop is assigned a
    /// message-number of "n"."
    /// </summary>
    [Fact]
    public void Messages_are_numbered_from_one_in_the_order_they_are_given()
    {
        Pop3Maildrop drop = Drop((7, 100), (11, 200), (19, 300));

        drop.Slots.Select(s => s.Number).ShouldBe([1, 2, 3]);
        drop.Slots.Select(s => s.Uid).ShouldBe([7L, 11L, 19L]);
    }

    /// <summary>§5 on <c>STAT</c>: "messages marked as deleted are not counted in either total".</summary>
    [Fact]
    public void A_marked_message_is_counted_in_neither_total()
    {
        Pop3Maildrop drop = Drop((7, 100), (11, 200));

        drop.Count.ShouldBe(2);
        drop.TotalOctets.ShouldBe(300);

        drop.Mark(1).ShouldBeTrue();

        drop.Count.ShouldBe(1);
        drop.TotalOctets.ShouldBe(200);
    }

    /// <summary>§5 and §7: "Note that messages marked as deleted are not listed."</summary>
    [Fact]
    public void A_marked_message_is_not_listed()
    {
        Pop3Maildrop drop = Drop((7, 100), (11, 200), (19, 300));

        drop.Mark(2);

        drop.Live.Select(s => s.Number).ShouldBe([1, 3]);
    }

    /// <summary>
    /// §5 on <c>DELE</c>: "Any future reference to the message-number associated with the message
    /// in a POP3 command generates an error."
    /// </summary>
    [Fact]
    public void A_marked_message_can_no_longer_be_found()
    {
        Pop3Maildrop drop = Drop((7, 100));

        drop.TryGet(1, out _).ShouldBeTrue();

        drop.Mark(1);

        drop.TryGet(1, out _).ShouldBeFalse();
        drop.IsMarked(1).ShouldBeTrue();
    }

    /// <summary>Marking twice is refused, which is how the second DELE earns its own refusal.</summary>
    [Fact]
    public void Marking_the_same_message_twice_is_refused()
    {
        Pop3Maildrop drop = Drop((7, 100));

        drop.Mark(1).ShouldBeTrue();
        drop.Mark(1).ShouldBeFalse();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(int.MaxValue)]
    public void A_number_outside_the_maildrop_finds_nothing(int number) =>
        Drop((7, 100)).TryGet(number, out _).ShouldBeFalse();

    /// <summary>§5 on <c>RSET</c>: "If any messages have been marked as deleted […] they are unmarked."</summary>
    [Fact]
    public void Reset_unmarks_everything()
    {
        Pop3Maildrop drop = Drop((7, 100), (11, 200));

        drop.Mark(1);
        drop.Mark(2);
        drop.HasMarks.ShouldBeTrue();

        drop.Reset();

        drop.HasMarks.ShouldBeFalse();
        drop.Count.ShouldBe(2);
        drop.MarkedUids.ShouldBeEmpty();
    }

    /// <summary>The UPDATE state removes by identifier, not by position.</summary>
    [Fact]
    public void The_marks_are_reported_as_identifiers()
    {
        Pop3Maildrop drop = Drop((7, 100), (11, 200), (19, 300));

        drop.Mark(1);
        drop.Mark(3);

        drop.MarkedUids.ShouldBe([7L, 19L]);
    }

    /// <summary>
    /// §7: "The unique-id of a message is an arbitrary server-determined string, consisting of one
    /// to 70 characters in the range 0x21 to 0x7E, which uniquely identifies a message within a
    /// maildrop and which persists across sessions."
    /// </summary>
    [Fact]
    public void A_unique_id_is_inside_the_length_and_character_ranges()
    {
        string id = Pop3Maildrop.UniqueIdOf(long.MaxValue, long.MaxValue);

        id.Length.ShouldBeGreaterThanOrEqualTo(1);
        id.Length.ShouldBeLessThanOrEqualTo(70);
        id.ShouldAllBe(c => c >= '!' && c <= '~');
    }

    /// <summary>
    /// The pair is what makes it unique: RFC 3501 §2.3.1.1 makes a UID and its UIDVALIDITY
    /// together "a 64-bit value that MUST NOT refer to any other message in the mailbox or any
    /// subsequent mailbox with the same name forever". The same UID under a different validity
    /// is a different message and must get a different id.
    /// </summary>
    [Fact]
    public void The_same_uid_under_a_different_validity_is_a_different_unique_id() =>
        Pop3Maildrop.UniqueIdOf(1, 7).ShouldNotBe(Pop3Maildrop.UniqueIdOf(2, 7));

    /// <summary>An empty maildrop is a maildrop, not an error.</summary>
    [Fact]
    public void An_empty_maildrop_has_nothing_in_it()
    {
        Pop3Maildrop drop = Drop();

        drop.Count.ShouldBe(0);
        drop.TotalOctets.ShouldBe(0);
        drop.Live.ShouldBeEmpty();
        drop.TryGet(1, out _).ShouldBeFalse();
    }
}
