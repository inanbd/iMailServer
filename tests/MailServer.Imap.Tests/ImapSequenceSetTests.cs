using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapSequenceSetTests
{
    // ---------------------------------------------------------------------------------------
    // Parsing.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(",")]
    [InlineData("1,")]
    [InlineData(",1")]
    [InlineData("1,,2")]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("01")]
    [InlineData("1:")]
    [InlineData(":1")]
    [InlineData("1:2:3")]
    [InlineData("abc")]
    [InlineData("1,abc")]
    [InlineData("**")]
    public void Rejects_malformed_input(string? text)
    {
        ImapSequenceSet.TryParse(text, out ImapSequenceSet? result).ShouldBeFalse();
        result.ShouldBeNull();
    }

    [Fact]
    public void Parses_a_single_number()
    {
        ImapSequenceSet.TryParse("5", out ImapSequenceSet? set).ShouldBeTrue();
        set!.Resolve(maxValue: 100).ShouldBe([(5L, 5L)]);
    }

    [Fact]
    public void Parses_a_comma_separated_list()
    {
        ImapSequenceSet.TryParse("1,3,5", out ImapSequenceSet? set).ShouldBeTrue();
        set!.Resolve(maxValue: 100).ShouldBe([(1L, 1L), (3L, 3L), (5L, 5L)]);
    }

    [Fact]
    public void Parses_a_range()
    {
        ImapSequenceSet.TryParse("3:5", out ImapSequenceSet? set).ShouldBeTrue();
        set!.Resolve(maxValue: 100).ShouldBe([(3L, 5L)]);
    }

    [Fact]
    public void Parses_the_full_grammar_example_from_rfc_3501_section_9()
    {
        ImapSequenceSet.TryParse("2,4:7,9,12:*", out ImapSequenceSet? set).ShouldBeTrue();
        set!.Resolve(maxValue: 15).ShouldBe([(2L, 2L), (4L, 7L), (9L, 9L), (12L, 15L)]);
    }

    // ---------------------------------------------------------------------------------------
    // Wildcard resolution and range normalisation.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_bare_wildcard_resolves_to_the_max_value()
    {
        ImapSequenceSet.TryParse("*", out ImapSequenceSet? set).ShouldBeTrue();
        set!.Resolve(maxValue: 42).ShouldBe([(42L, 42L)]);
    }

    [Fact]
    public void A_reversed_range_is_normalised_low_to_high()
    {
        // RFC 3501 §9's own example: "5:3" is equivalent to "3:5".
        ImapSequenceSet.TryParse("5:3", out ImapSequenceSet? set).ShouldBeTrue();
        set!.Resolve(maxValue: 100).ShouldBe([(3L, 5L)]);
    }

    [Fact]
    public void Star_colon_n_and_n_colon_star_resolve_the_same_way()
    {
        ImapSequenceSet.TryParse("*:4", out ImapSequenceSet? starFirst).ShouldBeTrue();
        ImapSequenceSet.TryParse("4:*", out ImapSequenceSet? starSecond).ShouldBeTrue();

        starFirst!.Resolve(maxValue: 10).ShouldBe(starSecond!.Resolve(maxValue: 10));
        starFirst.Resolve(maxValue: 10).ShouldBe([(4L, 10L)]);
    }

    [Fact]
    public void A_range_where_the_wildcard_side_is_smaller_still_normalises_low_to_high()
    {
        // maxValue (2) is smaller than the literal (7): "7:*" must not report (7, 2).
        ImapSequenceSet.TryParse("7:*", out ImapSequenceSet? set).ShouldBeTrue();
        set!.Resolve(maxValue: 2).ShouldBe([(2L, 7L)]);
    }

    // ---------------------------------------------------------------------------------------
    // Never materialising a huge range - the actual security property.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Resolving_an_enormous_range_against_a_huge_max_value_is_immediate_and_allocates_no_such_list()
    {
        // A long-lived folder's UIDNEXT can be enormous relative to how many messages it
        // currently holds. Resolving "1:*" must produce bounds, not a materialised sequence -
        // if this test hangs or exhausts memory, that guarantee has been broken.
        ImapSequenceSet.TryParse("1:*", out ImapSequenceSet? set).ShouldBeTrue();

        IReadOnlyList<(long Start, long End)> resolved = set!.Resolve(maxValue: 4_000_000_000L);

        resolved.ShouldBe([(1L, 4_000_000_000L)]);
    }

    [Fact]
    public void Exactly_the_segment_cap_is_accepted()
    {
        string text = string.Join(',', Enumerable.Range(1, ImapSequenceSet.MaxSegments));

        ImapSequenceSet.TryParse(text, out ImapSequenceSet? set).ShouldBeTrue();
        set!.Resolve(maxValue: ImapSequenceSet.MaxSegments).Count.ShouldBe(ImapSequenceSet.MaxSegments);
    }

    [Fact]
    public void One_more_than_the_segment_cap_is_refused()
    {
        string text = string.Join(',', Enumerable.Range(1, ImapSequenceSet.MaxSegments + 1));

        ImapSequenceSet.TryParse(text, out ImapSequenceSet? set).ShouldBeFalse();
        set.ShouldBeNull();
    }

    // ---------------------------------------------------------------------------------------
    // Contains.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(1L, true)]
    [InlineData(4L, true)]
    [InlineData(7L, true)]
    [InlineData(3L, false)]
    [InlineData(8L, false)]
    public void Contains_reflects_the_resolved_ranges(long candidate, bool expected)
    {
        ImapSequenceSet.TryParse("1,4:7", out ImapSequenceSet? set).ShouldBeTrue();

        set!.Contains(candidate, maxValue: 100).ShouldBe(expected);
    }
}
