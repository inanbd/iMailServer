using MailServer.Domain.Enums;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapFetchTests
{
    private static ImapMessageSummary Summary(
        long sequenceNumber = 1,
        long uid = 1,
        MessageFlags flags = MessageFlags.None,
        long sizeBytes = 100) =>
        new(
            sequenceNumber,
            uid,
            flags,
            new DateTimeOffset(2026, 3, 1, 9, 30, 15, TimeSpan.Zero),
            sizeBytes);

    // ---------------------------------------------------------------------------------------
    // Item names.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapFetchItem.Flags, "FLAGS")]
    [InlineData(ImapFetchItem.Uid, "UID")]
    [InlineData(ImapFetchItem.InternalDate, "INTERNALDATE")]
    [InlineData(ImapFetchItem.Rfc822Size, "RFC822.SIZE")]
    [InlineData(ImapFetchItem.Envelope, "ENVELOPE")]
    [InlineData(ImapFetchItem.Body, "BODY")]
    [InlineData(ImapFetchItem.BodyStructure, "BODYSTRUCTURE")]
    [InlineData(ImapFetchItem.Rfc822, "RFC822")]
    [InlineData(ImapFetchItem.Rfc822Header, "RFC822.HEADER")]
    [InlineData(ImapFetchItem.Rfc822Text, "RFC822.TEXT")]
    public void Every_item_has_the_name_its_grammar_gives_it(ImapFetchItem item, string expected) =>
        ImapFetchItems.NameOf(item).ShouldBe(expected);

    /// <summary>RFC 3501 §9 note (1): every token is matched case-insensitively.</summary>
    [Theory]
    [InlineData("FLAGS", ImapFetchItem.Flags)]
    [InlineData("flags", ImapFetchItem.Flags)]
    [InlineData("uid", ImapFetchItem.Uid)]
    [InlineData("InternalDate", ImapFetchItem.InternalDate)]
    [InlineData("rfc822.size", ImapFetchItem.Rfc822Size)]
    [InlineData("RFC822", ImapFetchItem.Rfc822)]
    [InlineData("rfc822.header", ImapFetchItem.Rfc822Header)]
    [InlineData("RFC822.TEXT", ImapFetchItem.Rfc822Text)]
    [InlineData("bodystructure", ImapFetchItem.BodyStructure)]
    [InlineData("BODY", ImapFetchItem.Body)]
    public void An_item_name_is_recognised_in_any_case(string name, ImapFetchItem expected)
    {
        ImapFetchItems.TryParse(name, out ImapFetchItem item).ShouldBeTrue();
        item.ShouldBe(expected);
    }

    /// <summary>
    /// §9's fetch-att lists "BODY" ["STRUCTURE"], "BODY" section and "BODY.PEEK" section as three
    /// alternatives, so a trailing bracket — not the name — decides which one arrived.
    /// </summary>
    [Theory]
    [InlineData("BODY[]")]
    [InlineData("BODY[HEADER]")]
    [InlineData("BODY[1.2.TEXT]")]
    [InlineData("BODY.PEEK[HEADER.FIELDS (DATE FROM)]")]
    [InlineData("body.peek[]")]
    [InlineData("BODY[]<0.2048>")]
    public void A_bracketed_item_is_the_body_section_family(string name)
    {
        ImapFetchItems.TryParse(name, out ImapFetchItem item).ShouldBeTrue();
        item.ShouldBe(ImapFetchItem.BodySection);
    }

    /// <summary>BODY.PEEK without a section is none of §9's three alternatives.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("BODY.PEEK")]
    [InlineData("BODY[")]
    [InlineData("NONSENSE")]
    [InlineData("RFC822.NONSENSE")]
    [InlineData("FLAG")]
    [InlineData("UIDS")]
    [InlineData("ENVELOPES")]
    [InlineData("HEADER[]")]
    public void A_name_the_grammar_does_not_have_is_refused(string name) =>
        ImapFetchItems.TryParse(name, out _).ShouldBeFalse();

    // ---------------------------------------------------------------------------------------
    // Macros.
    // ---------------------------------------------------------------------------------------

    /// <summary>RFC 3501 §6.4.5: "FAST — Macro equivalent to: (FLAGS INTERNALDATE RFC822.SIZE)".</summary>
    [Fact]
    public void Fast_expands_to_the_three_items_the_rfc_names()
    {
        ImapFetchItems.TryParseMacro("FAST", out IReadOnlyList<ImapFetchItem> items).ShouldBeTrue();

        items.ShouldBe(
        [
            ImapFetchItem.Flags,
            ImapFetchItem.InternalDate,
            ImapFetchItem.Rfc822Size,
        ]);
    }

    /// <summary>§6.4.5: "ALL — Macro equivalent to: (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)".</summary>
    [Fact]
    public void All_expands_to_fast_plus_the_envelope()
    {
        ImapFetchItems.TryParseMacro("ALL", out IReadOnlyList<ImapFetchItem> items).ShouldBeTrue();

        items.ShouldBe(
        [
            ImapFetchItem.Flags,
            ImapFetchItem.InternalDate,
            ImapFetchItem.Rfc822Size,
            ImapFetchItem.Envelope,
        ]);
    }

    /// <summary>
    /// §6.4.5: "FULL — Macro equivalent to: (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY)".
    /// </summary>
    [Fact]
    public void Full_expands_to_all_plus_the_body()
    {
        ImapFetchItems.TryParseMacro("full", out IReadOnlyList<ImapFetchItem> items).ShouldBeTrue();

        items.ShouldBe(
        [
            ImapFetchItem.Flags,
            ImapFetchItem.InternalDate,
            ImapFetchItem.Rfc822Size,
            ImapFetchItem.Envelope,
            ImapFetchItem.Body,
        ]);
    }

    [Theory]
    [InlineData("FLAGS")]
    [InlineData("QUICK")]
    [InlineData("")]
    public void A_name_that_is_not_a_macro_does_not_expand(string name) =>
        ImapFetchItems.TryParseMacro(name, out _).ShouldBeFalse();

    // ---------------------------------------------------------------------------------------
    // The whole argument.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_bare_item_is_a_request_for_one_thing()
    {
        ImapFetchItems.TryParseRequest("FLAGS", out IReadOnlyList<ImapFetchItem> items)
            .ShouldBeTrue();

        items.ShouldBe([ImapFetchItem.Flags]);
    }

    [Fact]
    public void A_bare_macro_expands()
    {
        ImapFetchItems.TryParseRequest("FAST", out IReadOnlyList<ImapFetchItem> items)
            .ShouldBeTrue();

        items.Count.ShouldBe(3);
    }

    [Fact]
    public void A_parenthesised_list_keeps_the_requested_order()
    {
        ImapFetchItems.TryParseRequest("(UID FLAGS)", out IReadOnlyList<ImapFetchItem> items)
            .ShouldBeTrue();

        items.ShouldBe([ImapFetchItem.Uid, ImapFetchItem.Flags]);
    }

    /// <summary>
    /// §9: fetch = "FETCH" SP sequence-set SP ("ALL" / "FULL" / "FAST" / fetch-att / "("
    /// fetch-att *(SP fetch-att) ")"). A macro is an alternative to the bracketed list, not a
    /// member of it — and §6.4.5 says so in prose: "A macro must be used by itself, and not in
    /// conjunction with other macros or data items."
    /// </summary>
    [Theory]
    [InlineData("(FAST)")]
    [InlineData("(ALL)")]
    [InlineData("(FULL)")]
    [InlineData("(FLAGS FAST)")]
    [InlineData("(FAST FLAGS)")]
    public void A_macro_inside_the_brackets_is_a_syntax_error(string text) =>
        ImapFetchItems.TryParseRequest(text, out _).ShouldBeFalse();

    /// <summary>Two bare arguments is a shape the grammar has nowhere to put.</summary>
    [Theory]
    [InlineData("FLAGS UID")]
    [InlineData("FAST FLAGS")]
    public void Two_bare_items_are_a_syntax_error(string text) =>
        ImapFetchItems.TryParseRequest(text, out _).ShouldBeFalse();

    /// <summary>§9's msg-att requires one item before the repetition.</summary>
    [Theory]
    [InlineData("()")]
    [InlineData("")]
    [InlineData("(")]
    [InlineData(")")]
    [InlineData("(FLAGS")]
    [InlineData("FLAGS)")]
    [InlineData("(NONSENSE)")]
    [InlineData("(FLAGS NONSENSE)")]
    public void A_malformed_argument_is_refused(string text) =>
        ImapFetchItems.TryParseRequest(text, out _).ShouldBeFalse();

    [Fact]
    public void A_repeated_item_is_requested_once()
    {
        ImapFetchItems.TryParseRequest("(FLAGS UID FLAGS)", out IReadOnlyList<ImapFetchItem> items)
            .ShouldBeTrue();

        items.ShouldBe([ImapFetchItem.Flags, ImapFetchItem.Uid]);
    }

    [Fact]
    public void A_list_longer_than_the_cap_is_refused()
    {
        string tooMany = "(" +
            string.Join(' ', Enumerable.Repeat("FLAGS", ImapFetchItems.MaxItemCount + 1)) +
            ")";

        ImapFetchItems.TryParseRequest(tooMany, out _).ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // Static versus dynamic.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// §9 puts exactly one item under msg-att-dynamic — "FLAGS", annotated "; MAY change for a
    /// message" — and everything else under msg-att-static, which "MUST NOT change for any
    /// particular message". A client caches on that distinction.
    /// </summary>
    [Fact]
    public void Flags_is_the_only_dynamic_item()
    {
        foreach (ImapFetchItem item in ImapFetchItems.All)
        {
            ImapFetchItems.IsDynamic(item).ShouldBe(item == ImapFetchItem.Flags);
        }
    }

    /// <summary>
    /// The stored columns, and the envelope. Everything else waits on the MIME reader.
    /// </summary>
    [Fact]
    public void The_stored_columns_and_the_envelope_are_available()
    {
        ImapFetchItems.Available.ShouldBe(
        [
            ImapFetchItem.Flags,
            ImapFetchItem.Uid,
            ImapFetchItem.InternalDate,
            ImapFetchItem.Rfc822Size,
            ImapFetchItem.Envelope,
        ]);
    }

    /// <summary>
    /// The two lists agree: an item is answerable from the summary alone exactly when it is
    /// available and does not need the message read. A disagreement would mean either a silent
    /// omission or a refused item that would have worked.
    /// </summary>
    [Fact]
    public void An_item_is_answerable_from_the_summary_exactly_when_it_needs_no_content()
    {
        foreach (ImapFetchItem item in ImapFetchItems.All)
        {
            bool fromColumns =
                ImapFetchItems.Available.Contains(item) && !ImapFetchItems.NeedsContent(item);

            (Summary().ValueOf(item) is not null).ShouldBe(fromColumns, $"{item} disagrees");
        }
    }

    /// <summary>
    /// <c>NeedsContent</c> is the complement of the four stored columns, over the whole item
    /// list — so adding an item without deciding which side it falls on fails here.
    /// </summary>
    [Fact]
    public void Everything_but_the_four_stored_columns_needs_the_message_read()
    {
        foreach (ImapFetchItem item in ImapFetchItems.All)
        {
            bool stored = item is
                ImapFetchItem.Flags or
                ImapFetchItem.Uid or
                ImapFetchItem.InternalDate or
                ImapFetchItem.Rfc822Size;

            ImapFetchItems.NeedsContent(item).ShouldBe(!stored, $"{item} disagrees");
        }
    }

    // ---------------------------------------------------------------------------------------
    // The values.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Flags_are_reported_as_a_parenthesised_list() =>
        Summary(flags: MessageFlags.Seen | MessageFlags.Answered)
            .ValueOf(ImapFetchItem.Flags)
            .ShouldBe(@"(\Seen \Answered)");

    [Fact]
    public void A_message_with_no_flags_reports_empty_brackets() =>
        Summary().ValueOf(ImapFetchItem.Flags).ShouldBe("()");

    [Fact]
    public void The_uid_and_the_size_are_reported_as_bare_numbers()
    {
        ImapMessageSummary summary = Summary(uid: 4_827_313, sizeBytes: 44_827);

        summary.ValueOf(ImapFetchItem.Uid).ShouldBe("4827313");
        summary.ValueOf(ImapFetchItem.Rfc822Size).ShouldBe("44827");
    }

    [Fact]
    public void An_item_this_server_cannot_answer_has_no_value() =>
        Summary().ValueOf(ImapFetchItem.Envelope).ShouldBeNull();

    // ---------------------------------------------------------------------------------------
    // INTERNALDATE.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// §9: date-day-fixed = (SP DIGIT) / 2DIGIT, "Fixed-format version of date-day". A
    /// single-digit day is padded with a SPACE, not a zero — the trap that makes an otherwise
    /// plausible formatter emit a string the grammar does not have.
    /// </summary>
    [Fact]
    public void A_single_digit_day_is_padded_with_a_space() =>
        ImapInternalDate
            .Format(new DateTimeOffset(2026, 1, 1, 9, 30, 15, TimeSpan.Zero))
            .ShouldBe("\" 1-Jan-2026 09:30:15 +0000\"");

    [Fact]
    public void A_two_digit_day_is_not_padded() =>
        ImapInternalDate
            .Format(new DateTimeOffset(2026, 12, 25, 23, 59, 59, TimeSpan.Zero))
            .ShouldBe("\"25-Dec-2026 23:59:59 +0000\"");

    /// <summary>§9: zone = ("+" / "-") 4DIGIT — four digits, no colon.</summary>
    [Theory]
    [InlineData(2, 0, "+0200")]
    [InlineData(5, 30, "+0530")]
    [InlineData(-8, 0, "-0800")]
    [InlineData(-3, -30, "-0330")]
    [InlineData(0, 0, "+0000")]
    public void The_zone_is_four_digits_with_a_sign(int hours, int minutes, string expected)
    {
        string formatted = ImapInternalDate.Format(
            new DateTimeOffset(2026, 6, 15, 12, 0, 0, new TimeSpan(hours, minutes, 0)));

        formatted.ShouldBe($"\"15-Jun-2026 12:00:00 {expected}\"");
    }

    /// <summary>
    /// The offset is preserved rather than normalised: the stored instant is when this server
    /// took delivery, and rewriting its offset would discard that for no gain.
    /// </summary>
    [Fact]
    public void The_offset_is_preserved_rather_than_converted_to_utc() =>
        ImapInternalDate
            .Format(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.FromHours(2)))
            .ShouldContain("12:00:00 +0200");

    [Theory]
    [InlineData(1, "Jan")]
    [InlineData(2, "Feb")]
    [InlineData(3, "Mar")]
    [InlineData(4, "Apr")]
    [InlineData(5, "May")]
    [InlineData(6, "Jun")]
    [InlineData(7, "Jul")]
    [InlineData(8, "Aug")]
    [InlineData(9, "Sep")]
    [InlineData(10, "Oct")]
    [InlineData(11, "Nov")]
    [InlineData(12, "Dec")]
    public void Every_month_has_the_abbreviation_the_grammar_lists(int month, string expected) =>
        ImapInternalDate
            .Format(new DateTimeOffset(2026, month, 15, 0, 0, 0, TimeSpan.Zero))
            .ShouldContain($"-{expected}-");

    /// <summary>
    /// Fixed width, which is the point of date-day-fixed: a server whose INTERNALDATE changed
    /// length with the value would be emitting something outside §9's date-time.
    /// </summary>
    [Fact]
    public void Every_internaldate_is_the_same_length()
    {
        int expected = ImapInternalDate
            .Format(new DateTimeOffset(2026, 12, 25, 23, 59, 59, TimeSpan.Zero))
            .Length;

        for (int day = 1; day <= 28; day++)
        {
            ImapInternalDate
                .Format(new DateTimeOffset(2026, 6, day, 1, 2, 3, TimeSpan.Zero))
                .Length
                .ShouldBe(expected, $"day {day}");
        }
    }
}
