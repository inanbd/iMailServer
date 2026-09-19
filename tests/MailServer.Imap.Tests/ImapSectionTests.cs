using System.Text;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapSectionTests
{
    private static ImapSection Parse(string item)
    {
        ImapSection.TryParse(item, out ImapSection? section).ShouldBeTrue($"could not parse [{item}]");

        return section!;
    }

    /// <summary>
    /// A small message with a folded header, so the subsetting tests have something to fold.
    /// </summary>
    private static readonly byte[] Message = Encoding.ASCII.GetBytes(
        "Date: Mon, 7 Feb 2026 21:52:25 -0800\r\n" +
        "From: Alice <alice@example.com>\r\n" +
        "Subject: a long one\r\n" +
        " that folds onto a second line\r\n" +
        "To: Bob <bob@example.net>\r\n" +
        "\r\n" +
        "This is the body.\r\n");

    private static string Extract(string item)
    {
        ReadOnlyMemory<byte>? octets = ImapBodySection.Extract(Message, Parse(item));

        octets.ShouldNotBeNull();

        return Encoding.ASCII.GetString(octets.Value.Span);
    }

    // ---------------------------------------------------------------------------------------
    // Parsing.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3501 §6.4.5: "An empty section specification refers to the entire message, including
    /// the header."
    /// </summary>
    [Fact]
    public void An_empty_specifier_is_the_whole_message()
    {
        ImapSection section = Parse("BODY[]");

        section.Kind.ShouldBe(ImapSectionKind.Full);
        section.Part.ShouldBeEmpty();
        section.Peek.ShouldBeFalse();
    }

    [Theory]
    [InlineData("BODY[HEADER]", ImapSectionKind.Header)]
    [InlineData("BODY[TEXT]", ImapSectionKind.Text)]
    [InlineData("body[header]", ImapSectionKind.Header)]
    [InlineData("BODY[1]", ImapSectionKind.Part)]
    [InlineData("BODY[1.2]", ImapSectionKind.Part)]
    [InlineData("BODY[1.MIME]", ImapSectionKind.Mime)]
    [InlineData("BODY[1.TEXT]", ImapSectionKind.Text)]
    public void Each_specifier_parses_to_its_kind(string item, ImapSectionKind expected) =>
        Parse(item).Kind.ShouldBe(expected);

    /// <summary>
    /// §6.4.5: "The \Seen flag is implicitly set" for BODY, and BODY.PEEK is "An alternate form
    /// of BODY[&lt;section&gt;] that does not implicitly set the \Seen flag."
    /// </summary>
    [Theory]
    [InlineData("BODY[]", false)]
    [InlineData("BODY.PEEK[]", true)]
    [InlineData("body.peek[HEADER]", true)]
    public void The_peek_form_is_recognised(string item, bool expected) =>
        Parse(item).Peek.ShouldBe(expected);

    [Fact]
    public void A_field_list_is_kept_in_the_order_written()
    {
        ImapSection section = Parse("BODY[HEADER.FIELDS (DATE FROM SUBJECT)]");

        section.Kind.ShouldBe(ImapSectionKind.HeaderFields);
        section.Fields.ShouldBe(["DATE", "FROM", "SUBJECT"]);
    }

    [Fact]
    public void The_not_form_is_distinguished_from_the_plain_one()
    {
        Parse("BODY[HEADER.FIELDS.NOT (RECEIVED)]").Kind
            .ShouldBe(ImapSectionKind.HeaderFieldsNot);
    }

    [Fact]
    public void A_numeric_prefix_is_kept_outermost_first() =>
        Parse("BODY[2.1.3.TEXT]").Part.ShouldBe([2, 1, 3]);

    /// <summary>§6.4.5's partial, which §9 types as number "." nz-number.</summary>
    [Fact]
    public void A_partial_carries_an_origin_and_a_length()
    {
        ImapSection section = Parse("BODY[]<0.2048>");

        section.Origin.ShouldBe(0);
        section.Length.ShouldBe(2048);
    }

    [Theory]
    [InlineData("BODY[]<0.0>")]
    [InlineData("BODY[]<0>")]
    [InlineData("BODY[]<>")]
    [InlineData("BODY[]<a.b>")]
    [InlineData("BODY[]<0.2048")]
    public void A_malformed_partial_is_refused(string item) =>
        ImapSection.TryParse(item, out _).ShouldBeFalse();

    /// <summary>
    /// §6.4.5: "The MIME part specifier MUST be prefixed by one or more numeric part specifiers."
    /// </summary>
    [Fact]
    public void A_bare_mime_specifier_is_refused() =>
        ImapSection.TryParse("BODY[MIME]", out _).ShouldBeFalse();

    [Theory]
    [InlineData("BODY")]
    [InlineData("BODY.PEEK")]
    [InlineData("BODYSTRUCTURE")]
    [InlineData("BODY[NONSENSE]")]
    [InlineData("BODY[HEADER.FIELDS]")]
    [InlineData("BODY[HEADER (DATE)]")]
    [InlineData("BODY[0]")]
    [InlineData("BODY[1.0]")]
    [InlineData("BODY[HEADER.FIELDS ()]")]
    public void A_specifier_the_grammar_does_not_have_is_refused(string item) =>
        ImapSection.TryParse(item, out _).ShouldBeFalse();

    [Fact]
    public void A_part_specifier_deeper_than_the_cap_is_refused()
    {
        string tooDeep = "BODY[" + string.Join('.', Enumerable.Repeat("1", ImapSection.MaxPartDepth + 1)) + "]";

        ImapSection.TryParse(tooDeep, out _).ShouldBeFalse();
    }

    /// <summary>
    /// The field names are echoed back in the response, so anything that could not have come
    /// from a real RFC 2822 header must not reach the wire.
    /// </summary>
    [Theory]
    [InlineData("BODY[HEADER.FIELDS (DATE:)]")]
    [InlineData("BODY[HEADER.FIELDS (\"DATE\")]")]
    [InlineData("BODY[HEADER.FIELDS (DA TE)]")]
    public void A_field_name_that_could_not_be_a_header_is_refused(string item)
    {
        if (ImapSection.TryParse(item, out ImapSection? section))
        {
            // "DA TE" splits into two legal names; the others must not parse at all.
            section!.Fields.ShouldAllBe(f => !f.Contains(':') && !f.Contains('"'));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Rendering the response's data item.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// §9's msg-att-static has "BODY" section and no BODY.PEEK anywhere: the peek is a property
    /// of the request, never of the answer.
    /// </summary>
    [Theory]
    [InlineData("BODY.PEEK[]", "BODY[]")]
    [InlineData("BODY.PEEK[HEADER]", "BODY[HEADER]")]
    [InlineData("BODY[TEXT]", "BODY[TEXT]")]
    [InlineData("BODY[1.2.TEXT]", "BODY[1.2.TEXT]")]
    [InlineData("BODY[HEADER.FIELDS (DATE FROM)]", "BODY[HEADER.FIELDS (DATE FROM)]")]
    public void The_response_never_echoes_peek(string item, string expected) =>
        Parse(item).Format().ShouldBe(expected);

    /// <summary>
    /// §9: <c>section-spec = section-msgtext / (section-part ["." section-text])</c> and
    /// <c>section-part = nz-number *("." nz-number)</c>. The dot separates pieces and never
    /// trails the last one, so a bare numbered part echoes as <c>BODY[2]</c> — a client that
    /// matches the echo against what it asked for would not recognise <c>BODY[2.]</c>.
    /// </summary>
    [Theory]
    [InlineData("BODY[1]")]
    [InlineData("BODY[2]")]
    [InlineData("BODY[1.2]")]
    [InlineData("BODY[4.2.2.1]")]
    [InlineData("BODY[1.MIME]")]
    [InlineData("BODY[3.HEADER]")]
    [InlineData("BODY[3.HEADER.FIELDS.NOT (RECEIVED)]")]
    public void Every_specifier_echoes_as_the_client_wrote_it(string item) =>
        Parse(item).Format().ShouldBe(item);

    /// <summary>
    /// §7.4.2's response form is BODY[&lt;section&gt;]&lt;&lt;origin octet&gt;&gt; — one number,
    /// the origin. §9 types it ["&lt;" number "&gt;"], with no place for the length.
    /// </summary>
    [Fact]
    public void The_response_echoes_the_origin_and_not_the_length() =>
        Parse("BODY[]<100.2048>").Format().ShouldBe("BODY[]<100>");

    // ---------------------------------------------------------------------------------------
    // Extraction.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_full_section_is_the_whole_message() =>
        Extract("BODY[]").ShouldBe(Encoding.ASCII.GetString(Message));

    /// <summary>
    /// §6.4.5: "the blank line is always included as part of header data".
    /// </summary>
    [Fact]
    public void The_header_ends_with_the_blank_line()
    {
        string header = Extract("BODY[HEADER]");

        header.ShouldStartWith("Date: ");
        header.ShouldEndWith("\r\n\r\n");
        header.ShouldNotContain("This is the body");
    }

    [Fact]
    public void The_text_is_everything_after_the_header()
    {
        Extract("BODY[TEXT]").ShouldBe("This is the body.\r\n");
    }

    /// <summary>
    /// §6.4.5: "The field-matching is case-insensitive but otherwise exact."
    /// </summary>
    [Fact]
    public void A_header_subset_keeps_only_the_named_fields()
    {
        string subset = Extract("BODY[HEADER.FIELDS (from)]");

        subset.ShouldBe("From: Alice <alice@example.com>\r\n\r\n");
    }

    /// <summary>
    /// A folded header travels with its field. Keeping the first line of a folded Subject and
    /// dropping the rest would hand the client a truncated subject with no sign of it.
    /// </summary>
    [Fact]
    public void A_header_subset_carries_folded_continuation_lines()
    {
        string subset = Extract("BODY[HEADER.FIELDS (SUBJECT)]");

        subset.ShouldBe("Subject: a long one\r\n that folds onto a second line\r\n\r\n");
    }

    [Fact]
    public void The_not_form_returns_the_complement()
    {
        string subset = Extract("BODY[HEADER.FIELDS.NOT (DATE FROM SUBJECT)]");

        subset.ShouldBe("To: Bob <bob@example.net>\r\n\r\n");
    }

    [Fact]
    public void A_partial_returns_the_substring_it_names() =>
        Extract("BODY[TEXT]<0.4>").ShouldBe("This");

    [Fact]
    public void A_partial_past_the_end_returns_nothing() =>
        Extract("BODY[TEXT]<9999.10>").ShouldBeEmpty();

    /// <summary>
    /// §6.4.5: "BODY[]&lt;0&gt; MAY be truncated, but BODY[] is NEVER truncated." A length longer
    /// than what remains returns what remains.
    /// </summary>
    [Fact]
    public void A_partial_longer_than_the_content_returns_what_there_is() =>
        Extract("BODY[TEXT]<0.9999>").ShouldBe("This is the body.\r\n");

    /// <summary>
    /// A message written by another tool may use bare LF. A scan that recognised only CRLF would
    /// treat such a message as all header and no body.
    /// </summary>
    [Fact]
    public void A_bare_lf_message_still_splits_at_the_blank_line()
    {
        byte[] message = Encoding.ASCII.GetBytes("From: a@b\nSubject: hi\n\nbody\n");

        ImapSection.TryParse("BODY[TEXT]", out ImapSection? text).ShouldBeTrue();
        ImapSection.TryParse("BODY[HEADER]", out ImapSection? header).ShouldBeTrue();

        Encoding.ASCII.GetString(ImapBodySection.Extract(message, text!)!.Value.Span)
            .ShouldBe("body\n");

        Encoding.ASCII.GetString(ImapBodySection.Extract(message, header!)!.Value.Span)
            .ShouldBe("From: a@b\nSubject: hi\n\n");
    }

    /// <summary>
    /// "except in the case of a message which has no body and no blank line" — the header then
    /// runs to the end and the body is empty.
    /// </summary>
    [Fact]
    public void A_message_with_no_blank_line_is_all_header()
    {
        byte[] message = Encoding.ASCII.GetBytes("From: a@b\r\nSubject: hi\r\n");

        ImapSection.TryParse("BODY[HEADER]", out ImapSection? header).ShouldBeTrue();
        ImapSection.TryParse("BODY[TEXT]", out ImapSection? text).ShouldBeTrue();

        ImapBodySection.Extract(message, header!)!.Value.Length.ShouldBe(message.Length);
        ImapBodySection.Extract(message, text!)!.Value.Length.ShouldBe(0);
    }

    /// <summary>
    /// 8-bit octets survive, because nothing here decodes to text. Sanitising or re-encoding
    /// them would corrupt every attachment.
    /// </summary>
    [Fact]
    public void Eight_bit_octets_pass_through_untouched()
    {
        byte[] message = [.. "From: a@b\r\n\r\n"u8, 0xC3, 0xA9, 0xFF, 0x00, 0x80];

        ImapSection.TryParse("BODY[TEXT]", out ImapSection? text).ShouldBeTrue();

        ImapBodySection.Extract(message, text!)!.Value.ToArray()
            .ShouldBe([0xC3, 0xA9, 0xFF, 0x00, 0x80]);
    }

    /// <summary>
    /// A numbered part needs the MIME tree walked, which is a later increment — so it returns
    /// null and the handler refuses it by name rather than guessing.
    /// </summary>
    [Theory]
    [InlineData("BODY[1]")]
    [InlineData("BODY[1.2]")]
    [InlineData("BODY[1.MIME]")]
    public void A_specifier_needing_the_mime_tree_is_not_extracted_yet(string item) =>
        ImapBodySection.Extract(Message, Parse(item)).ShouldBeNull();
}
