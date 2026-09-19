using System.Text;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapMimeTreeTests
{
    private static ReadOnlyMemory<byte> Octets(string message) =>
        Encoding.Latin1.GetBytes(message);

    private static string Text(ReadOnlyMemory<byte>? octets) =>
        octets is null ? "<NIL>" : Encoding.Latin1.GetString(octets.Value.Span);

    /// <summary>Renders a message's structure the way the wire would see it.</summary>
    private static string Structure(string message, bool extended = true)
    {
        ImapSegmentBuilder builder = new();

        ImapBodyStructure.Format(ImapMimeTree.Parse(Octets(message)), extended, builder);

        StringBuilder text = new();

        foreach (ImapResponseSegment segment in builder.Build())
        {
            text.Append(segment.Text ?? Encoding.Latin1.GetString(segment.Octets.Span));
        }

        return text.ToString();
    }

    /// <summary>The octets one <c>BODY[…]</c> specifier names, or <c>&lt;NIL&gt;</c>.</summary>
    private static string Section(string message, string specifier)
    {
        ImapSection.TryParse($"BODY[{specifier}]", out ImapSection? section)
            .ShouldBeTrue($"could not parse BODY[{specifier}]");

        ReadOnlyMemory<byte> octets = Octets(message);

        return Text(ImapMimeTree.Extract(ImapMimeTree.Parse(octets), octets, section!));
    }

    // -------------------------------------------------------------------------------------------
    // The structures the specification publishes.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3501 §7.4.2: "For example, a simple text message of 48 lines and 2279 octets can have
    /// a body structure of: ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 2279 48)".
    /// </summary>
    [Fact]
    public void A_simple_text_message_has_the_structure_the_specification_shows()
    {
        const string Message =
            "Subject: hello\r\n" +
            "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n" +
            "\r\n" +
            "one\r\ntwo\r\nthree\r\n";

        Structure(Message, extended: false)
            .ShouldBe("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 17 3)");
    }

    /// <summary>
    /// §7.4.2: "a two part message consisting of a text and a BASE64-encoded text attachment can
    /// have a body structure of: (("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 1152
    /// 23)("TEXT" "PLAIN" ("CHARSET" "US-ASCII" "NAME" "cc.diff")
    /// "&lt;960723163407.20117h@cac.washington.edu&gt;" "Compiler diff" "BASE64" 4554 73)
    /// "MIXED")". The shape is reproduced exactly; only the sizes differ, because this message
    /// is the one that fits in a test rather than the one the document had.
    /// </summary>
    [Fact]
    public void A_two_part_message_has_the_shape_the_specification_shows()
    {
        const string Message =
            "Subject: hello\r\n" +
            "Content-Type: multipart/mixed; boundary=\"frontier\"\r\n" +
            "\r\n" +
            "--frontier\r\n" +
            "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n" +
            "\r\n" +
            "plain\r\n" +
            "--frontier\r\n" +
            "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII; NAME=cc.diff\r\n" +
            "Content-ID: <960723163407.20117h@cac.washington.edu>\r\n" +
            "Content-Description: Compiler diff\r\n" +
            "Content-Transfer-Encoding: BASE64\r\n" +
            "\r\n" +
            "Y2M=\r\n" +
            "--frontier--\r\n";

        Structure(Message, extended: false).ShouldBe(
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 5 1)" +
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\" \"NAME\" \"cc.diff\") " +
            "\"<960723163407.20117h@cac.washington.edu>\" \"Compiler diff\" \"BASE64\" 4 1) " +
            "\"MIXED\")");
    }

    // -------------------------------------------------------------------------------------------
    // Part numbering, against §6.4.5's worked example.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A message built to match §6.4.5's "example of a complex message with some of its part
    /// specifiers" exactly: a mixed multipart whose third part is a message carrying another
    /// multipart, and whose fourth is a multipart carrying a message carrying a multipart
    /// carrying an alternative.
    /// </summary>
    private const string Complex =
        "Subject: complex\r\n" +
        "Content-Type: multipart/mixed; boundary=\"A\"\r\n" +
        "\r\n" +
        "preamble, which RFC 2046 §5.1.1 says is to be ignored\r\n" +
        "--A\r\n" +
        "Content-Type: text/plain\r\n" +
        "\r\n" +
        "part one\r\n" +
        "--A\r\n" +
        "Content-Type: application/octet-stream\r\n" +
        "\r\n" +
        "part two\r\n" +
        "--A\r\n" +
        "Content-Type: message/rfc822\r\n" +
        "\r\n" +
        "Subject: inner three\r\n" +
        "Content-Type: multipart/mixed; boundary=\"B\"\r\n" +
        "\r\n" +
        "--B\r\n" +
        "Content-Type: text/plain\r\n" +
        "\r\n" +
        "part three one\r\n" +
        "--B\r\n" +
        "Content-Type: application/octet-stream\r\n" +
        "\r\n" +
        "part three two\r\n" +
        "--B--\r\n" +
        "--A\r\n" +
        "Content-Type: multipart/mixed; boundary=\"C\"\r\n" +
        "\r\n" +
        "--C\r\n" +
        "Content-Type: image/gif\r\n" +
        "\r\n" +
        "GIF89a\r\n" +
        "--C\r\n" +
        "Content-Type: message/rfc822\r\n" +
        "\r\n" +
        "Subject: inner four two\r\n" +
        "Content-Type: multipart/mixed; boundary=\"D\"\r\n" +
        "\r\n" +
        "--D\r\n" +
        "Content-Type: text/plain\r\n" +
        "\r\n" +
        "part four two one\r\n" +
        "--D\r\n" +
        "Content-Type: multipart/alternative; boundary=\"E\"\r\n" +
        "\r\n" +
        "--E\r\n" +
        "Content-Type: text/plain\r\n" +
        "\r\n" +
        "part four two two one\r\n" +
        "--E\r\n" +
        "Content-Type: text/richtext\r\n" +
        "\r\n" +
        "part four two two two\r\n" +
        "--E--\r\n" +
        "--D--\r\n" +
        "--C--\r\n" +
        "--A--\r\n" +
        "epilogue, which RFC 2046 §5.1.1 also says is to be ignored\r\n";

    /// <summary>
    /// Every numbered leaf of §6.4.5's example resolves to its own content — and to nothing
    /// else, which is what a wrong boundary scan or a wrong nesting rule would produce.
    /// </summary>
    [Theory]
    [InlineData("1", "part one")]
    [InlineData("2", "part two")]
    [InlineData("3.1", "part three one")]
    [InlineData("3.2", "part three two")]
    [InlineData("4.1", "GIF89a")]
    [InlineData("4.2.1", "part four two one")]
    [InlineData("4.2.2.1", "part four two two one")]
    [InlineData("4.2.2.2", "part four two two two")]
    public void Every_numbered_part_of_the_worked_example_resolves(string specifier, string expected) =>
        Section(Complex, specifier).ShouldBe(expected);

    /// <summary>
    /// §6.4.5: "A part of type MESSAGE/RFC822 also has nested part numbers, referring to parts
    /// of the MESSAGE part's body." So <c>BODY[3]</c> is the whole encapsulated message, header
    /// included — the part's content, exactly as a client would have to parse it itself.
    /// </summary>
    [Fact]
    public void A_message_part_is_the_encapsulated_message_header_and_all()
    {
        string part = Section(Complex, "3");

        part.ShouldStartWith("Subject: inner three\r\n");
        part.ShouldContain("part three two");
        part.ShouldEndWith("--B--");
    }

    /// <summary>
    /// §6.4.5: "The HEADER, HEADER.FIELDS, HEADER.FIELDS.NOT, and TEXT part specifiers […] can
    /// be prefixed by one or more numeric part specifiers, provided that the numeric part
    /// specifier refers to a part of type MESSAGE/RFC822", and they "refer to the [RFC-2822]
    /// header of the message or of an encapsulated [MIME-IMT] MESSAGE/RFC822 message."
    /// </summary>
    [Fact]
    public void A_message_parts_header_and_text_are_read_from_the_message_it_carries()
    {
        Section(Complex, "3.HEADER").ShouldBe(
            "Subject: inner three\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n");

        Section(Complex, "3.TEXT").ShouldStartWith("--B\r\n");
        Section(Complex, "3.TEXT").ShouldEndWith("--B--");
    }

    /// <summary>
    /// §6.4.5: "The MIME part specifier refers to the [MIME-IMB] header for this part." Its own
    /// header, not the message's and not the part's content.
    /// </summary>
    [Fact]
    public void A_mime_specifier_is_the_parts_own_header() =>
        Section(Complex, "4.1.MIME").ShouldBe("Content-Type: image/gif\r\n\r\n");

    /// <summary>
    /// §6.4.5 allows the prefix only when it "refers to a part of type MESSAGE/RFC822". Part 1 is
    /// a TEXT/PLAIN, so <c>1.HEADER</c> names nothing — answered NIL, because whether a part
    /// exists is a fact about one message and a FETCH covers many.
    /// </summary>
    [Theory]
    [InlineData("1.HEADER")]
    [InlineData("1.TEXT")]
    [InlineData("2.TEXT")]
    public void A_header_or_text_prefix_that_is_not_a_message_part_has_no_answer(string specifier) =>
        Section(Complex, specifier).ShouldBe("<NIL>");

    /// <summary>A part number past the end of a multipart names nothing.</summary>
    [Theory]
    [InlineData("5")]
    [InlineData("1.1")]
    [InlineData("4.3")]
    [InlineData("4.2.2.3")]
    public void A_part_number_that_is_not_there_has_no_answer(string specifier) =>
        Section(Complex, specifier).ShouldBe("<NIL>");

    /// <summary>
    /// Two shapes are refused by the parser rather than answered NIL, because they are not
    /// specifiers at all: §9's <c>section-part = nz-number *("." nz-number)</c> has no part
    /// zero, and §6.4.5 says "The MIME part specifier MUST be prefixed by one or more numeric
    /// part specifiers". §6.4.5 separates that from a fetch that cannot be served — "BAD -
    /// command unknown or arguments invalid" against "NO - fetch error: can't fetch that data".
    /// </summary>
    [Theory]
    [InlineData("BODY[0]")]
    [InlineData("BODY[0.1]")]
    [InlineData("BODY[1.0]")]
    [InlineData("BODY[MIME]")]
    public void A_specifier_the_grammar_does_not_have_is_not_a_specifier(string item) =>
        ImapSection.TryParse(item, out _).ShouldBeFalse($"{item} is not in §9's grammar");

    /// <summary>
    /// §6.4.5: "Non-[MIME-IMB] messages, and non-multipart [MIME-IMB] messages with no
    /// encapsulated message, only have a part 1." So part 1 of a plain message is its body, and
    /// there is no part 2.
    /// </summary>
    [Fact]
    public void A_plain_message_has_exactly_part_one()
    {
        const string Message = "Subject: plain\r\n\r\nthe body\r\n";

        Section(Message, "1").ShouldBe("the body\r\n");
        Section(Message, "2").ShouldBe("<NIL>");
        Section(Message, "1.1").ShouldBe("<NIL>");
    }

    /// <summary>
    /// A message that is itself a <c>MESSAGE/RFC822</c> has more than a part 1, which is the
    /// other half of the sentence above: part 1 is the encapsulated message, and its own parts
    /// hang off it.
    /// </summary>
    [Fact]
    public void A_message_whose_body_is_a_message_addresses_inside_it()
    {
        const string Message =
            "Subject: outer\r\n" +
            "Content-Type: message/rfc822\r\n" +
            "\r\n" +
            "Subject: inner\r\n" +
            "\r\n" +
            "inner body\r\n";

        Section(Message, "1").ShouldBe("Subject: inner\r\n\r\ninner body\r\n");
        Section(Message, "1.HEADER").ShouldBe("Subject: inner\r\n\r\n");
        Section(Message, "1.TEXT").ShouldBe("inner body\r\n");
        Section(Message, "1.1").ShouldBe("inner body\r\n");
    }

    // -------------------------------------------------------------------------------------------
    // Boundaries.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 2046 §5.1.1: "the initial CRLF is considered to be attached to the boundary delimiter
    /// line rather than part of the preceding part." A server that kept it would report every
    /// part two octets longer than it is.
    /// </summary>
    [Fact]
    public void The_line_ending_before_a_boundary_belongs_to_the_boundary()
    {
        const string Message =
            "Content-Type: multipart/mixed; boundary=\"x\"\r\n" +
            "\r\n" +
            "--x\r\n" +
            "\r\n" +
            "abc\r\n" +
            "--x--\r\n";

        Section(Message, "1").ShouldBe("abc");
        Structure(Message, extended: false).ShouldContain("\"7BIT\" 3 1)");
    }

    /// <summary>
    /// §5.1.1: the preamble is "to be ignored", and so is the epilogue. Neither is a part, and
    /// neither belongs to one.
    /// </summary>
    [Fact]
    public void A_preamble_and_an_epilogue_are_not_parts()
    {
        Section(Complex, "1").ShouldNotContain("preamble");
        Section(Complex, "4").ShouldNotContain("epilogue");
    }

    /// <summary>
    /// §5.1.1 permits "transport padding" — white space — after a delimiter, and the closing
    /// delimiter is the same line with a trailing "--".
    /// </summary>
    [Fact]
    public void Trailing_white_space_on_a_delimiter_is_ignored()
    {
        const string Message =
            "Content-Type: multipart/mixed; boundary=\"x\"\r\n" +
            "\r\n" +
            "--x  \t\r\n" +
            "\r\n" +
            "abc\r\n" +
            "--x--  \r\n";

        Section(Message, "1").ShouldBe("abc");
    }

    /// <summary>
    /// A boundary that merely begins with another one belongs to a different multipart. Matching
    /// on a prefix would cut a nested message in half at its parent's first delimiter.
    /// </summary>
    [Fact]
    public void A_boundary_that_is_a_prefix_of_another_is_not_it()
    {
        const string Message =
            "Content-Type: multipart/mixed; boundary=\"x\"\r\n" +
            "\r\n" +
            "--x\r\n" +
            "Content-Type: multipart/mixed; boundary=\"xy\"\r\n" +
            "\r\n" +
            "--xy\r\n" +
            "\r\n" +
            "nested\r\n" +
            "--xy--\r\n" +
            "--x\r\n" +
            "\r\n" +
            "sibling\r\n" +
            "--x--\r\n";

        Section(Message, "1.1").ShouldBe("nested");
        Section(Message, "2").ShouldBe("sibling");
    }

    /// <summary>
    /// A multipart whose closing delimiter never arrives still yields its parts. A client that
    /// cut the message up itself would see the same thing, and refusing to describe a truncated
    /// message would hide it rather than the truncation.
    /// </summary>
    [Fact]
    public void A_multipart_with_no_closing_delimiter_still_yields_its_parts()
    {
        const string Message =
            "Content-Type: multipart/mixed; boundary=\"x\"\r\n" +
            "\r\n" +
            "--x\r\n" +
            "\r\n" +
            "first\r\n" +
            "--x\r\n" +
            "\r\n" +
            "second\r\n";

        Section(Message, "1").ShouldBe("first");
        Section(Message, "2").ShouldBe("second\r\n");
    }

    /// <summary>
    /// A multipart with no boundary parameter has no discoverable parts, and §9's
    /// <c>body-type-mpart = 1*body SP media-subtype</c> has no form for a multipart with none.
    /// It is described as what it is: an opaque part of its declared type, which
    /// <c>media-basic</c>'s closing <c>/ string</c> alternative makes grammatical.
    /// </summary>
    [Fact]
    public void A_multipart_with_no_boundary_is_described_as_an_opaque_part()
    {
        const string Message =
            "Content-Type: multipart/mixed\r\n" +
            "\r\n" +
            "whatever this is\r\n";

        Structure(Message, extended: false)
            .ShouldBe("(\"MULTIPART\" \"MIXED\" NIL NIL NIL \"7BIT\" 18)");
    }

    // -------------------------------------------------------------------------------------------
    // Defaults.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 2045 §5.2: "Default RFC 822 messages without a MIME Content-Type header are taken by
    /// this protocol to be plain text in the US-ASCII character set".
    /// </summary>
    [Fact]
    public void A_message_with_no_content_type_is_plain_us_ascii_text() =>
        Structure("Subject: bare\r\n\r\nhello\r\n", extended: false)
            .ShouldBe("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 7 1)");

    /// <summary>RFC 2045 §6.1: 7bit is assumed when no encoding is declared.</summary>
    [Fact]
    public void A_part_with_no_encoding_is_seven_bit() =>
        Structure("\r\nhello\r\n", extended: false).ShouldContain("\"7BIT\"");

    /// <summary>
    /// RFC 2046 §5.1.5: "In a digest, the default Content-Type value for a body part is changed
    /// from 'text/plain' to 'message/rfc822'." A digest whose parts declare nothing would
    /// otherwise be described as text, and its enclosed messages would have no envelope.
    /// </summary>
    [Fact]
    public void A_part_of_a_digest_defaults_to_an_enclosed_message()
    {
        const string Message =
            "Content-Type: multipart/digest; boundary=\"x\"\r\n" +
            "\r\n" +
            "--x\r\n" +
            "\r\n" +
            "Subject: enclosed\r\n" +
            "From: a@b.test\r\n" +
            "\r\n" +
            "body\r\n" +
            "--x--\r\n";

        string structure = Structure(Message, extended: false);

        structure.ShouldContain("(\"MESSAGE\" \"RFC822\"");
        structure.ShouldContain("\"enclosed\"");
        structure.ShouldContain("\"DIGEST\")");
    }

    /// <summary>
    /// §7.4.2: "A body type of type MESSAGE and subtype RFC822 contains, immediately after the
    /// basic fields, the envelope structure, body structure, and size in text lines of the
    /// encapsulated message."
    /// </summary>
    [Fact]
    public void A_message_part_carries_an_envelope_a_structure_and_a_line_count()
    {
        const string Message =
            "Content-Type: message/rfc822\r\n" +
            "\r\n" +
            "Subject: enclosed\r\n" +
            "From: Ann <ann@example.test>\r\n" +
            "\r\n" +
            "one\r\ntwo\r\n";

        Structure(Message, extended: false).ShouldBe(
            "(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 61 " +
            "(NIL \"enclosed\" ((\"Ann\" NIL \"ann\" \"example.test\")) " +
            "((\"Ann\" NIL \"ann\" \"example.test\")) " +
            "((\"Ann\" NIL \"ann\" \"example.test\")) NIL NIL NIL NIL NIL) " +
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 10 2) 5)");
    }

    // -------------------------------------------------------------------------------------------
    // Parameters and extension data.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 2045 §5.1: <c>value := token / quoted-string</c>, so a parameter value may be quoted —
    /// and a quoted one may contain the semicolon that otherwise separates parameters. A split
    /// that did not respect quoting would cut a filename in half.
    /// </summary>
    [Fact]
    public void A_quoted_parameter_value_may_contain_a_semicolon() =>
        Structure(
            "Content-Type: application/pdf; name=\"report; final.pdf\"\r\n\r\nx\r\n",
            extended: false)
            .ShouldBe("(\"APPLICATION\" \"PDF\" (\"NAME\" \"report; final.pdf\") NIL NIL \"7BIT\" 3)");

    /// <summary>
    /// RFC 2045 §5.1 makes parameter names case-insensitive, so they are normalised — and says
    /// nothing of the kind about values, which carry filenames and are kept exactly as written.
    /// </summary>
    [Fact]
    public void Parameter_names_are_normalised_and_values_are_not() =>
        Structure("Content-Type: text/plain; ChArSeT=UtF-8; name=MyFile.TXT\r\n\r\nx\r\n")
            .ShouldContain("(\"CHARSET\" \"UtF-8\" \"NAME\" \"MyFile.TXT\")");

    /// <summary>
    /// §7.4.2: extension data "is never returned with the BODY fetch, but can be returned with a
    /// BODYSTRUCTURE fetch", and §9 annotates both <c>body-ext-1part</c> and
    /// <c>body-ext-mpart</c> "MUST NOT be returned on non-extensible 'BODY' fetch".
    /// </summary>
    [Fact]
    public void Extension_data_is_sent_for_bodystructure_and_never_for_body()
    {
        const string Message =
            "Content-Type: text/plain; charset=us-ascii\r\n" +
            "Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\r\n" +
            "Content-Disposition: attachment; filename=\"notes.txt\"\r\n" +
            "Content-Language: en-GB\r\n" +
            "Content-Location: http://example.test/notes.txt\r\n" +
            "\r\n" +
            "hello\r\n";

        Structure(Message, extended: false).ShouldBe(
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 7 1)");

        Structure(Message).ShouldBe(
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 7 1 " +
            "\"Q2hlY2sgSW50ZWdyaXR5IQ==\" " +
            "(\"ATTACHMENT\" (\"FILENAME\" \"notes.txt\")) " +
            "\"en-GB\" \"http://example.test/notes.txt\")");
    }

    /// <summary>
    /// §9: <c>body-ext-mpart = body-fld-param [SP body-fld-dsp [SP body-fld-lang [SP
    /// body-fld-loc …]]]</c>. A multipart's parameters are extension data, which is why they
    /// appear after its subtype rather than before it as a single part's do.
    /// </summary>
    [Fact]
    public void A_multiparts_parameters_come_after_its_subtype()
    {
        const string Message =
            "Content-Type: multipart/related; boundary=\"x\"; type=\"text/html\"\r\n" +
            "\r\n" +
            "--x\r\n" +
            "\r\n" +
            "hi\r\n" +
            "--x--\r\n";

        Structure(Message).ShouldBe(
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 2 1 NIL NIL NIL NIL) " +
            "\"RELATED\" (\"BOUNDARY\" \"x\" \"TYPE\" \"text/html\") NIL NIL NIL)");
    }

    /// <summary>
    /// §9: <c>body-fld-lang = nstring / "(" string *(SP string) ")"</c> — one tag is a bare
    /// string and several are a list. RFC 3282 §2 makes <c>Content-Language</c> a
    /// comma-separated list.
    /// </summary>
    [Fact]
    public void Several_languages_become_a_list() =>
        Structure("Content-Language: en-GB, fr, de\r\n\r\nx\r\n")
            .ShouldContain("(\"en-GB\" \"fr\" \"de\")");

    /// <summary>
    /// §9: <c>body-fld-param = "(" string SP string *(SP string SP string) ")" / nil</c> has no
    /// empty-list form, so a part with no parameters reports NIL rather than <c>()</c>.
    /// </summary>
    [Fact]
    public void A_part_with_no_parameters_reports_nil_rather_than_an_empty_list()
    {
        string structure = Structure("Content-Type: application/octet-stream\r\n\r\nx\r\n");

        structure.ShouldBe("(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"7BIT\" 3 NIL NIL NIL NIL)");
        structure.Contains("()", StringComparison.Ordinal)
            .ShouldBeFalse("the grammar has no empty parameter list");
    }

    // -------------------------------------------------------------------------------------------
    // Bounds.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Nesting is taken apart only as deep as a client may address, which
    /// <see cref="ImapSection.MaxPartDepth"/> already bounds. A message nested deeper is a
    /// decompression bomb rather than mail, and the part at the limit is still described — as
    /// itself, opaquely — rather than dropped.
    /// </summary>
    [Fact]
    public void Nesting_is_taken_apart_only_as_deep_as_a_client_may_address()
    {
        StringBuilder message = new();

        for (int depth = 0; depth < ImapMimeTree.MaxDepth + 4; depth++)
        {
            message
                .Append(CultureInfoFreeFormat(depth))
                .Append("\r\n\r\n--b")
                .Append(depth)
                .Append("\r\n");
        }

        message.Append("Content-Type: text/plain\r\n\r\ndeep\r\n");

        ImapBodyPart root = ImapMimeTree.Parse(Octets(message.ToString()));

        int levels = 0;

        for (ImapBodyPart? node = root; node is not null; node = node.Children.FirstOrDefault())
        {
            levels++;
        }

        levels.ShouldBeLessThanOrEqualTo(ImapMimeTree.MaxDepth + 1);
    }

    private static string CultureInfoFreeFormat(int depth) =>
        $"Content-Type: multipart/mixed; boundary=\"b{depth}\"";

    /// <summary>
    /// RFC 2046 §5.1.1: "(If a boundary delimiter line appears to end with white space, the white
    /// space must be presumed to have been added by a gateway, and must be deleted.)" The
    /// unquoted spelling of the same parameter is already trimmed by the parameter reader, so
    /// without this the two spellings of one header disagree — and the quoted one loses every
    /// part of the multipart.
    /// </summary>
    [Theory]
    [InlineData("boundary=\"x \"")]
    [InlineData("boundary=\"x\t\"")]
    [InlineData("boundary=x ")]
    public void A_boundary_ending_in_white_space_is_trimmed(string parameter)
    {
        string message =
            $"Content-Type: multipart/mixed; {parameter}\r\n" +
            "\r\n" +
            "--x\r\n" +
            "Content-Type: text/plain\r\n" +
            "\r\n" +
            "the body\r\n" +
            "--x--\r\n";

        Section(message, "1").ShouldBe("the body");
    }

    /// <summary>
    /// A closing delimiter carrying trailing text still closes the multipart. RFC 2046 §5.1.1's
    /// note to implementors — "An exact match of the entire candidate line is not required; it is
    /// sufficient that the boundary appear in its entirety following the CRLF" — and, more to the
    /// point, the same section's "implementations must ignore anything that appears […] after the
    /// last one". A server that missed the close runs the final part to the end of the content
    /// and hands the client the epilogue as message data, with an octet count to match.
    /// </summary>
    [Fact]
    public void A_closing_delimiter_with_trailing_text_still_closes()
    {
        const string Message =
            "Content-Type: multipart/mixed; boundary=\"x\"\r\n" +
            "\r\n" +
            "--x\r\n" +
            "Content-Type: text/plain\r\n" +
            "\r\n" +
            "the body\r\n" +
            "--x--junk\r\n" +
            "\r\n" +
            "This is the epilogue. It is also to be ignored.\r\n";

        Section(Message, "1").ShouldBe("the body");
        Section(Message, "1").ShouldNotContain("epilogue");
    }

    /// <summary>
    /// RFC 2045 §1: every MIME header field except <c>Content-Disposition</c> "can include RFC
    /// 822 comments, which have no semantic content and should be ignored during MIME
    /// processing". The content type is already read that way; the encoding was not, so a client
    /// matching the token against "BASE64" would refuse to decode and show the user raw base64.
    /// </summary>
    [Fact]
    public void An_encoding_carrying_a_comment_reports_only_the_token() =>
        Structure(
            "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64 (encoded)\r\n\r\naGk=\r\n",
            extended: false)
            .ShouldBe("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"BASE64\" 6 1)");

    /// <summary>
    /// RFC 2045 §6.1: "This is the default value -- that is, "Content-Transfer-Encoding: 7BIT" is
    /// assumed if the Content-Transfer-Encoding header field is not present." A field that is
    /// present but empty declares nothing, so the default applies to it too — and §9's
    /// <c>body-fld-enc</c> has no empty form to report instead.
    /// </summary>
    [Fact]
    public void An_empty_encoding_field_falls_back_to_the_default() =>
        Structure(
            "Content-Type: text/plain\r\nContent-Transfer-Encoding:\r\n\r\nhi\r\n",
            extended: false)
            .ShouldBe("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 4 1)");

    /// <summary>
    /// §9's <c>body-type-basic</c> is annotated "MESSAGE subtype MUST NOT be "RFC822"", and
    /// <c>body-type-msg</c> requires an envelope, a nested body and a line count after the basic
    /// fields. A part that stopped at the nesting limit had neither form: it kept the type and
    /// dropped the three fields, producing a node that matches no alternative of §9's
    /// <c>body</c>. A client parsing positionally would read the next token as this part's and
    /// mis-read the rest of the structure.
    /// </summary>
    [Fact]
    public void A_message_part_at_the_nesting_limit_is_still_grammatical()
    {
        StringBuilder message = new();

        for (int depth = 0; depth < ImapMimeTree.MaxDepth + 2; depth++)
        {
            message.Append("Content-Type: message/rfc822\r\n\r\n");
        }

        message.Append("Content-Type: text/plain\r\n\r\nx\r\n");

        string structure = Structure(message.ToString(), extended: false);

        // The message really does nest past the limit, so the loop below is not vacuous: one
        // node per level from 0 to MaxDepth inclusive, and Split returns one more piece than
        // there are occurrences. The level past the limit is the one Terminal re-types, which is
        // why it does not appear.
        structure.Split("\"MESSAGE\" \"RFC822\"").Length
            .ShouldBe(ImapMimeTree.MaxDepth + 2);

        // Every MESSAGE/RFC822 node must be followed by its envelope, which begins with "(".
        int at = 0;

        while ((at = structure.IndexOf("\"MESSAGE\" \"RFC822\"", at, StringComparison.Ordinal)) >= 0)
        {
            string rest = structure[at..];

            rest.ShouldContain("\"7BIT\" ");

            int fields = rest.IndexOf("\"7BIT\" ", StringComparison.Ordinal) + 7;
            string afterOctets = rest[fields..];
            int space = afterOctets.IndexOf(' ', StringComparison.Ordinal);

            // §9's body-type-msg puts an envelope after the octet count, and an envelope
            // begins with "(".
            space.ShouldBeGreaterThan(0);
            afterOctets[(space + 1)..].ShouldStartWith("(");

            at += 1;
        }
    }

    /// <summary>
    /// Breadth is bounded as depth is. Every delimiter line becomes a part, so a message that is
    /// nothing but delimiter lines expands into a tree many times its own size and renders into a
    /// response many times larger again — and the FETCH handler holds the whole response set in
    /// memory before writing a byte of it. A message that is small enough to accept must not be
    /// able to cost the server hundreds of times its size to describe.
    /// </summary>
    [Fact]
    public void A_multipart_with_absurdly_many_parts_is_bounded()
    {
        StringBuilder message = new("Content-Type: multipart/mixed; boundary=\"A\"\r\n\r\n");

        for (int part = 0; part < ImapMimeTree.MaxPartCount * 3; part++)
        {
            message.Append("--A\r\n");
        }

        message.Append("--A--\r\n");

        ImapBodyPart root = ImapMimeTree.Parse(Octets(message.ToString()));

        Count(root).ShouldBeLessThanOrEqualTo(ImapMimeTree.MaxPartCount + 1);
    }

    /// <summary>The same bound holds when the breadth is spread across nesting levels.</summary>
    [Fact]
    public void A_deeply_and_broadly_nested_message_is_bounded()
    {
        StringBuilder message = new("Content-Type: multipart/mixed; boundary=\"A\"\r\n\r\n");

        for (int part = 0; part < 400; part++)
        {
            message.Append("--A\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n");

            for (int child = 0; child < 400; child++)
            {
                message.Append("--B\r\n");
            }

            message.Append("--B--\r\n");
        }

        message.Append("--A--\r\n");

        Count(ImapMimeTree.Parse(Octets(message.ToString())))
            .ShouldBeLessThanOrEqualTo(ImapMimeTree.MaxPartCount + 1);
    }

    /// <summary>Every node of a tree, including the ones an encapsulated message carries.</summary>
    private static int Count(ImapBodyPart part)
    {
        int total = 1;

        foreach (ImapBodyPart child in part.Children)
        {
            total += Count(child);
        }

        if (part.Message is { } message)
        {
            total += Count(message);
        }

        return total;
    }

    /// <summary>
    /// The count a part reports and the octets it hands over are the same number. They come from
    /// one slice, and a client reading a literal of one size into a buffer sized by the other is
    /// how a connection desynchronises.
    /// </summary>
    [Theory]
    [InlineData("1")]
    [InlineData("2")]
    [InlineData("3.1")]
    [InlineData("4.1")]
    [InlineData("4.2.2.2")]
    public void A_parts_reported_size_is_the_size_of_what_it_hands_over(string specifier)
    {
        ReadOnlyMemory<byte> octets = Octets(Complex);
        ImapBodyPart root = ImapMimeTree.Parse(octets);

        long[] numbers = [.. specifier.Split('.').Select(long.Parse)];

        ImapBodyPart part = ImapMimeTree.Find(root, numbers).ShouldNotBeNull();

        part.Content.Length.ShouldBe(Section(Complex, specifier).Length);
    }
}
