using System.Text;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapEnvelopeTests
{
    /// <summary>Renders an envelope the way the wire would see it.</summary>
    /// <remarks>
    /// Literal octets come back through Latin-1 so that a byte and the character it is written
    /// as stay the same thing; a UTF-8 decode here would hide exactly the corruption these tests
    /// exist to catch.
    /// </remarks>
    private static string Wire(ImapEnvelope envelope)
    {
        ImapSegmentBuilder builder = new();

        ImapEnvelopes.Format(envelope, builder);

        StringBuilder text = new();

        foreach (ImapResponseSegment segment in builder.Build())
        {
            text.Append(segment.Text ?? Encoding.Latin1.GetString(segment.Octets.Span));
        }

        return text.ToString();
    }

    private static ImapEnvelope Read(string header) =>
        ImapEnvelopes.Read(Encoding.Latin1.GetBytes(header));

    private static string WireOf(string header) => Wire(Read(header));

    // ---------------------------------------------------------------------------------------
    // The worked example both revisions of the protocol publish.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3501 §6.4.5's own example, header and answer. The document shows the message's header
    /// in its reply to <c>a004 fetch 12 body[header]</c> and the envelope the same server
    /// computed from it in its reply to <c>a003 fetch 12 full</c>, so this is the specification
    /// checking the implementation rather than the implementation checking itself.
    /// </summary>
    [Fact]
    public void The_specifications_own_example_header_produces_its_own_example_envelope()
    {
        const string Header =
            "Date: Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\r\n" +
            "From: Terry Gray <gray@cac.washington.edu>\r\n" +
            "Subject: IMAP4rev1 WG mtg summary and minutes\r\n" +
            "To: imap@cac.washington.edu\r\n" +
            "cc: minutes@CNRI.Reston.VA.US, John Klensin <KLENSIN@MIT.EDU>\r\n" +
            "Message-Id: <B27397-0100000@cac.washington.edu>\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n" +
            "\r\n" +
            "body\r\n";

        WireOf(Header).ShouldBe(
            "(\"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\" " +
            "\"IMAP4rev1 WG mtg summary and minutes\" " +
            "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " +
            "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " +
            "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " +
            "((NIL NIL \"imap\" \"cac.washington.edu\")) " +
            "((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\")" +
            "(\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\")) " +
            "NIL NIL \"<B27397-0100000@cac.washington.edu>\")");
    }

    /// <summary>
    /// RFC 2822 §A.5's "aesthetically displeasing, but perfectly legal" message, which is the
    /// appendix's deliberate collection of every oddity at once: a quoted-pair inside a comment,
    /// comments in the middle of an addr-spec, a group whose name is followed by a comment, a
    /// nested comment, and folding in the middle of the date.
    /// </summary>
    [Fact]
    public void The_message_format_specifications_torture_example_parses()
    {
        const string Header =
            "From: Pete(A wonderful \\) chap) <pete(his account)@silly.test(his host)>\r\n" +
            "To:A Group(Some people)\r\n" +
            "     :Chris Jones <c@(Chris's host.)public.example>,\r\n" +
            "         joe@example.org,\r\n" +
            "  John <jdoe@one.test> (my dear friend); (the end of the group)\r\n" +
            "Cc:(Empty list)(start)Undisclosed recipients  :(nobody(that I know))  ;\r\n" +
            "Message-ID:              <testabcd.1234@silly.test>\r\n" +
            "\r\n" +
            "Testing.\r\n";

        ImapEnvelope envelope = Read(Header);

        envelope.From.ShouldBe([new ImapAddress("Pete", null, "pete", "silly.test")]);

        envelope.To.ShouldBe(
        [
            ImapAddress.GroupStart("A Group"),
            new ImapAddress("Chris Jones", null, "c", "public.example"),
            new ImapAddress(null, null, "joe", "example.org"),
            new ImapAddress("John", null, "jdoe", "one.test"),
            ImapAddress.GroupEnd,
        ]);

        envelope.Cc.ShouldBe(
        [
            ImapAddress.GroupStart("Undisclosed recipients"),
            ImapAddress.GroupEnd,
        ]);

        envelope.MessageId.ShouldBe("<testabcd.1234@silly.test>");
    }

    // ---------------------------------------------------------------------------------------
    // Absent, empty, and defaulted members.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// §7.4.2: "If the Date, Subject, In-Reply-To, and Message-ID header lines are absent in the
    /// [RFC-2822] header, the corresponding member of the envelope is NIL".
    /// </summary>
    [Fact]
    public void An_absent_string_member_is_nil()
    {
        ImapEnvelope envelope = Read("From: a@b.test\r\n\r\n");

        envelope.Date.ShouldBeNull();
        envelope.Subject.ShouldBeNull();
        envelope.InReplyTo.ShouldBeNull();
        envelope.MessageId.ShouldBeNull();
    }

    /// <summary>
    /// §7.4.2: "if these header lines are present but empty the corresponding member of the
    /// envelope is the empty string". Distinct from NIL, and clients that show a subject column
    /// act on the difference.
    /// </summary>
    [Fact]
    public void A_present_but_empty_string_member_is_the_empty_string()
    {
        ImapEnvelope envelope = Read("Subject:\r\nDate:   \r\n\r\n");

        envelope.Subject.ShouldBe(string.Empty);
        envelope.Date.ShouldBe(string.Empty);
    }

    /// <summary>
    /// §7.4.2: "If the From, To, cc, and bcc header lines are absent in the [RFC-2822] header,
    /// or are present but empty, the corresponding member of the envelope is NIL." Both cases,
    /// because §9's <c>env-to</c> is <c>"(" 1*address ")" / nil</c> and has no empty list.
    /// </summary>
    [Theory]
    [InlineData("Subject: x\r\n\r\n")]
    [InlineData("To:\r\n\r\n")]
    [InlineData("To:    \r\n\r\n")]
    public void An_absent_or_empty_address_member_is_nil(string header) =>
        Read(header).To.ShouldBeNull();

    /// <summary>
    /// §7.4.2: "If the Sender or Reply-To lines are absent […] the server sets the corresponding
    /// member of the envelope to be the same value as the from member (the client is not
    /// expected to know to do this)."
    /// </summary>
    [Fact]
    public void Sender_and_reply_to_default_to_from()
    {
        ImapEnvelope envelope = Read("From: Ann <ann@example.test>\r\n\r\n");

        envelope.Sender.ShouldBe(envelope.From);
        envelope.ReplyTo.ShouldBe(envelope.From);
    }

    /// <summary>The defaulting is only for a member that is not there.</summary>
    [Fact]
    public void A_sender_that_is_present_is_not_replaced_by_from()
    {
        ImapEnvelope envelope = Read(
            "From: Ann <ann@example.test>\r\nSender: Bob <bob@example.test>\r\n\r\n");

        envelope.Sender.ShouldBe([new ImapAddress("Bob", null, "bob", "example.test")]);
        envelope.From.ShouldBe([new ImapAddress("Ann", null, "ann", "example.test")]);
    }

    /// <summary>
    /// A message with no From at all: the default has nothing to copy, so all three stay NIL
    /// rather than one of them becoming an empty list, which §9 cannot express.
    /// </summary>
    [Fact]
    public void Without_a_from_the_defaulted_members_are_nil_too()
    {
        ImapEnvelope envelope = Read("Subject: orphan\r\n\r\n");

        envelope.From.ShouldBeNull();
        envelope.Sender.ShouldBeNull();
        envelope.ReplyTo.ShouldBeNull();
    }

    /// <summary>
    /// §9's <c>msg-att-static</c> is <c>"ENVELOPE" SP envelope</c> with no NIL alternative, so a
    /// message whose octets cannot be read is answered with the empty structure.
    /// </summary>
    [Fact]
    public void A_message_that_cannot_be_read_still_has_an_envelope() =>
        Wire(ImapEnvelopes.Missing).ShouldBe("(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)");

    /// <summary>Ten members, always, in §9's order.</summary>
    [Fact]
    public void The_envelope_always_has_ten_members() =>
        Wire(ImapEnvelopes.Missing).Split(' ').Length.ShouldBe(10);

    // ---------------------------------------------------------------------------------------
    // Address structures.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// §7.4.2: the personal name "holds phrase from [RFC-2822] mailbox after removing [RFC-2822]
    /// quoting", so the escaped quotes inside the display name reach the client as quotes and
    /// are re-escaped by IMAP's own quoting rather than passed through raw.
    /// </summary>
    [Fact]
    public void A_quoted_display_name_loses_its_message_quoting_and_gains_imap_quoting()
    {
        ImapEnvelope envelope = Read("From: \"John \\\"Q\\\" Public\" <jqp@x.test>\r\n\r\n");

        envelope.From.ShouldBe([new ImapAddress("John \"Q\" Public", null, "jqp", "x.test")]);

        Wire(envelope).ShouldContain("(\"John \\\"Q\\\" Public\" NIL \"jqp\" \"x.test\")");
    }

    /// <summary>
    /// §7.4.2's <c>addr-mailbox</c> "holds [RFC-2822] local-part after removing [RFC-2822]
    /// quoting". RFC 2822 §3.4.1 allows a quoted local part, and the at-sign it may contain must
    /// not be mistaken for the one that separates the local part from the domain.
    /// </summary>
    [Fact]
    public void A_quoted_local_part_is_unquoted_and_its_at_sign_is_not_the_separator() =>
        Read("From: \"odd@name\"@strange.test\r\n\r\n").From
            .ShouldBe([new ImapAddress(null, null, "odd@name", "strange.test")]);

    /// <summary>
    /// §9's <c>addr-adl</c> "holds route from [RFC-2822] route-addr if non-NIL". RFC 2822 §4.4's
    /// <c>obs-route</c> puts it before the addr-spec inside the angle brackets, terminated by a
    /// colon that is not part of the route.
    /// </summary>
    [Fact]
    public void A_source_route_becomes_the_at_domain_list() =>
        Read("From: <@a.test,@b.test:c@d.test>\r\n\r\n").From
            .ShouldBe([new ImapAddress(null, "@a.test,@b.test", "c", "d.test")]);

    /// <summary>
    /// §7.4.2 reserves a NIL host for group syntax — "[RFC-2822] group syntax is indicated by a
    /// special form of address structure in which the host name field is NIL" — so an address
    /// this server could not split gets an empty host instead. Answering NIL would open a group
    /// the client never sees closed, and every address after it would be read as a member.
    /// </summary>
    [Fact]
    public void An_address_with_no_domain_does_not_masquerade_as_a_group()
    {
        ImapEnvelope envelope = Read("From: Mailer Daemon\r\nTo: a@b.test\r\n\r\n");

        envelope.From.ShouldBe([new ImapAddress(null, null, "Mailer Daemon", string.Empty)]);
        envelope.From![0].IsGroupStart.ShouldBeFalse();

        Wire(envelope).ShouldContain("((NIL NIL \"Mailer Daemon\" \"\"))");
    }

    /// <summary>
    /// §7.4.2: "If the mailbox name field is also NIL, this is an end of group marker
    /// (semi-colon in RFC 822 syntax)."
    /// </summary>
    [Fact]
    public void An_empty_group_is_a_start_marker_and_an_end_marker()
    {
        ImapEnvelope envelope = Read("To: undisclosed-recipients:;\r\n\r\n");

        envelope.To.ShouldBe(
        [
            ImapAddress.GroupStart("undisclosed-recipients"),
            ImapAddress.GroupEnd,
        ]);

        Wire(envelope).ShouldContain(
            "((NIL NIL \"undisclosed-recipients\" NIL)(NIL NIL NIL NIL))");
    }

    /// <summary>
    /// RFC 2822 §3.4's <c>group</c> takes a <c>mailbox-list</c>, so a group cannot contain
    /// another group. A colon inside one is read as text rather than opening a second, which is
    /// also what keeps a crafted header from driving the parser as deep as the field is long.
    /// </summary>
    [Fact]
    public void A_colon_inside_a_group_does_not_open_another_group()
    {
        IReadOnlyList<ImapAddress> parsed = ImapAddressList.Parse("A: b:c@d.test;");

        parsed.Count(a => a.IsGroupStart).ShouldBe(1);
        parsed.Count(a => a.IsGroupEnd).ShouldBe(1);
    }

    /// <summary>Several addresses in one field keep the order they were written in.</summary>
    [Fact]
    public void An_address_list_keeps_its_order() =>
        Read("To: a@one.test, B <b@two.test>, c@three.test\r\n\r\n").To
            .ShouldBe(
            [
                new ImapAddress(null, null, "a", "one.test"),
                new ImapAddress("B", null, "b", "two.test"),
                new ImapAddress(null, null, "c", "three.test"),
            ]);

    /// <summary>
    /// §9's <c>env-to = "(" 1*address ")"</c> is a bare repetition, so nothing separates one
    /// address structure from the next. A client reading positionally would otherwise find a
    /// stray token between them.
    /// </summary>
    [Fact]
    public void Address_structures_are_not_separated_by_a_space() =>
        WireOf("To: a@one.test, b@two.test\r\n\r\n")
            .ShouldContain("((NIL NIL \"a\" \"one.test\")(NIL NIL \"b\" \"two.test\"))");

    /// <summary>An empty element in a list is skipped rather than becoming a blank address.</summary>
    [Fact]
    public void Repeated_commas_do_not_produce_empty_addresses() =>
        ImapAddressList.Parse("a@one.test,,, b@two.test")
            .ShouldBe(
            [
                new ImapAddress(null, null, "a", "one.test"),
                new ImapAddress(null, null, "b", "two.test"),
            ]);

    /// <summary>
    /// RFC 2047 §6.2 puts encoded-word decoding in the client, and the envelope has no field in
    /// which a server could name the charset it decoded into. So the display name goes out as
    /// written.
    /// </summary>
    [Fact]
    public void An_encoded_word_display_name_is_passed_through_unchanged() =>
        Read("From: =?utf-8?B?w4RwZmVs?= <a@b.test>\r\n\r\n").From
            .ShouldBe([new ImapAddress("=?utf-8?B?w4RwZmVs?=", null, "a", "b.test")]);

    /// <summary>An unterminated angle bracket still yields the address inside it.</summary>
    [Fact]
    public void An_unterminated_angle_address_is_still_read() =>
        ImapAddressList.Parse("Ann <ann@example.test")
            .ShouldBe([new ImapAddress("Ann", null, "ann", "example.test")]);

    /// <summary>An unterminated quoted string does not run the parser off the end.</summary>
    [Fact]
    public void An_unterminated_quoted_display_name_is_still_read() =>
        ImapAddressList.Parse("\"Ann <ann@example.test>")
            .ShouldBe([new ImapAddress(null, null, "Ann <ann@example.test>", string.Empty)]);

    // ---------------------------------------------------------------------------------------
    // Octets that a quoted string cannot hold.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// §9's <c>QUOTED-CHAR</c> is US-ASCII, so a subject carrying a raw 8-bit octet — which
    /// RFC 2822 §2.2 forbids and which arrives anyway — has no quoted form and goes out as a
    /// literal. The count is octets: the two-byte character below is <c>{5}</c>, not <c>{4}</c>.
    /// </summary>
    [Fact]
    public void An_eight_bit_subject_goes_out_as_a_literal()
    {
        // "caf" then the Latin-1 octet 0xE9, which is what an unencoded French subject arrives
        // as from a client that ignored RFC 2047.
        string wire = WireOf("Subject: café\r\n\r\n");

        wire.ShouldContain("{4}\r\ncafé ");
        wire.Contains("\"café\"", StringComparison.Ordinal)
            .ShouldBeFalse("an 8-bit value has no quoted form");
    }

    /// <summary>
    /// The literal interrupts the envelope rather than ending it: everything after the octets is
    /// still part of the same structure, and the segments carry it.
    /// </summary>
    [Fact]
    public void A_literal_in_the_middle_of_an_envelope_is_followed_by_the_rest_of_it()
    {
        ImapEnvelope envelope = Read(
            "Date: Mon, 2 Mar 2026 09:00:00 +0000\r\n" +
            "Subject: ¡hola!\r\n" +
            "From: a@b.test\r\n\r\n");

        ImapSegmentBuilder builder = new();

        ImapEnvelopes.Format(envelope, builder);

        IReadOnlyList<ImapResponseSegment> segments = builder.Build();

        segments.Count.ShouldBe(3);
        segments[0].Text.ShouldBe("(\"Mon, 2 Mar 2026 09:00:00 +0000\" {6}\r\n");
        Encoding.Latin1.GetString(segments[1].Octets.Span).ShouldBe("¡hola!");
        segments[2].Text.ShouldStartWith(" ((NIL NIL \"a\" \"b.test\"))");
        segments[2].Text.ShouldEndWith(")");
    }

    /// <summary>
    /// A subject that folds keeps the whitespace the fold introduced. RFC 2822 §2.2.3:
    /// "Unfolding is accomplished by simply removing any CRLF that is immediately followed by
    /// WSP" — the WSP itself stays.
    /// </summary>
    [Fact]
    public void A_folded_subject_is_unfolded_without_losing_its_whitespace() =>
        Read("Subject: a very long\r\n  subject line\r\n\r\n").Subject
            .ShouldBe("a very long  subject line");

    /// <summary>
    /// A tab is a <c>CHAR</c> and so a legal <c>QUOTED-CHAR</c>; forcing a literal for one would
    /// put a byte count in the middle of most subjects that were folded with a tab.
    /// </summary>
    [Fact]
    public void A_tab_does_not_force_a_literal() =>
        WireOf("Subject: one\r\n\ttwo\r\n\r\n").ShouldStartWith("(NIL \"one\ttwo\" ");

    /// <summary>
    /// After a Latin-1 decode, octet 0xA0 is a byte of somebody's subject line rather than
    /// whitespace — so it must survive the trim that removes the space after the colon.
    /// </summary>
    [Fact]
    public void A_no_break_space_is_not_trimmed_away_as_whitespace() =>
        Read("Subject:  \r\n\r\n").Subject.ShouldBe(" ");

    // ---------------------------------------------------------------------------------------
    // Header reading.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 2822 §3.6 allows each of these fields at most once, so a message with two is
    /// malformed and the server has to choose. The first is what a reader sees at the top of the
    /// file and what <c>BODY[HEADER]</c> shows first.
    /// </summary>
    [Fact]
    public void The_first_of_a_repeated_field_wins() =>
        Read("Subject: first\r\nSubject: second\r\n\r\n").Subject.ShouldBe("first");

    /// <summary>The body is not scanned: a line in it that looks like a header is not one.</summary>
    [Fact]
    public void A_header_shaped_line_in_the_body_is_not_a_header() =>
        Read("Subject: real\r\n\r\nSubject: not a header\r\n").Subject.ShouldBe("real");

    /// <summary>
    /// RFC 2822 §2.2 makes the field name the text before the colon, so a line with no colon is
    /// not a field. It is dropped rather than failing the parse: the rest of the header is still
    /// worth reading.
    /// </summary>
    [Fact]
    public void A_line_with_no_colon_is_dropped()
    {
        IReadOnlyList<ImapHeaderField> fields =
            ImapHeaderFields.Read(Encoding.Latin1.GetBytes("nonsense\r\nSubject: real\r\n\r\n"));

        fields.Count.ShouldBe(1);
        fields[0].Name.ShouldBe("Subject");
    }

    /// <summary>
    /// A message stored with bare LF line endings — which RFC 3501 §6.3.11 warns about for
    /// <c>APPEND</c> and which local delivery produces — parses the same way.
    /// </summary>
    [Fact]
    public void Bare_line_feeds_are_read_as_line_endings() =>
        Read("Subject: bare\nFrom: a@b.test\n\nbody\n").Subject.ShouldBe("bare");

    /// <summary>Field names are matched case-insensitively, as the worked example's "cc" shows.</summary>
    [Theory]
    [InlineData("SUBJECT: x\r\n\r\n")]
    [InlineData("subject: x\r\n\r\n")]
    [InlineData("SuBjEcT: x\r\n\r\n")]
    public void Field_names_are_matched_without_regard_to_case(string header) =>
        Read(header).Subject.ShouldBe("x");

    /// <summary>A header with no body and no terminating blank line still parses.</summary>
    [Fact]
    public void A_message_that_is_only_a_header_parses() =>
        Read("Subject: alone\r\n").Subject.ShouldBe("alone");
}
