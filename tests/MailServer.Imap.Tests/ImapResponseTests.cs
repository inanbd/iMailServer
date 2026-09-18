using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Imap.Tests;

public sealed class ImapResponseTests
{
    // ---------------------------------------------------------------------------------------
    // The three line shapes. RFC 3501 section 7.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_tagged_response_echoes_the_tag_and_the_status()
    {
        ImapResponse.Tagged("A001", ImapResponseStatus.Ok, "NOOP completed")
            .Format()
            .ShouldBe("A001 OK NOOP completed\r\n");
    }

    [Theory]
    [InlineData(ImapResponseStatus.Ok, "OK")]
    [InlineData(ImapResponseStatus.No, "NO")]
    [InlineData(ImapResponseStatus.Bad, "BAD")]
    public void Every_tagged_status_has_its_wire_word(ImapResponseStatus status, string word)
    {
        ImapResponse.Tagged("A001", status, "text").Format().ShouldBe($"A001 {word} text\r\n");
    }

    [Fact]
    public void An_untagged_status_response_begins_with_a_star()
    {
        ImapResponse.Untagged(ImapResponseStatus.Bye, "Closing connection")
            .Format()
            .ShouldBe("* BYE Closing connection\r\n");
    }

    [Fact]
    public void An_untagged_data_response_carries_no_status_word()
    {
        ImapResponse.Data("CAPABILITY IMAP4rev1").Format().ShouldBe("* CAPABILITY IMAP4rev1\r\n");
    }

    [Fact]
    public void A_continuation_request_begins_with_a_plus()
    {
        // RFC 3501 section 7.5. The server's one chance to refuse a synchronising literal before
        // any of it is transmitted.
        ImapResponse.Continuation("Ready for literal data")
            .Format()
            .ShouldBe("+ Ready for literal data\r\n");
    }

    [Theory]
    [InlineData(ImapResponseStatus.PreAuth)]
    [InlineData(ImapResponseStatus.Bye)]
    public void The_untagged_only_statuses_cannot_be_tagged(ImapResponseStatus status)
    {
        // RFC 3501 sections 7.1.4 and 7.1.5 define both as untagged. There is no "a1 BYE".
        Should.Throw<ArgumentException>(() => ImapResponse.Tagged("A001", status, "text"));
    }

    [Fact]
    public void Every_response_ends_with_crlf()
    {
        ImapResponse[] responses =
        [
            ImapResponse.Tagged("A001", ImapResponseStatus.Ok, "done"),
            ImapResponse.Untagged(ImapResponseStatus.Bye, "bye"),
            ImapResponse.Data("FLAGS ()"),
            ImapResponse.Continuation("go on"),
        ];

        foreach (ImapResponse response in responses)
        {
            response.Format().ShouldEndWith("\r\n");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Response splitting. Everything in this section is the reason the type exists.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("Mailbox not found: X\r\n* 1 EXPUNGE")]
    [InlineData("Mailbox not found: X\n* 1 EXPUNGE")]
    [InlineData("Mailbox not found: X\r* 0 EXISTS")]
    public void Text_can_never_add_a_line(string hostile)
    {
        // A forged untagged EXPUNGE makes a caching client delete messages from its local store,
        // and untagged responses are unsolicited by design (RFC 3501 section 7) so a client has
        // no grounds to reject one as out of place. This is the silent client-side mail loss
        // docs/IMAP.md opens by naming.
        string formatted = ImapResponse.Tagged("A001", ImapResponseStatus.No, hostile).Format();

        formatted.Count(c => c == '\n').ShouldBe(1);
        formatted.Count(c => c == '\r').ShouldBe(1);
        formatted.ShouldEndWith("\r\n");
        formatted.ShouldNotContain("\r\n* ");
    }

    [Fact]
    public void A_forged_tagged_completion_cannot_be_injected()
    {
        // Worse than forged data: clients match completions to commands by tag, so a forged
        // "A002 OK STORE completed" tells the client a different in-flight command succeeded
        // when it did not.
        string formatted = ImapResponse
            .Tagged("A001", ImapResponseStatus.Bad, "bad\r\nA002 OK STORE completed")
            .Format();

        formatted.ShouldBe("A001 BAD badA002 OK STORE completed\r\n");
        formatted.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length.ShouldBe(1);
    }

    [Theory]
    [InlineData("\u0000")]
    [InlineData("\u0001")]
    [InlineData("\u001f")]
    [InlineData("\u007f")]
    [InlineData("\t")]
    public void Control_characters_are_stripped_from_text(string control)
    {
        // Stripped, not escaped: an escape sequence is still a sequence the receiver has to
        // decode correctly, and a defence that depends on the other end's decoder being right is
        // not a defence.
        ImapResponse.Tagged("A001", ImapResponseStatus.No, $"a{control}b")
            .Format()
            .ShouldBe("A001 NO ab\r\n");
    }

    [Theory]
    [InlineData("caf\u00e9")]
    [InlineData("\u00ff")]
    [InlineData("\u4e2d\u6587")]
    public void Text_is_reduced_to_seven_bit_ascii(string eightBit)
    {
        // Stricter than the SMTP rule, which lets 8-bit through because SMTPUTF8 exists.
        // RFC 3501 section 9 gives no such licence: TEXT-CHAR is CHAR minus CR and LF, and CHAR
        // is %x01-7F, so anything above 0x7F is ungrammatical until RFC 6855 UTF8=ACCEPT is
        // advertised, which this server does not do. The filter stops at 0x7E rather than 0x7F
        // on purpose - DEL is a legal TEXT-CHAR and is dropped anyway, because "what can be
        // displayed" needs no argument about which control characters are harmless in which
        // client.
        string formatted = ImapResponse.Tagged("A001", ImapResponseStatus.No, eightBit).Format();

        foreach (char c in formatted[..^2])
        {
            (c <= (char)0x7E).ShouldBeTrue($"'{c}' is above 0x7E.");
        }
    }

    [Theory]
    [InlineData("\r\n")]
    [InlineData("\u0000\u0001\u0002")]
    [InlineData("\u4e2d\u6587")]
    [InlineData("")]
    public void Text_that_sanitises_away_to_nothing_is_replaced(string hostile)
    {
        // RFC 3501 section 9's text is 1*TEXT-CHAR, so a line ending in a bare space is not a
        // response at all. A mailbox name made entirely of control characters reduces to
        // nothing, so this is reachable from input rather than merely tidy.
        string formatted = ImapResponse.Tagged("A001", ImapResponseStatus.No, hostile).Format();

        formatted.ShouldBe($"A001 NO {ImapResponse.EmptyTextPlaceholder}\r\n");
        formatted.ShouldNotEndWith(" \r\n");
    }

    // ---------------------------------------------------------------------------------------
    // The tag is refused, never repaired.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("A\r\nB")]
    [InlineData("A B")]
    [InlineData("*")]
    [InlineData("+")]
    [InlineData("")]
    [InlineData("A(1")]
    public void A_tag_this_server_would_not_have_accepted_cannot_be_echoed(string tag)
    {
        // Refusing rather than sanitising means the hostile bytes never enter the output stream
        // at all, not even in reduced form. RFC 3501 section 7.1.3's untagged "* BAD" is what an
        // unparseable tag earns instead.
        Should.Throw<ArgumentException>(
            () => ImapResponse.Tagged(tag, ImapResponseStatus.Ok, "completed"));
    }

    [Fact]
    public void A_tag_longer_than_the_parser_accepts_cannot_be_echoed()
    {
        string tag = new('A', ImapCommand.MaxTagLength + 1);

        Should.Throw<ArgumentException>(
            () => ImapResponse.Tagged(tag, ImapResponseStatus.Ok, "completed"));
    }

    [Fact]
    public void The_untagged_refusal_is_what_an_unparseable_tag_earns()
    {
        ImapResponses.UntaggedBad("Invalid tag").Format().ShouldBe("* BAD Invalid tag\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // Response codes. RFC 3501 section 7.1.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_response_code_without_an_argument_is_bracketed_alone()
    {
        ImapResponse.Tagged("A001", ImapResponseStatus.Ok, "SELECT completed", ImapResponseCode.ReadWrite)
            .Format()
            .ShouldBe("A001 OK [READ-WRITE] SELECT completed\r\n");
    }

    [Fact]
    public void A_response_code_with_an_argument_separates_it_with_a_space()
    {
        ImapResponse.Untagged(ImapResponseStatus.Ok, "UIDs valid", ImapResponseCode.UidValidity(3857529045))
            .Format()
            .ShouldBe("* OK [UIDVALIDITY 3857529045] UIDs valid\r\n");
    }

    [Theory]
    [InlineData("ALERT")]
    [InlineData("PARSE")]
    [InlineData("READ-ONLY")]
    [InlineData("READ-WRITE")]
    [InlineData("TRYCREATE")]
    public void The_argumentless_codes_take_no_argument(string name)
    {
        ImapResponseCode code = name switch
        {
            "ALERT" => ImapResponseCode.Alert,
            "PARSE" => ImapResponseCode.Parse,
            "READ-ONLY" => ImapResponseCode.ReadOnly,
            "READ-WRITE" => ImapResponseCode.ReadWrite,
            _ => ImapResponseCode.TryCreate,
        };

        code.Argument.ShouldBeNull();
        ImapResponse.Untagged(ImapResponseStatus.Ok, "x", code).Format().ShouldContain($"[{name}]");
    }

    [Fact]
    public void A_closing_bracket_cannot_escape_a_response_code()
    {
        // RFC 3501 section 9's resp-text-code argument is 1*<any TEXT-CHAR except "]"> precisely
        // because the bracket would close the code early, after which the client reads the
        // remainder as ordinary text - the same class of confusion as a CRLF in the text, one
        // nesting level down.
        ImapResponseCode hostile = new("BADCHARSET", "US-ASCII] OK injected");

        ImapResponse.Tagged("A001", ImapResponseStatus.No, "bad charset", hostile)
            .Format()
            .ShouldBe("A001 NO [BADCHARSET US-ASCII OK injected] bad charset\r\n");
    }

    [Fact]
    public void A_response_code_name_carries_no_space_or_bracket()
    {
        ImapResponseCode hostile = new("BAD] OK x [", null);

        ImapResponse.Untagged(ImapResponseStatus.Ok, "text", hostile)
            .Format()
            .ShouldBe("* OK [BADOKx] text\r\n");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_numeric_response_code_refuses_a_value_below_one(long value)
    {
        // RFC 3501 section 9 types these as nz-number. [UNSEEN 0] is ungrammatical: a mailbox
        // with nothing unseen omits the whole line instead.
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponseCode.Unseen(value));
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponseCode.UidNext(value));
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponseCode.UidValidity(value));
    }

    [Fact]
    public void The_capability_code_carries_the_listing_inline()
    {
        ImapResponseCode.Capability(["IMAP4rev1", "STARTTLS", "LOGINDISABLED"])
            .Argument
            .ShouldBe("IMAP4rev1 STARTTLS LOGINDISABLED");
    }

    // ---------------------------------------------------------------------------------------
    // The numeric data responses put the number first.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Exists_puts_the_count_before_the_keyword()
    {
        // "* EXISTS 172" is not IMAP. This is the single most common defect in a hand-rolled
        // server, which is why the factory exists rather than a comment.
        ImapResponses.Exists(172).Format().ShouldBe("* 172 EXISTS\r\n");
    }

    [Fact]
    public void Recent_puts_the_count_before_the_keyword() =>
        ImapResponses.Recent(0).Format().ShouldBe("* 0 RECENT\r\n");

    [Fact]
    public void Expunge_puts_the_sequence_number_before_the_keyword() =>
        ImapResponses.Expunge(44).Format().ShouldBe("* 44 EXPUNGE\r\n");

    [Fact]
    public void An_empty_mailbox_reports_zero_rather_than_omitting_the_line()
    {
        // RFC 3501 section 9: mailbox-data takes "number SP EXISTS", and number admits zero.
        ImapResponses.Exists(0).Format().ShouldBe("* 0 EXISTS\r\n");
        ImapResponses.Recent(0).Format().ShouldBe("* 0 RECENT\r\n");
    }

    [Fact]
    public void Expunge_refuses_a_sequence_number_of_zero()
    {
        // A different production from EXISTS and RECENT, and the difference is not pedantry.
        // RFC 3501 section 9: message-data = nz-number SP ("EXPUNGE" / ...), while mailbox-data
        // takes a plain number. Sequence numbers are one-based, so "* 0 EXPUNGE" names no
        // message; a client that renumbers its cache from it either rejects the line or acts on
        // the wrong message - and this is the one response where acting on the wrong message
        // means deleting the wrong mail.
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponses.Expunge(0));
    }

    [Fact]
    public void A_numeric_data_response_refuses_a_negative_number()
    {
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponses.Exists(-1));
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponses.Recent(-1));
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponses.Expunge(-1));
    }

    [Fact]
    public void A_numeric_data_response_refuses_a_number_wider_than_the_protocol_carries()
    {
        // RFC 3501 section 9: "number = 1*DIGIT ; Unsigned 32-bit integer (0 <= n <
        // 4,294,967,296)". These are longs here because a UID counter is stored as one, so the
        // ceiling has to be checked rather than assumed - emitting a number no client can parse
        // is the worse of the two failures.
        ImapResponses.Exists(4_294_967_295).Format().ShouldBe("* 4294967295 EXISTS\r\n");

        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponses.Exists(4_294_967_296));
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponses.Expunge(8_589_934_592));
        Should.Throw<ArgumentOutOfRangeException>(() => ImapResponseCode.UidNext(4_294_967_296));
    }

    // ---------------------------------------------------------------------------------------
    // Whitespace is not text.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(" ")]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData(" \r\n ")]
    public void Text_that_is_only_whitespace_is_replaced(string whitespace)
    {
        // SP is a TEXT-CHAR, so " " survives a filter defined as "printable US-ASCII" and would
        // render as "A001 OK  " - two spaces, no text, ending in exactly the bare space this
        // type promises never to emit.
        string formatted = ImapResponse.Tagged("A001", ImapResponseStatus.Ok, whitespace).Format();

        formatted.ShouldBe($"A001 OK {ImapResponse.EmptyTextPlaceholder}\r\n");
    }

    [Fact]
    public void Text_is_trimmed_rather_than_padded()
    {
        ImapResponse.Tagged("A001", ImapResponseStatus.Ok, "  done  ")
            .Format()
            .ShouldBe("A001 OK done\r\n");
    }

    [Fact]
    public void No_response_ever_carries_a_double_space()
    {
        string[] awkward = ["", " ", "  x  ", "\r\n", "\u0000 \u0000"];

        foreach (string text in awkward)
        {
            ImapResponse.Untagged(ImapResponseStatus.Ok, text)
                .Format()
                .ShouldNotContain("  ", Case.Sensitive, $"from [{text}]");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Rendering. Format is the only definition of what is safe to emit.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Rendering_a_response_never_leaks_the_unsanitised_text()
    {
        // The same defect ImapCommand carries, in the opposite direction: a record's generated
        // ToString prints every property, and Text holds whatever the client sent - unsanitised,
        // because sanitisation happens in Format. Interpolating a refusal that quotes a hostile
        // mailbox name would otherwise put that name's CRLF into a log file, by the one route
        // that does not go through Format.
        ImapResponse response =
            ImapResponse.Tagged("A001", ImapResponseStatus.No, "x\r\n* 1 EXPUNGE");

        foreach (string rendered in (string[])[response.ToString(), $"{response}"])
        {
            rendered.ShouldNotContain("\r", Case.Sensitive);
            rendered.ShouldNotContain("\n", Case.Sensitive);
            rendered.ShouldContain("A001 NO");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Flags.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_flags_response_lists_the_system_flags()
    {
        ImapResponses.Flags(ImapFlagNames.Settable)
            .Format()
            .ShouldBe("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n");
    }

    [Fact]
    public void Recent_is_never_listed_as_a_flag()
    {
        // Reserved and never set (see MessageFlags.Recent), and RFC 3501 section 2.3.2 does not
        // permit a client to set it via STORE in any case - so listing it would be wrong twice.
        ImapFlagNames.Ordered.ShouldNotContain(MessageFlags.Recent);
        ImapFlagNames.Format(MessageFlags.Recent).ShouldBeEmpty();
        ImapFlagNames.Settable.HasFlag(MessageFlags.Recent).ShouldBeFalse();
    }

    [Fact]
    public void A_read_only_mailbox_permits_no_flags()
    {
        // An empty PERMANENTFLAGS list is correct and meaningful for EXAMINE: nothing may be
        // changed, so nothing persists.
        ImapResponse.Untagged(
                ImapResponseStatus.Ok,
                "Flags permitted",
                ImapResponseCode.PermanentFlags(MessageFlags.None))
            .Format()
            .ShouldBe("* OK [PERMANENTFLAGS ()] Flags permitted\r\n");
    }

    [Theory]
    [InlineData(MessageFlags.Seen, "\\Seen")]
    [InlineData(MessageFlags.Answered, "\\Answered")]
    [InlineData(MessageFlags.Flagged, "\\Flagged")]
    [InlineData(MessageFlags.Deleted, "\\Deleted")]
    [InlineData(MessageFlags.Draft, "\\Draft")]
    public void Every_system_flag_has_its_wire_name(MessageFlags flag, string name) =>
        ImapFlagNames.NameOf(flag).ShouldBe(name);

    [Fact]
    public void Flags_are_listed_in_a_stable_order()
    {
        // A set is unordered; a response is not. Emitting the same flags in a different order
        // from one SELECT to the next is a needless diff for anyone reading a packet capture.
        ImapFlagNames.Format(MessageFlags.Draft | MessageFlags.Seen)
            .ShouldBe("\\Seen \\Draft");
    }

    [Fact]
    public void A_combination_is_not_a_single_flag_name() =>
        Should.Throw<ArgumentOutOfRangeException>(
            () => ImapFlagNames.NameOf(MessageFlags.Seen | MessageFlags.Draft));

    // ---------------------------------------------------------------------------------------
    // The composed responses.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_greeting_carries_the_capability_listing()
    {
        ImapResponses.Greeting("AetherMail", ["IMAP4rev1", "STARTTLS", "LOGINDISABLED"])
            .Format()
            .ShouldBe("* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] AetherMail IMAP4rev1 ready\r\n");
    }

    [Fact]
    public void Bye_is_untagged()
    {
        ImapResponse response = ImapResponses.Bye("Autologout; idle for too long");

        response.Kind.ShouldBe(ImapResponseKind.Untagged);
        response.Format().ShouldBe("* BYE Autologout; idle for too long\r\n");
    }

    [Fact]
    public void The_capability_response_is_untagged_data()
    {
        ImapResponses.Capability(["IMAP4rev1"]).Format().ShouldBe("* CAPABILITY IMAP4rev1\r\n");
    }

    [Fact]
    public void The_tagged_factories_produce_their_statuses()
    {
        ImapResponses.Ok("A1", "done").Format().ShouldBe("A1 OK done\r\n");
        ImapResponses.No("A1", "refused").Format().ShouldBe("A1 NO refused\r\n");
        ImapResponses.Bad("A1", "malformed").Format().ShouldBe("A1 BAD malformed\r\n");
    }

    [Fact]
    public void Trycreate_rides_on_the_refusal_that_can_be_recovered_from()
    {
        // The difference between a client showing "failed" and a client offering to create the
        // folder. RFC 3501 sections 6.3.11 and 6.4.7.
        ImapResponses.No("A1", "Mailbox does not exist", ImapResponseCode.TryCreate)
            .Format()
            .ShouldBe("A1 NO [TRYCREATE] Mailbox does not exist\r\n");
    }

    [Fact]
    public void The_literal_continuation_is_a_plus_line() =>
        ImapResponses.ReadyForLiteral().Format().ShouldBe("+ Ready for literal data\r\n");

    [Fact]
    public void The_factories_reject_null_arguments()
    {
        Should.Throw<ArgumentNullException>(() => ImapResponse.Tagged(null!, ImapResponseStatus.Ok, "x"));
        Should.Throw<ArgumentNullException>(() => ImapResponse.Tagged("A1", ImapResponseStatus.Ok, null!));
        Should.Throw<ArgumentNullException>(() => ImapResponse.Untagged(ImapResponseStatus.Ok, null!));
        Should.Throw<ArgumentNullException>(() => ImapResponse.Data(null!));
        Should.Throw<ArgumentNullException>(() => ImapResponse.Continuation(null!));
        Should.Throw<ArgumentNullException>(() => ImapResponseCode.Capability(null!));
        Should.Throw<ArgumentNullException>(() => ImapResponses.Capability(null!));
    }
    // ---------------------------------------------------------------------------------------
    // LIST and LSUB.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3501 §9: mailbox-list = "(" [mbx-list-flags] ")" SP (DQUOTE QUOTED-CHAR DQUOTE / nil)
    /// SP mailbox. The delimiter is quoted, the attributes are bracketed, and the name comes
    /// last.
    /// </summary>
    [Fact]
    public void A_list_line_has_attributes_then_delimiter_then_name() =>
        ImapResponses.List(ImapMailboxAttribute.HasNoChildren, "INBOX").Format()
            .ShouldBe("* LIST (\\HasNoChildren) \"/\" INBOX\r\n");

    [Fact]
    public void A_folder_with_nothing_to_say_about_itself_has_empty_brackets() =>
        ImapResponses.List(ImapMailboxAttribute.None, "Notes").Format()
            .ShouldBe("* LIST () \"/\" Notes\r\n");

    [Fact]
    public void An_lsub_line_differs_from_a_list_line_only_in_its_keyword() =>
        ImapResponses.Lsub(ImapMailboxAttribute.HasNoChildren, "INBOX").Format()
            .ShouldBe("* LSUB (\\HasNoChildren) \"/\" INBOX\r\n");

    [Fact]
    public void A_special_use_folder_carries_its_attribute() =>
        ImapResponses.List(
                ImapMailboxAttribute.HasNoChildren | ImapMailboxAttribute.Sent,
                "Sent")
            .Format()
            .ShouldBe("* LIST (\\HasNoChildren \\Sent) \"/\" Sent\r\n");

    /// <summary>
    /// A name needing quotes is quoted, because astring's first branch is 1*ASTRING-CHAR and a
    /// space is not one of them.
    /// </summary>
    [Fact]
    public void A_name_containing_a_space_is_quoted() =>
        ImapResponses.List(ImapMailboxAttribute.None, "My Folder").Format()
            .ShouldBe("* LIST () \"/\" \"My Folder\"\r\n");

    /// <summary>
    /// Encoded first and quoted second. RFC 3501 §5.1.3's modified UTF-7 introduces '&amp;' and
    /// base64 characters, none of which need quoting — but a name encoded after being quoted
    /// would have its quotes encoded too, and a client would receive a name with literal quote
    /// characters in it.
    /// </summary>
    [Fact]
    public void A_non_ascii_name_is_encoded_before_it_is_considered_for_quoting()
    {
        string formatted = ImapResponses.List(ImapMailboxAttribute.None, "Rechnungen/Jänner")
            .Format();

        formatted.ShouldBe("* LIST () \"/\" Rechnungen/J&AOQ-nner\r\n");
        formatted.ShouldNotContain("ä");
    }

    /// <summary>
    /// RFC 3501 §6.3.8's own worked example: C: A101 LIST "" "" answered with
    /// S: * LIST (\Noselect) "/" "". The empty name has no unquoted form, so it must be "".
    /// </summary>
    [Fact]
    public void The_hierarchy_delimiter_probe_is_answered_with_an_empty_quoted_name() =>
        ImapResponses.HierarchyDelimiter(string.Empty).Format()
            .ShouldBe("* LIST (\\Noselect) \"/\" \"\"\r\n");

    [Fact]
    public void The_probe_can_be_answered_as_an_lsub_line() =>
        ImapResponses.LsubHierarchyDelimiter(string.Empty).Format()
            .ShouldBe("* LSUB (\\Noselect) \"/\" \"\"\r\n");

    /// <summary>
    /// A derived hierarchy level is \Noselect because it is not a mailbox, and \HasChildren
    /// because it exists only by virtue of something beneath it.
    /// </summary>
    [Fact]
    public void A_derived_hierarchy_level_is_unselectable_and_has_children() =>
        ImapResponses.List(
                ImapMailboxAttribute.NoSelect | ImapMailboxAttribute.HasChildren,
                "Projects")
            .Format()
            .ShouldBe("* LIST (\\Noselect \\HasChildren) \"/\" Projects\r\n");

    [Fact]
    public void A_list_line_refuses_a_null_name() =>
        Should.Throw<ArgumentNullException>(
            () => ImapResponses.List(ImapMailboxAttribute.None, null!));

    // ---------------------------------------------------------------------------------------
    // STATUS.
    // ---------------------------------------------------------------------------------------

    private static ImapFolderStatus StatusOf(
        long messageCount = 231,
        long unseenCount = 7,
        long uidValidity = 3_857_529_045,
        long nextUid = 44_292)
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

    /// <summary>
    /// RFC 3501 §6.3.10's own example, verbatim: C: A042 STATUS blurdybloop (UIDNEXT MESSAGES)
    /// answered S: * STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292).
    /// </summary>
    [Fact]
    public void The_rfcs_own_status_example_is_reproduced() =>
        ImapResponses
            .Status(
                "blurdybloop",
                [ImapStatusItem.Messages, ImapStatusItem.UidNext],
                StatusOf(messageCount: 231, nextUid: 44_292))
            .Format()
            .ShouldBe("* STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292)\r\n");

    [Fact]
    public void A_status_line_reports_only_the_items_asked_for() =>
        ImapResponses
            .Status("INBOX", [ImapStatusItem.Unseen], StatusOf(unseenCount: 7))
            .Format()
            .ShouldBe("* STATUS INBOX (UNSEEN 7)\r\n");

    [Fact]
    public void A_status_line_reports_them_in_the_order_asked() =>
        ImapResponses
            .Status(
                "INBOX",
                [ImapStatusItem.Unseen, ImapStatusItem.Messages],
                StatusOf(messageCount: 231, unseenCount: 7))
            .Format()
            .ShouldBe("* STATUS INBOX (UNSEEN 7 MESSAGES 231)\r\n");

    /// <summary>
    /// The pairing is done here rather than by the caller, so every name is followed by its own
    /// number — a client reading UNSEEN where the server meant MESSAGES would badge every
    /// message in the folder as unread.
    /// </summary>
    [Fact]
    public void Every_name_is_followed_by_its_own_number()
    {
        string formatted = ImapResponses
            .Status(
                "INBOX",
                ImapStatusItems.All,
                StatusOf(messageCount: 231, unseenCount: 7, uidValidity: 42, nextUid: 300))
            .Format();

        formatted.ShouldBe(
            "* STATUS INBOX (MESSAGES 231 RECENT 0 UIDNEXT 300 UIDVALIDITY 42 UNSEEN 7)\r\n");
    }

    [Fact]
    public void A_status_line_quotes_a_mailbox_name_that_needs_it() =>
        ImapResponses
            .Status("My Folder", [ImapStatusItem.Messages], StatusOf(messageCount: 1))
            .Format()
            .ShouldBe("* STATUS \"My Folder\" (MESSAGES 1)\r\n");

    [Fact]
    public void A_status_line_encodes_a_non_ascii_mailbox_name() =>
        ImapResponses
            .Status("Jänner", [ImapStatusItem.Messages], StatusOf(messageCount: 1))
            .Format()
            .ShouldBe("* STATUS J&AOQ-nner (MESSAGES 1)\r\n");

    [Fact]
    public void A_status_line_refuses_null_arguments()
    {
        Should.Throw<ArgumentNullException>(
            () => ImapResponses.Status(null!, [ImapStatusItem.Messages], StatusOf()));

        Should.Throw<ArgumentNullException>(
            () => ImapResponses.Status("INBOX", null!, StatusOf()));

        Should.Throw<ArgumentNullException>(
            () => ImapResponses.Status("INBOX", [ImapStatusItem.Messages], null!));
    }
}
