using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapCommandTests
{
    // ---------------------------------------------------------------------------------------
    // Tags this server accepts.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("A001")]
    [InlineData("a001")]
    [InlineData("1")]
    [InlineData("99999")]
    [InlineData("A00000001")]
    [InlineData(".")]
    [InlineData("tag-with.lots_of~punctuation!")]
    public void Accepts_the_tags_real_clients_send(string tag)
    {
        ImapCommand.TryParse($"{tag} NOOP", out ImapCommand? command, out ImapTagFailure failure)
            .ShouldBeTrue();

        failure.ShouldBe(ImapTagFailure.None);
        command!.Tag.ShouldBe(tag);
        command.Verb.ShouldBe(ImapVerb.Noop);
    }

    [Theory]
    [InlineData("A]1")]
    [InlineData("]")]
    public void Accepts_a_closing_bracket_in_a_tag(string tag)
    {
        // RFC 3501 section 9's double negative: atom-specials removes resp-specials (']'), and
        // ASTRING-CHAR adds it back. ']' is legal in a tag and illegal in an atom, so a single
        // shared "is this an atom character" predicate would be wrong in one direction.
        ImapCommand.TryParse($"{tag} NOOP", out ImapCommand? command, out _).ShouldBeTrue();
        command!.Tag.ShouldBe(tag);
    }

    [Fact]
    public void Accepts_a_tag_of_exactly_the_maximum_length()
    {
        string tag = new('A', ImapCommand.MaxTagLength);

        ImapCommand.TryParse($"{tag} NOOP", out ImapCommand? command, out _).ShouldBeTrue();
        command!.Tag.ShouldBe(tag);
    }

    // ---------------------------------------------------------------------------------------
    // Tags this server refuses. A refusal is answered untagged; see ImapCommand.TryParse.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData(" NOOP")]
    [InlineData("  NOOP")]
    public void Refuses_a_line_with_no_tag(string line)
    {
        ImapCommand.TryParse(line, out ImapCommand? command, out ImapTagFailure failure)
            .ShouldBeFalse();

        command.ShouldBeNull();
        failure.ShouldBe(ImapTagFailure.Missing);
    }

    [Fact]
    public void The_tag_cap_is_the_value_the_remarks_argue_for()
    {
        // Every other test of the cap builds its input as MaxTagLength + 1, so it holds for any
        // value of the constant and none of them would notice it being raised to a megabyte -
        // which would give back exactly the echo and log amplification the constant's remarks
        // say it exists to bound. Pinning the number is what makes those tests mean something.
        ImapCommand.MaxTagLength.ShouldBe(32);
    }

    [Fact]
    public void Refuses_a_tag_longer_than_the_maximum()
    {
        string tag = new('A', ImapCommand.MaxTagLength + 1);

        ImapCommand.TryParse($"{tag} NOOP", out ImapCommand? command, out ImapTagFailure failure)
            .ShouldBeFalse();

        command.ShouldBeNull();
        failure.ShouldBe(ImapTagFailure.TooLong);
    }

    [Theory]
    [InlineData("A(1")]
    [InlineData("A)1")]
    [InlineData("A{1")]
    [InlineData("A%1")]
    [InlineData("A*1")]
    [InlineData("A\"1")]
    [InlineData("A\\1")]
    [InlineData("A+1")]
    [InlineData("(")]
    public void Refuses_a_tag_containing_a_character_the_grammar_forbids(string tag)
    {
        ImapCommand.TryParse($"{tag} NOOP", out ImapCommand? command, out ImapTagFailure failure)
            .ShouldBeFalse();

        command.ShouldBeNull();
        failure.ShouldBe(ImapTagFailure.IllegalCharacter);
    }

    [Fact]
    public void Refuses_a_tag_of_star_or_plus_because_they_classify_a_response_line()
    {
        // Every line the server writes is classified by its first token: '*' is untagged,
        // '+' is a continuation request, anything else is a tag. A command tagged '+' would be
        // answered "+ OK NOOP completed", which the client reads as a request for a literal it
        // never intended to send - after which the connection is permanently out of step.
        ImapCommand.TryParse("* NOOP", out _, out ImapTagFailure star).ShouldBeFalse();
        ImapCommand.TryParse("+ NOOP", out _, out ImapTagFailure plus).ShouldBeFalse();

        star.ShouldBe(ImapTagFailure.IllegalCharacter);
        plus.ShouldBe(ImapTagFailure.IllegalCharacter);
    }

    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    [InlineData("\u0000")]
    [InlineData("\u007f")]
    [InlineData("\t")]
    public void Refuses_a_tag_carrying_a_control_character(string control)
    {
        // The response-splitting defence, and not a theoretical one: ImapLineReader strips only
        // the CR immediately before a line's terminating LF, so a line whose tag has a CR in the
        // middle reaches this parser with that CR intact. Echoing that tag back would put an
        // attacker-chosen line break into the response stream.
        string tag = $"A{control}BBB";

        ImapCommand.TryParse($"{tag} NOOP", out ImapCommand? command, out ImapTagFailure failure)
            .ShouldBeFalse();

        command.ShouldBeNull();
        failure.ShouldBe(ImapTagFailure.IllegalCharacter);
    }

    [Theory]
    [InlineData("é")]
    [InlineData("λ")]
    [InlineData("ÿ")]
    public void Refuses_a_tag_outside_ascii(string letter)
    {
        // RFC 3501 section 9's CHAR is %x01-7F. Anything above that was never a tag.
        ImapCommand.TryParse($"A{letter}1 NOOP", out _, out ImapTagFailure failure).ShouldBeFalse();
        failure.ShouldBe(ImapTagFailure.IllegalCharacter);
    }

    [Fact]
    public void Never_rewrites_a_tag_it_accepts()
    {
        // Unlike SMTP reply text, an IMAP tag is load-bearing: the client byte-matches the
        // tagged completion against the command it issued. A tag that was silently repaired is
        // a completion the client cannot match.
        ImapCommand.TryParse("aBc.19]Z NOOP", out ImapCommand? command, out _).ShouldBeTrue();
        command!.Tag.ShouldBe("aBc.19]Z");
    }

    // ---------------------------------------------------------------------------------------
    // Verbs.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("CAPABILITY", ImapVerb.Capability)]
    [InlineData("NOOP", ImapVerb.Noop)]
    [InlineData("LOGOUT", ImapVerb.Logout)]
    [InlineData("STARTTLS", ImapVerb.StartTls)]
    [InlineData("AUTHENTICATE", ImapVerb.Authenticate)]
    [InlineData("LOGIN", ImapVerb.Login)]
    [InlineData("SELECT", ImapVerb.Select)]
    [InlineData("EXAMINE", ImapVerb.Examine)]
    [InlineData("CREATE", ImapVerb.Create)]
    [InlineData("DELETE", ImapVerb.Delete)]
    [InlineData("RENAME", ImapVerb.Rename)]
    [InlineData("SUBSCRIBE", ImapVerb.Subscribe)]
    [InlineData("UNSUBSCRIBE", ImapVerb.Unsubscribe)]
    [InlineData("LIST", ImapVerb.List)]
    [InlineData("LSUB", ImapVerb.Lsub)]
    [InlineData("STATUS", ImapVerb.Status)]
    [InlineData("APPEND", ImapVerb.Append)]
    [InlineData("CHECK", ImapVerb.Check)]
    [InlineData("CLOSE", ImapVerb.Close)]
    [InlineData("EXPUNGE", ImapVerb.Expunge)]
    [InlineData("SEARCH", ImapVerb.Search)]
    [InlineData("FETCH", ImapVerb.Fetch)]
    [InlineData("STORE", ImapVerb.Store)]
    [InlineData("COPY", ImapVerb.Copy)]
    [InlineData("IDLE", ImapVerb.Idle)]
    [InlineData("NAMESPACE", ImapVerb.Namespace)]
    [InlineData("UNSELECT", ImapVerb.Unselect)]
    [InlineData("MOVE", ImapVerb.Move)]
    public void Recognises_every_implemented_command(string word, ImapVerb expected)
    {
        ImapCommand.TryParse($"A001 {word}", out ImapCommand? command, out _).ShouldBeTrue();
        command!.Verb.ShouldBe(expected);
    }

    [Theory]
    [InlineData("noop")]
    [InlineData("NoOp")]
    [InlineData("nOOp")]
    public void Matches_a_command_word_case_insensitively(string word)
    {
        // RFC 3501 section 9: the formal syntax is case-insensitive except where noted. Mailbox
        // names are one of the places it is noted, which is why only the verb is upper-cased
        // here and the argument is left exactly as it arrived.
        ImapCommand.TryParse($"A001 {word}", out ImapCommand? command, out _).ShouldBeTrue();
        command!.Verb.ShouldBe(ImapVerb.Noop);
    }

    [Theory]
    [InlineData("A001 FROBNICATE")]
    [InlineData("A001 MAILFROM")]
    [InlineData("A001 SELECTED")]
    [InlineData("A001 ")]
    [InlineData("A001")]
    public void Parses_an_unrecognised_command_rather_than_failing(string line)
    {
        // A usable tag means the refusal can be tagged, and a tagged BAD is what lets the client
        // match the refusal to the command it sent. Only the tag can fail this parse.
        ImapCommand.TryParse(line, out ImapCommand? command, out ImapTagFailure failure)
            .ShouldBeTrue();

        failure.ShouldBe(ImapTagFailure.None);
        command!.Tag.ShouldBe("A001");
        command.Verb.ShouldBe(ImapVerb.Unknown);
    }

    [Fact]
    public void Does_not_match_a_command_by_prefix()
    {
        ImapCommand.TryParse("A001 LOGINX", out ImapCommand? command, out _).ShouldBeTrue();
        command!.Verb.ShouldBe(ImapVerb.Unknown);
    }

    // ---------------------------------------------------------------------------------------
    // The UID prefix - RFC 3501 section 6.4.8.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("FETCH", ImapVerb.Fetch)]
    [InlineData("STORE", ImapVerb.Store)]
    [InlineData("COPY", ImapVerb.Copy)]
    [InlineData("SEARCH", ImapVerb.Search)]
    [InlineData("MOVE", ImapVerb.Move)]
    public void Reads_the_uid_prefix_as_a_flag_on_the_inner_command(string word, ImapVerb expected)
    {
        ImapCommand.TryParse($"A001 UID {word} 1:*", out ImapCommand? command, out _).ShouldBeTrue();

        command!.Verb.ShouldBe(expected);
        command.IsUid.ShouldBeTrue();
        command.Argument.ShouldBe("1:*");
    }

    [Fact]
    public void Reads_a_lower_case_uid_prefix()
    {
        ImapCommand.TryParse("A001 uid fetch 1 FLAGS", out ImapCommand? command, out _).ShouldBeTrue();

        command!.Verb.ShouldBe(ImapVerb.Fetch);
        command.IsUid.ShouldBeTrue();
    }

    [Theory]
    [InlineData("A001 UID SELECT INBOX")]
    [InlineData("A001 UID LOGIN a b")]
    [InlineData("A001 UID EXPUNGE 1:5")]
    [InlineData("A001 UID FROBNICATE")]
    [InlineData("A001 UID")]
    public void Refuses_a_uid_prefix_on_a_command_that_has_no_uid_form(string line)
    {
        // There is no such command, so there is no such verb: reporting the inner verb with the
        // flag attached would invite a handler to act on one and ignore the other. UID EXPUNGE
        // is RFC 4315 UIDPLUS, which this server does not implement yet.
        ImapCommand.TryParse(line, out ImapCommand? command, out _).ShouldBeTrue();

        command!.Verb.ShouldBe(ImapVerb.Unknown);
        command.IsUid.ShouldBeTrue();
    }

    [Theory]
    [InlineData(ImapVerb.Fetch, true)]
    [InlineData(ImapVerb.Store, true)]
    [InlineData(ImapVerb.Copy, true)]
    [InlineData(ImapVerb.Search, true)]
    [InlineData(ImapVerb.Move, true)]
    [InlineData(ImapVerb.Expunge, false)]
    [InlineData(ImapVerb.Select, false)]
    [InlineData(ImapVerb.Noop, false)]
    [InlineData(ImapVerb.Unknown, false)]
    public void Reports_which_commands_take_the_uid_prefix(ImapVerb verb, bool expected) =>
        ImapCommand.SupportsUidPrefix(verb).ShouldBe(expected);

    [Fact]
    public void A_command_without_the_prefix_is_not_a_uid_command()
    {
        ImapCommand.TryParse("A001 FETCH 1 FLAGS", out ImapCommand? command, out _).ShouldBeTrue();
        command!.IsUid.ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // Arguments and the raw line.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Keeps_the_argument_text_exactly_as_it_arrived()
    {
        // This server matches mailbox names exactly (RFC 3501 section 5.1 leaves that open) and a
        // trailing space inside a
        // quoted name is part of the name, so nothing here is normalised.
        ImapCommand.TryParse("A001 SELECT \"My Folder \"", out ImapCommand? command, out _)
            .ShouldBeTrue();

        command!.Argument.ShouldBe("\"My Folder \"");
    }

    [Fact]
    public void Tolerates_extra_spaces_between_the_tag_and_the_command()
    {
        ImapCommand.TryParse("A001   NOOP", out ImapCommand? command, out _).ShouldBeTrue();
        command!.Verb.ShouldBe(ImapVerb.Noop);
    }

    [Fact]
    public void Keeps_the_raw_line_for_logging_but_drops_the_terminator()
    {
        ImapCommand.TryParse("A001 NOOP\r\n", out ImapCommand? command, out _).ShouldBeTrue();
        command!.Raw.ShouldBe("A001 NOOP");
    }

    [Fact]
    public void Carries_a_literal_specifier_through_untouched()
    {
        // The line ends at the specifier; the octets it names arrive after it. Reading them is
        // the connection's job, not this parser's.
        ImapCommand.TryParse("A001 APPEND INBOX {310}", out ImapCommand? command, out _)
            .ShouldBeTrue();

        command!.Verb.ShouldBe(ImapVerb.Append);
        command.Argument.ShouldBe("INBOX {310}");
    }

    // ---------------------------------------------------------------------------------------
    // Rendering. LOGIN's argument is a cleartext password.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Rendering_a_command_never_reveals_its_argument()
    {
        // A record's generated ToString prints every property. RFC 3501 section 6.2.3's LOGIN
        // puts the password in the argument in the clear - no base64, unlike SMTP's AUTH PLAIN -
        // so the generated form would render a customer's password into any log line, exception
        // message or crash dump that interpolated a command.
        ImapCommand.TryParse("a1 LOGIN alice hunter2", out ImapCommand? command, out _)
            .ShouldBeTrue();

        string rendered = command!.ToString();

        rendered.ShouldNotContain("hunter2");
        rendered.ShouldNotContain("alice");
        rendered.ShouldContain("a1");
        rendered.ShouldContain("Login");
    }

    [Fact]
    public void Interpolating_a_command_never_reveals_its_argument()
    {
        // The shape a source scan cannot catch: the offending line names neither Raw nor
        // Argument, so nothing but this override stands between it and the log.
        ImapCommand.TryParse("a1 LOGIN alice hunter2", out ImapCommand? command, out _)
            .ShouldBeTrue();

        $"Unexpected command {command}".ShouldNotContain("hunter2");
    }

    [Fact]
    public void The_argument_is_still_reachable_for_the_handler_that_needs_it()
    {
        // Redacted from rendering, not from the type. Whatever executes LOGIN still has to read
        // the credential in order to verify it.
        ImapCommand.TryParse("a1 LOGIN alice hunter2", out ImapCommand? command, out _)
            .ShouldBeTrue();

        command!.Argument.ShouldBe("alice hunter2");
        command.Raw.ShouldBe("a1 LOGIN alice hunter2");
    }

    [Fact]
    public void Rejects_a_null_line() =>
        Should.Throw<ArgumentNullException>(() => ImapCommand.TryParse(null!, out _, out _));
}
