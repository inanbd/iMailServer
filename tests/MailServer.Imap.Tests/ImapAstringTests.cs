using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapAstringReaderTests
{
    // ---------------------------------------------------------------------------------------
    // Unquoted arguments.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("INBOX")]
    [InlineData("NIL")]
    [InlineData("42")]
    [InlineData("Invoices/2026")]
    [InlineData("a.b-c_d~e!")]
    public void Reads_an_unquoted_argument(string text)
    {
        ImapAstringReader reader = new(text);

        ImapAstringToken token = reader.Read();

        token.Kind.ShouldBe(ImapAstringKind.Unquoted);
        token.Value.ShouldBe(text);
        reader.AtEnd.ShouldBeTrue();
    }

    [Theory]
    [InlineData("Invoices]2026")]
    [InlineData("]")]
    [InlineData("a]b]c")]
    public void Accepts_a_closing_bracket_in_an_unquoted_argument(string text)
    {
        // The same double negative the tag carries: atom-specials excludes ']' and ASTRING-CHAR
        // adds it straight back, so ']' is legal in an astring and illegal in a bare atom. A
        // mailbox genuinely named "Invoices]2026" may arrive unquoted, and refusing it would
        // refuse a conformant client.
        ImapAstringReader reader = new(text);

        reader.Read().Value.ShouldBe(text);
    }

    [Fact]
    public void Reads_two_unquoted_arguments_in_order()
    {
        ImapAstringReader reader = new("alice hunter2");

        reader.TryReadText(out string? first).ShouldBeTrue();
        reader.TryReadText(out string? second).ShouldBeTrue();

        first.ShouldBe("alice");
        second.ShouldBe("hunter2");
        reader.AtEnd.ShouldBeTrue();
    }

    [Theory]
    [InlineData("(")]
    [InlineData(")")]
    [InlineData("%")]
    [InlineData("*")]
    [InlineData("\\")]
    public void Refuses_a_character_the_grammar_excludes(string text)
    {
        new ImapAstringReader(text).Read().Kind.ShouldBe(ImapAstringKind.Malformed);
    }

    // ---------------------------------------------------------------------------------------
    // Quoted strings.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Reads_a_quoted_argument_and_removes_the_quotes()
    {
        ImapAstringReader reader = new("\"My Folder\"");

        ImapAstringToken token = reader.Read();

        token.Kind.ShouldBe(ImapAstringKind.Quoted);
        token.Value.ShouldBe("My Folder");
        reader.AtEnd.ShouldBeTrue();
    }

    [Fact]
    public void Reads_the_empty_quoted_string()
    {
        // Legal and meaningful: LIST "" "*" is how every client opens a mailbox listing, the
        // empty reference being the point. An implementation requiring at least one character
        // would break the first thing every client does.
        ImapAstringReader reader = new("\"\" \"*\"");

        ImapAstringToken first = reader.Read();

        first.Kind.ShouldBe(ImapAstringKind.Quoted);
        first.Value.ShouldBeEmpty();

        reader.Read().Value.ShouldBe("*");
        reader.AtEnd.ShouldBeTrue();
    }

    [Fact]
    public void Keeps_spaces_inside_a_quoted_argument()
    {
        // Not space-delimited in any useful sense, which is why this is a cursor and not a split.
        new ImapAstringReader("\"  leading and trailing  \"").Read().Value
            .ShouldBe("  leading and trailing  ");
    }

    [Theory]
    [InlineData("\"a\\\"b\"", "a\"b")]
    [InlineData("\"a\\\\b\"", "a\\b")]
    [InlineData("\"\\\"\"", "\"")]
    [InlineData("\"\\\\\"", "\\")]
    [InlineData("\"Projects\\\\2026\"", "Projects\\2026")]
    public void Resolves_the_two_escapes_the_grammar_has(string wire, string expected)
    {
        // quoted-specials is exactly '"' and '\', so those two are the only escapes there are.
        new ImapAstringReader(wire).Read().Value.ShouldBe(expected);
    }

    [Theory]
    [InlineData("\"a\\nb\"")]
    [InlineData("\"a\\tb\"")]
    [InlineData("\"a\\x41b\"")]
    [InlineData("\"a\\0b\"")]
    public void Refuses_an_escape_the_grammar_does_not_have(string wire)
    {
        // A server that resolved \n would hand a client a character no client asked for, and one
        // that passed the backslash through would disagree with every other server about what
        // the name is.
        new ImapAstringReader(wire).Read().Kind.ShouldBe(ImapAstringKind.Malformed);
    }

    [Theory]
    [InlineData("\"unterminated")]
    [InlineData("\"trailing escape\\")]
    [InlineData("\"")]
    public void Refuses_an_unterminated_quoted_argument(string wire)
    {
        new ImapAstringReader(wire).Read().Kind.ShouldBe(ImapAstringKind.Malformed);
    }

    [Theory]
    [InlineData("\"spans\ra line\"")]
    [InlineData("\"spans\na line\"")]
    public void Refuses_a_quoted_argument_carrying_a_line_break(string wire)
    {
        // TEXT-CHAR excludes CR and LF. Neither reaches here through ImapLineReader, which ends
        // a line at the LF - but a caller composing an argument another way must not get a
        // quoted string that spans lines.
        new ImapAstringReader(wire).Read().Kind.ShouldBe(ImapAstringKind.Malformed);
    }

    [Fact]
    public void Mixes_quoted_and_unquoted_arguments()
    {
        ImapAstringReader reader = new("INBOX \"My Folder\" Sent");

        reader.TryReadText(out string? a).ShouldBeTrue();
        reader.TryReadText(out string? b).ShouldBeTrue();
        reader.TryReadText(out string? c).ShouldBeTrue();

        a.ShouldBe("INBOX");
        b.ShouldBe("My Folder");
        c.ShouldBe("Sent");
    }

    // ---------------------------------------------------------------------------------------
    // Literals are reported, not resolved.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("{5}", 5L, true)]
    [InlineData("{5+}", 5L, false)]
    [InlineData("{0}", 0L, true)]
    public void Reports_a_literal_specifier_rather_than_guessing_at_its_content(
        string wire,
        long byteCount,
        bool synchronizing)
    {
        // This reader is handed one line and a literal's content is not on it. A reader that
        // pretended otherwise would either block on I/O it has no access to or return the wrong
        // argument.
        ImapAstringToken token = new ImapAstringReader(wire).Read();

        token.Kind.ShouldBe(ImapAstringKind.Literal);
        token.Literal.ByteCount.ShouldBe(byteCount);
        token.Literal.IsSynchronizing.ShouldBe(synchronizing);
        token.Value.ShouldBeEmpty();
    }

    [Fact]
    public void Reads_an_argument_after_a_literal_specifier()
    {
        ImapAstringReader reader = new("INBOX {310}");

        reader.TryReadText(out string? mailbox).ShouldBeTrue();
        mailbox.ShouldBe("INBOX");

        reader.Read().Kind.ShouldBe(ImapAstringKind.Literal);
        reader.AtEnd.ShouldBeTrue();
    }

    [Fact]
    public void A_literal_is_not_usable_as_text()
    {
        // The convenience the ordinary commands want: a mailbox name that arrived as a literal
        // is not something most handlers can proceed with.
        new ImapAstringReader("{5}").TryReadText(out string? value).ShouldBeFalse();
        value.ShouldBeNull();
    }

    [Theory]
    [InlineData("{5")]
    [InlineData("{}")]
    [InlineData("{-1}")]
    [InlineData("{ 5}")]
    [InlineData("{abc}")]
    public void Refuses_a_malformed_literal_specifier(string wire)
    {
        new ImapAstringReader(wire).Read().Kind.ShouldBe(ImapAstringKind.Malformed);
    }

    // ---------------------------------------------------------------------------------------
    // Exhaustion and the tail.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("   ")]
    public void An_empty_argument_list_is_at_the_end(string text)
    {
        ImapAstringReader reader = new(text);

        reader.AtEnd.ShouldBeTrue();
        reader.Read().Kind.ShouldBe(ImapAstringKind.None);
    }

    [Fact]
    public void A_trailing_space_does_not_read_as_another_argument()
    {
        ImapAstringReader reader = new("INBOX ");

        reader.TryReadText(out _).ShouldBeTrue();
        reader.AtEnd.ShouldBeTrue();
    }

    [Fact]
    public void Tolerates_more_than_one_space_between_arguments()
    {
        ImapAstringReader reader = new("a   b");

        reader.TryReadText(out string? first).ShouldBeTrue();
        reader.TryReadText(out string? second).ShouldBeTrue();

        first.ShouldBe("a");
        second.ShouldBe("b");
    }

    [Fact]
    public void Exposes_the_unread_tail_verbatim()
    {
        // For a caller whose remaining grammar is its own - a FETCH attribute list, say.
        ImapAstringReader reader = new("INBOX (FLAGS BODY[HEADER])");

        reader.TryReadText(out _).ShouldBeTrue();
        reader.Remainder.ShouldBe(" (FLAGS BODY[HEADER])");
    }

    [Fact]
    public void Nothing_is_normalised()
    {
        // This server matches mailbox names exactly - RFC 3501 section 5.1 leaves that open for
        // every name but INBOX - and INBOX's exception is the
        // caller's to apply. A reader that folded case would make two mailboxes look like one.
        new ImapAstringReader("inbox").Read().Value.ShouldBe("inbox");
        new ImapAstringReader("MyFolder").Read().Value.ShouldBe("MyFolder");
    }

    [Fact]
    public void Rejects_a_null_argument_string() =>
        Should.Throw<ArgumentNullException>(() => new ImapAstringReader(null!));
    // ---------------------------------------------------------------------------------------
    // list-mailbox, where the wildcards are ordinary characters.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3501 §9: list-mailbox = 1*list-char / string, and list-char admits list-wildcards.
    /// Reading a pattern as an astring would reject the commonest form of the commonest command.
    /// </summary>
    [Theory]
    [InlineData("*")]
    [InlineData("%")]
    [InlineData("*%*")]
    [InlineData("INBOX*")]
    [InlineData("Projects/%")]
    [InlineData("%/2026")]
    [InlineData("Invoices]2026*")]
    public void An_unquoted_pattern_may_contain_wildcards(string pattern)
    {
        ImapAstringReader reader = new(pattern);

        reader.TryReadListMailbox(out string? value).ShouldBeTrue();
        value.ShouldBe(pattern);
        reader.AtEnd.ShouldBeTrue();
    }

    /// <summary>
    /// The same characters in an astring are atom-specials, and that asymmetry is the reason
    /// ReadListMailbox exists at all.
    /// </summary>
    [Theory]
    [InlineData("*")]
    [InlineData("%")]
    public void The_same_wildcard_is_refused_by_the_astring_reader(string text) =>
        new ImapAstringReader(text).TryReadText(out _).ShouldBeFalse();

    [Fact]
    public void A_reference_and_a_pattern_are_read_from_one_line()
    {
        ImapAstringReader reader = new("\"\" *");

        reader.TryReadText(out string? reference).ShouldBeTrue();
        reference.ShouldBe(string.Empty);

        reader.TryReadListMailbox(out string? pattern).ShouldBeTrue();
        pattern.ShouldBe("*");

        reader.AtEnd.ShouldBeTrue();
    }

    /// <summary>
    /// list-mailbox's second branch is string unchanged, so a quoted wildcard means exactly what
    /// the bare one does — and that is what most clients actually send.
    /// </summary>
    [Theory]
    [InlineData("\"*\"", "*")]
    [InlineData("\"%\"", "%")]
    [InlineData("\"Projects/%\"", "Projects/%")]
    [InlineData("\"\"", "")]
    public void A_quoted_pattern_reads_the_same_as_an_unquoted_one(string wire, string expected)
    {
        new ImapAstringReader(wire).TryReadListMailbox(out string? value).ShouldBeTrue();
        value.ShouldBe(expected);
    }

    /// <summary>
    /// The structural characters stay excluded: a pattern needing one of them is quoted.
    /// </summary>
    [Theory]
    [InlineData("(")]
    [InlineData(")")]
    public void A_structural_character_is_still_not_a_pattern(string text) =>
        new ImapAstringReader(text).TryReadListMailbox(out _).ShouldBeFalse();

    [Fact]
    public void A_pattern_stops_at_the_space_after_it()
    {
        ImapAstringReader reader = new("* trailing");

        reader.TryReadListMailbox(out string? value).ShouldBeTrue();
        value.ShouldBe("*");
        reader.AtEnd.ShouldBeFalse();
        reader.Remainder.ShouldBe("trailing");
    }

    [Fact]
    public void A_missing_pattern_is_not_a_pattern()
    {
        ImapAstringReader reader = new(string.Empty);

        reader.ReadListMailbox().Kind.ShouldBe(ImapAstringKind.None);
    }

    /// <summary>
    /// A literal is reported rather than resolved, as everywhere else in this reader: the octets
    /// have not arrived yet, so there is nothing to match against.
    /// </summary>
    [Fact]
    public void A_pattern_sent_as_a_literal_is_reported_and_not_invented()
    {
        ImapAstringReader reader = new("{5}");

        ImapAstringToken token = reader.ReadListMailbox();

        token.Kind.ShouldBe(ImapAstringKind.Literal);
        reader.TryReadListMailbox(out _).ShouldBeFalse();
    }
    // ---- Resolved literals ------------------------------------------------------------------

    /// <summary>
    /// The whole point of the literals list: a mailbox name that arrived as octets after the
    /// line reads back as ordinary text, so every handler that calls TryReadText works
    /// unchanged.
    /// </summary>
    [Fact]
    public void Resolves_a_literal_from_the_values_the_connection_read()
    {
        ImapAstringReader reader = new("{5}", ["INBOX"]);

        ImapAstringToken token = reader.Read();

        token.Kind.ShouldBe(ImapAstringKind.ResolvedLiteral);
        token.IsText.ShouldBeTrue();
        token.Value.ShouldBe("INBOX");
        token.Literal.ByteCount.ShouldBe(5L);
        reader.AtEnd.ShouldBeTrue();
    }

    /// <summary>
    /// Two literals on one line are matched to their specifiers by position, left to right —
    /// LOGIN's userid and password, which is the shape that would silently swap a credential if
    /// the order were ever taken from anywhere else.
    /// </summary>
    [Fact]
    public void Resolves_several_literals_in_order()
    {
        ImapAstringReader reader = new("{17} {7}", ["alice@example.com", "hunter2"]);

        reader.TryReadText(out string? user).ShouldBeTrue();
        reader.TryReadText(out string? password).ShouldBeTrue();

        user.ShouldBe("alice@example.com");
        password.ShouldBe("hunter2");
        reader.AtEnd.ShouldBeTrue();
    }

    /// <summary>
    /// A specifier with no value behind it stays unresolved, which is what leaves APPEND's
    /// message literal for ImapAppend to find.
    /// </summary>
    [Fact]
    public void Leaves_a_specifier_unresolved_when_no_value_was_read()
    {
        ImapAstringReader reader = new("{5} {310}", ["INBOX"]);

        reader.TryReadText(out string? mailbox).ShouldBeTrue();
        mailbox.ShouldBe("INBOX");

        ImapAstringToken message = reader.Read();

        message.Kind.ShouldBe(ImapAstringKind.Literal);
        message.IsText.ShouldBeFalse();
        message.Value.ShouldBe(string.Empty);
        message.Literal.ByteCount.ShouldBe(310L);
    }

    /// <summary>
    /// Mixing forms is conformant — RFC 3501 §4.3 makes atom, quoted and literal alternatives of
    /// one production — and the index must count only the literals.
    /// </summary>
    [Fact]
    public void Counts_only_literals_when_the_forms_are_mixed()
    {
        ImapAstringReader reader = new("\"first\" {6} third {5}", ["second", "fourth"]);

        reader.TryReadText(out string? a).ShouldBeTrue();
        reader.TryReadText(out string? b).ShouldBeTrue();
        reader.TryReadText(out string? c).ShouldBeTrue();
        reader.TryReadText(out string? d).ShouldBeTrue();

        a.ShouldBe("first");
        b.ShouldBe("second");
        c.ShouldBe("third");
        d.ShouldBe("fourth");
    }

    /// <summary>
    /// A LIST pattern may arrive as a literal too, and goes through the separate list-mailbox
    /// production — RFC 3501 §9's <c>list-mailbox = 1*list-char / string</c>.
    /// </summary>
    [Fact]
    public void Resolves_a_literal_list_pattern()
    {
        ImapAstringReader reader = new("\"\" {3}", ["%/%"]);

        reader.TryReadText(out string? reference).ShouldBeTrue();
        reader.TryReadListMailbox(out string? pattern).ShouldBeTrue();

        reference.ShouldBe(string.Empty);
        pattern.ShouldBe("%/%");
    }

    /// <summary>
    /// Passing no literals leaves the reader exactly as it behaved before they were supported,
    /// which is what every caller parsing a line in isolation relies on.
    /// </summary>
    [Fact]
    public void Reports_an_unresolved_literal_when_none_were_supplied()
    {
        new ImapAstringReader("{5}").Read().Kind.ShouldBe(ImapAstringKind.Literal);
        new ImapAstringReader("{5}", null).Read().Kind.ShouldBe(ImapAstringKind.Literal);
        new ImapAstringReader("{5}", []).Read().Kind.ShouldBe(ImapAstringKind.Literal);
    }
}

public sealed class ImapAstringFormatTests
{
    [Theory]
    [InlineData("INBOX", "INBOX")]
    [InlineData("Sent", "Sent")]
    [InlineData("Invoices/2026", "Invoices/2026")]
    [InlineData("a]b", "a]b")]
    public void Leaves_a_value_bare_when_the_grammar_allows_it(string value, string expected) =>
        ImapAstring.Format(value).ShouldBe(expected);

    [Fact]
    public void Quotes_the_empty_string()
    {
        // astring's unquoted branch is 1*ASTRING-CHAR - one or more - so an empty argument can
        // only be a quoted string. It comes up immediately: the hierarchy-delimiter probe every
        // client makes is answered with an empty mailbox name, and emitting nothing there shifts
        // every following token in the response.
        ImapAstring.Format(string.Empty).ShouldBe("\"\"");
    }

    [Theory]
    [InlineData("My Folder", "\"My Folder\"")]
    [InlineData("a(b", "\"a(b\"")]
    [InlineData("a)b", "\"a)b\"")]
    [InlineData("a%b", "\"a%b\"")]
    [InlineData("a*b", "\"a*b\"")]
    [InlineData("a{b", "\"a{b\"")]
    public void Quotes_a_value_the_grammar_would_not_accept_bare(string value, string expected) =>
        ImapAstring.Format(value).ShouldBe(expected);

    [Theory]
    [InlineData("a\"b", "\"a\\\"b\"")]
    [InlineData("Projects\\2026", "\"Projects\\\\2026\"")]
    [InlineData("\\", "\"\\\\\"")]
    [InlineData("\"", "\"\\\"\"")]
    public void Escapes_exactly_the_two_quoted_specials(string value, string expected)
    {
        // Escaping anything else is not IMAP and delivers a backslash to the user as a
        // character; failing to escape a backslash in an ordinary folder name terminates the
        // string early on the client side and shifts every token after it - a parse
        // desynchronisation produced by a user's own folder name rather than by an attacker.
        ImapAstring.Format(value).ShouldBe(expected);
    }

    [Fact]
    public void What_it_formats_it_can_read_back()
    {
        string[] names =
        [
            "INBOX", "", "My Folder", "a\"b", "Projects\\2026", "a]b", "  spaced  ", "a(b)c",
        ];

        foreach (string name in names)
        {
            ImapAstringReader reader = new(ImapAstring.Format(name));

            reader.TryReadText(out string? read).ShouldBeTrue($"could not read back [{name}]");
            read.ShouldBe(name);
            reader.AtEnd.ShouldBeTrue();
        }
    }

    [Theory]
    [InlineData("a\rb")]
    [InlineData("a\nb")]
    [InlineData("a\0b")]
    [InlineData("café")]
    [InlineData("中文")]
    public void Refuses_a_value_that_would_need_a_literal(string value)
    {
        // A literal is required when the octets contain CR, LF, NUL or 8-bit data.
        // ImapMailboxName.Encode emits printable US-ASCII by construction, so every mailbox name
        // reaching here is quotable - but silently emitting a broken quoted string would
        // desynchronise a client, so this refuses rather than assumes.
        Should.Throw<ArgumentException>(() => ImapAstring.Format(value));
    }

    [Fact]
    public void A_modified_utf7_mailbox_name_is_always_formattable()
    {
        // The guarantee the refusal above leans on, asserted rather than assumed.
        string[] names = ["Entwürfe", "受信箱", "☺", "Gelöscht"];

        foreach (string name in names)
        {
            string encoded = ImapMailboxName.Encode(name);

            Should.NotThrow(() => ImapAstring.Format(encoded));
            ImapMailboxName.TryDecode(encoded, out string? decoded).ShouldBeTrue();
            decoded.ShouldBe(name);
        }
    }

    [Theory]
    [InlineData("INBOX", false)]
    [InlineData("", true)]
    [InlineData("My Folder", true)]
    [InlineData("a\"b", true)]
    [InlineData("a]b", false)]
    public void Reports_whether_a_value_needs_quoting(string value, bool expected) =>
        ImapAstring.NeedsQuoting(value).ShouldBe(expected);

    [Fact]
    public void Rejects_null()
    {
        Should.Throw<ArgumentNullException>(() => ImapAstring.Format(null!));
        Should.Throw<ArgumentNullException>(() => ImapAstring.NeedsQuoting(null!));
    }
}
