using MailServer.Domain.Pop3;

namespace MailServer.Pop3.Tests;

public sealed class Pop3CommandTests
{
    private static Pop3Command Parse(string line)
    {
        Pop3Command.TryParse(line, out Pop3Command? command)
            .ShouldBeTrue($"could not parse [{line}]");

        return command!;
    }

    /// <summary>RFC 1939 §3: "Commands in the POP3 consist of a case-insensitive keyword".</summary>
    [Theory]
    [InlineData("USER", Pop3Verb.User)]
    [InlineData("user", Pop3Verb.User)]
    [InlineData("UsEr", Pop3Verb.User)]
    [InlineData("PASS", Pop3Verb.Pass)]
    [InlineData("QUIT", Pop3Verb.Quit)]
    [InlineData("STAT", Pop3Verb.Stat)]
    [InlineData("LIST", Pop3Verb.List)]
    [InlineData("RETR", Pop3Verb.Retr)]
    [InlineData("DELE", Pop3Verb.Dele)]
    [InlineData("NOOP", Pop3Verb.Noop)]
    [InlineData("RSET", Pop3Verb.Rset)]
    [InlineData("TOP", Pop3Verb.Top)]
    [InlineData("UIDL", Pop3Verb.Uidl)]
    [InlineData("CAPA", Pop3Verb.Capa)]
    [InlineData("STLS", Pop3Verb.Stls)]
    [InlineData("APOP", Pop3Verb.Apop)]
    public void Every_keyword_is_matched_without_regard_to_case(string keyword, Pop3Verb expected) =>
        Parse(keyword).Verb.ShouldBe(expected);

    /// <summary>
    /// §3: "Keywords are three or four characters long." A keyword outside that is not a command
    /// this grammar has, so the line does not parse at all rather than parsing as unknown.
    /// </summary>
    [Theory]
    [InlineData("AB")]
    [InlineData("A")]
    [InlineData("TOOLONG")]
    [InlineData("FIVE5")]
    public void A_keyword_of_the_wrong_length_does_not_parse(string line) =>
        Pop3Command.TryParse(line, out _).ShouldBeFalse();

    /// <summary>
    /// A keyword that is well formed but unrecognised parses, so that §3's "unrecognized,
    /// unimplemented, or syntactically invalid" can be answered with a reply that says which.
    /// A keyword of the wrong length is not well formed and does not parse at all — §3 gives
    /// both the same negative status indicator, so only the text differs.
    /// </summary>
    [Theory]
    [InlineData("XYZZ plugh")]
    [InlineData("AUTH PLAIN")]
    [InlineData("UTF8")]
    public void A_well_formed_unknown_keyword_parses_as_unknown(string line) =>
        Parse(line).Verb.ShouldBe(Pop3Verb.Unknown);

    /// <summary>
    /// §7 on <c>PASS</c>: "Since the PASS command has exactly one argument, a POP3 server may
    /// treat spaces in the argument as part of the password, instead of as argument separators."
    /// A parser that tokenised would refuse every passphrase.
    /// </summary>
    [Fact]
    public void The_argument_is_taken_whole_including_its_spaces() =>
        Parse("PASS correct horse battery staple").Argument
            .ShouldBe("correct horse battery staple");

    /// <summary>A command with no argument has an empty one, not a null one.</summary>
    [Fact]
    public void A_command_with_no_argument_has_an_empty_argument() =>
        Parse("STAT").Argument.ShouldBe(string.Empty);

    /// <summary>
    /// §3: keywords and arguments "consist of printable ASCII characters", which is RFC 2449
    /// §3's <c>VCHAR</c>. A control character in either would end the line early if it were
    /// echoed, so the line does not parse.
    /// </summary>
    [Theory]
    [InlineData("USER al\rice")]
    [InlineData("USER al\nice")]
    [InlineData("US\tER alice")]
    [InlineData("USER al\u0000ice")]
    public void A_control_character_anywhere_refuses_the_line(string line) =>
        Pop3Command.TryParse(line, out _).ShouldBeFalse();

    /// <summary>
    /// A non-ASCII octet is not a <c>VCHAR</c> either. A mailbox name is an address, and this
    /// server has no POP3 extension that would make one internationalised.
    /// </summary>
    [Fact]
    public void A_non_ascii_argument_refuses_the_line() =>
        Pop3Command.TryParse("USER café", out _).ShouldBeFalse();

    /// <summary>
    /// RFC 2449 §4: "The maximum length of a command is increased from 47 characters […] to 255
    /// octets, including the terminating CRLF." The reader has already removed the CRLF, so the
    /// text may be 253.
    /// </summary>
    [Fact]
    public void A_line_at_the_limit_parses_and_one_past_it_does_not()
    {
        string atLimit = "PASS " + new string('x', 253 - 5);
        string pastLimit = atLimit + "x";

        atLimit.Length.ShouldBe(253);

        Pop3Command.TryParse(atLimit, out _).ShouldBeTrue();
        Pop3Command.TryParse(pastLimit, out _).ShouldBeFalse();
    }

    [Fact]
    public void An_empty_line_does_not_parse() =>
        Pop3Command.TryParse(string.Empty, out _).ShouldBeFalse();

    /// <summary>The keyword is reported upper-cased, so a refusal cannot echo the peer's case.</summary>
    [Fact]
    public void The_keyword_is_reported_upper_cased() =>
        Parse("uidl 3").Keyword.ShouldBe("UIDL");

    /// <summary>
    /// §5: "In POP3 commands and responses, all message-numbers and message sizes are expressed
    /// in base-10". Read strictly, so that a message cannot be named by two spellings.
    /// </summary>
    [Theory]
    [InlineData("1", 1)]
    [InlineData("0", 0)]
    [InlineData("42", 42)]
    [InlineData("000123", 123)]
    public void A_message_number_is_read_in_base_ten(string text, int expected)
    {
        Pop3Command.TryReadNumber(text, out int number).ShouldBeTrue();
        number.ShouldBe(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("+1")]
    [InlineData("-1")]
    [InlineData("1 ")]
    [InlineData(" 1")]
    [InlineData("1.0")]
    [InlineData("0x1")]
    [InlineData("1234567890")]
    public void Anything_that_is_not_a_base_ten_number_is_refused(string text) =>
        Pop3Command.TryReadNumber(text, out _).ShouldBeFalse();
}
