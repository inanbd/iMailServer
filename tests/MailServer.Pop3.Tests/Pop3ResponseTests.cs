using MailServer.Domain.Pop3;

namespace MailServer.Pop3.Tests;

public sealed class Pop3ResponseTests
{
    /// <summary>
    /// RFC 1939 §3: "There are currently two status indicators: positive ("+OK") and negative
    /// ("-ERR"). Servers MUST send the "+OK" and "-ERR" in upper case."
    /// </summary>
    [Fact]
    public void The_status_indicators_are_upper_case()
    {
        Pop3Response.Ok("ready").Format().ShouldBe("+OK ready\r\n");
        Pop3Response.Error("no").Format().ShouldBe("-ERR no\r\n");
    }

    /// <summary>§3: "All responses are terminated by a CRLF pair."</summary>
    [Fact]
    public void Every_status_line_ends_with_one_crlf() =>
        Pop3Response.Ok("x").Format().ShouldEndWith("\r\n");

    /// <summary>A response with nothing to say is the indicator alone.</summary>
    [Fact]
    public void An_empty_text_leaves_the_indicator_alone() =>
        Pop3Response.Ok(string.Empty).Format().ShouldBe("+OK\r\n");

    /// <summary>
    /// A CR or LF in the text would end the response early and turn whatever followed into a
    /// second response — the injection this sanitisation exists to prevent.
    /// </summary>
    [Theory]
    [InlineData("one\r\ntwo")]
    [InlineData("one\rtwo")]
    [InlineData("one\ntwo")]
    [InlineData("one\u0000two")]
    public void A_line_ending_in_the_text_cannot_reach_the_wire(string text)
    {
        string wire = Pop3Response.Ok(text).Format();

        wire.ShouldBe("+OK onetwo\r\n");
        wire.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length.ShouldBe(1);
    }

    /// <summary>
    /// RFC 2449 §8: "any response text issued by this server which begins with an open square
    /// bracket ("[") is an extended response code". A server that advertises RESP-CODES and then
    /// let ordinary text start with a bracket would have that text read as a code.
    /// </summary>
    [Fact]
    public void A_bracket_in_ordinary_text_is_dropped() =>
        Pop3Response.Error("[IN-USE] pretending").Format().ShouldBe("-ERR IN-USE pretending\r\n");

    /// <summary>
    /// §8: "an optional response code, enclosed in square brackets, at the beginning of the human
    /// readable text portion". The brackets come from the response rather than from the text.
    /// </summary>
    [Fact]
    public void A_response_code_is_bracketed_before_the_text() =>
        Pop3Response.ErrorWithCode("IN-USE", "Maildrop is locked")
            .Format()
            .ShouldBe("-ERR [IN-USE] Maildrop is locked\r\n");

    /// <summary>
    /// §3: <c>resp-code = "[" resp-level *("/" resp-level) "]"</c>, so a slash separates levels
    /// and is kept.
    /// </summary>
    [Fact]
    public void A_hierarchical_response_code_keeps_its_slash() =>
        Pop3Response.ErrorWithCode("SYS/TEMP", "try later")
            .Format()
            .ShouldBe("-ERR [SYS/TEMP] try later\r\n");

    /// <summary>A bracket inside a code would close it early, so it is dropped.</summary>
    [Fact]
    public void A_bracket_inside_a_response_code_is_dropped() =>
        Pop3Response.ErrorWithCode("IN]USE", "x").Format().ShouldBe("-ERR [INUSE] x\r\n");

    /// <summary>
    /// RFC 2449 §4: "The maximum length of the first line of a command response (including the
    /// initial greeting) is unchanged at 512 octets (including the terminating CRLF)."
    /// </summary>
    [Fact]
    public void A_status_line_stays_inside_the_length_limit() =>
        Pop3Response.Ok(new string('x', 4_000)).Format().Length
            .ShouldBeLessThanOrEqualTo(Pop3Response.MaxLineOctets);

    /// <summary>
    /// RFC 2449 §6: "Clients discover server support of APOP by the presence in the greeting
    /// banner of an initial challenge enclosed in angle brackets ("&lt;&gt;")." This server
    /// cannot perform APOP, so its greeting must never contain one.
    /// </summary>
    [Theory]
    [InlineData("AetherMail")]
    [InlineData("AetherMail <1896.697170952@dbc.mtview.ca.us>")]
    [InlineData("<>")]
    public void The_greeting_never_carries_an_apop_challenge(string product)
    {
        string wire = Pop3Responses.Greeting(product).Format();

        wire.ShouldStartWith("+OK ");
        wire.Contains('<', StringComparison.Ordinal).ShouldBeFalse("an angle bracket offers APOP");
        wire.Contains('>', StringComparison.Ordinal).ShouldBeFalse("an angle bracket offers APOP");
    }

    /// <summary>A product name that sanitises away still leaves a usable greeting.</summary>
    [Fact]
    public void A_greeting_with_no_product_still_says_something() =>
        Pop3Responses.Greeting("<>").Format().ShouldBe("+OK POP3 server ready\r\n");

    /// <summary>
    /// §5 on <c>STAT</c>: "the number of messages in the maildrop, a single space, and the size
    /// of the maildrop in octets. […] This memo STRONGLY discourages implementations from
    /// supplying additional information in the drop listing."
    /// </summary>
    [Fact]
    public void The_drop_listing_is_two_numbers_and_nothing_else() =>
        Pop3Responses.Stat(2, 320).Format().ShouldBe("+OK 2 320\r\n");

    /// <summary>
    /// §5 on <c>LIST</c>: "A scan listing consists of the message-number of the message, followed
    /// by a single space and the exact size of the message in octets."
    /// </summary>
    [Fact]
    public void A_scan_listing_is_a_number_and_a_size() =>
        Pop3Responses.ScanLine(2, 200).ShouldBe("2 200");

    /// <summary>
    /// §7 on <c>UIDL</c>: "the message-number of the message, followed by a single space and the
    /// unique-id of the message. No information follows the unique-id".
    /// </summary>
    [Fact]
    public void A_unique_id_listing_is_a_number_and_an_id() =>
        Pop3Responses.UniqueLine(2, "3857529045.7").ShouldBe("2 3857529045.7");

    /// <summary>
    /// A record's generated <c>ToString</c> would print the unsanitised text, which would put a
    /// CR or LF into a log line that the wire form would never carry.
    /// </summary>
    [Fact]
    public void Rendering_a_response_as_text_is_as_safe_as_the_wire_form() =>
        Pop3Response.Ok("one\r\ntwo").ToString()
            .Contains('\n', StringComparison.Ordinal)
            .ShouldBeFalse("a rendered response must not carry a line ending");
}
