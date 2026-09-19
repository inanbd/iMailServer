using System.Text;
using MailServer.Domain.Pop3;

namespace MailServer.Pop3.Tests;

public sealed class Pop3DotStuffingTests
{
    private static string Frame(string body) =>
        Encoding.Latin1.GetString(Pop3DotStuffing.Frame(Encoding.Latin1.GetBytes(body)).Span);

    private static string Top(string message, int lines) =>
        Encoding.Latin1.GetString(Pop3DotStuffing.Top(Encoding.Latin1.GetBytes(message), lines).Span);

    /// <summary>
    /// RFC 1939 §3: "a multi-line response is terminated with the five octets "CRLF.CRLF"."
    /// </summary>
    [Fact]
    public void A_body_is_terminated_with_the_five_octets_the_specification_names() =>
        Frame("hello\r\n").ShouldBe("hello\r\n.\r\n");

    /// <summary>
    /// §3: "If any line of the multi-line response begins with the termination octet, the line is
    /// "byte-stuffed" by pre-pending the termination octet to that line of the response." Without
    /// this the response ends at that line and the rest of the message is read as protocol.
    /// </summary>
    [Fact]
    public void A_line_that_begins_with_a_stop_is_stuffed() =>
        Frame("one\r\n.two\r\nthree\r\n").ShouldBe("one\r\n..two\r\nthree\r\n.\r\n");

    /// <summary>The first line of a body is a line too.</summary>
    [Fact]
    public void A_body_that_begins_with_a_stop_is_stuffed() =>
        Frame(".signature\r\n").ShouldBe("..signature\r\n.\r\n");

    /// <summary>
    /// A line that is only a stop is the exact shape of the terminator, and is the case that
    /// would end the response mid-message.
    /// </summary>
    [Fact]
    public void A_line_that_is_only_a_stop_is_stuffed() =>
        Frame("one\r\n.\r\ntwo\r\n").ShouldBe("one\r\n..\r\ntwo\r\n.\r\n");

    /// <summary>
    /// A stop that is not at the start of a line is content. A client removes one leading stop
    /// from every line it receives, so stuffing one here would corrupt the message silently.
    /// </summary>
    [Fact]
    public void A_stop_inside_a_line_is_left_alone() =>
        Frame("see fig. 1\r\n").ShouldBe("see fig. 1\r\n.\r\n");

    /// <summary>
    /// A message written by local delivery may use bare line feeds, and a scan that knew only
    /// CRLF would leave the stop on such a line unstuffed — which is the desynchronisation this
    /// whole file exists to prevent.
    /// </summary>
    [Fact]
    public void A_bare_line_feed_still_starts_a_line() =>
        Frame("one\n.two\n").ShouldBe("one\n..two\n.\r\n");

    /// <summary>
    /// §3's terminator has to begin a line, so a body whose last line was never terminated gets
    /// a line ending before it. Without one the client reads the stop as part of the message and
    /// then waits for an end that never comes.
    /// </summary>
    [Fact]
    public void A_body_with_no_final_line_ending_gets_one() =>
        Frame("no newline").ShouldBe("no newline\r\n.\r\n");

    /// <summary>An empty body is a multi-line response with no lines in it.</summary>
    [Fact]
    public void An_empty_body_is_just_the_terminator() =>
        Frame(string.Empty).ShouldBe(".\r\n");

    // -------------------------------------------------------------------------------------------
    // TOP.
    // -------------------------------------------------------------------------------------------

    private const string Message =
        "Subject: hello\r\n" +
        "From: a@b.test\r\n" +
        "\r\n" +
        "one\r\n" +
        "two\r\n" +
        "three\r\n";

    /// <summary>
    /// §7: "the POP3 server sends the headers of the message, the blank line separating the
    /// headers from the body, and then the number of lines of the indicated message's body".
    /// </summary>
    [Fact]
    public void Top_sends_the_header_the_blank_line_and_the_lines_asked_for() =>
        Top(Message, 2).ShouldBe("Subject: hello\r\nFrom: a@b.test\r\n\r\none\r\ntwo\r\n");

    /// <summary>
    /// §7 makes the count "a non-negative number of lines", so zero is how a client asks for the
    /// header alone — which is what most clients do first, and what makes TOP worth having.
    /// </summary>
    [Fact]
    public void Top_with_no_lines_is_the_header_alone() =>
        Top(Message, 0).ShouldBe("Subject: hello\r\nFrom: a@b.test\r\n\r\n");

    /// <summary>
    /// §7: "if the number of lines requested by the POP3 client is greater than than the number
    /// of lines in the body, then the POP3 server sends the entire message."
    /// </summary>
    [Fact]
    public void Top_with_more_lines_than_the_body_has_sends_the_whole_message() =>
        Top(Message, 100).ShouldBe(Message);

    /// <summary>A message that is all header has no body lines to send.</summary>
    [Fact]
    public void Top_of_a_message_with_no_body_is_the_message() =>
        Top("Subject: bare\r\n", 5).ShouldBe("Subject: bare\r\n");

    /// <summary>A final body line with no terminator is still a line.</summary>
    [Fact]
    public void Top_counts_an_unterminated_final_line() =>
        Top("Subject: x\r\n\r\none\r\ntwo", 2).ShouldBe("Subject: x\r\n\r\none\r\ntwo");

    /// <summary>Bare line feeds delimit the header and the body lines just as CRLF does.</summary>
    [Fact]
    public void Top_accepts_bare_line_feeds() =>
        Top("Subject: x\n\none\ntwo\nthree\n", 1).ShouldBe("Subject: x\n\none\n");

    [Fact]
    public void Top_refuses_a_negative_line_count() =>
        Should.Throw<ArgumentOutOfRangeException>(() =>
            Pop3DotStuffing.Top(Encoding.Latin1.GetBytes(Message), -1));
}
