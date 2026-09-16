using System.Text;
using MailServer.Domain.Mail;

namespace MailServer.Authentication.Tests;

public class RawMessageHeadersTests
{
    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void Parses_simple_headers_and_locates_the_body_boundary()
    {
        byte[] buffer = Ascii("From: alice@example.com\r\nTo: bob@example.com\r\n\r\nBody text.");

        bool ok = RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error);

        ok.ShouldBeTrue(error);
        headers!.Fields.Count.ShouldBe(2);
        headers.Fields[0].Name.ShouldBe("From");
        headers.Fields[1].Name.ShouldBe("To");
        headers.HeaderBlockLength.ShouldBe(buffer.Length - "Body text.".Length);

        string bodyStart = Encoding.ASCII.GetString(buffer, headers.HeaderBlockLength, "Body text.".Length);
        bodyStart.ShouldBe("Body text.");
    }

    [Fact]
    public void Joins_a_folded_continuation_line_into_a_single_field()
    {
        byte[] buffer = Ascii("Subject: Hello,\r\n World\r\n\r\n");

        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error).ShouldBeTrue(error);

        headers!.Fields.Count.ShouldBe(1);
        headers.Fields[0].Name.ShouldBe("Subject");

        string raw = Encoding.ASCII.GetString(headers.Fields[0].RawBytes.Span);
        raw.ShouldBe("Subject: Hello,\r\n World\r\n");
    }

    [Fact]
    public void Captures_repeated_header_names_in_wire_order_for_oversigning()
    {
        byte[] buffer = Ascii("Received: first\r\nReceived: second\r\nFrom: a@b.example\r\n\r\n");

        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out _).ShouldBeTrue();

        var received = headers!.GetAll("received").ToList();
        received.Count.ShouldBe(2);
        Encoding.ASCII.GetString(received[0].RawBytes.Span).ShouldBe("Received: first\r\n");
        Encoding.ASCII.GetString(received[1].RawBytes.Span).ShouldBe("Received: second\r\n");
    }

    [Fact]
    public void GetAll_is_case_insensitive()
    {
        byte[] buffer = Ascii("FROM: a@b.example\r\n\r\n");

        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out _).ShouldBeTrue();

        headers!.GetAll("from").Count().ShouldBe(1);
    }

    [Fact]
    public void An_empty_header_block_still_locates_the_body()
    {
        byte[] buffer = Ascii("\r\nBody.");

        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error).ShouldBeTrue(error);

        headers!.Fields.ShouldBeEmpty();
        headers.HeaderBlockLength.ShouldBe(2);
    }

    [Fact]
    public void Fails_when_the_buffer_ends_before_the_terminating_blank_line()
    {
        byte[] buffer = Ascii("From: a@b.example\r\nTo: c@d.example\r\n");

        bool ok = RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error);

        ok.ShouldBeFalse();
        headers.ShouldBeNull();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Fails_when_a_folded_field_runs_past_the_end_of_the_buffer()
    {
        byte[] buffer = Ascii("Subject: Hello,\r\n World");

        bool ok = RawMessageHeaders.TryParse(buffer, out _, out string? error);

        ok.ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Fails_on_a_line_with_no_colon()
    {
        byte[] buffer = Ascii("This is not a header\r\n\r\n");

        bool ok = RawMessageHeaders.TryParse(buffer, out _, out string? error);

        ok.ShouldBeFalse();
        error.ShouldNotBeNull();
    }
}
