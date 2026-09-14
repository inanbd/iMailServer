using System.Text;
using MailServer.Domain.Smtp;

namespace MailServer.Smtp.Tests;

/// <summary>
/// Stuffing on send and unstuffing on receipt are two halves of one guarantee, so most of
/// these tests exercise the round trip rather than either half alone.
/// </summary>
public sealed class SmtpDotStuffingTests
{
    private static string Stuff(string body) =>
        Encoding.UTF8.GetString(SmtpDotStuffing.StuffEntireBodyForTesting(Encoding.UTF8.GetBytes(body)));

    /// <summary>Sends a body and decodes what arrives, which is the only test that matters.</summary>
    private static string RoundTrip(string body)
    {
        byte[] wire = SmtpDotStuffing.StuffEntireBodyForTesting(Encoding.UTF8.GetBytes(body));

        SmtpDataDecoder decoder = new();
        byte[] output = new byte[SmtpDataDecoder.MaxOutputFor(wire.Length)];

        decoder.Decode(wire, output, out _, out int written)
            .ShouldBeTrue(customMessage: "The stuffed body did not produce a complete message.");

        return Encoding.UTF8.GetString(output, 0, written);
    }

    [Fact]
    public void A_plain_body_is_unchanged_apart_from_the_marker()
    {
        Stuff("Subject: hi\r\n\r\ntext\r\n").ShouldBe("Subject: hi\r\n\r\ntext\r\n.\r\n");
    }

    [Fact]
    public void A_line_beginning_with_a_dot_is_stuffed()
    {
        Stuff(".signature\r\n").ShouldBe("..signature\r\n.\r\n");
    }

    [Fact]
    public void A_line_that_is_only_a_dot_is_stuffed_and_so_cannot_end_the_message_early()
    {
        // The whole point. Unstuffed, this line is the end-of-data marker and the rest of the
        // message is lost - or worse, executed.
        Stuff("before\r\n.\r\nafter\r\n").ShouldBe("before\r\n..\r\nafter\r\n.\r\n");
    }

    [Fact]
    public void A_dot_in_the_middle_of_a_line_is_left_alone()
    {
        Stuff("see www.example.com\r\n").ShouldBe("see www.example.com\r\n.\r\n");
    }

    [Fact]
    public void A_body_that_does_not_end_with_a_line_ending_gets_one_before_the_marker()
    {
        // Appending ".CRLF" directly would put the dot mid-line, the receiver would never see a
        // marker, and the delivery would hang until the peer's session timeout.
        Stuff("no trailing newline").ShouldBe("no trailing newline\r\n.\r\n");
    }

    [Fact]
    public void An_empty_body_is_just_the_marker()
    {
        Stuff(string.Empty).ShouldBe(".\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // Round trips.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("plain text\r\n")]
    [InlineData(".leading dot\r\n")]
    [InlineData("..two leading dots\r\n")]
    [InlineData("before\r\n.\r\nafter\r\n")]
    [InlineData("before\r\n..\r\nafter\r\n")]
    [InlineData("...\r\n")]
    [InlineData("a\r\n.\r\n.\r\n.\r\nb\r\n")]
    [InlineData("Subject: test\r\n\r\nMAIL FROM:<not@a.command>\r\n")]
    [InlineData("ünicode ünd emoji 📧\r\n")]
    [InlineData("\r\n")]
    [InlineData("")]
    public void What_is_sent_is_what_arrives(string body)
    {
        RoundTrip(body).ShouldBe(body);
    }

    [Fact]
    public void A_body_that_is_an_entire_smtp_conversation_survives_intact()
    {
        // The adversarial round trip: a message whose content is itself a transcript, including
        // an end-of-data marker. If stuffing and unstuffing do not agree exactly, this either
        // truncates or injects.
        const string Body =
            "Here is the transcript you asked for:\r\n" +
            "\r\n" +
            "MAIL FROM:<attacker@evil.example>\r\n" +
            "RCPT TO:<victim@example.com>\r\n" +
            "DATA\r\n" +
            "forged\r\n" +
            ".\r\n" +
            "QUIT\r\n";

        RoundTrip(Body).ShouldBe(Body);
    }

    [Fact]
    public void Stuffing_streams_without_depending_on_chunk_boundaries()
    {
        const string Body = "a\r\n.\r\n.b\r\nc\r\n";

        for (int chunkSize = 1; chunkSize <= Body.Length; chunkSize++)
        {
            SmtpDotStuffing stuffing = new();
            byte[] input = Encoding.UTF8.GetBytes(Body);
            MemoryStream wire = new();

            for (int offset = 0; offset < input.Length; offset += chunkSize)
            {
                ReadOnlySpan<byte> chunk = input.AsSpan(offset, Math.Min(chunkSize, input.Length - offset));
                byte[] output = new byte[SmtpDotStuffing.MaxOutputFor(chunk.Length)];

                wire.Write(output, 0, stuffing.Stuff(chunk, output));
            }

            byte[] marker = new byte[5];
            wire.Write(marker, 0, stuffing.WriteTerminator(marker));

            Encoding.UTF8.GetString(wire.ToArray()).ShouldBe(
                "a\r\n..\r\n..b\r\nc\r\n.\r\n",
                customMessage: $"Chunk size {chunkSize} produced different octets.");
        }
    }

    [Fact]
    public void An_undersized_buffer_is_refused_rather_than_overrun()
    {
        SmtpDotStuffing stuffing = new();

        Should.Throw<ArgumentException>(() => stuffing.Stuff(".\r\n"u8, new byte[2]));
        Should.Throw<ArgumentException>(() => stuffing.WriteTerminator(new byte[4]));
    }

    [Fact]
    public void The_output_bound_covers_the_worst_case()
    {
        // A body of nothing but dot lines, where one octet in three doubles.
        string body = string.Concat(Enumerable.Repeat(".\r\n", 300));
        byte[] input = Encoding.UTF8.GetBytes(body);

        SmtpDotStuffing stuffing = new();
        byte[] output = new byte[SmtpDotStuffing.MaxOutputFor(input.Length)];

        int written = stuffing.Stuff(input, output);

        written.ShouldBe(input.Length + 300);
        written.ShouldBeLessThanOrEqualTo(output.Length);
    }
}
