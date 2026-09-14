using System.Text;
using MailServer.Domain.Smtp;

namespace MailServer.Smtp.Tests;

/// <summary>
/// The end-of-DATA scanner and the body normaliser.
/// </summary>
/// <remarks>
/// <c>docs/SMTP.md</c> names dot-stuffing as hard part number one, and these tests are the
/// reason: every case below is one where a plausible implementation is wrong in a way that
/// either truncates mail or executes attacker-supplied commands.
/// </remarks>
public sealed class SmtpDataDecoderTests
{
    /// <summary>Feeds a whole message through in one chunk.</summary>
    private static (string Body, bool Complete, int Consumed) Decode(string wire)
    {
        byte[] input = Encoding.UTF8.GetBytes(wire);
        return DecodeChunks([input]);
    }

    /// <summary>
    /// Feeds a message in arbitrary chunks, which is how it actually arrives.
    /// </summary>
    private static (string Body, bool Complete, int Consumed) DecodeChunks(IReadOnlyList<byte[]> chunks)
    {
        SmtpDataDecoder decoder = new();
        MemoryStream body = new();

        bool complete = false;
        int consumedTotal = 0;

        foreach (byte[] chunk in chunks)
        {
            if (complete)
            {
                break;
            }

            byte[] output = new byte[SmtpDataDecoder.MaxOutputFor(chunk.Length)];

            complete = decoder.Decode(chunk, output, out int consumed, out int written);

            body.Write(output, 0, written);
            consumedTotal += consumed;
        }

        return (Encoding.UTF8.GetString(body.ToArray()), complete, consumedTotal);
    }

    /// <summary>Splits a message into chunks of a fixed size to exercise the carry-over state.</summary>
    private static IReadOnlyList<byte[]> Split(string wire, int chunkSize)
    {
        byte[] all = Encoding.UTF8.GetBytes(wire);
        List<byte[]> chunks = [];

        for (int offset = 0; offset < all.Length; offset += chunkSize)
        {
            chunks.Add(all[offset..Math.Min(offset + chunkSize, all.Length)]);
        }

        return chunks;
    }

    [Fact]
    public void A_plain_message_decodes_to_its_body()
    {
        (string body, bool complete, _) = Decode("Subject: hello\r\n\r\nBody text\r\n.\r\n");

        complete.ShouldBeTrue();
        body.ShouldBe("Subject: hello\r\n\r\nBody text\r\n");
    }

    [Fact]
    public void The_crlf_before_the_marker_belongs_to_the_body()
    {
        // The last line of the message is a line, and a line ends with CRLF. A decoder that
        // treated the whole five octets as marker would strip the final line ending off every
        // message it ever received.
        (string body, _, _) = Decode("one\r\n.\r\n");

        body.ShouldBe("one\r\n");
    }

    [Fact]
    public void A_message_with_no_content_is_empty_not_a_dot()
    {
        // ".CRLF" as the entire DATA content. The decoder starts at a line start, so this is
        // the marker, not a body consisting of a dot.
        (string body, bool complete, _) = Decode(".\r\n");

        complete.ShouldBeTrue();
        body.ShouldBe(string.Empty);
    }

    [Fact]
    public void A_stuffed_dot_line_is_unstuffed()
    {
        (string body, _, _) = Decode("before\r\n..\r\nafter\r\n.\r\n");

        body.ShouldBe("before\r\n.\r\nafter\r\n");
    }

    [Fact]
    public void A_body_containing_the_marker_sequence_does_not_truncate()
    {
        // The case docs/SMTP.md calls out. The sender stuffed it, so the octets on the wire are
        // "CRLF .. CRLF"; the true content is "CRLF . CRLF" and the message continues past it.
        (string body, bool complete, _) = Decode("head\r\n..\r\ntail\r\n.\r\n");

        complete.ShouldBeTrue();
        body.ShouldBe("head\r\n.\r\ntail\r\n");
        body.ShouldContain("\r\n.\r\n");
    }

    [Fact]
    public void Exactly_one_dot_is_removed()
    {
        (string body, _, _) = Decode("...\r\n.\r\n");

        body.ShouldBe("..\r\n");
    }

    [Fact]
    public void A_leading_dot_on_the_very_first_line_is_unstuffed()
    {
        (string body, _, _) = Decode("..signature\r\n.\r\n");

        body.ShouldBe(".signature\r\n");
    }

    [Fact]
    public void A_dot_that_is_not_at_a_line_start_is_content()
    {
        (string body, _, _) = Decode("a.b.c\r\n.\r\n");

        body.ShouldBe("a.b.c\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // SMTP smuggling. These are the tests that matter most.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("\n.\n")]      // bare LF either side
    [InlineData("\r\n.\n")]    // CRLF then bare LF
    [InlineData("\n.\r\n")]    // bare LF then CRLF
    [InlineData("\r.\r\n")]    // lone CR then CRLF
    [InlineData("\r\n.\r")]    // no closing LF at all
    public void Only_the_exact_crlf_dot_crlf_sequence_ends_a_message(string nearMiss)
    {
        // SMTP smuggling (2023): a server that accepts a near-miss as end-of-data, while the
        // next hop accepts only the real thing (or vice versa), lets an attacker append a
        // second, forged message to a legitimate one. The near miss must be content.
        string wire = $"legitimate{nearMiss}MAIL FROM:<attacker@evil.example>\r\n.\r\n";

        (string body, bool complete, int consumed) = Decode(wire);

        complete.ShouldBeTrue();
        consumed.ShouldBe(Encoding.UTF8.GetByteCount(wire));
        body.ShouldContain(
            "MAIL FROM:<attacker@evil.example>",
            customMessage:
                "The injected command must be part of the message body, never executed as a command.");
    }

    [Fact]
    public void Normalisation_runs_after_termination_not_before()
    {
        // The ordering test, stated directly. "\n.\n" normalises to "\r\n.\r\n", so an
        // implementation that normalised first would find a marker here that never arrived and
        // would hand the remainder to the command parser.
        (string body, bool complete, _) = Decode("x\n.\ny\r\n.\r\n");

        complete.ShouldBeTrue();
        body.ShouldBe("x\r\n\r\ny\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // Line-ending normalisation.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Bare_line_feeds_are_normalised_to_crlf()
    {
        (string body, _, _) = Decode("one\ntwo\nthree\r\n.\r\n");

        body.ShouldBe("one\r\ntwo\r\nthree\r\n");
    }

    [Fact]
    public void A_lone_carriage_return_is_normalised_to_crlf()
    {
        (string body, _, _) = Decode("old\rmac\r\n.\r\n");

        body.ShouldBe("old\r\nmac\r\n");
    }

    [Fact]
    public void Normalisation_does_not_corrupt_the_content_around_it()
    {
        // The requirement in docs/SMTP.md is that bare LF is normalised "without corrupting
        // content". Every octet that is not a line ending must survive unchanged.
        (string body, _, _) = Decode("héllo\nwörld — ünicode\r\n.\r\n");

        body.ShouldBe("héllo\r\nwörld — ünicode\r\n");
    }

    [Fact]
    public void Consecutive_bare_line_feeds_each_become_a_crlf()
    {
        (string body, _, _) = Decode("a\n\n\nb\r\n.\r\n");

        body.ShouldBe("a\r\n\r\n\r\nb\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // Chunking. The state machine must not depend on where the packet boundaries fall.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(64)]
    public void The_result_is_the_same_whatever_the_chunk_size(int chunkSize)
    {
        const string Wire = "From: a@b.example\r\n\r\n..dotted\r\nplain\nmixed\r\n..\r\nend\r\n.\r\n";

        (string body, bool complete, int consumed) = DecodeChunks(Split(Wire, chunkSize));

        complete.ShouldBeTrue();
        consumed.ShouldBe(Encoding.UTF8.GetByteCount(Wire));
        body.ShouldBe("From: a@b.example\r\n\r\n.dotted\r\nplain\r\nmixed\r\n.\r\nend\r\n");
    }

    [Fact]
    public void A_marker_split_across_every_boundary_is_still_recognised()
    {
        // Five octets, so five ways to cut it in two. Each one exercises a different held-back
        // state, and a decoder that only looked at the current buffer would miss at least one.
        const string Wire = "body\r\n.\r\n";

        for (int cut = 1; cut < Wire.Length; cut++)
        {
            byte[] all = Encoding.UTF8.GetBytes(Wire);

            (string body, bool complete, _) = DecodeChunks([all[..cut], all[cut..]]);

            complete.ShouldBeTrue(customMessage: $"Cut at {cut} did not complete.");
            body.ShouldBe("body\r\n", customMessage: $"Cut at {cut} produced the wrong body.");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Accounting and misuse.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Octets_after_the_marker_are_not_consumed()
    {
        // PIPELINING puts the next command in the same packet as the end of the message. Those
        // octets belong to the session; folding them into the body loses a command, and
        // consuming them silently loses it without trace.
        const string Wire = "hi\r\n.\r\nQUIT\r\n";

        (string body, bool complete, int consumed) = Decode(Wire);

        complete.ShouldBeTrue();
        body.ShouldBe("hi\r\n");
        consumed.ShouldBe(Encoding.UTF8.GetByteCount("hi\r\n.\r\n"));
    }

    [Fact]
    public void The_raw_count_charges_the_sender_for_everything_sent()
    {
        // Size limits are enforced on the raw count. If they were enforced on the decoded body,
        // a sender could exceed the limit by padding with octets the decoder discards - stuffed
        // dots, for instance.
        SmtpDataDecoder decoder = new();

        byte[] input = Encoding.UTF8.GetBytes("..\r\n..\r\n.\r\n");
        byte[] output = new byte[SmtpDataDecoder.MaxOutputFor(input.Length)];

        decoder.Decode(input, output, out _, out _).ShouldBeTrue();

        decoder.RawByteCount.ShouldBe(input.Length);
        decoder.BodyByteCount.ShouldBe(6L);   // ".\r\n.\r\n"
        decoder.RawByteCount.ShouldBeGreaterThan(decoder.BodyByteCount);
    }

    [Fact]
    public void Decoding_after_completion_is_refused()
    {
        // A caller that kept feeding would append the next command to the message body. The
        // decoder refuses rather than letting that happen quietly.
        SmtpDataDecoder decoder = new();

        byte[] input = Encoding.UTF8.GetBytes("x\r\n.\r\n");
        byte[] output = new byte[SmtpDataDecoder.MaxOutputFor(input.Length)];

        decoder.Decode(input, output, out _, out _).ShouldBeTrue();

        Should.Throw<InvalidOperationException>(
            () => decoder.Decode("QUIT\r\n"u8, output, out _, out _));
    }

    [Fact]
    public void An_undersized_output_buffer_is_refused_rather_than_overrun()
    {
        SmtpDataDecoder decoder = new();
        byte[] tooSmall = new byte[2];

        Should.Throw<ArgumentException>(
            () => decoder.Decode("hello\r\n.\r\n"u8, tooSmall, out _, out _));
    }

    [Fact]
    public void The_output_bound_covers_the_worst_case()
    {
        // Every octet a bare LF, which doubles. If MaxOutputFor were wrong the decoder would
        // write past the end of a correctly sized caller buffer.
        byte[] input = Encoding.UTF8.GetBytes(new string('\n', 512) + "\r\n.\r\n");
        byte[] output = new byte[SmtpDataDecoder.MaxOutputFor(input.Length)];

        SmtpDataDecoder decoder = new();
        decoder.Decode(input, output, out _, out int written).ShouldBeTrue();

        written.ShouldBeLessThanOrEqualTo(output.Length);
        written.ShouldBe(1026);   // 512 CRLFs, plus the CRLF that ends the last line
    }
}
