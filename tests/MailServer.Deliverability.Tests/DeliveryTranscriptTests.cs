using MailServer.Domain.Deliverability;
using MailServer.Domain.Smtp;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// The record of one SMTP conversation. What an operator reads when a receiver is refusing
/// them, so every derived value here is one they will act on.
/// </summary>
public sealed class DeliveryTranscriptTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 20, 10, 0, 0, TimeSpan.Zero);

    private static SmtpReply Reply(int code, string text, params string[] continuations) =>
        new(code, null, text) { ContinuationLines = continuations };

    /// <summary>A whole successful conversation over TLS, as the client records one.</summary>
    private static DeliveryTranscript Delivered()
    {
        DeliveryTranscript transcript = new();

        transcript.Record(DeliveryStage.Connect, Start, detail: "mx.example.net:25 [203.0.113.9]");
        transcript.Record(DeliveryStage.Banner, Start.AddMilliseconds(40),
            reply: Reply(220, "mx.example.net ESMTP"));
        transcript.Record(DeliveryStage.Ehlo, Start.AddMilliseconds(80),
            "EHLO mail.example.com", Reply(250, "mx.example.net", "SIZE 52428800", "STARTTLS"));
        transcript.Record(DeliveryStage.StartTls, Start.AddMilliseconds(120),
            "STARTTLS", Reply(220, "Ready to start TLS"));
        transcript.Record(DeliveryStage.Handshake, Start.AddMilliseconds(180),
            detail: "Tls13, chain trusted");
        transcript.Record(DeliveryStage.EhloAfterTls, Start.AddMilliseconds(220),
            "EHLO mail.example.com", Reply(250, "mx.example.net", "SIZE 52428800", "8BITMIME"));
        transcript.Record(DeliveryStage.MailFrom, Start.AddMilliseconds(260),
            "MAIL FROM:<postmaster@example.com>", Reply(250, "OK"));
        transcript.Record(DeliveryStage.RcptTo, Start.AddMilliseconds(300),
            "RCPT TO:<someone@example.net>", Reply(250, "OK"));
        transcript.Record(DeliveryStage.Data, Start.AddMilliseconds(340),
            "DATA", Reply(354, "End data with <CRLF>.<CRLF>"));
        transcript.Record(DeliveryStage.Body, Start.AddMilliseconds(380),
            detail: "612 octets sent, DKIM-signed");
        transcript.Record(DeliveryStage.EndOfData, Start.AddMilliseconds(900),
            reply: Reply(250, "2.0.0 OK 1758362400 - gsmtp"));
        transcript.Record(DeliveryStage.Quit, Start.AddMilliseconds(940),
            "QUIT", Reply(221, "closing connection"));

        return transcript;
    }

    // ---------------------------------------------------------------------------------------
    // The timeline.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Steps_come_back_in_the_order_they_happened()
    {
        Delivered().Steps.Select(s => s.Stage).ShouldBe(
        [
            DeliveryStage.Connect,
            DeliveryStage.Banner,
            DeliveryStage.Ehlo,
            DeliveryStage.StartTls,
            DeliveryStage.Handshake,
            DeliveryStage.EhloAfterTls,
            DeliveryStage.MailFrom,
            DeliveryStage.RcptTo,
            DeliveryStage.Data,
            DeliveryStage.Body,
            DeliveryStage.EndOfData,
            DeliveryStage.Quit,
        ]);
    }

    /// <summary>
    /// Elapsed since the first step rather than since the previous one. The thing an operator is
    /// looking for is which single stage took the time, and a greylisting receiver that pauses
    /// before its reply shows up as a jump in this column.
    /// </summary>
    [Fact]
    public void Each_step_is_timed_from_the_start_of_the_conversation()
    {
        IReadOnlyList<DeliveryStepTiming> timed = Delivered().Timed;

        timed[0].Elapsed.ShouldBe(TimeSpan.Zero);
        timed[1].Elapsed.ShouldBe(TimeSpan.FromMilliseconds(40));
        timed[^1].Elapsed.ShouldBe(TimeSpan.FromMilliseconds(940));
    }

    [Fact]
    public void The_duration_spans_the_whole_conversation()
    {
        Delivered().Duration.ShouldBe(TimeSpan.FromMilliseconds(940));
    }

    /// <summary>
    /// A transcript with nothing in it has no duration rather than a zero one. Zero would say
    /// the conversation happened instantly; null says it did not happen.
    /// </summary>
    [Fact]
    public void An_empty_transcript_has_no_duration_and_no_last_stage()
    {
        DeliveryTranscript transcript = new();

        transcript.Steps.ShouldBeEmpty();
        transcript.Timed.ShouldBeEmpty();
        transcript.Duration.ShouldBeNull();
        transcript.LastStage.ShouldBeNull();
        transcript.Banner.ShouldBeNull();
        transcript.FinalReply.ShouldBeNull();
        transcript.Capabilities.ShouldBeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // What the conversation established.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_banner_is_the_remotes_opening_greeting()
    {
        Delivered().Banner.ShouldBe("mx.example.net ESMTP");
    }

    /// <summary>
    /// <b>The capabilities are the ones learned after the handshake.</b> RFC 3207 §4.2 has the
    /// client discard everything it learned before it, so the pre-TLS list is not what this
    /// conversation ran on — and it is also the list a network attacker can edit. Reporting it
    /// would show an operator capabilities their mail was never offered.
    /// </summary>
    [Fact]
    public void The_capabilities_come_from_the_greeting_after_the_upgrade()
    {
        Delivered().Capabilities.ShouldBe(["SIZE 52428800", "8BITMIME"]);
    }

    /// <summary>
    /// A conversation with no upgrade has only one greeting, and that one is what it ran on.
    /// </summary>
    [Fact]
    public void Without_an_upgrade_the_only_greeting_is_the_one_reported()
    {
        DeliveryTranscript transcript = new();

        transcript.Record(DeliveryStage.Banner, Start, reply: Reply(220, "mx"));
        transcript.Record(DeliveryStage.Ehlo, Start, "EHLO mail.example.com",
            Reply(250, "mx", "SIZE 10240"));

        transcript.Capabilities.ShouldBe(["SIZE 10240"]);
    }

    /// <summary>
    /// A stage can speak twice: RFC 5321 §4.1.1.1 has a client that is refused <c>EHLO</c> fall
    /// back to <c>HELO</c>, and both are this conversation's greeting. What the session actually
    /// ran on is the second one, so that is the reply reported — and a refusal's own
    /// continuation lines are not capabilities the session ever had.
    /// </summary>
    [Fact]
    public void A_stage_that_spoke_twice_reports_what_the_session_ran_on()
    {
        DeliveryTranscript transcript = new();

        transcript.Record(DeliveryStage.Banner, Start, reply: Reply(220, "mx"));

        // A multi-line refusal, which real servers do send.
        transcript.Record(DeliveryStage.Ehlo, Start.AddMilliseconds(10),
            "EHLO mail.example.com",
            Reply(500, "Command not recognized", "Try HELO instead", "SIZE 99"));

        transcript.Record(DeliveryStage.Ehlo, Start.AddMilliseconds(20),
            "HELO mail.example.com", Reply(250, "mx"));

        transcript.Capabilities.ShouldBeEmpty();
    }

    /// <summary>
    /// The reply after the terminating dot, not the one after <c>QUIT</c>. RFC 5321 §4.1.1.4
    /// makes the first of those the receiver accepting responsibility for the message; the
    /// second only means the socket closed politely.
    /// </summary>
    [Fact]
    public void The_final_reply_is_the_one_that_decided_delivery()
    {
        SmtpReply final = Delivered().FinalReply.ShouldNotBeNull();

        final.Code.ShouldBe(250);
        final.Text.ShouldBe("2.0.0 OK 1758362400 - gsmtp");
    }

    /// <summary>
    /// Where it stopped is the diagnosis: refused at <c>RCPT TO</c> is the recipient, refused at
    /// <c>MAIL FROM</c> is usually SPF or a blocklist, and stopping at the banner means it never
    /// got to speak.
    /// </summary>
    [Fact]
    public void The_last_stage_is_where_the_conversation_stopped()
    {
        DeliveryTranscript transcript = new();

        transcript.Record(DeliveryStage.Connect, Start);
        transcript.Record(DeliveryStage.Banner, Start, reply: Reply(220, "mx"));
        transcript.Record(DeliveryStage.Ehlo, Start, "EHLO mail.example.com", Reply(250, "mx"));
        transcript.Record(DeliveryStage.MailFrom, Start, "MAIL FROM:<a@b.example>",
            Reply(550, "5.7.1 SPF check failed"));

        transcript.LastStage.ShouldBe(DeliveryStage.MailFrom);
        transcript.FinalReply.ShouldBeNull();
    }

    // ---------------------------------------------------------------------------------------
    // The rendering, which is what gets pasted into a support ticket.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Sent_and_received_lines_are_marked_the_way_a_mail_log_marks_them()
    {
        string[] lines = Delivered().Render()
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.TrimEnd('\r'))
            .ToArray();

        lines.ShouldContain("    80ms > EHLO mail.example.com");
        lines.ShouldContain("    40ms < 220 mx.example.net ESMTP");
    }

    /// <summary>
    /// Continuation lines carry the code and a hyphen, which is how they appear on the wire —
    /// RFC 5321 §4.2.1 — so the rendering can be compared against somebody else's log directly.
    /// </summary>
    [Fact]
    public void Continuation_lines_are_rendered_as_the_wire_carries_them()
    {
        Delivered().Render().ShouldContain("< 250-STARTTLS");
    }

    /// <summary>
    /// A stage that sends nothing and receives nothing still appears. The handshake and the body
    /// are where a conversation most often spends its time, and leaving them out would make the
    /// elapsed column jump with nothing to explain it.
    /// </summary>
    [Fact]
    public void A_stage_with_no_command_and_no_reply_is_still_in_the_timeline()
    {
        string text = Delivered().Render();

        text.ShouldContain("[Handshake] Tls13, chain trusted");
        text.ShouldContain("[Body] 612 octets sent, DKIM-signed");
        text.ShouldContain("[Connect] mx.example.net:25 [203.0.113.9]");
    }

    /// <summary>
    /// Milliseconds, invariant. This text is compared against another operator's log, and a
    /// decimal comma would make two transcripts of the same conversation look different.
    /// </summary>
    [Fact]
    public void The_elapsed_column_is_invariant_milliseconds()
    {
        DeliveryTranscript transcript = new();

        transcript.Record(DeliveryStage.Connect, Start);
        transcript.Record(DeliveryStage.Banner, Start.AddMilliseconds(1234.9), reply: Reply(220, "mx"));

        transcript.Render().ShouldContain("  1234ms < 220 mx");
    }

    /// <summary>
    /// A detail alongside a command or a reply is a note on that line rather than a replacement
    /// for it — otherwise a stage that carried both would lose one of them.
    /// </summary>
    [Fact]
    public void A_detail_on_a_stage_that_also_spoke_is_kept_beside_it()
    {
        DeliveryTranscript transcript = new();

        transcript.Record(
            DeliveryStage.MailFrom,
            Start,
            "MAIL FROM:<a@b.example>",
            Reply(250, "OK"),
            "size advertised");

        string text = transcript.Render();

        text.ShouldContain("> MAIL FROM:<a@b.example>");
        text.ShouldContain("< 250 OK");
        text.ShouldContain("[MailFrom] size advertised");
    }
}
