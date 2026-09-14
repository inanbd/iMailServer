using MailServer.Domain.Smtp;

namespace MailServer.Smtp.Tests;

public sealed class SmtpReplyTests
{
    [Fact]
    public void A_single_line_reply_has_a_space_after_the_code()
    {
        new SmtpReply(250, "2.0.0", "OK").Format().ShouldBe("250 2.0.0 OK\r\n");
    }

    [Fact]
    public void A_reply_without_an_enhanced_status_omits_it_entirely()
    {
        // 220 greetings and 354 carry no enhanced status. Emitting an empty one would leave a
        // double space that some clients parse as part of the text.
        new SmtpReply(220, null, "mail.example ESMTP ready").Format()
            .ShouldBe("220 mail.example ESMTP ready\r\n");
    }

    [Fact]
    public void Continuation_lines_use_a_hyphen_and_only_the_last_uses_a_space()
    {
        // The single most common way to break a client: a client reads continuation lines until
        // it sees "code<space>", so a missing final space leaves it waiting for a line that
        // never arrives, and a premature one truncates the capability list.
        SmtpReply reply = SmtpReplies.EhloResponse("mail.example", ["PIPELINING", "SIZE 36700160", "STARTTLS"]);

        reply.Format().ShouldBe(
            "250-mail.example greets you\r\n" +
            "250-PIPELINING\r\n" +
            "250-SIZE 36700160\r\n" +
            "250 STARTTLS\r\n");
    }

    [Fact]
    public void An_ehlo_reply_with_no_capabilities_is_a_single_line()
    {
        SmtpReplies.EhloResponse("mail.example", []).Format()
            .ShouldBe("250 mail.example greets you\r\n");
    }

    [Fact]
    public void Every_line_ends_with_crlf()
    {
        string formatted = SmtpReplies.EhloResponse("h", ["A", "B"]).Format();

        formatted.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length.ShouldBe(3);
        formatted.ShouldEndWith("\r\n");
        formatted.Replace("\r\n", string.Empty, StringComparison.Ordinal).ShouldNotContain("\n");
    }

    // ---------------------------------------------------------------------------------------
    // Response splitting.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("evil\r\n250 injected")]
    [InlineData("evil\n250 injected")]
    [InlineData("evil\r250 injected")]
    [InlineData("evil\0250 injected")]
    public void Control_characters_in_peer_supplied_text_cannot_add_a_line(string hostile)
    {
        // Reply text quotes what the peer sent - an unrecognised command, an address that would
        // not parse. If the peer could put a line ending in it, it could make this server emit
        // a reply line of its choosing, and a client acts on reply codes.
        string formatted = SmtpReplies.CommandNotRecognised(hostile).Format();

        formatted.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length.ShouldBe(1);
        formatted.ShouldBe("500 5.5.1 Command not recognised: evil250 injected\r\n");
    }

    [Fact]
    public void Line_structure_comes_only_from_the_continuation_list()
    {
        // Stated as its own test because it is the property the whole design rests on: Text is
        // one line, always, no matter what it contains.
        SmtpReply reply = new(250, "2.0.0", "first\r\nsecond\r\nthird");

        reply.Format().ShouldBe("250 2.0.0 firstsecondthird\r\n");
    }

    [Fact]
    public void A_hostile_capability_name_cannot_forge_a_final_line()
    {
        // Capabilities are server-controlled today, but a future extension could echo something
        // configured by an operator, and a line ending there would end the reply early.
        SmtpReply reply = SmtpReplies.EhloResponse("h", ["GOOD", "BAD\r\n250 OK", "LAST"]);

        reply.Format().ShouldBe(
            "250-h greets you\r\n" +
            "250-GOOD\r\n" +
            "250-BAD250 OK\r\n" +
            "250 LAST\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // The reply vocabulary. Codes chosen wrongly either lose mail or wedge a queue.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Relay_refusal_is_a_permanent_554_with_the_relaying_denied_status()
    {
        SmtpReply reply = SmtpReplies.RelayDenied("not a hosted domain");

        reply.Code.ShouldBe(554);
        reply.EnhancedStatus.ShouldBe("5.7.1");
        reply.IsPermanentFailure.ShouldBeTrue();
    }

    [Fact]
    public void A_full_mailbox_is_transient_so_the_sender_keeps_the_message()
    {
        // 4xx, not 5xx. A full mailbox is fixable; bouncing permanently destroys mail that a
        // few minutes of tidying would have let through.
        SmtpReply reply = SmtpReplies.MailboxFull("user@example.com");

        reply.IsTransientFailure.ShouldBeTrue();
        reply.IsPermanentFailure.ShouldBeFalse();
        reply.Code.ShouldBe(452);
    }

    [Fact]
    public void An_unknown_mailbox_is_permanent_so_the_sender_stops_retrying()
    {
        // 5xx, not 4xx. Retrying for five days against an address that does not exist wastes
        // the sender's queue and delays the bounce the human actually needs to see.
        SmtpReplies.MailboxNotFound("nobody@example.com").IsPermanentFailure.ShouldBeTrue();
    }

    [Fact]
    public void An_oversized_message_is_permanent_but_too_many_recipients_is_not()
    {
        // Size will not change on retry. A recipient cap is this server's own throttle, and the
        // sender can succeed by splitting the message, so it must not be a bounce.
        SmtpReplies.MessageTooLarge(1024).IsPermanentFailure.ShouldBeTrue();
        SmtpReplies.TooManyRecipients(100).IsTransientFailure.ShouldBeTrue();
    }

    [Fact]
    public void Shutdown_and_timeout_are_transient_so_mail_is_not_lost_to_a_restart()
    {
        SmtpReplies.ShuttingDown("mail.example").IsTransientFailure.ShouldBeTrue();
        SmtpReplies.Timeout().IsTransientFailure.ShouldBeTrue();
        SmtpReplies.TooManyConnections().IsTransientFailure.ShouldBeTrue();
        SmtpReplies.LocalError("disk").IsTransientFailure.ShouldBeTrue();
    }

    [Fact]
    public void The_data_prompt_is_intermediate()
    {
        SmtpReply reply = SmtpReplies.StartMailInput();

        reply.Code.ShouldBe(354);
        reply.IsIntermediate.ShouldBeTrue();
        reply.IsSuccess.ShouldBeFalse();
    }

    [Fact]
    public void Authentication_failure_uses_5_7_8_so_a_client_stops_rather_than_retrying()
    {
        SmtpReply reply = SmtpReplies.AuthenticationFailed();

        reply.Code.ShouldBe(535);
        reply.EnhancedStatus.ShouldBe("5.7.8");
    }

    [Fact]
    public void No_reply_in_the_vocabulary_leaks_a_credential_or_a_key()
    {
        // Brief rule 77. The reply vocabulary is the server's entire externally visible
        // language, so it is the right place to assert that none of it can carry a secret.
        SmtpReply[] all =
        [
            SmtpReplies.Ok(),
            SmtpReplies.Greeting("h", "p"),
            SmtpReplies.Closing("h"),
            SmtpReplies.StartMailInput(),
            SmtpReplies.ReadyForTls(),
            SmtpReplies.MessageAccepted("id"),
            SmtpReplies.AuthenticationRequired(),
            SmtpReplies.AuthenticationFailed(),
            SmtpReplies.TlsRequired(),
            SmtpReplies.LineTooLong(4096),
            SmtpReplies.Timeout(),
            SmtpReplies.ShuttingDown("mail.example"),
        ];

        foreach (SmtpReply reply in all)
        {
            string text = reply.Format();

            text.ShouldNotContain("password", Case.Insensitive);
            text.ShouldNotContain("PRIVATE KEY", Case.Insensitive);
            text.ShouldNotContain("secret", Case.Insensitive);
        }
    }

    [Fact]
    public void Authentication_failure_does_not_say_whether_the_account_exists()
    {
        // A reply that distinguished "no such user" from "wrong password" would be an account
        // enumeration oracle, which is the same reason VRFY is refused.
        string text = SmtpReplies.AuthenticationFailed().Format();

        text.ShouldNotContain("no such", Case.Insensitive);
        text.ShouldNotContain("unknown user", Case.Insensitive);
        text.ShouldNotContain("wrong password", Case.Insensitive);
    }
}
