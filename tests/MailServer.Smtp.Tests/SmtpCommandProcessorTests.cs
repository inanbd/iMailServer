using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

public sealed class SmtpCommandProcessorTests
{
    private const long SizeLimit = 36_700_160;

    private readonly FakeSmtpDirectory _directory = new();

    private SmtpCommandProcessor Processor(
        SmtpListenerRole role = SmtpListenerRole.InboundMta,
        bool tls = false,
        bool authAvailable = false,
        int maxRecipients = 100,
        string remoteAddress = "203.0.113.7")
    {
        SmtpSessionContext session = new(
            role,
            IpAddressValue.Parse(remoteAddress),
            new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero),
            tls);

        SmtpProcessorOptions options = new(
            "mail.example.com",
            "AetherMail",
            maxRecipients,
            SizeLimit,
            authAvailable);

        return new SmtpCommandProcessor(
            session,
            options,
            _directory,
            new RelayPolicy(),
            NullLogger.Instance);
    }

    private static async Task<SmtpReply> SendAsync(SmtpCommandProcessor processor, string line) =>
        (await processor.ExecuteAsync(SmtpCommand.Parse(line), default)).Reply;

    private static async Task<SmtpCommandResult> ExecuteAsync(SmtpCommandProcessor processor, string line) =>
        await processor.ExecuteAsync(SmtpCommand.Parse(line), default);

    /// <summary>Runs a conversation and returns every reply, so a test can read it like a transcript.</summary>
    private static async Task<List<SmtpReply>> ConverseAsync(
        SmtpCommandProcessor processor,
        params string[] lines)
    {
        List<SmtpReply> replies = [];

        foreach (string line in lines)
        {
            replies.Add(await SendAsync(processor, line));
        }

        return replies;
    }

    // ---------------------------------------------------------------------------------------
    // The happy path.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_banner_names_the_host_and_the_product()
    {
        SmtpReply banner = Processor().Banner();

        banner.Code.ShouldBe(220);
        banner.Format().ShouldBe("220 mail.example.com ESMTP AetherMail ready\r\n");
    }

    [Fact]
    public async Task An_inbound_message_for_a_local_mailbox_is_accepted_through_to_data()
    {
        SmtpCommandProcessor processor = Processor();

        List<SmtpReply> replies = await ConverseAsync(
            processor,
            "EHLO relay.example.net",
            "MAIL FROM:<sender@example.net>",
            "RCPT TO:<user@example.com>",
            "DATA");

        replies[0].Code.ShouldBe(250);
        replies[1].Code.ShouldBe(250);
        replies[2].Code.ShouldBe(250);
        replies[3].Code.ShouldBe(354);

        processor.Session.State.ShouldBe(SmtpSessionState.ReceivingData);
        processor.Session.Recipients.Count.ShouldBe(1);
        processor.Session.Recipients[0].Decision.ShouldBe(RelayDecision.AcceptLocal);
    }

    [Fact]
    public async Task Data_asks_the_connection_loop_to_read_the_message()
    {
        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(processor, "EHLO r.example.net", "MAIL FROM:<a@example.net>", "RCPT TO:<user@example.com>");

        SmtpCommandResult result = await ExecuteAsync(processor, "DATA");

        result.Action.ShouldBe(SmtpSessionAction.ReceiveMessageData);
    }

    [Fact]
    public async Task Ehlo_advertises_and_helo_does_not()
    {
        // A HELO client has not asked for extensions and would not understand a multi-line
        // capability list.
        (await SendAsync(Processor(), "EHLO r.example.net")).Format()
            .ShouldContain("250-PIPELINING");

        (await SendAsync(Processor(), "HELO r.example.net")).Format()
            .ShouldBe("250 mail.example.com greets you\r\n");
    }

    [Fact]
    public async Task Ehlo_without_a_name_is_a_syntax_error()
    {
        (await SendAsync(Processor(), "EHLO")).Code.ShouldBe(501);
    }

    // ---------------------------------------------------------------------------------------
    // Relay. The tests that decide whether this product is safe to run.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Port_25_refuses_to_relay_to_a_foreign_domain()
    {
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.InboundMta);

        await ConverseAsync(processor, "EHLO spammer.example.net", "MAIL FROM:<spammer@example.net>");

        SmtpReply reply = await SendAsync(processor, "RCPT TO:<victim@elsewhere.example>");

        reply.Code.ShouldBe(554);
        reply.EnhancedStatus.ShouldBe("5.7.1");
        processor.Session.Recipients.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Port_25_refuses_to_relay_whether_or_not_tls_is_active(bool tls)
    {
        // TLS is confidentiality, not authorisation. A server that relayed for anyone who
        // completed a handshake would be an open relay with a certificate.
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.InboundMta, tls);

        await ConverseAsync(processor, "EHLO spammer.example.net", "MAIL FROM:<s@example.net>");

        (await SendAsync(processor, "RCPT TO:<victim@elsewhere.example>")).Code.ShouldBe(554);
    }

    [Fact]
    public async Task A_refused_recipient_does_not_let_data_through()
    {
        // The state must not advance on a refusal, or DATA would be accepted for a transaction
        // with nowhere to deliver - and a message accepted with no recipients is a message the
        // sender believes was delivered.
        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(
            processor,
            "EHLO spammer.example.net",
            "MAIL FROM:<s@example.net>",
            "RCPT TO:<victim@elsewhere.example>");

        SmtpReply reply = await SendAsync(processor, "DATA");

        reply.Code.ShouldBe(503);
        processor.Session.State.ShouldBe(SmtpSessionState.MailFromAccepted);
    }

    [Fact]
    public async Task An_address_on_the_relay_allow_list_may_relay()
    {
        _directory.AuthorizedRelayAddresses.Add("192.0.2.50");

        SmtpCommandProcessor processor = Processor(remoteAddress: "192.0.2.50");

        await ConverseAsync(processor, "EHLO app.internal.example", "MAIL FROM:<app@example.com>");

        SmtpReply reply = await SendAsync(processor, "RCPT TO:<partner@elsewhere.example>");

        reply.Code.ShouldBe(250);
        processor.Session.Recipients[0].Decision.ShouldBe(RelayDecision.AcceptRelay);
    }

    [Fact]
    public async Task An_address_not_on_the_relay_allow_list_may_not()
    {
        _directory.AuthorizedRelayAddresses.Add("192.0.2.50");

        SmtpCommandProcessor processor = Processor(remoteAddress: "192.0.2.51");

        await ConverseAsync(processor, "EHLO app.internal.example", "MAIL FROM:<app@example.com>");

        (await SendAsync(processor, "RCPT TO:<partner@elsewhere.example>")).Code.ShouldBe(554);
    }

    [Fact]
    public async Task The_directory_is_not_asked_about_a_mailbox_in_a_domain_we_do_not_host()
    {
        // Cheap refusals first. A stranger must not be able to make this server run a mailbox
        // lookup per RCPT for domains it has nothing to do with.
        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(
            processor,
            "EHLO spammer.example.net",
            "MAIL FROM:<s@example.net>",
            "RCPT TO:<a@elsewhere.example>",
            "RCPT TO:<b@elsewhere.example>");

        _directory.RecipientInspections.ShouldBe(0);
    }

    // ---------------------------------------------------------------------------------------
    // Submission listeners fail closed while authentication is unavailable.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(SmtpListenerRole.Submission)]
    [InlineData(SmtpListenerRole.ImplicitTlsSubmission)]
    public async Task A_submission_listener_refuses_an_unauthenticated_sender(SmtpListenerRole role)
    {
        // Refused at MAIL FROM, not left to be refused at RCPT TO. A submission port that
        // accepted unauthenticated mail for local domains would be a port 25 nobody audited.
        SmtpCommandProcessor processor = Processor(role, tls: true);

        await SendAsync(processor, "EHLO client.example.net");

        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<user@example.com>");

        reply.Code.ShouldBe(530);
        processor.Session.HasTransaction.ShouldBeFalse();
    }

    [Fact]
    public async Task A_submission_listener_refuses_even_for_a_local_recipient()
    {
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.Submission, tls: true, authAvailable: true);

        await SendAsync(processor, "EHLO client.example.net");

        (await SendAsync(processor, "MAIL FROM:<user@example.com>")).Code.ShouldBe(530);
    }

    // ---------------------------------------------------------------------------------------
    // Local recipient states, each with the code that makes the sender behave correctly.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_unknown_local_mailbox_is_a_permanent_refusal()
    {
        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(processor, "EHLO r.example.net", "MAIL FROM:<a@example.net>");

        SmtpReply reply = await SendAsync(processor, "RCPT TO:<nobody@example.com>");

        reply.Code.ShouldBe(550);
        reply.EnhancedStatus.ShouldBe("5.1.1");
    }

    [Fact]
    public async Task A_disabled_mailbox_is_a_permanent_refusal_with_its_own_status()
    {
        _directory.Mailboxes["dormant@example.com"] = LocalRecipientStatus.Disabled;

        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(processor, "EHLO r.example.net", "MAIL FROM:<a@example.net>");

        SmtpReply reply = await SendAsync(processor, "RCPT TO:<dormant@example.com>");

        reply.Code.ShouldBe(550);
        reply.EnhancedStatus.ShouldBe("5.2.1");
    }

    [Fact]
    public async Task A_full_mailbox_is_a_transient_refusal_so_the_sender_keeps_the_message()
    {
        _directory.Mailboxes["full@example.com"] = LocalRecipientStatus.OverQuota;

        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(processor, "EHLO r.example.net", "MAIL FROM:<a@example.net>");

        SmtpReply reply = await SendAsync(processor, "RCPT TO:<full@example.com>");

        reply.Code.ShouldBe(452);
        reply.IsTransientFailure.ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // Limits.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_recipient_cap_is_enforced_and_is_transient()
    {
        SmtpCommandProcessor processor = Processor(maxRecipients: 2);

        _directory.Mailboxes["a@example.com"] = LocalRecipientStatus.Deliverable;
        _directory.Mailboxes["b@example.com"] = LocalRecipientStatus.Deliverable;
        _directory.Mailboxes["c@example.com"] = LocalRecipientStatus.Deliverable;

        await ConverseAsync(processor, "EHLO r.example.net", "MAIL FROM:<s@example.net>");

        (await SendAsync(processor, "RCPT TO:<a@example.com>")).Code.ShouldBe(250);
        (await SendAsync(processor, "RCPT TO:<b@example.com>")).Code.ShouldBe(250);

        SmtpReply third = await SendAsync(processor, "RCPT TO:<c@example.com>");

        third.Code.ShouldBe(452);
        processor.Session.Recipients.Count.ShouldBe(2);
    }

    [Fact]
    public async Task A_declared_size_over_the_limit_is_refused_before_the_message_arrives()
    {
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO r.example.net");

        SmtpReply reply = await SendAsync(processor, $"MAIL FROM:<s@example.net> SIZE={SizeLimit + 1}");

        reply.Code.ShouldBe(552);
        processor.Session.HasTransaction.ShouldBeFalse();
    }

    [Fact]
    public async Task A_declared_size_at_the_limit_is_accepted()
    {
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO r.example.net");

        (await SendAsync(processor, $"MAIL FROM:<s@example.net> SIZE={SizeLimit}")).Code.ShouldBe(250);
    }

    // ---------------------------------------------------------------------------------------
    // Sequencing.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("MAIL FROM:<a@example.net>")]
    [InlineData("RCPT TO:<user@example.com>")]
    [InlineData("DATA")]
    [InlineData("STARTTLS")]
    public async Task Commands_before_a_greeting_are_out_of_sequence(string line)
    {
        (await SendAsync(Processor(), line)).Code.ShouldBe(503);
    }

    [Fact]
    public async Task An_unrecognised_command_is_500_not_503()
    {
        // Telling a client its command was out of sequence when the server simply does not know
        // the command sends its operator looking for a sequencing bug that is not there.
        SmtpReply reply = await SendAsync(Processor(), "XCLIENT NAME=evil");

        reply.Code.ShouldBe(500);
        reply.Format().ShouldContain("XCLIENT NAME=evil");
    }

    [Fact]
    public async Task An_enormous_unrecognised_command_is_not_echoed_back_in_full()
    {
        // Echoing the whole line would let a peer make this server send a line per refused
        // command, amplified by whatever length it chose.
        string huge = new('Z', 4000);

        SmtpReply reply = await SendAsync(Processor(), huge);

        reply.Format().Length.ShouldBeLessThan(200);
        reply.Format().ShouldContain("...");
    }

    [Fact]
    public async Task A_second_mail_from_inside_a_transaction_is_refused()
    {
        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(processor, "EHLO r.example.net", "MAIL FROM:<first@example.net>");

        (await SendAsync(processor, "MAIL FROM:<second@example.net>")).Code.ShouldBe(503);

        processor.Session.ReversePath!.ToString().ShouldBe("first@example.net");
    }

    [Fact]
    public async Task Rset_clears_the_envelope_and_keeps_the_greeting()
    {
        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(
            processor,
            "EHLO r.example.net",
            "MAIL FROM:<s@example.net>",
            "RCPT TO:<user@example.com>");

        (await SendAsync(processor, "RSET")).Code.ShouldBe(250);

        processor.Session.Recipients.ShouldBeEmpty();
        processor.Session.HasTransaction.ShouldBeFalse();
        processor.Session.GreetedName.ShouldBe("r.example.net");
    }

    [Fact]
    public async Task A_new_greeting_abandons_the_transaction()
    {
        SmtpCommandProcessor processor = Processor();

        await ConverseAsync(
            processor,
            "EHLO r.example.net",
            "MAIL FROM:<s@example.net>",
            "RCPT TO:<user@example.com>",
            "EHLO again.example.net");

        processor.Session.Recipients.ShouldBeEmpty();
        processor.Session.HasTransaction.ShouldBeFalse();
    }

    [Fact]
    public async Task Quit_closes_after_the_reply()
    {
        SmtpCommandProcessor processor = Processor();

        SmtpCommandResult result = await ExecuteAsync(processor, "QUIT");

        result.Reply.Code.ShouldBe(221);
        result.Action.ShouldBe(SmtpSessionAction.CloseAfterReply);
        processor.Session.State.ShouldBe(SmtpSessionState.Closing);
    }

    // ---------------------------------------------------------------------------------------
    // Address enumeration.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Vrfy_answers_the_same_for_an_address_that_exists_and_one_that_does_not()
    {
        // Answering truthfully turns VRFY into an address-enumeration oracle: a spammer walks a
        // dictionary and learns which mailboxes exist.
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO r.example.net");

        SmtpReply real = await SendAsync(processor, "VRFY user@example.com");
        SmtpReply fake = await SendAsync(processor, "VRFY nobody@example.com");

        real.Code.ShouldBe(252);
        real.Format().ShouldBe(fake.Format());
        _directory.RecipientInspections.ShouldBe(0);
    }

    [Fact]
    public async Task Expn_is_refused_outright()
    {
        // Worse than VRFY: it expands a list, so one question yields many addresses.
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO r.example.net");

        (await SendAsync(processor, "EXPN staff")).Code.ShouldBe(502);
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS and AUTH availability.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Starttls_asks_the_connection_loop_to_handshake()
    {
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO r.example.net");

        SmtpCommandResult result = await ExecuteAsync(processor, "STARTTLS");

        result.Reply.Code.ShouldBe(220);
        result.Action.ShouldBe(SmtpSessionAction.StartTlsHandshake);
    }

    [Fact]
    public async Task Starttls_inside_tls_is_refused()
    {
        // RFC 3207 §4.2. A client that took a nested offer would be renegotiating inside an
        // existing session.
        SmtpCommandProcessor processor = Processor(tls: true);

        await SendAsync(processor, "EHLO r.example.net");

        SmtpCommandResult result = await ExecuteAsync(processor, "STARTTLS");

        result.Reply.Code.ShouldBe(502);
        result.Action.ShouldBe(SmtpSessionAction.Continue);
    }

    [Fact]
    public async Task Auth_on_port_25_is_refused_even_inside_tls()
    {
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.InboundMta, tls: true, authAvailable: true);

        await SendAsync(processor, "EHLO r.example.net");

        SmtpReply reply = await SendAsync(processor, "AUTH PLAIN dGVzdA==");

        reply.Code.ShouldBe(502);
        processor.Session.IsAuthenticated.ShouldBeFalse();
    }

    [Fact]
    public async Task Auth_on_submission_before_tls_demands_tls_rather_than_accepting_credentials()
    {
        // Rule 105: no plaintext SMTP AUTH over Internet. The capability is not advertised, and
        // an attempt anyway is refused rather than read.
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.Submission, tls: false, authAvailable: true);

        await SendAsync(processor, "EHLO client.example.net");

        SmtpReply reply = await SendAsync(processor, "AUTH PLAIN dGVzdA==");

        reply.Code.ShouldBe(530);
        processor.Session.IsAuthenticated.ShouldBeFalse();
    }

    [Fact]
    public async Task Auth_is_refused_as_not_implemented_while_sasl_is_unbuilt()
    {
        // docs/Standards.md has SASL at Milestone 7. Saying so is better than a 535, which
        // would imply the credentials were read and found wrong.
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.Submission, tls: true, authAvailable: false);

        await SendAsync(processor, "EHLO client.example.net");

        (await SendAsync(processor, "AUTH PLAIN dGVzdA==")).Code.ShouldBe(502);
    }

    [Fact]
    public async Task No_reply_on_any_path_echoes_an_auth_argument()
    {
        // Brief rule 77: never log or echo AUTH credentials. The base64 blob after AUTH is a
        // password, and a reply that quoted the command back would put it in the peer's logs,
        // in any intermediary's logs, and in a packet capture.
        const string Credential = "AGFsaWNlAGh1bnRlcjI=";

        foreach (SmtpCommandProcessor processor in (SmtpCommandProcessor[])
        [
            Processor(SmtpListenerRole.InboundMta, tls: true, authAvailable: true),
            Processor(SmtpListenerRole.Submission, tls: false, authAvailable: true),
            Processor(SmtpListenerRole.Submission, tls: true, authAvailable: true),
            Processor(SmtpListenerRole.Submission, tls: true, authAvailable: false),
        ])
        {
            await SendAsync(processor, "EHLO client.example.net");

            SmtpReply reply = await SendAsync(processor, $"AUTH PLAIN {Credential}");

            reply.Format().ShouldNotContain(Credential);
            reply.Format().ShouldNotContain("alice");
        }
    }
}
