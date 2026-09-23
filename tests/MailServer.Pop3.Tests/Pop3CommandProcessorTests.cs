using System.Text;
using MailServer.Domain.Enums;
using MailServer.Domain.Pop3;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Pop3;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Pop3.Tests;

public sealed class Pop3CommandProcessorTests
{
    private const string FirstMessage =
        "Subject: first\r\nFrom: a@b.test\r\n\r\nHello.\r\n";

    private const string SecondMessage =
        "Subject: second\r\nFrom: c@d.test\r\n\r\n.leading stop\r\nand more\r\n";

    private static readonly DateTimeOffset Start = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private sealed record Harness(
        Pop3CommandProcessor Processor,
        ScriptedPop3Mailboxes Mailboxes,
        ScriptedPop3Authenticator Authenticator,
        ScriptedPop3MessageStore Messages,
        Pop3MaildropLocks Locks);

    private static Harness Build(
        Pop3ListenerRole role = Pop3ListenerRole.ImplicitTls,
        bool authAvailable = true,
        bool tlsActive = true,
        int maxAttempts = 3,
        Pop3MaildropLocks? locks = null,
        ScriptedPop3Authenticator? authenticator = null)
    {
        authenticator ??= new ScriptedPop3Authenticator();

        ScriptedPop3Mailboxes mailboxes = new(authenticator.KnownMailboxId);

        mailboxes.Deliver(7, FirstMessage).Deliver(11, SecondMessage);

        ScriptedPop3MessageStore messages = new(mailboxes);
        Pop3MaildropLocks maildropLocks = locks ?? new Pop3MaildropLocks();

        Pop3SessionContext session = new(
            IpAddressValue.Parse("198.51.100.20"),
            Start,
            tlsActive);

        Pop3CommandProcessor processor = new(
            session,
            new Pop3ProcessorOptions("AetherMail", role, authAvailable, maxAttempts),
            NullLogger.Instance,
            authenticator,
            mailboxes,
            mailboxes,
            messages,
            maildropLocks);

        return new Harness(processor, mailboxes, authenticator, messages, maildropLocks);
    }

    private static async Task<Pop3CommandResult> RunAsync(Pop3CommandProcessor processor, string line)
    {
        Pop3Command.TryParse(line, out Pop3Command? command).ShouldBeTrue($"could not parse [{line}]");

        return await processor.ExecuteAsync(command!, CancellationToken.None);
    }

    /// <summary>The octets this result would put on the wire, as text.</summary>
    private static string Wire(Pop3CommandResult result)
    {
        StringBuilder wire = new(result.Response.Format());

        if (result.Response.Lines is { } lines)
        {
            foreach (string line in lines)
            {
                if (line.StartsWith('.'))
                {
                    wire.Append('.');
                }

                wire.Append(line).Append("\r\n");
            }

            wire.Append(".\r\n");
        }

        if (result.Response.Octets is { } octets)
        {
            wire.Append(Encoding.Latin1.GetString(octets.Span));
        }

        return wire.ToString();
    }

    private static async Task<Harness> AuthenticatedAsync(
        Pop3MaildropLocks? locks = null,
        ScriptedPop3Authenticator? authenticator = null)
    {
        Harness harness = Build(locks: locks, authenticator: authenticator);

        await RunAsync(harness.Processor, "USER alice@example.com");
        await RunAsync(harness.Processor, "PASS hunter2");

        harness.Processor.Session.State.ShouldBe(Pop3SessionState.Transaction);

        return harness;
    }

    // -------------------------------------------------------------------------------------------
    // AUTHORIZATION.
    // -------------------------------------------------------------------------------------------

    /// <summary>RFC 1939 §4: "the POP3 server issues a one line greeting."</summary>
    [Fact]
    public void The_greeting_is_a_positive_response() =>
        Build().Processor.Greeting().Format().ShouldBe("+OK AetherMail POP3 server ready\r\n");

    /// <summary>
    /// RFC 2595 §2 requires a server implementing the TLS upgrade to refuse plaintext
    /// authentication until it has run. POP3 has no capability for the refusal, so the command
    /// itself refuses — a client that ignored the capability listing gains nothing.
    /// </summary>
    [Theory]
    [InlineData("USER alice@example.com")]
    [InlineData("PASS hunter2")]
    public async Task Plaintext_authentication_is_refused_before_tls(string line)
    {
        Harness harness = Build(role: Pop3ListenerRole.Cleartext, tlsActive: false);

        string wire = Wire(await RunAsync(harness.Processor, line));

        wire.ShouldStartWith("-ERR ");
        wire.ShouldContain("STLS");
    }

    /// <summary>
    /// RFC 2449 §6.2: "The USER capability indicates that the USER and PASS commands are
    /// supported". Not announcing it is the POP3 counterpart of IMAP's LOGINDISABLED.
    /// </summary>
    [Fact]
    public async Task The_user_capability_is_withheld_until_tls_is_active()
    {
        Harness cleartext = Build(role: Pop3ListenerRole.Cleartext, tlsActive: false);
        Harness secure = Build();

        Wire(await RunAsync(cleartext.Processor, "CAPA")).ShouldNotContain("USER\r\n");
        Wire(await RunAsync(secure.Processor, "CAPA")).ShouldContain("USER\r\n");
    }

    /// <summary>
    /// RFC 2595 §4: "The capability name "STLS" indicates this command is present and permitted
    /// in the current state", and the command is "Only permitted in AUTHORIZATION state".
    /// </summary>
    [Fact]
    public async Task Stls_is_announced_only_where_it_is_legal()
    {
        Harness cleartext = Build(role: Pop3ListenerRole.Cleartext, tlsActive: false);

        Wire(await RunAsync(cleartext.Processor, "CAPA")).ShouldContain("STLS\r\n");
        Wire(await RunAsync(Build().Processor, "CAPA")).ShouldNotContain("STLS\r\n");
    }

    /// <summary>
    /// §5 of RFC 2449: the listing "is terminated by a line containing a termination octet (".")
    /// and a CRLF pair".
    /// </summary>
    [Fact]
    public async Task The_capability_listing_is_a_multi_line_response()
    {
        string wire = Wire(await RunAsync(Build().Processor, "CAPA"));

        wire.ShouldStartWith("+OK ");
        wire.ShouldEndWith("\r\n.\r\n");
        wire.ShouldContain("TOP\r\n");
        wire.ShouldContain("UIDL\r\n");
        wire.ShouldContain("RESP-CODES\r\n");
        wire.ShouldContain("PIPELINING\r\n");
        wire.ShouldContain("IMPLEMENTATION AetherMail\r\n");
    }

    /// <summary>
    /// RFC 2595 §4: "A TLS negotiation begins immediately after the CRLF at the end of the +OK
    /// response from the server."
    /// </summary>
    [Fact]
    public async Task Stls_asks_the_loop_for_a_handshake()
    {
        Harness harness = Build(role: Pop3ListenerRole.Cleartext, tlsActive: false);

        Pop3CommandResult result = await RunAsync(harness.Processor, "STLS");

        result.Response.Format().ShouldBe("+OK Begin TLS negotiation\r\n");
        result.Action.ShouldBe(Pop3SessionAction.StartTlsHandshake);
    }

    /// <summary>§4: "A -ERR response MAY result if a security layer is already active."</summary>
    [Fact]
    public async Task Stls_is_refused_once_tls_is_active() =>
        Wire(await RunAsync(Build(role: Pop3ListenerRole.Cleartext).Processor, "STLS"))
            .ShouldBe("-ERR Command not permitted when TLS active\r\n");

    /// <summary>There is no honest moment on the implicit-TLS port when an upgrade would mean anything.</summary>
    [Fact]
    public async Task Stls_is_refused_on_the_implicit_tls_port() =>
        Wire(await RunAsync(Build().Processor, "STLS"))
            .ShouldBe("-ERR STLS is not available on this port\r\n");

    /// <summary>
    /// §7: <c>PASS</c> "may only be given in the AUTHORIZATION state immediately after a
    /// successful USER command".
    /// </summary>
    [Fact]
    public async Task Pass_without_user_is_refused() =>
        Wire(await RunAsync(Build().Processor, "PASS hunter2"))
            .ShouldBe("-ERR Send USER before PASS\r\n");

    /// <summary>A correct credential opens the maildrop and reports what is in it.</summary>
    [Fact]
    public async Task A_correct_credential_opens_the_maildrop()
    {
        Harness harness = Build();

        Wire(await RunAsync(harness.Processor, "USER alice@example.com"))
            .ShouldBe("+OK Name accepted; send PASS\r\n");

        string wire = Wire(await RunAsync(harness.Processor, "PASS hunter2"));

        wire.ShouldStartWith("+OK maildrop has 2 messages (");
        harness.Processor.Session.State.ShouldBe(Pop3SessionState.Transaction);
        harness.Processor.Session.AuthenticatedMailbox!.Value.ShouldBe("alice@example.com");
    }

    /// <summary>
    /// POP3 asks the authenticator about POP3 access. Its flag was once never consulted at all,
    /// so every mailbox that could submit could also read and delete its mail here.
    /// </summary>
    [Fact]
    public async Task Pass_asks_for_pop3_access()
    {
        Harness harness = Build();

        await RunAsync(harness.Processor, "USER alice@example.com");
        await RunAsync(harness.Processor, "PASS hunter2");

        harness.Authenticator.SeenProtocols.ShouldBe([MailboxAccess.Pop3]);
    }

    /// <summary>
    /// §7: "Since the PASS command has exactly one argument, a POP3 server may treat spaces in
    /// the argument as part of the password". The whole argument reaches the authenticator.
    /// </summary>
    [Fact]
    public async Task A_password_containing_spaces_reaches_the_authenticator_whole()
    {
        Harness harness = Build();

        await RunAsync(harness.Processor, "USER alice@example.com");
        await RunAsync(harness.Processor, "PASS correct horse battery staple");

        harness.Authenticator.Attempts.ShouldContain(
            ("alice@example.com", "correct horse battery staple"));
    }

    /// <summary>
    /// A refused credential says nothing about whether the mailbox exists. §7 permits a positive
    /// USER response "even though no such mailbox exists", and the refusal is the same either
    /// way, because any difference is an address oracle.
    /// </summary>
    [Theory]
    [InlineData("alice@example.com", "wrong")]
    [InlineData("nobody@example.com", "hunter2")]
    public async Task Every_refusal_reads_the_same(string user, string password)
    {
        Harness harness = Build();

        Wire(await RunAsync(harness.Processor, $"USER {user}"))
            .ShouldBe("+OK Name accepted; send PASS\r\n");

        Wire(await RunAsync(harness.Processor, $"PASS {password}"))
            .ShouldBe("-ERR Authentication failed\r\n");
    }

    /// <summary>
    /// §3: "After returning a negative status indicator, the server may close the connection." A
    /// connection is otherwise a free retry budget.
    /// </summary>
    [Fact]
    public async Task The_connection_closes_after_too_many_refusals()
    {
        Harness harness = Build(maxAttempts: 2);

        for (int attempt = 1; attempt <= 2; attempt++)
        {
            await RunAsync(harness.Processor, "USER alice@example.com");

            Pop3CommandResult result = await RunAsync(harness.Processor, "PASS wrong");

            result.Action.ShouldBe(attempt < 2
                ? Pop3SessionAction.Continue
                : Pop3SessionAction.CloseAfterResponse);
        }
    }

    /// <summary>A second USER replaces the first, so a PASS cannot pair with a stale name.</summary>
    [Fact]
    public async Task A_second_user_replaces_the_first()
    {
        Harness harness = Build();

        await RunAsync(harness.Processor, "USER mallory@example.com");
        await RunAsync(harness.Processor, "USER alice@example.com");
        await RunAsync(harness.Processor, "PASS hunter2");

        harness.Authenticator.Attempts.ShouldBe([("alice@example.com", "hunter2")]);
    }

    /// <summary>
    /// APOP needs a secret the server can hash, and this server stores verifiers it cannot
    /// reverse. It is named in the refusal rather than answered "unknown command".
    /// </summary>
    [Fact]
    public async Task Apop_is_refused_by_name() =>
        Wire(await RunAsync(Build().Processor, "APOP alice c4c9334bac560ecc979e58001b3e22fb"))
            .ShouldBe("-ERR APOP is not supported; use STLS and USER/PASS\r\n");

    /// <summary>
    /// RFC 2449 §8.1.2: "[IN-USE] […] indicates the authentication was successful, but the user's
    /// maildrop is currently in use (probably by another POP3 client)."
    /// </summary>
    [Fact]
    public async Task A_second_session_for_the_same_mailbox_is_told_in_use()
    {
        Pop3MaildropLocks locks = new();

        // One authenticator, so both sessions resolve to the same mailbox - which is the whole
        // point: the lock is per maildrop, and two sessions for different mailboxes must not
        // collide.
        ScriptedPop3Authenticator authenticator = new();

        await AuthenticatedAsync(locks, authenticator);

        Harness second = Build(locks: locks, authenticator: authenticator);

        await RunAsync(second.Processor, "USER alice@example.com");

        Wire(await RunAsync(second.Processor, "PASS hunter2"))
            .ShouldBe("-ERR [IN-USE] Maildrop is locked by another session\r\n");
    }

    /// <summary>
    /// The control for the test above: the lock is per maildrop, so two sessions for different
    /// mailboxes do not collide. A lock that refused every second session would have passed the
    /// test above for the wrong reason.
    /// </summary>
    [Fact]
    public async Task Two_sessions_for_different_mailboxes_do_not_collide()
    {
        Pop3MaildropLocks locks = new();

        await AuthenticatedAsync(locks);

        Harness other = Build(locks: locks);

        await RunAsync(other.Processor, "USER alice@example.com");

        Wire(await RunAsync(other.Processor, "PASS hunter2")).ShouldStartWith("+OK ");
        locks.Count.ShouldBe(2);
    }

    /// <summary>
    /// §3: "A server MUST respond to a command issued when the session is in an incorrect state
    /// by responding with a negative status indicator."
    /// </summary>
    [Theory]
    [InlineData("STAT")]
    [InlineData("LIST")]
    [InlineData("RETR 1")]
    [InlineData("DELE 1")]
    [InlineData("NOOP")]
    [InlineData("RSET")]
    [InlineData("TOP 1 1")]
    [InlineData("UIDL")]
    public async Task A_transaction_command_is_refused_before_authentication(string line) =>
        Wire(await RunAsync(Build().Processor, line)).ShouldStartWith("-ERR ");

    // -------------------------------------------------------------------------------------------
    // TRANSACTION.
    // -------------------------------------------------------------------------------------------

    /// <summary>§5: "+OK" followed by the count and the size, and nothing else.</summary>
    [Fact]
    public async Task Stat_is_the_count_and_the_size()
    {
        Harness harness = await AuthenticatedAsync();

        long total = FirstMessage.Length + SecondMessage.Length;

        Wire(await RunAsync(harness.Processor, "STAT")).ShouldBe($"+OK 2 {total}\r\n");
    }

    /// <summary>§5: without an argument the scan listing is multi-line, one line per message.</summary>
    [Fact]
    public async Task List_without_an_argument_lists_every_message()
    {
        Harness harness = await AuthenticatedAsync();

        Wire(await RunAsync(harness.Processor, "LIST")).ShouldBe(
            "+OK 2 messages\r\n" +
            $"1 {FirstMessage.Length}\r\n" +
            $"2 {SecondMessage.Length}\r\n" +
            ".\r\n");
    }

    /// <summary>§5: with an argument it is one line, and §5's example is "-ERR no such message".</summary>
    [Fact]
    public async Task List_with_an_argument_is_one_line()
    {
        Harness harness = await AuthenticatedAsync();

        Wire(await RunAsync(harness.Processor, "LIST 2"))
            .ShouldBe($"+OK 2 {SecondMessage.Length}\r\n");

        Wire(await RunAsync(harness.Processor, "LIST 3"))
            .ShouldBe("-ERR no such message, only 2 messages in maildrop\r\n");
    }

    /// <summary>
    /// §7: "A unique-id listing consists of the message-number of the message, followed by a
    /// single space and the unique-id of the message."
    /// </summary>
    [Fact]
    public async Task Uidl_lists_a_unique_id_for_every_message()
    {
        Harness harness = await AuthenticatedAsync();

        Wire(await RunAsync(harness.Processor, "UIDL")).ShouldBe(
            "+OK 2 messages\r\n" +
            "1 3857529045.7\r\n" +
            "2 3857529045.11\r\n" +
            ".\r\n");
    }

    /// <summary>
    /// §5: "the POP3 server sends the message corresponding to the given message-number, being
    /// careful to byte-stuff the termination character".
    /// </summary>
    [Fact]
    public async Task Retr_sends_the_message_stuffed_and_terminated()
    {
        Harness harness = await AuthenticatedAsync();

        Wire(await RunAsync(harness.Processor, "RETR 1"))
            .ShouldBe($"+OK {FirstMessage.Length} octets\r\n{FirstMessage}.\r\n");
    }

    /// <summary>A body line that begins with a stop is stuffed on its way out.</summary>
    [Fact]
    public async Task Retr_stuffs_a_body_line_that_begins_with_a_stop()
    {
        Harness harness = await AuthenticatedAsync();

        Wire(await RunAsync(harness.Processor, "RETR 2"))
            .ShouldContain("\r\n..leading stop\r\n");
    }

    /// <summary>
    /// §7: "the POP3 server sends the headers of the message, the blank line separating the
    /// headers from the body, and then the number of lines of the indicated message's body".
    /// </summary>
    [Fact]
    public async Task Top_sends_the_header_and_the_lines_asked_for()
    {
        Harness harness = await AuthenticatedAsync();

        Wire(await RunAsync(harness.Processor, "TOP 1 0"))
            .ShouldBe("+OK top of message follows\r\nSubject: first\r\nFrom: a@b.test\r\n\r\n.\r\n");
    }

    /// <summary>§7 makes both arguments required, so a bare TOP is malformed.</summary>
    [Theory]
    [InlineData("TOP")]
    [InlineData("TOP 1")]
    [InlineData("TOP 1 x")]
    [InlineData("TOP x 1")]
    public async Task Top_needs_both_of_its_arguments(string line) =>
        Wire(await RunAsync((await AuthenticatedAsync()).Processor, line))
            .ShouldBe("-ERR TOP requires a message number and a line count\r\n");

    /// <summary>
    /// §5: "The POP3 server marks the message as deleted. […] The POP3 server does not actually
    /// delete the message until the POP3 session enters the UPDATE state."
    /// </summary>
    [Fact]
    public async Task Dele_marks_without_removing()
    {
        Harness harness = await AuthenticatedAsync();

        Wire(await RunAsync(harness.Processor, "DELE 1")).ShouldBe("+OK message 1 deleted\r\n");

        harness.Mailboxes.Removed.ShouldBeEmpty();
        Wire(await RunAsync(harness.Processor, "STAT")).ShouldBe($"+OK 1 {SecondMessage.Length}\r\n");
    }

    /// <summary>§5's own example: "-ERR message 2 already deleted".</summary>
    [Fact]
    public async Task Deleting_twice_says_so()
    {
        Harness harness = await AuthenticatedAsync();

        await RunAsync(harness.Processor, "DELE 2");

        Wire(await RunAsync(harness.Processor, "DELE 2"))
            .ShouldBe("-ERR message 2 already deleted\r\n");
    }

    /// <summary>
    /// §5: "Any future reference to the message-number associated with the message in a POP3
    /// command generates an error."
    /// </summary>
    [Theory]
    [InlineData("RETR 1")]
    [InlineData("LIST 1")]
    [InlineData("UIDL 1")]
    [InlineData("TOP 1 1")]
    public async Task A_marked_message_cannot_be_referred_to_again(string line)
    {
        Harness harness = await AuthenticatedAsync();

        await RunAsync(harness.Processor, "DELE 1");

        Wire(await RunAsync(harness.Processor, line)).ShouldStartWith("-ERR no such message");
    }

    /// <summary>§5 on <c>RSET</c>: everything marked is unmarked.</summary>
    [Fact]
    public async Task Rset_unmarks_everything()
    {
        Harness harness = await AuthenticatedAsync();

        await RunAsync(harness.Processor, "DELE 1");
        await RunAsync(harness.Processor, "DELE 2");

        Wire(await RunAsync(harness.Processor, "RSET")).ShouldStartWith("+OK maildrop has 2 messages");
        Wire(await RunAsync(harness.Processor, "RETR 1")).ShouldStartWith("+OK ");
    }

    /// <summary>§5: "The POP3 server does nothing, it merely replies with a positive response."</summary>
    [Fact]
    public async Task Noop_does_nothing() =>
        Wire(await RunAsync((await AuthenticatedAsync()).Processor, "NOOP")).ShouldBe("+OK\r\n");

    // -------------------------------------------------------------------------------------------
    // UPDATE.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// §6: "When the client issues the QUIT command from the TRANSACTION state, the POP3 session
    /// enters the UPDATE state. […] The POP3 server removes all messages marked as deleted from
    /// the maildrop".
    /// </summary>
    [Fact]
    public async Task Quit_from_transaction_removes_what_was_marked()
    {
        Harness harness = await AuthenticatedAsync();

        await RunAsync(harness.Processor, "DELE 1");

        Pop3CommandResult result = await RunAsync(harness.Processor, "QUIT");

        result.Action.ShouldBe(Pop3SessionAction.CloseAfterResponse);
        result.Response.Format().ShouldStartWith("+OK ");

        harness.Mailboxes.Removed.ShouldBe([new long[] { 7 }]);
    }

    /// <summary>
    /// §6: "In no case may the server remove any messages not marked as deleted." A session that
    /// marked nothing removes nothing, and the removal is never even attempted.
    /// </summary>
    [Fact]
    public async Task Quit_with_nothing_marked_removes_nothing()
    {
        Harness harness = await AuthenticatedAsync();

        await RunAsync(harness.Processor, "QUIT");

        harness.Mailboxes.Removed.ShouldBeEmpty();
    }

    /// <summary>
    /// §6: "Note that if the client issues the QUIT command from the AUTHORIZATION state, the
    /// POP3 session terminates but does NOT enter the UPDATE state."
    /// </summary>
    [Fact]
    public async Task Quit_from_authorization_does_not_enter_update()
    {
        Harness harness = Build();

        Pop3CommandResult result = await RunAsync(harness.Processor, "QUIT");

        result.Action.ShouldBe(Pop3SessionAction.CloseAfterResponse);
        harness.Processor.Session.State.ShouldBe(Pop3SessionState.Authorization);
    }

    /// <summary>§6 has a reply for a removal that fails: "-ERR some deleted messages not removed".</summary>
    [Fact]
    public async Task A_failed_removal_says_so()
    {
        Harness harness = await AuthenticatedAsync();

        await RunAsync(harness.Processor, "DELE 1");

        harness.Mailboxes.FailRemoval = true;

        Wire(await RunAsync(harness.Processor, "QUIT"))
            .ShouldBe("-ERR some deleted messages not removed\r\n");
    }

    /// <summary>
    /// §6: "Whether the removal was successful or not, the server then releases any
    /// exclusive-access lock on the maildrop". The next session must be able to log in.
    /// </summary>
    [Fact]
    public async Task Quit_releases_the_maildrop_lock()
    {
        Pop3MaildropLocks locks = new();

        Harness harness = await AuthenticatedAsync(locks);

        locks.Count.ShouldBe(1);

        await RunAsync(harness.Processor, "QUIT");

        locks.Count.ShouldBe(0);
    }

    /// <summary>
    /// §6: "If a session terminates for some reason other than a client-issued QUIT command, the
    /// POP3 session does NOT enter the UPDATE state and MUST not remove any messages from the
    /// maildrop." The handler calls this on every exit path, and it must remove nothing.
    /// </summary>
    [Fact]
    public async Task Abandoning_a_session_releases_the_lock_and_removes_nothing()
    {
        Pop3MaildropLocks locks = new();

        Harness harness = await AuthenticatedAsync(locks);

        await RunAsync(harness.Processor, "DELE 1");

        harness.Processor.ReleaseMaildrop();

        locks.Count.ShouldBe(0);
        harness.Mailboxes.Removed.ShouldBeEmpty();
    }

    // -------------------------------------------------------------------------------------------
    // Failure paths.
    // -------------------------------------------------------------------------------------------

    /// <summary>One unreadable message must not end the session.</summary>
    [Fact]
    public async Task A_message_that_cannot_be_read_is_refused_and_the_session_continues()
    {
        Harness harness = await AuthenticatedAsync();

        harness.Messages.FailReads = true;

        Pop3CommandResult result = await RunAsync(harness.Processor, "RETR 1");

        Wire(result).ShouldBe("-ERR Message could not be read\r\n");
        result.Action.ShouldBe(Pop3SessionAction.Continue);
    }

    /// <summary>A mailbox with no INBOX cannot open a maildrop, and says so.</summary>
    [Fact]
    public async Task A_missing_maildrop_is_refused()
    {
        Harness harness = Build();

        harness.Mailboxes.FolderExists = false;

        await RunAsync(harness.Processor, "USER alice@example.com");

        Wire(await RunAsync(harness.Processor, "PASS hunter2"))
            .ShouldBe("-ERR Unable to open maildrop\r\n");

        harness.Locks.Count.ShouldBe(0);
    }

    /// <summary>§3: an unrecognised command gets a negative status indicator.</summary>
    [Fact]
    public async Task An_unknown_command_is_refused() =>
        Wire(await RunAsync(Build().Processor, "XYZZ")).ShouldBe("-ERR Unrecognised command\r\n");

    /// <summary>A line that did not parse is never quoted back into the refusal.</summary>
    [Fact]
    public void A_malformed_line_is_refused_without_being_echoed() =>
        Pop3CommandProcessor.Malformed().Response.Format().ShouldBe("-ERR Malformed command\r\n");

    /// <summary>
    /// RFC 2449 §5: "Capabilities available in the AUTHORIZATION state MUST be announced in both
    /// states", which is about the ones that remain available — STLS and USER do not.
    /// </summary>
    [Fact]
    public async Task The_transaction_listing_drops_the_commands_that_are_no_longer_legal()
    {
        Harness harness = await AuthenticatedAsync();

        string wire = Wire(await RunAsync(harness.Processor, "CAPA"));

        wire.ShouldNotContain("USER\r\n");
        wire.ShouldNotContain("STLS\r\n");
        wire.ShouldContain("UIDL\r\n");
    }
}
