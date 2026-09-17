using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Imap;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Imap.Tests;

/// <summary>An authenticator that answers from a script, and remembers what it was shown.</summary>
internal sealed class ScriptedImapAuthenticator : IMailboxAuthenticator
{
    public string KnownMailbox { get; set; } = "alice@example.com";

    public string KnownPassword { get; set; } = "hunter2";

    public MailboxId KnownMailboxId { get; } = new(Guid.NewGuid());

    /// <summary>Every identity this authenticator was shown, to prove what reached it.</summary>
    public List<string> SeenIdentities { get; } = [];

    /// <summary>Every password it was shown, to prove the right one was extracted.</summary>
    public List<string> SeenPasswords { get; } = [];

    public int Calls { get; private set; }

    public Task<MailboxAuthenticationResult> AuthenticateAsync(
        SaslCredential credential,
        IpAddressValue remoteAddress,
        CancellationToken cancellationToken)
    {
        Calls++;
        SeenIdentities.Add(credential.AuthenticationIdentity);
        SeenPasswords.Add(credential.Password.ToString());

        bool ok = credential.AuthenticationIdentity == KnownMailbox &&
                  credential.Password.ToString() == KnownPassword;

        return Task.FromResult(ok
            ? new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Succeeded,
                EmailAddress.Parse(KnownMailbox),
                "Authenticated.",
                KnownMailboxId)
            : new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Failed,
                null,
                "Wrong password."));
    }
}

public sealed class ImapCommandProcessorTests
{
    private static readonly DateTimeOffset Start = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private static ImapSessionContext Session(bool tls = true) =>
        new(IpAddressValue.Parse("198.51.100.20"), Start, tls);

    private static ImapCommandProcessor Processor(
        ImapSessionContext? session = null,
        ImapListenerRole role = ImapListenerRole.ImplicitTls,
        bool authAvailable = true,
        IMailboxAuthenticator? authenticator = null,
        int maxAttempts = 3) =>
        new(
            session ?? Session(),
            new ImapProcessorOptions("AetherMail", role, authAvailable, maxAttempts),
            NullLogger.Instance,
            authenticator);

    private static ImapCommand Parse(string line)
    {
        ImapCommand.TryParse(line, out ImapCommand? command, out _).ShouldBeTrue($"could not parse [{line}]");
        return command!;
    }

    private static async Task<ImapCommandResult> ExecuteAsync(ImapCommandProcessor processor, string line) =>
        await processor.ExecuteAsync(Parse(line), CancellationToken.None);

    private static string Wire(ImapCommandResult result) =>
        string.Concat(result.Responses.Select(r => r.Format()));

    // ---------------------------------------------------------------------------------------
    // The greeting.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_greeting_is_untagged_and_carries_the_capabilities()
    {
        // RFC 3501 section 7.1.1, with the listing inline per section 7.2.1 - which saves the
        // client the round trip it would otherwise spend discovering whether it may log in.
        string greeting = Processor().Greeting().Format();

        greeting.ShouldStartWith("* OK [CAPABILITY IMAP4rev1 ");
        greeting.ShouldContain("AetherMail");
        greeting.ShouldEndWith("\r\n");
    }

    [Fact]
    public void A_cleartext_greeting_says_login_is_disabled()
    {
        Processor(Session(tls: false), ImapListenerRole.Cleartext)
            .Greeting()
            .Format()
            .ShouldContain("LOGINDISABLED");
    }

    // ---------------------------------------------------------------------------------------
    // The any-state commands. RFC 3501 section 6.1.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Capability_answers_untagged_data_then_a_tagged_completion()
    {
        // RFC 3501 section 6.1.1: "The server MUST send a single untagged CAPABILITY response
        // ... before the (tagged) OK response."
        ImapCommandResult result = await ExecuteAsync(Processor(), "a1 CAPABILITY");

        result.Responses.Count.ShouldBe(2);
        result.Responses[0].Format().ShouldStartWith("* CAPABILITY IMAP4rev1");
        result.Responses[1].Format().ShouldBe("a1 OK CAPABILITY completed\r\n");
        result.Action.ShouldBe(ImapSessionAction.Continue);
    }

    [Fact]
    public async Task Noop_answers_a_tagged_ok()
    {
        ImapCommandResult result = await ExecuteAsync(Processor(), "a1 NOOP");

        Wire(result).ShouldBe("a1 OK NOOP completed\r\n");
    }

    [Fact]
    public async Task Logout_sends_bye_before_the_completion_and_closes()
    {
        // RFC 3501 section 6.1.3 is explicit that the untagged BYE comes first. A client that
        // saw only the OK could not tell an orderly close from the connection dropping.
        ImapCommandProcessor processor = Processor();

        ImapCommandResult result = await ExecuteAsync(processor, "a1 LOGOUT");

        result.Responses.Count.ShouldBe(2);
        result.Responses[0].Format().ShouldStartWith("* BYE ");
        result.Responses[1].Format().ShouldBe("a1 OK LOGOUT completed\r\n");
        result.Action.ShouldBe(ImapSessionAction.CloseAfterResponse);
        processor.Session.State.ShouldBe(ImapSessionState.Logout);
    }

    [Theory]
    [InlineData("a1 CAPABILITY")]
    [InlineData("a1 NOOP")]
    [InlineData("a1 LOGOUT")]
    public async Task The_any_state_commands_work_before_authentication(string line)
    {
        ImapCommandResult result = await ExecuteAsync(
            Processor(Session(tls: false), ImapListenerRole.Cleartext),
            line);

        Wire(result).ShouldNotContain(" BAD ");
        Wire(result).ShouldNotContain(" NO ");
    }

    // ---------------------------------------------------------------------------------------
    // Unrecognised and out-of-sequence commands.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_unrecognised_command_earns_a_tagged_bad()
    {
        ImapCommandResult result = await ExecuteAsync(Processor(), "a1 FROBNICATE");

        Wire(result).ShouldBe("a1 BAD Unrecognised command\r\n");
    }

    [Fact]
    public async Task An_unrecognised_command_is_never_echoed_back()
    {
        // The unrecognised word is the client's own text, and a refusal must not quote it back.
        ImapCommandResult result = await ExecuteAsync(Processor(), "a1 FROBNICATE secret-data");

        Wire(result).ShouldNotContain("FROBNICATE");
        Wire(result).ShouldNotContain("secret-data");
    }

    [Theory]
    [InlineData("a1 SELECT INBOX")]
    [InlineData("a1 FETCH 1 FLAGS")]
    [InlineData("a1 LIST \"\" \"*\"")]
    [InlineData("a1 APPEND INBOX {10}")]
    public async Task A_command_needing_an_identity_is_out_of_sequence_before_login(string line)
    {
        // BAD rather than NO: NO says the request was well-formed and invites a retry, and a
        // client told NO for a command it sent in the wrong state retries in the wrong state.
        ImapCommandResult result = await ExecuteAsync(Processor(), line);

        Wire(result).ShouldContain(" BAD ");
        Wire(result).ShouldContain("not valid in this state");
    }

    [Fact]
    public async Task Re_authentication_is_refused_as_out_of_sequence()
    {
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        (await ExecuteAsync(processor, "a1 LOGIN alice@example.com hunter2")).Responses[0]
            .Format().ShouldContain(" OK ");

        Wire(await ExecuteAsync(processor, "a2 LOGIN mallory@example.com hunter2"))
            .ShouldContain("not valid in this state");
    }

    // ---------------------------------------------------------------------------------------
    // Commands that exist, are in sequence, and are not built yet.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("a1 SELECT INBOX", "SELECT")]
    [InlineData("a1 LIST \"\" \"*\"", "LIST")]
    [InlineData("a1 STATUS INBOX (MESSAGES)", "STATUS")]
    [InlineData("a1 CREATE Archive", "CREATE")]
    [InlineData("a1 IDLE", "IDLE")]
    public async Task An_unimplemented_command_says_so_rather_than_pretending(string line, string verb)
    {
        // A tagged NO naming the command, not a BAD: the request was well-formed and in
        // sequence, and telling a client otherwise sends someone debugging a mail client looking
        // for a syntax error that is not there.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        string wire = Wire(await ExecuteAsync(processor, line));

        wire.ShouldContain(" NO ");
        wire.ShouldContain(verb);
        wire.ShouldContain("not implemented yet");
    }

    [Fact]
    public async Task Nothing_unimplemented_is_advertised_as_available()
    {
        // The pairing that keeps the refusals honest: a complying client never sends a command
        // this processor would refuse, because the capability listing never offered it.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        IReadOnlyList<string> capabilities = processor.Capabilities();

        capabilities.ShouldNotContain("IDLE");
        capabilities.ShouldNotContain("NAMESPACE");
        capabilities.ShouldNotContain("UNSELECT");
        capabilities.ShouldNotContain("MOVE");
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS. RFC 3501 section 6.2.1.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Starttls_is_accepted_on_a_cleartext_connection_and_asks_for_the_handshake()
    {
        ImapCommandResult result = await ExecuteAsync(
            Processor(Session(tls: false), ImapListenerRole.Cleartext),
            "a1 STARTTLS");

        Wire(result).ShouldBe("a1 OK Begin TLS negotiation now\r\n");
        result.Action.ShouldBe(ImapSessionAction.StartTlsHandshake);
    }

    [Fact]
    public async Task Starttls_is_refused_inside_the_tunnel_it_would_create()
    {
        // Not caught by the state machine: a successful STARTTLS leaves the session in the
        // not-authenticated state, so sequencing alone would let a client ask twice.
        ImapCommandResult result = await ExecuteAsync(
            Processor(Session(tls: true), ImapListenerRole.Cleartext),
            "a1 STARTTLS");

        Wire(result).ShouldBe("a1 BAD TLS is already active\r\n");
        result.Action.ShouldBe(ImapSessionAction.Continue);
    }

    [Fact]
    public async Task Starttls_is_refused_on_the_implicit_tls_listener()
    {
        // There is no honest moment on port 993 when STARTTLS is legal.
        Wire(await ExecuteAsync(Processor(Session(tls: false), ImapListenerRole.ImplicitTls), "a1 STARTTLS"))
            .ShouldContain("not available on this listener");
    }

    // ---------------------------------------------------------------------------------------
    // LOGIN. RFC 3501 section 6.2.3. The argument is a cleartext password.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Login_authenticates_and_moves_the_session_on()
    {
        ScriptedImapAuthenticator authenticator = new();
        ImapCommandProcessor processor = Processor(authenticator: authenticator);

        ImapCommandResult result = await ExecuteAsync(processor, "a1 LOGIN alice@example.com hunter2");

        Wire(result).ShouldContain("a1 OK ");
        processor.Session.State.ShouldBe(ImapSessionState.Authenticated);
        processor.Session.AuthenticatedMailbox!.Value.ShouldBe("alice@example.com");
        processor.Session.AuthenticatedMailboxId.ShouldBe(authenticator.KnownMailboxId);
    }

    [Fact]
    public async Task A_successful_login_carries_the_new_capability_listing()
    {
        // RFC 3501 section 7.2.1: the list changes on authentication - STARTTLS, LOGINDISABLED
        // and the AUTH= atoms all drop out - so it rides on the completion.
        string wire = Wire(await ExecuteAsync(
            Processor(authenticator: new ScriptedImapAuthenticator()),
            "a1 LOGIN alice@example.com hunter2"));

        wire.ShouldContain("[CAPABILITY IMAP4rev1");
        wire.ShouldNotContain("LOGINDISABLED");
        wire.ShouldNotContain("AUTH=");
    }

    [Fact]
    public async Task Login_reads_a_quoted_password()
    {
        ScriptedImapAuthenticator authenticator = new() { KnownPassword = "pass word" };

        Wire(await ExecuteAsync(
                Processor(authenticator: authenticator),
                "a1 LOGIN \"alice@example.com\" \"pass word\""))
            .ShouldContain(" OK ");

        authenticator.SeenPasswords.ShouldContain("pass word");
    }

    [Fact]
    public async Task Login_reads_a_password_containing_an_escaped_quote()
    {
        ScriptedImapAuthenticator authenticator = new() { KnownPassword = "pa\"ss" };

        Wire(await ExecuteAsync(
                Processor(authenticator: authenticator),
                "a1 LOGIN alice@example.com \"pa\\\"ss\""))
            .ShouldContain(" OK ");
    }

    [Fact]
    public async Task Login_is_refused_without_tls()
    {
        // Not redundant with LOGINDISABLED. That capability tells a complying client not to try;
        // this is what happens when one tries anyway, and RFC 3501 section 6.2.3 requires the
        // refusal to exist as well as the advertisement.
        ScriptedImapAuthenticator authenticator = new();

        ImapCommandResult result = await ExecuteAsync(
            Processor(Session(tls: false), ImapListenerRole.Cleartext, authenticator: authenticator),
            "a1 LOGIN alice@example.com hunter2");

        Wire(result).ShouldContain("LOGIN is disabled without TLS");
        authenticator.Calls.ShouldBe(0, "the credential must not even be checked in the clear.");
    }

    [Fact]
    public async Task Login_is_refused_while_authentication_is_unimplemented()
    {
        ImapCommandResult result = await ExecuteAsync(
            Processor(authAvailable: false, authenticator: new ScriptedImapAuthenticator()),
            "a1 LOGIN alice@example.com hunter2");

        Wire(result).ShouldContain("LOGIN is not available");
    }

    [Fact]
    public async Task Login_with_no_authenticator_configured_is_refused_rather_than_crashing()
    {
        Wire(await ExecuteAsync(Processor(), "a1 LOGIN alice@example.com hunter2"))
            .ShouldContain(" NO ");
    }

    [Theory]
    [InlineData("a1 LOGIN")]
    [InlineData("a1 LOGIN alice@example.com")]
    [InlineData("a1 LOGIN alice@example.com hunter2 extra")]
    [InlineData("a1 LOGIN \"unterminated hunter2")]
    public async Task A_malformed_login_earns_a_bad(string line)
    {
        ImapCommandResult result = await ExecuteAsync(
            Processor(authenticator: new ScriptedImapAuthenticator()),
            line);

        Wire(result).ShouldContain(" BAD ");
        Wire(result).ShouldContain("userid and a password");
    }

    [Fact]
    public async Task A_wrong_password_is_refused_without_saying_which_part_was_wrong()
    {
        // "The username was fine" is a fact about which mailboxes exist, and address enumeration
        // is the first step of every credential-stuffing run against a mail server.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        string wrongPassword = Wire(await ExecuteAsync(processor, "a1 LOGIN alice@example.com wrong"));
        string unknownUser = Wire(await ExecuteAsync(processor, "a2 LOGIN nobody@example.com hunter2"));

        wrongPassword.ShouldBe("a1 NO Authentication failed\r\n");
        unknownUser.ShouldBe("a2 NO Authentication failed\r\n");
    }

    [Theory]
    [InlineData("a1 LOGIN alice@example.com hunter2")]
    [InlineData("a1 LOGIN alice@example.com wrong")]
    [InlineData("a1 LOGIN \"alice@example.com\" \"s3cr3t p@ss\"")]
    [InlineData("a1 AUTHENTICATE PLAIN AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI=")]
    public async Task No_response_to_an_authentication_command_ever_contains_the_credential(string line)
    {
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        string wire = Wire(await ExecuteAsync(processor, line));

        wire.ShouldNotContain("hunter2");
        wire.ShouldNotContain("wrong");
        wire.ShouldNotContain("s3cr3t");
        wire.ShouldNotContain("AGFsaWNl");
    }

    // ---------------------------------------------------------------------------------------
    // AUTHENTICATE. RFC 3501 section 6.2.2.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Authenticate_plain_with_an_initial_response_succeeds_in_one_round_trip()
    {
        // RFC 4959's initial response rides on the AUTHENTICATE line. "alice@example.com" and
        // "hunter2" as SASL PLAIN's NUL-separated triple.
        ScriptedImapAuthenticator authenticator = new();
        ImapCommandProcessor processor = Processor(authenticator: authenticator);

        ImapCommandResult result = await ExecuteAsync(
            processor,
            "a1 AUTHENTICATE PLAIN AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI=");

        Wire(result).ShouldContain("a1 OK ");
        processor.Session.State.ShouldBe(ImapSessionState.Authenticated);
        authenticator.SeenIdentities.ShouldContain("alice@example.com");
    }

    [Fact]
    public async Task Authenticate_without_an_initial_response_asks_for_a_continuation()
    {
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        ImapCommandResult result = await ExecuteAsync(processor, "a1 AUTHENTICATE PLAIN");

        result.Responses[0].Format().ShouldStartWith("+ ");
        result.Action.ShouldBe(ImapSessionAction.ReadAuthenticationResponse);
        processor.IsAuthenticationInFlight.ShouldBeTrue();
    }

    [Fact]
    public async Task The_continuation_line_completes_the_exchange_with_the_original_tag()
    {
        // The continuation carries no tag of its own: the exchange is one command spread over
        // several lines, and the completion belongs to the command that started it.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a7 AUTHENTICATE PLAIN");

        ImapCommandResult result = await processor.ContinueAuthenticationAsync(
            "AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI=",
            CancellationToken.None);

        Wire(result).ShouldContain("a7 OK ");
        processor.IsAuthenticationInFlight.ShouldBeFalse();
    }

    [Fact]
    public async Task A_cancelled_exchange_ends_it()
    {
        // RFC 3501 section 6.2.2: "If the client wishes to cancel an authentication exchange, it
        // issues a line consisting of a single '*'."
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a1 AUTHENTICATE PLAIN");

        ImapCommandResult result = await processor.ContinueAuthenticationAsync(
            "*",
            CancellationToken.None);

        Wire(result).ShouldContain("a1 BAD ");
        processor.IsAuthenticationInFlight.ShouldBeFalse();
    }

    [Fact]
    public async Task Authenticate_is_refused_without_tls()
    {
        ScriptedImapAuthenticator authenticator = new();

        Wire(await ExecuteAsync(
                Processor(Session(tls: false), ImapListenerRole.Cleartext, authenticator: authenticator),
                "a1 AUTHENTICATE PLAIN AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI="))
            .ShouldContain("disabled without TLS");

        authenticator.Calls.ShouldBe(0);
    }

    [Fact]
    public async Task An_unsupported_mechanism_is_refused_without_being_echoed()
    {
        // A client that sends "AUTHENTICATE <base64>" with no mechanism puts its credential in
        // the mechanism position, and no shape test separates that from a mistyped name.
        string wire = Wire(await ExecuteAsync(
            Processor(authenticator: new ScriptedImapAuthenticator()),
            "a1 AUTHENTICATE AGFsaWNlAGh1bnRlcjI="));

        wire.ShouldBe("a1 NO Unsupported authentication mechanism\r\n");
        wire.ShouldNotContain("AGFsaWNl");
    }

    [Fact]
    public async Task A_continuation_with_no_exchange_in_flight_is_answered_untagged()
    {
        // A caller bug rather than a client one - there is no tag to answer with.
        Wire(await Processor().ContinueAuthenticationAsync("x", CancellationToken.None))
            .ShouldBe("* BAD No authentication in progress\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // The attempt budget.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_connection_closes_once_the_attempt_budget_is_spent()
    {
        ImapCommandProcessor processor = Processor(
            authenticator: new ScriptedImapAuthenticator(),
            maxAttempts: 2);

        (await ExecuteAsync(processor, "a1 LOGIN alice@example.com wrong")).Action
            .ShouldBe(ImapSessionAction.Continue);

        ImapCommandResult last = await ExecuteAsync(processor, "a2 LOGIN alice@example.com wrong");

        last.Action.ShouldBe(ImapSessionAction.CloseAfterResponse);
        last.Responses[0].Format().ShouldStartWith("* BYE ");
        last.Responses[1].Format().ShouldContain("a2 NO ");
    }

    [Fact]
    public async Task A_closing_refusal_still_says_bye_first()
    {
        // Closing without one is indistinguishable from a network failure, which invites the
        // reconnect-and-retry loop that makes an attempt limit pointless.
        ImapCommandProcessor processor = Processor(
            authenticator: new ScriptedImapAuthenticator(),
            maxAttempts: 1);

        ImapCommandResult result = await ExecuteAsync(processor, "a1 LOGIN alice@example.com wrong");

        result.Responses.Count.ShouldBe(2);
        result.Responses[0].Format().ShouldStartWith("* BYE ");
    }

    [Fact]
    public async Task A_spent_budget_refuses_further_attempts_without_checking_them()
    {
        ScriptedImapAuthenticator authenticator = new();
        ImapCommandProcessor processor = Processor(authenticator: authenticator, maxAttempts: 1);

        await ExecuteAsync(processor, "a1 LOGIN alice@example.com wrong");
        authenticator.Calls.ShouldBe(1);

        // Even the correct password: the budget is this server's own accounting of the
        // connection, and nothing the client sends buys back another guess.
        ImapCommandResult result = await ExecuteAsync(processor, "a2 LOGIN alice@example.com hunter2");

        result.Action.ShouldBe(ImapSessionAction.CloseAfterResponse);
        authenticator.Calls.ShouldBe(1, "the credential must not be checked after the budget is spent.");
    }

    // ---------------------------------------------------------------------------------------
    // Malformed lines, which never reach ExecuteAsync.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapTagFailure.Missing)]
    [InlineData(ImapTagFailure.TooLong)]
    [InlineData(ImapTagFailure.IllegalCharacter)]
    public void A_line_with_an_unusable_tag_is_answered_untagged(ImapTagFailure failure)
    {
        // RFC 3501 section 7.1.3's untagged BAD: "a protocol-level error for which the
        // associated command can not be determined". There is nothing to tag the answer with.
        ImapCommandResult result = Processor().MalformedLine(failure);

        result.Responses.Count.ShouldBe(1);
        result.Responses[0].Format().ShouldStartWith("* BAD ");
    }

    [Fact]
    public void The_offending_tag_is_never_echoed_in_any_form()
    {
        foreach (ImapTagFailure failure in Enum.GetValues<ImapTagFailure>())
        {
            string wire = Wire(Processor().MalformedLine(failure));

            wire.ShouldStartWith("* BAD ");
            wire.ShouldEndWith("\r\n");
            wire.Count(c => c == '\n').ShouldBe(1);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Every response the processor can produce is a single well-formed line.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("a1 CAPABILITY")]
    [InlineData("a1 NOOP")]
    [InlineData("a1 LOGOUT")]
    [InlineData("a1 STARTTLS")]
    [InlineData("a1 FROBNICATE")]
    [InlineData("a1 SELECT INBOX")]
    [InlineData("a1 LOGIN a b")]
    [InlineData("a1 AUTHENTICATE PLAIN")]
    [InlineData("a1 AUTHENTICATE NOSUCH")]
    [InlineData("a1 UID FETCH 1:* FLAGS")]
    public async Task Every_response_is_one_line_ending_in_crlf(string line)
    {
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        foreach (ImapResponse response in (await ExecuteAsync(processor, line)).Responses)
        {
            string formatted = response.Format();

            formatted.ShouldEndWith("\r\n");
            formatted.Count(c => c == '\n').ShouldBe(1, formatted);
            formatted.Count(c => c == '\r').ShouldBe(1, formatted);
        }
    }

    [Fact]
    public async Task A_hostile_argument_cannot_reach_the_response_stream()
    {
        // The argument is the one place a client's bytes could reach the wire, and the refusals
        // are the responses that would carry them.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        string[] hostile =
        [
            "a1 SELECT \"x\" \r\n* 1 EXPUNGE",
            "a1 LOGIN \"x\r\n* 1 EXPUNGE\" y",
            "a1 FROBNICATE \r\n* 0 EXISTS",
        ];

        foreach (string line in hostile)
        {
            if (!ImapCommand.TryParse(line, out ImapCommand? command, out _))
            {
                continue;
            }

            string wire = Wire(await processor.ExecuteAsync(command, CancellationToken.None));

            wire.ShouldNotContain("EXPUNGE");
            wire.ShouldNotContain("EXISTS");
            wire.Count(c => c == '\n').ShouldBeLessThanOrEqualTo(2, wire);
        }
    }

    [Fact]
    public void The_processor_rejects_null_dependencies()
    {
        ImapProcessorOptions options = new("AetherMail", ImapListenerRole.ImplicitTls);

        Should.Throw<ArgumentNullException>(() => new ImapCommandProcessor(null!, options, NullLogger.Instance));
        Should.Throw<ArgumentNullException>(() => new ImapCommandProcessor(Session(), null!, NullLogger.Instance));
        Should.Throw<ArgumentNullException>(() => new ImapCommandProcessor(Session(), options, null!));
    }

    [Fact]
    public async Task Executing_a_null_command_is_refused()
    {
        await Should.ThrowAsync<ArgumentNullException>(
            async () => await Processor().ExecuteAsync(null!, CancellationToken.None));
    }
}
