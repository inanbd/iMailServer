using System.Text;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

/// <summary>An authenticator with one known password, so the exchange can be driven to success.</summary>
internal sealed class ScriptedAuthenticator : IMailboxAuthenticator
{
    public string KnownMailbox { get; set; } = "alice@example.com";

    public string KnownPassword { get; set; } = "hunter2";

    public MailboxAuthenticationOutcome ForcedOutcome { get; set; } = MailboxAuthenticationOutcome.Failed;

    public List<string> SeenIdentities { get; } = [];

    /// <summary>Every password this authenticator was shown, to prove the callers cleared them.</summary>
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

        bool matches =
            string.Equals(credential.AuthenticationIdentity, KnownMailbox, StringComparison.OrdinalIgnoreCase) &&
            credential.Password.SequenceEqual(KnownPassword);

        if (!matches)
        {
            return Task.FromResult(new MailboxAuthenticationResult(
                ForcedOutcome == MailboxAuthenticationOutcome.Succeeded
                    ? MailboxAuthenticationOutcome.Failed
                    : ForcedOutcome,
                null,
                "Refused."));
        }

        return Task.FromResult(new MailboxAuthenticationResult(
            MailboxAuthenticationOutcome.Succeeded,
            EmailAddress.Parse(KnownMailbox),
            "Authenticated."));
    }
}

public sealed class SmtpAuthenticationTests
{
    private readonly FakeSmtpDirectory _directory = new();
    private readonly ScriptedAuthenticator _authenticator = new();

    private SmtpCommandProcessor Processor(
        SmtpListenerRole role = SmtpListenerRole.Submission,
        bool tls = true,
        bool authAvailable = true,
        int maxAttempts = 3)
    {
        SmtpSessionContext session = new(
            role,
            IpAddressValue.Parse("198.51.100.20"),
            new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero),
            tls);

        return new SmtpCommandProcessor(
            session,
            new SmtpProcessorOptions(
                "mail.example.com",
                "AetherMail",
                100,
                1_000_000,
                authAvailable,
                MaxAuthenticationAttempts: maxAttempts),
            _directory,
            new RelayPolicy(),
            NullLogger.Instance,
            _authenticator);
    }

    private static async Task<SmtpCommandResult> SendAsync(SmtpCommandProcessor processor, string line) =>
        await processor.ExecuteAsync(SmtpCommand.Parse(line), default);

    private static string Plain(string authcid, string password) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{authcid}\0{password}"));

    private static string B64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    /// <summary>Greets, then runs an AUTH PLAIN with an initial response.</summary>
    private static async Task<SmtpCommandResult> AuthPlainAsync(
        SmtpCommandProcessor processor,
        string user,
        string password)
    {
        await SendAsync(processor, "EHLO client.example.net");

        return await SendAsync(processor, $"AUTH PLAIN {Plain(user, password)}");
    }

    // ---------------------------------------------------------------------------------------
    // The happy path.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_correct_credential_authenticates_the_session()
    {
        SmtpCommandProcessor processor = Processor();

        SmtpCommandResult result = await AuthPlainAsync(processor, "alice@example.com", "hunter2");

        result.Reply.Code.ShouldBe(235);
        result.Action.ShouldBe(SmtpSessionAction.Continue);

        processor.Session.IsAuthenticated.ShouldBeTrue();
        processor.Session.AuthenticatedMailbox!.Value.ShouldBe("alice@example.com");
    }

    [Fact]
    public async Task Auth_plain_without_an_initial_response_takes_one_more_line()
    {
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO client.example.net");

        SmtpCommandResult challenge = await SendAsync(processor, "AUTH PLAIN");

        challenge.Reply.Code.ShouldBe(334);
        challenge.Action.ShouldBe(SmtpSessionAction.ReadAuthenticationResponse);

        SmtpCommandResult done = await processor
            .ContinueAuthenticationAsync(Plain("alice@example.com", "hunter2"), default);

        done.Reply.Code.ShouldBe(235);
        processor.Session.IsAuthenticated.ShouldBeTrue();
    }

    [Fact]
    public async Task Auth_login_runs_its_two_challenges()
    {
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO client.example.net");

        SmtpCommandResult username = await SendAsync(processor, "AUTH LOGIN");

        username.Reply.Code.ShouldBe(334);
        Encoding.UTF8.GetString(Convert.FromBase64String(username.Reply.Text)).ShouldBe("Username:");

        SmtpCommandResult password = await processor
            .ContinueAuthenticationAsync(B64("alice@example.com"), default);

        password.Reply.Code.ShouldBe(334);
        Encoding.UTF8.GetString(Convert.FromBase64String(password.Reply.Text)).ShouldBe("Password:");

        SmtpCommandResult done = await processor.ContinueAuthenticationAsync(B64("hunter2"), default);

        done.Reply.Code.ShouldBe(235);
        processor.Session.IsAuthenticated.ShouldBeTrue();
    }

    [Fact]
    public async Task An_authenticated_session_may_then_submit()
    {
        SmtpCommandProcessor processor = Processor();

        await AuthPlainAsync(processor, "alice@example.com", "hunter2");

        (await SendAsync(processor, "MAIL FROM:<alice@example.com>")).Reply.Code.ShouldBe(250);
    }

    // ---------------------------------------------------------------------------------------
    // Refusals.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_wrong_password_is_refused_with_535()
    {
        SmtpCommandProcessor processor = Processor();

        SmtpCommandResult result = await AuthPlainAsync(processor, "alice@example.com", "wrong");

        result.Reply.Code.ShouldBe(535);
        result.Reply.EnhancedStatus.ShouldBe("5.7.8");
        processor.Session.IsAuthenticated.ShouldBeFalse();
    }

    [Fact]
    public async Task An_unknown_mailbox_receives_exactly_what_a_wrong_password_receives()
    {
        // Any difference here is an address-enumeration oracle, which is the first step of every
        // credential-stuffing run against a mail server.
        SmtpCommandResult unknown = await AuthPlainAsync(Processor(), "nobody@example.com", "hunter2");
        SmtpCommandResult wrong = await AuthPlainAsync(Processor(), "alice@example.com", "wrong");

        unknown.Reply.Format().ShouldBe(wrong.Reply.Format());
    }

    [Fact]
    public async Task A_locked_out_mailbox_receives_exactly_what_a_wrong_password_receives()
    {
        // "This account is locked" confirms the account exists.
        _authenticator.ForcedOutcome = MailboxAuthenticationOutcome.LockedOut;

        SmtpCommandResult locked = await AuthPlainAsync(Processor(), "alice@example.com", "wrong");

        _authenticator.ForcedOutcome = MailboxAuthenticationOutcome.Failed;

        SmtpCommandResult wrong = await AuthPlainAsync(Processor(), "alice@example.com", "wrong");

        locked.Reply.Format().ShouldBe(wrong.Reply.Format());
    }

    [Fact]
    public async Task A_mechanism_this_server_does_not_offer_is_refused_with_504()
    {
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO client.example.net");

        SmtpCommandResult result = await SendAsync(processor, "AUTH CRAM-MD5");

        result.Reply.Code.ShouldBe(504);
        _authenticator.Calls.ShouldBe(0);
    }

    [Fact]
    public async Task Auth_without_a_mechanism_is_a_syntax_error()
    {
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO client.example.net");

        (await SendAsync(processor, "AUTH")).Reply.Code.ShouldBe(501);
    }

    [Fact]
    public async Task A_second_authentication_on_one_session_is_refused()
    {
        // RFC 4954 §4. Allowing it would raise the question of what happens to envelope state
        // collected under the first identity.
        SmtpCommandProcessor processor = Processor();

        await AuthPlainAsync(processor, "alice@example.com", "hunter2");

        SmtpCommandResult second = await SendAsync(
            processor,
            $"AUTH PLAIN {Plain("mallory@example.com", "hunter2")}");

        second.Reply.Code.ShouldBe(503);
        processor.Session.AuthenticatedMailbox!.Value.ShouldBe("alice@example.com");
    }

    [Fact]
    public async Task A_cancelled_exchange_does_not_count_as_a_failed_attempt()
    {
        // A client that changed its mind has not guessed a password wrongly. Counting it would
        // walk a hesitant client into a lockout it never earned.
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO client.example.net");
        await SendAsync(processor, "AUTH PLAIN");

        SmtpCommandResult cancelled = await processor.ContinueAuthenticationAsync("*", default);

        cancelled.Reply.Code.ShouldBe(501);
        cancelled.Action.ShouldBe(SmtpSessionAction.Continue);

        processor.Session.FailedAuthenticationAttempts.ShouldBe(0);
        _authenticator.Calls.ShouldBe(0);
    }

    [Fact]
    public async Task A_malformed_exchange_does_count()
    {
        // Otherwise a client probes indefinitely by sending garbage and the attempt budget
        // bounds nothing.
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO client.example.net");

        SmtpCommandResult result = await SendAsync(processor, "AUTH PLAIN not-base64!!");

        result.Reply.Code.ShouldBe(535);
        processor.Session.FailedAuthenticationAttempts.ShouldBe(1);
    }

    [Fact]
    public async Task A_response_with_no_exchange_in_progress_is_refused()
    {
        SmtpCommandProcessor processor = Processor();

        await SendAsync(processor, "EHLO client.example.net");

        (await processor.ContinueAuthenticationAsync(B64("anything"), default)).Reply.Code.ShouldBe(503);
    }

    // ---------------------------------------------------------------------------------------
    // The attempt budget.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_connection_closes_once_the_attempt_budget_is_spent()
    {
        // Bounds online guessing at the connection level, underneath the per-mailbox lockout.
        // The two are different defences: lockout protects one account across every connection,
        // this stops one connection walking a dictionary across many accounts.
        SmtpCommandProcessor processor = Processor(maxAttempts: 3);

        await SendAsync(processor, "EHLO client.example.net");

        for (int attempt = 1; attempt <= 2; attempt++)
        {
            SmtpCommandResult result = await SendAsync(
                processor,
                $"AUTH PLAIN {Plain("alice@example.com", "wrong")}");

            result.Reply.Code.ShouldBe(535);
            result.Action.ShouldBe(SmtpSessionAction.Continue);
        }

        SmtpCommandResult last = await SendAsync(
            processor,
            $"AUTH PLAIN {Plain("alice@example.com", "wrong")}");

        last.Reply.Code.ShouldBe(421);
        last.Action.ShouldBe(SmtpSessionAction.CloseAfterReply);
    }

    [Fact]
    public async Task The_budget_refusal_is_transient_not_permanent()
    {
        // A legitimate client whose user mistyped three times should reconnect and try again; a
        // 5xx would tell it to stop for good.
        SmtpCommandProcessor processor = Processor(maxAttempts: 1);

        await SendAsync(processor, "EHLO client.example.net");

        SmtpCommandResult result = await SendAsync(
            processor,
            $"AUTH PLAIN {Plain("alice@example.com", "wrong")}");

        result.Reply.IsTransientFailure.ShouldBeTrue();
        result.Reply.IsPermanentFailure.ShouldBeFalse();
    }

    [Fact]
    public async Task A_further_attempt_after_the_budget_is_refused_without_reaching_the_authenticator()
    {
        SmtpCommandProcessor processor = Processor(maxAttempts: 1);

        await SendAsync(processor, "EHLO client.example.net");
        await SendAsync(processor, $"AUTH PLAIN {Plain("alice@example.com", "wrong")}");

        int callsAfterBudget = _authenticator.Calls;

        SmtpCommandResult beyond = await SendAsync(
            processor,
            $"AUTH PLAIN {Plain("alice@example.com", "hunter2")}");

        beyond.Reply.Code.ShouldBe(421);
        beyond.Action.ShouldBe(SmtpSessionAction.CloseAfterReply);

        _authenticator.Calls.ShouldBe(callsAfterBudget);
        processor.Session.IsAuthenticated.ShouldBeFalse();
    }

    [Fact]
    public async Task The_starttls_reset_does_not_refund_the_attempt_budget()
    {
        // Already asserted at the context level; asserted again here because this is the path
        // that would otherwise let a client buy three more guesses per handshake.
        SmtpCommandProcessor processor = Processor(tls: false, maxAttempts: 3);

        await SendAsync(processor, "EHLO client.example.net");
        await SendAsync(processor, "STARTTLS");

        processor.Session.CompleteTlsHandshake();

        processor.Session.FailedAuthenticationAttempts.ShouldBe(0);

        await SendAsync(processor, "EHLO client.example.net");
        await SendAsync(processor, $"AUTH PLAIN {Plain("alice@example.com", "wrong")}");

        processor.Session.FailedAuthenticationAttempts.ShouldBe(1);
    }

    // ---------------------------------------------------------------------------------------
    // Rule 105 and rule 77.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(SmtpListenerRole.Submission)]
    [InlineData(SmtpListenerRole.ImplicitTlsSubmission)]
    public async Task Auth_before_tls_demands_tls_rather_than_reading_the_credential(SmtpListenerRole role)
    {
        // Rule 105: no plaintext SMTP AUTH over Internet. The capability was not advertised, and
        // an attempt anyway is refused BEFORE the credential is decoded.
        SmtpCommandProcessor processor = Processor(role, tls: false);

        await SendAsync(processor, "EHLO client.example.net");

        SmtpCommandResult result = await SendAsync(
            processor,
            $"AUTH PLAIN {Plain("alice@example.com", "hunter2")}");

        result.Reply.Code.ShouldBe(530);
        _authenticator.Calls.ShouldBe(0);
        processor.Session.IsAuthenticated.ShouldBeFalse();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Auth_on_port_25_never_reaches_the_authenticator(bool tls)
    {
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.InboundMta, tls);

        await SendAsync(processor, "EHLO relay.example.net");

        SmtpCommandResult result = await SendAsync(
            processor,
            $"AUTH PLAIN {Plain("alice@example.com", "hunter2")}");

        result.Reply.Code.ShouldBe(502);
        _authenticator.Calls.ShouldBe(0);
    }

    [Fact]
    public async Task No_reply_on_any_authentication_path_contains_the_credential()
    {
        // Rule 77. A reply that quoted the AUTH line back would put the password in the peer's
        // logs, any intermediary's logs, and a packet capture.
        const string Password = "s3cr3t-hunter2";
        const string User = "alice@example.com";

        List<SmtpReply> replies = [];

        // Success, wrong password, unknown mailbox, bad base64, unsupported mechanism.
        foreach (string line in (string[])
        [
            $"AUTH PLAIN {Plain(User, "hunter2")}",
            $"AUTH PLAIN {Plain(User, Password)}",
            $"AUTH PLAIN {Plain("nobody@example.com", Password)}",
            $"AUTH PLAIN {Password}",
            $"AUTH CRAM-MD5 {Plain(User, Password)}",
        ])
        {
            SmtpCommandProcessor processor = Processor();

            await SendAsync(processor, "EHLO client.example.net");
            replies.Add((await SendAsync(processor, line)).Reply);
        }

        // And the LOGIN exchange, where the password arrives on its own line.
        SmtpCommandProcessor login = Processor();

        await SendAsync(login, "EHLO client.example.net");
        replies.Add((await SendAsync(login, "AUTH LOGIN")).Reply);
        replies.Add((await login.ContinueAuthenticationAsync(B64(User), default)).Reply);
        replies.Add((await login.ContinueAuthenticationAsync(B64(Password), default)).Reply);

        foreach (SmtpReply reply in replies)
        {
            string text = reply.Format();

            text.ShouldNotContain(Password);
            text.ShouldNotContain(B64(Password));
            text.ShouldNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{User}\0{Password}")));
        }
    }

    [Fact]
    public async Task The_password_buffer_is_cleared_once_the_exchange_ends()
    {
        // The credential lives in a clearable array precisely so the processor can overwrite it
        // the moment verification is done. A test that only checked SaslCredential.Dispose would
        // not prove the processor actually calls it.
        SmtpCommandProcessor processor = Processor();

        SaslCredential? captured = null;

        CapturingAuthenticator capturing = new(c => captured = c);

        SmtpCommandProcessor withCapture = new(
            processor.Session,
            new SmtpProcessorOptions("mail.example.com", "AetherMail", 100, 1_000_000, true),
            _directory,
            new RelayPolicy(),
            NullLogger.Instance,
            capturing);

        await SendAsync(withCapture, "EHLO client.example.net");
        await SendAsync(withCapture, $"AUTH PLAIN {Plain("alice@example.com", "hunter2")}");

        captured.ShouldNotBeNull();

        Should.Throw<ObjectDisposedException>(() => captured.Password.ToString());
    }

    /// <summary>Hands the credential back to the test so it can be inspected after disposal.</summary>
    private sealed class CapturingAuthenticator(Action<SaslCredential> capture) : IMailboxAuthenticator
    {
        public Task<MailboxAuthenticationResult> AuthenticateAsync(
            SaslCredential credential,
            IpAddressValue remoteAddress,
            CancellationToken cancellationToken)
        {
            capture(credential);

            return Task.FromResult(new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Failed,
                null,
                "Captured."));
        }
    }
}

/// <summary>A rate limiter a test can set to whatever it needs.</summary>
internal sealed class ScriptedRateLimiter : ISubmissionRateLimiter
{
    public bool WithinLimit { get; set; } = true;

    public int Limit { get; set; } = 200;

    public long Count { get; set; }

    public List<string> Checked { get; } = [];

    public Task<SubmissionRateDecision> CheckAsync(EmailAddress mailbox, CancellationToken cancellationToken)
    {
        Checked.Add(mailbox.Value);

        return Task.FromResult(new SubmissionRateDecision(
            WithinLimit,
            Count,
            Limit,
            TimeSpan.FromHours(1)));
    }
}

/// <summary>
/// The submission policy and the rate limit, through the command processor.
/// </summary>
/// <remarks>
/// <c>SubmissionPolicyTests</c> proves the decision function is right. These prove the server
/// asks it, and asks it at MAIL FROM rather than after a body has crossed the wire.
/// </remarks>
public sealed class SmtpSubmissionPolicyTests
{
    private readonly FakeSmtpDirectory _directory = new();
    private readonly ScriptedAuthenticator _authenticator = new();
    private readonly ScriptedRateLimiter _rateLimiter = new();

    private SmtpCommandProcessor Processor(SmtpListenerRole role = SmtpListenerRole.Submission)
    {
        SmtpSessionContext session = new(
            role,
            IpAddressValue.Parse("198.51.100.20"),
            new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero),
            isTlsActive: true);

        return new SmtpCommandProcessor(
            session,
            new SmtpProcessorOptions("mail.example.com", "AetherMail", 100, 1_000_000, true),
            _directory,
            new RelayPolicy(),
            NullLogger.Instance,
            _authenticator,
            new SubmissionPolicy(),
            _rateLimiter);
    }

    private static async Task<SmtpReply> SendAsync(SmtpCommandProcessor processor, string line) =>
        (await processor.ExecuteAsync(SmtpCommand.Parse(line), default)).Reply;

    private static string Plain(string authcid, string password) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{authcid}\0{password}"));

    /// <summary>Greets and authenticates as alice.</summary>
    private static async Task AuthenticateAsync(SmtpCommandProcessor processor)
    {
        await SendAsync(processor, "EHLO client.example.net");
        await SendAsync(processor, $"AUTH PLAIN {Plain("alice@example.com", "hunter2")}");

        processor.Session.IsAuthenticated.ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // Sender forgery.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_authenticated_mailbox_may_send_as_itself()
    {
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        (await SendAsync(processor, "MAIL FROM:<alice@example.com>")).Code.ShouldBe(250);
    }

    [Fact]
    public async Task An_authenticated_mailbox_may_not_send_as_a_colleague()
    {
        // One stolen password must not become every address in the organisation.
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<ceo@example.com>");

        reply.Code.ShouldBe(550);
        reply.EnhancedStatus.ShouldBe("5.7.1");
        processor.Session.HasTransaction.ShouldBeFalse();
    }

    [Fact]
    public async Task The_forgery_refusal_happens_before_a_recipient_is_even_named()
    {
        // Refused at MAIL FROM, the cheapest possible moment, and long before a body arrives.
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);
        await SendAsync(processor, "MAIL FROM:<ceo@example.com>");

        // No transaction, so RCPT is out of sequence rather than evaluated.
        (await SendAsync(processor, "RCPT TO:<user@example.com>")).Code.ShouldBe(503);
    }

    [Fact]
    public async Task An_alias_the_mailbox_is_behind_may_be_used()
    {
        _directory.SendAsPermissions["alice@example.com"] = ["sales@example.com"];

        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        (await SendAsync(processor, "MAIL FROM:<sales@example.com>")).Code.ShouldBe(250);
    }

    [Fact]
    public async Task The_null_reverse_path_is_refused_on_a_submission_listener()
    {
        // A mail client does not send bounces.
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        (await SendAsync(processor, "MAIL FROM:<>")).Code.ShouldBe(550);
    }

    [Fact]
    public async Task The_null_reverse_path_is_still_accepted_on_port_25()
    {
        // Where it belongs: an MTA delivering a bounce. The submission refusal must not leak
        // into the inbound path, or this server would reject every delivery status notification
        // on the Internet.
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.InboundMta);

        await SendAsync(processor, "EHLO relay.example.net");

        (await SendAsync(processor, "MAIL FROM:<>")).Code.ShouldBe(250);
    }

    [Fact]
    public async Task An_unauthenticated_inbound_session_is_not_subject_to_the_submission_policy()
    {
        // Port 25 has no authenticated mailbox, so there is nothing to compare a sender against.
        // Applying the policy there would refuse all inbound mail.
        SmtpCommandProcessor processor = Processor(SmtpListenerRole.InboundMta);

        await SendAsync(processor, "EHLO relay.example.net");

        (await SendAsync(processor, "MAIL FROM:<anyone@elsewhere.example>")).Code.ShouldBe(250);
        _rateLimiter.Checked.ShouldBeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // Rate limiting.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_mailbox_within_its_limit_may_submit()
    {
        _rateLimiter.WithinLimit = true;

        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        (await SendAsync(processor, "MAIL FROM:<alice@example.com>")).Code.ShouldBe(250);
        _rateLimiter.Checked.ShouldHaveSingleItem().ShouldBe("alice@example.com");
    }

    [Fact]
    public async Task A_mailbox_over_its_limit_is_refused_transiently()
    {
        // Transient on purpose: the sender is over a throttle, not wrong. The message is
        // perfectly deliverable an hour from now, and a 5xx would destroy legitimate mail to
        // enforce a rate limit.
        _rateLimiter.WithinLimit = false;
        _rateLimiter.Count = 250;
        _rateLimiter.Limit = 200;

        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<alice@example.com>");

        reply.Code.ShouldBe(451);
        reply.IsTransientFailure.ShouldBeTrue();
        reply.IsPermanentFailure.ShouldBeFalse();
        reply.Format().ShouldContain("200");

        processor.Session.HasTransaction.ShouldBeFalse();
    }

    [Fact]
    public async Task The_rate_limit_is_charged_to_the_authenticated_mailbox_not_the_claimed_sender()
    {
        // Otherwise a compromised account sends as a different alias per message and each one
        // gets its own budget, which is no limit at all.
        _directory.SendAsPermissions["alice@example.com"] = ["sales@example.com"];

        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);
        await SendAsync(processor, "MAIL FROM:<sales@example.com>");

        _rateLimiter.Checked.ShouldHaveSingleItem().ShouldBe("alice@example.com");
    }

    [Fact]
    public async Task A_forged_sender_is_refused_before_the_rate_limiter_is_asked()
    {
        // Cheap refusals first: a forgery attempt should not cost a database query.
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);
        await SendAsync(processor, "MAIL FROM:<ceo@example.com>");

        _rateLimiter.Checked.ShouldBeEmpty();
    }
}
