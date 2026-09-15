using System.Reflection;
using System.Text;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.SecurityTests;

/// <summary>An authenticator with one known credential, so the exchange can reach success.</summary>
internal sealed class OneAccountAuthenticator : IMailboxAuthenticator
{
    public const string Mailbox = "alice@example.com";
    public const string Password = "hunter2-correct-horse";

    public int Calls { get; private set; }

    public Task<MailboxAuthenticationResult> AuthenticateAsync(
        SaslCredential credential,
        IpAddressValue remoteAddress,
        CancellationToken cancellationToken)
    {
        Calls++;

        bool matches =
            string.Equals(credential.AuthenticationIdentity, Mailbox, StringComparison.OrdinalIgnoreCase) &&
            credential.Password.SequenceEqual(Password);

        return Task.FromResult(matches
            ? new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Succeeded,
                EmailAddress.Parse(Mailbox),
                "Authenticated.")
            : new MailboxAuthenticationResult(MailboxAuthenticationOutcome.Failed, null, "Refused."));
    }
}

/// <summary>
/// The submission surface: who may authenticate, and what authenticating entitles them to.
/// </summary>
/// <remarks>
/// <c>OpenRelayTests</c> covers who may be a RECIPIENT. This covers who may be a SENDER, which is
/// the half a stolen password attacks.
/// </remarks>
public sealed class SubmissionSecurityTests
{
    private readonly SingleDomainDirectory _directory = new();
    private readonly OneAccountAuthenticator _authenticator = new();

    private SmtpCommandProcessor Processor(
        SmtpListenerRole role = SmtpListenerRole.Submission,
        bool tls = true,
        bool authenticationAvailable = true,
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
                authenticationAvailable,
                MaxAuthenticationAttempts: maxAttempts),
            _directory,
            new RelayPolicy(),
            NullLogger.Instance,
            _authenticator,
            new SubmissionPolicy());
    }

    private static async Task<SmtpReply> SendAsync(SmtpCommandProcessor processor, string line) =>
        (await processor.ExecuteAsync(SmtpCommand.Parse(line), default)).Reply;

    private static string Plain(string user, string password) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{user}\0{password}"));

    private static async Task AuthenticateAsync(SmtpCommandProcessor processor)
    {
        await SendAsync(processor, "EHLO client.example.net");
        await SendAsync(
            processor,
            $"AUTH PLAIN {Plain(OneAccountAuthenticator.Mailbox, OneAccountAuthenticator.Password)}");

        processor.Session.IsAuthenticated.ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // Rule 105: no plaintext SMTP AUTH over Internet.
    // ---------------------------------------------------------------------------------------

    public static TheoryData<SmtpListenerRole, bool, bool> EveryRoleTlsAndAvailability()
    {
        TheoryData<SmtpListenerRole, bool, bool> data = [];

        foreach (SmtpListenerRole role in Enum.GetValues<SmtpListenerRole>())
        {
            // Not a listener role at all - see its own remarks. No session is ever constructed
            // with it, so it has no place in a matrix of "how does a session with this role
            // behave".
            if (role == SmtpListenerRole.Generated)
            {
                continue;
            }

            foreach (bool tls in (bool[])[false, true])
            {
                foreach (bool available in (bool[])[false, true])
                {
                    data.Add(role, tls, available);
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndAvailability))]
    public async Task A_credential_never_reaches_the_authenticator_except_on_submission_over_tls(
        SmtpListenerRole role,
        bool tls,
        bool available)
    {
        // The whole matrix in one assertion. A credential that reached the verifier on port 25,
        // or before TLS, would already have crossed the network in the clear.
        SmtpCommandProcessor processor = Processor(role, tls, available);

        await SendAsync(processor, "EHLO client.example.net");
        await SendAsync(
            processor,
            $"AUTH PLAIN {Plain(OneAccountAuthenticator.Mailbox, OneAccountAuthenticator.Password)}");

        bool isSubmission =
            role is SmtpListenerRole.Submission or SmtpListenerRole.ImplicitTlsSubmission;

        bool shouldHaveReached = isSubmission && tls && available;

        _authenticator.Calls.ShouldBe(
            shouldHaveReached ? 1 : 0,
            $"role {role}, TLS {tls}, available {available}");

        processor.Session.IsAuthenticated.ShouldBe(shouldHaveReached);
    }

    [Fact]
    public void The_session_context_refuses_to_record_an_authentication_without_tls()
    {
        // The last line of defence behind capability advertisement and the command check. A
        // defence that depends on two other components being right is not a defence.
        SmtpSessionContext session = new(
            SmtpListenerRole.Submission,
            IpAddressValue.Parse("198.51.100.20"),
            DateTimeOffset.UtcNow,
            isTlsActive: false);

        Should.Throw<InvalidOperationException>(
            () => session.Authenticate(EmailAddress.Parse(OneAccountAuthenticator.Mailbox)));
    }

    // ---------------------------------------------------------------------------------------
    // Sender forgery: what a stolen password is actually worth.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("ceo@example.com")]
    [InlineData("payroll@example.com")]
    [InlineData("postmaster@example.com")]
    [InlineData("alice@elsewhere.example")]
    [InlineData("Alice@example.com.elsewhere.example")]
    [InlineData("\"alice@example.com\"@elsewhere.example")]
    public async Task An_authenticated_mailbox_may_not_send_as_another_address(string claimed)
    {
        // The case that matters. A compromised account sending as the finance director, from the
        // real server, passes SPF, DKIM and DMARC - because as far as every downstream check is
        // concerned the mail genuinely is from this domain.
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        SmtpReply reply = await SendAsync(processor, $"MAIL FROM:<{claimed}>");

        reply.Code.ShouldBe(550, $"'{claimed}' was accepted as a sender.");
        reply.EnhancedStatus.ShouldBe("5.7.1");
        processor.Session.HasTransaction.ShouldBeFalse();
    }

    [Fact]
    public async Task An_authenticated_mailbox_may_send_as_itself()
    {
        // The other direction, so the suite cannot pass against a server that refuses everything.
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        (await SendAsync(processor, $"MAIL FROM:<{OneAccountAuthenticator.Mailbox}>")).Code.ShouldBe(250);
    }

    [Fact]
    public async Task The_null_reverse_path_is_refused_on_a_submission_listener()
    {
        // "<>" is a bounce's sender. An authenticated client emitting mail that cannot itself be
        // bounced is the shape of a backscatter campaign.
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        (await SendAsync(processor, "MAIL FROM:<>")).Code.ShouldBe(550);
    }

    [Fact]
    public void The_product_states_outright_that_authentication_is_not_a_blank_cheque()
    {
        SubmissionPolicy.MayAuthenticatedSenderUseAnyAddress.ShouldBeFalse();
    }

    [Fact]
    public void No_configuration_option_disables_the_sender_check()
    {
        // There is no "AllowAnySender" or "TrustAuthenticatedSenders" setting, and adding one
        // must be a deliberate act that fails the build rather than a plausible convenience.
        string[] forbidden =
        [
            "AllowAnySender", "TrustAuthenticatedSenders", "AllowSenderSpoofing",
            "SkipSenderCheck", "DisableSubmissionPolicy", "AllowSendAs",
        ];

        string[] properties =
        [
            .. typeof(MailServer.Infrastructure.Configuration.SmtpOptions).GetProperties().Select(p => p.Name),
            .. typeof(MailServer.Infrastructure.Configuration.LimitsOptions).GetProperties().Select(p => p.Name),
        ];

        foreach (string name in forbidden)
        {
            properties.ShouldNotContain(
                p => p.Contains(name, StringComparison.OrdinalIgnoreCase),
                $"A configuration option resembling '{name}' exists.");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Online guessing.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_connection_may_not_be_used_to_walk_a_dictionary()
    {
        SmtpCommandProcessor processor = Processor(maxAttempts: 3);

        await SendAsync(processor, "EHLO client.example.net");

        for (int attempt = 1; attempt <= 2; attempt++)
        {
            (await SendAsync(processor, $"AUTH PLAIN {Plain($"user{attempt}@example.com", "guess")}"))
                .Code.ShouldBe(535);
        }

        SmtpCommandResult last = await processor.ExecuteAsync(
            SmtpCommand.Parse($"AUTH PLAIN {Plain("user3@example.com", "guess")}"),
            default);

        last.Reply.Code.ShouldBe(421);
        last.Action.ShouldBe(SmtpSessionAction.CloseAfterReply);
    }

    [Fact]
    public async Task The_budget_is_not_refunded_by_a_correct_password_arriving_late()
    {
        // Otherwise an attacker spends the budget guessing and then walks in the moment one
        // guess lands, which is the opposite of what a budget is for.
        SmtpCommandProcessor processor = Processor(maxAttempts: 1);

        await SendAsync(processor, "EHLO client.example.net");
        await SendAsync(processor, $"AUTH PLAIN {Plain(OneAccountAuthenticator.Mailbox, "guess")}");

        SmtpReply correct = await SendAsync(
            processor,
            $"AUTH PLAIN {Plain(OneAccountAuthenticator.Mailbox, OneAccountAuthenticator.Password)}");

        correct.Code.ShouldBe(421);
        processor.Session.IsAuthenticated.ShouldBeFalse();
    }

    [Fact]
    public async Task An_unknown_mailbox_and_a_wrong_password_are_indistinguishable()
    {
        // Address enumeration is the first step of every credential-stuffing run against a mail
        // server. Any difference - in the code, the text, or the enhanced status - is the oracle.
        SmtpCommandProcessor unknown = Processor();
        await SendAsync(unknown, "EHLO client.example.net");
        SmtpReply unknownReply = await SendAsync(unknown, $"AUTH PLAIN {Plain("nobody@example.com", "x")}");

        SmtpCommandProcessor wrong = Processor();
        await SendAsync(wrong, "EHLO client.example.net");
        SmtpReply wrongReply = await SendAsync(
            wrong,
            $"AUTH PLAIN {Plain(OneAccountAuthenticator.Mailbox, "x")}");

        unknownReply.Format().ShouldBe(wrongReply.Format());
    }

    // ---------------------------------------------------------------------------------------
    // Rule 77: credentials never appear anywhere they could be read later.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task No_reply_on_any_authentication_path_contains_the_credential()
    {
        const string Secret = "s3cr3t-do-not-echo";

        List<SmtpReply> replies = [];

        foreach (string line in (string[])
        [
            $"AUTH PLAIN {Plain(OneAccountAuthenticator.Mailbox, Secret)}",
            $"AUTH PLAIN {Plain("nobody@example.com", Secret)}",
            $"AUTH PLAIN {Secret}",
            $"AUTH LOGIN {Convert.ToBase64String(Encoding.UTF8.GetBytes(Secret))}",
            $"AUTH CRAM-MD5 {Plain(OneAccountAuthenticator.Mailbox, Secret)}",
            $"AUTH {Secret}",
        ])
        {
            SmtpCommandProcessor processor = Processor();

            await SendAsync(processor, "EHLO client.example.net");
            replies.Add(await SendAsync(processor, line));
        }

        foreach (SmtpReply reply in replies)
        {
            string formatted = reply.Format();

            formatted.ShouldNotContain(Secret);
            formatted.ShouldNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(Secret)));
            formatted.ShouldNotContain(Plain(OneAccountAuthenticator.Mailbox, Secret));
        }
    }

    [Fact]
    public void A_sasl_credential_clears_its_password_and_has_no_finaliser()
    {
        // A finaliser would clear it at an unpredictable time, which is the same as not clearing
        // it. The Dispose contract is the whole mechanism, so the absence is deliberate.
        char[] password = "hunter2".ToCharArray();

        SaslCredential credential = new("alice@example.com", string.Empty, password);

        credential.Dispose();

        password.ShouldAllBe(c => c == '\0');

        typeof(SaslCredential)
            .GetMethod("Finalize", BindingFlags.NonPublic | BindingFlags.Instance)!
            .DeclaringType.ShouldBe(typeof(object));
    }

    [Fact]
    public void The_password_hasher_accepts_a_clearable_buffer()
    {
        // Routing a SASL password through the string overload would create an immutable copy on
        // the managed heap that nothing can clear, which is what the char[] exists to avoid.
        Type hasher = typeof(MailServer.Application.Abstractions.Security.IPasswordHasher);

        foreach (string name in (string[])["Hash", "Verify", "VerifyAgainstDummy"])
        {
            // Compared by name rather than against typeof(ReadOnlySpan<char>), which a LINQ
            // expression tree cannot carry: it is a ref struct.
            bool hasSpanOverload = hasher.GetMethods().Any(m =>
                m.Name == name &&
                m.GetParameters()[0].ParameterType.Name.StartsWith("ReadOnlySpan", StringComparison.Ordinal));

            hasSpanOverload.ShouldBeTrue(
                $"IPasswordHasher.{name} has no span overload, so the SMTP path must " +
                "materialise a string it cannot clear.");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Mechanisms.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("CRAM-MD5")]
    [InlineData("DIGEST-MD5")]
    [InlineData("ANONYMOUS")]
    [InlineData("EXTERNAL")]
    [InlineData("PLAINTEXT")]
    public void No_mechanism_outside_the_offered_set_can_be_selected(string name)
    {
        // ANONYMOUS above all: a mechanism that authenticates nobody, on a listener whose whole
        // purpose is to relay for people it has authenticated.
        SaslMechanisms.Create(name).ShouldBeNull();
        SaslMechanisms.IsSupported(name).ShouldBeFalse();
    }

    [Fact]
    public void No_offered_mechanism_would_require_storing_a_recoverable_password()
    {
        // CRAM-MD5 and DIGEST-MD5 need the server to hold something it can compute a challenge
        // response from - in practice the password. One database read would then be every user's
        // password, and users reuse them. See addendum A5.1.
        foreach (string name in SmtpCapabilities.SaslMechanisms)
        {
            name.ShouldNotContain("CRAM", Case.Insensitive);
            name.ShouldNotContain("DIGEST", Case.Insensitive);
            name.ShouldNotContain("SCRAM", Case.Insensitive);
        }
    }

    [Fact]
    public async Task A_second_authentication_cannot_change_who_the_session_is()
    {
        // RFC 4954 §4. Allowing it would raise the question of what happens to envelope state
        // collected under the first identity - and answering it wrongly is a privilege change
        // mid-transaction.
        SmtpCommandProcessor processor = Processor();

        await AuthenticateAsync(processor);

        await SendAsync(processor, $"AUTH PLAIN {Plain("mallory@example.com", "anything")}");

        processor.Session.AuthenticatedMailbox!.Value.ShouldBe(OneAccountAuthenticator.Mailbox);
    }
}
