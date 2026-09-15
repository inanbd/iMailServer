using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

/// <summary>
/// The submission listener over a real socket and a real TLS handshake.
/// </summary>
/// <remarks>
/// Everything below the wire is real: listener, connection handler, TLS, reader, SASL mechanisms,
/// message store. Only the directory, the authenticator and the delivery service are stand-ins.
/// </remarks>
public sealed class SmtpSubmissionWireTests : IAsyncLifetime
{
    private const string Mailbox = "alice@example.com";
    private const string Password = "hunter2-correct-horse";

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "aethermail-submission-" + Guid.NewGuid().ToString("N"));

    private readonly FakeSmtpDirectory _directory = new();
    private readonly RecordingDeliveryService _delivery = new();
    private readonly TestCertificateProvider _certificates = new();
    private readonly CountingSecurityEventRecorder _recorder = new();
    private readonly ScriptedAuthenticator _authenticator = new();
    private readonly ScriptedRateLimiter _rateLimiter = new();

    private SmtpListener _listener = null!;
    private ServiceProvider _services = null!;
    private int _port;

    public Task InitializeAsync()
    {
        _authenticator.KnownMailbox = Mailbox;
        _authenticator.KnownPassword = Password;

        FileSystemMessageStore store = new(
            _root,
            new TestClock(),
            NullLogger<FileSystemMessageStore>.Instance);

        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddSingleton<ISmtpDirectory>(_directory);
        services.AddSingleton<ITlsCertificateProvider>(_certificates);
        services.AddSingleton<ILocalDeliveryService>(_delivery);
        services.AddSingleton<IMessageStore>(store);
        services.AddSingleton<RelayPolicy>();
        services.AddSingleton<SubmissionPolicy>();
        services.AddSingleton<ISubmissionRateLimiter>(_rateLimiter);
        services.AddSingleton<ISecurityEventRecorder>(_recorder);

        // Records a failure like the real authenticator, so the evidence tests have something
        // to look for.
        services.AddSingleton<IMailboxAuthenticator>(
            new RecordingAuthenticator(_authenticator, _recorder));

        services.AddScoped<SmtpDataReceiver>();
        services.AddScoped<SmtpConnectionHandler>();

        _services = services.BuildServiceProvider();

        SmtpConnectionOptions options = new(
            SmtpListenerRole.Submission,
            new SmtpProcessorOptions(
                "mail.example.com",
                "AetherMail",
                100,
                1_000_000,
                IsAuthenticationAvailable: true,
                MaxAuthenticationAttempts: 3),
            MaxLineOctets: 4096,
            CommandTimeout: TimeSpan.FromSeconds(10),
            SessionTimeout: TimeSpan.FromSeconds(30),
            CertificatePurpose.SmtpSubmission);

        _listener = new SmtpListener(
            new IPEndPoint(IPAddress.Loopback, 0),
            options,
            new SmtpConnectionLimiter(maxTotal: 10, maxPerAddress: 10),
            _services.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<SmtpListener>.Instance);

        _ = _listener.StartAsync(CancellationToken.None);
        _port = _listener.BoundPort;

        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _listener.StopAsync(TimeSpan.FromSeconds(2));
        await _listener.DisposeAsync();
        await _services.DisposeAsync();

        _certificates.Dispose();

        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    /// <summary>Wraps the scripted authenticator so a refusal leaves evidence, as the real one does.</summary>
    private sealed class RecordingAuthenticator(
        IMailboxAuthenticator inner,
        ISecurityEventRecorder recorder) : IMailboxAuthenticator
    {
        public async Task<MailboxAuthenticationResult> AuthenticateAsync(
            SaslCredential credential,
            IpAddressValue remoteAddress,
            CancellationToken cancellationToken)
        {
            MailboxAuthenticationResult result = await inner
                .AuthenticateAsync(credential, remoteAddress, cancellationToken)
                .ConfigureAwait(false);

            await recorder.RecordAsync(
                result.IsSuccess
                    ? SecurityEventType.MailboxAuthenticationSucceeded
                    : SecurityEventType.MailboxAuthenticationFailed,
                credential.AuthenticationIdentity,
                remoteAddress.Value,

                // Uniform text, exactly as the real authenticator writes it: a description that
                // distinguished an unknown mailbox from a wrong password would hand whoever can
                // read the log the enumeration oracle the reply codes refuse to give.
                result.IsSuccess ? "Authenticated on a submission listener." : "Authentication failed.",
                cancellationToken).ConfigureAwait(false);

            return result;
        }
    }

    /// <summary>A client that speaks submission SMTP: connect, STARTTLS, AUTH, send.</summary>
    private sealed class Client(TcpClient client) : IAsyncDisposable
    {
        private Stream _stream = client.GetStream();
        private StreamReader _reader = new(client.GetStream(), Encoding.UTF8);

        public async Task<string> ReadReplyAsync()
        {
            StringBuilder reply = new();

            while (await _reader.ReadLineAsync() is { } line)
            {
                reply.AppendLine(line);

                if (line.Length < 4 || line[3] != '-')
                {
                    break;
                }
            }

            return reply.ToString();
        }

        public async Task<string> SendAsync(string line)
        {
            byte[] octets = Encoding.UTF8.GetBytes(line + "\r\n");

            await _stream.WriteAsync(octets);
            await _stream.FlushAsync();

            return await ReadReplyAsync();
        }

        public async Task StartTlsAsync()
        {
            await SendAsync("STARTTLS");

            SslStream tls = new(_stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "mail.example.com",
            });

            _stream = tls;
            _reader = new StreamReader(tls, Encoding.UTF8);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await _stream.DisposeAsync();
            }
            catch (IOException)
            {
                // The server may already have closed it, which is the point of some tests.
            }

            client.Dispose();
        }
    }

    private async Task<Client> ConnectAsync()
    {
        TcpClient client = new();

        await client.ConnectAsync(IPAddress.Loopback, _port);

        Client peer = new(client);

        await peer.ReadReplyAsync();

        return peer;
    }

    /// <summary>Connects, upgrades to TLS and greets again.</summary>
    private async Task<Client> ConnectSecureAsync()
    {
        Client peer = await ConnectAsync();

        await peer.SendAsync("EHLO client.example.net");
        await peer.StartTlsAsync();
        await peer.SendAsync("EHLO client.example.net");

        return peer;
    }

    private static string Plain(string user, string password) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{user}\0{password}"));

    // ---------------------------------------------------------------------------------------
    // The exit criterion: a client authenticates and sends.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_client_authenticates_over_tls_and_submits()
    {
        await using Client peer = await ConnectSecureAsync();

        (await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, Password)}")).ShouldStartWith("235");
        (await peer.SendAsync($"MAIL FROM:<{Mailbox}>")).ShouldStartWith("250");
        (await peer.SendAsync("RCPT TO:<user@example.com>")).ShouldStartWith("250");
        (await peer.SendAsync("DATA")).ShouldStartWith("354");

        await peer.SendAsync("Subject: submitted\r\n\r\nBody.\r\n.");

        _delivery.Requests.ShouldHaveSingleItem();
        _delivery.Requests[0].AuthenticatedAs!.Value.ShouldBe(Mailbox);
        _delivery.Requests[0].TlsActive.ShouldBeTrue();
    }

    [Fact]
    public async Task Auth_login_works_over_the_wire()
    {
        // Outlook and others support LOGIN and not PLAIN, which is the only reason it is offered.
        await using Client peer = await ConnectSecureAsync();

        string usernamePrompt = await peer.SendAsync("AUTH LOGIN");

        usernamePrompt.ShouldStartWith("334");
        Encoding.UTF8.GetString(Convert.FromBase64String(usernamePrompt[4..].Trim())).ShouldBe("Username:");

        string passwordPrompt = await peer.SendAsync(
            Convert.ToBase64String(Encoding.UTF8.GetBytes(Mailbox)));

        Encoding.UTF8.GetString(Convert.FromBase64String(passwordPrompt[4..].Trim())).ShouldBe("Password:");

        (await peer.SendAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(Password))))
            .ShouldStartWith("235");
    }

    // ---------------------------------------------------------------------------------------
    // Rule 105 over the wire.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Auth_is_not_advertised_before_tls_and_is_refused_if_attempted()
    {
        await using Client peer = await ConnectAsync();

        string ehlo = await peer.SendAsync("EHLO client.example.net");

        ehlo.ShouldNotContain("AUTH");
        ehlo.ShouldContain("STARTTLS");

        (await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, Password)}")).ShouldStartWith("530");
    }

    [Fact]
    public async Task Auth_is_advertised_once_tls_is_active()
    {
        await using Client peer = await ConnectSecureAsync();

        // The greeting inside the tunnel has already been read by ConnectSecureAsync; ask again.
        (await peer.SendAsync("EHLO client.example.net")).ShouldContain("AUTH PLAIN LOGIN");
    }

    [Fact]
    public async Task An_unauthenticated_session_cannot_submit_even_for_a_local_recipient()
    {
        // The safe failure: a submission port refuses everything until somebody proves who they
        // are, rather than behaving like a second port 25.
        await using Client peer = await ConnectSecureAsync();

        (await peer.SendAsync("MAIL FROM:<alice@example.com>")).ShouldStartWith("530");
    }

    // ---------------------------------------------------------------------------------------
    // Guessing.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_wrong_password_and_an_unknown_mailbox_are_answered_identically()
    {
        await using Client wrongPassword = await ConnectSecureAsync();
        string wrong = await wrongPassword.SendAsync($"AUTH PLAIN {Plain(Mailbox, "guess")}");

        await using Client unknownMailbox = await ConnectSecureAsync();
        string unknown = await unknownMailbox.SendAsync($"AUTH PLAIN {Plain("nobody@example.com", Password)}");

        wrong.ShouldBe(unknown);
        wrong.ShouldStartWith("535");
    }

    [Fact]
    public async Task The_connection_closes_after_the_attempt_budget_is_spent()
    {
        await using Client peer = await ConnectSecureAsync();

        (await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, "guess1")}")).ShouldStartWith("535");
        (await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, "guess2")}")).ShouldStartWith("535");

        (await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, "guess3")}")).ShouldStartWith("421");

        // Closed, so there is nothing further to read.
        (await peer.ReadReplyAsync()).ShouldBeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // Sender forgery and rate limiting, over the wire.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_authenticated_client_may_not_send_as_a_colleague()
    {
        await using Client peer = await ConnectSecureAsync();

        await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, Password)}");

        (await peer.SendAsync("MAIL FROM:<ceo@example.com>")).ShouldStartWith("550 5.7.1");

        _delivery.Requests.ShouldBeEmpty();
    }

    [Fact]
    public async Task An_authenticated_client_may_send_as_an_alias_it_owns()
    {
        _directory.SendAsPermissions[Mailbox] = ["sales@example.com"];

        await using Client peer = await ConnectSecureAsync();

        await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, Password)}");

        (await peer.SendAsync("MAIL FROM:<sales@example.com>")).ShouldStartWith("250");
    }

    [Fact]
    public async Task A_client_over_its_rate_limit_is_refused_transiently()
    {
        _rateLimiter.WithinLimit = false;
        _rateLimiter.Limit = 200;
        _rateLimiter.Count = 201;

        await using Client peer = await ConnectSecureAsync();

        await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, Password)}");

        (await peer.SendAsync($"MAIL FROM:<{Mailbox}>")).ShouldStartWith("451 4.7.1");
    }

    [Fact]
    public async Task An_authenticated_client_may_relay_to_a_foreign_domain()
    {
        // The point of a submission port. A suite that only proved refusals would pass against a
        // server that refused everything.
        await using Client peer = await ConnectSecureAsync();

        await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, Password)}");
        await peer.SendAsync($"MAIL FROM:<{Mailbox}>");

        (await peer.SendAsync("RCPT TO:<partner@elsewhere.example>")).ShouldStartWith("250");
    }

    // ---------------------------------------------------------------------------------------
    // Evidence. A security log that is not written is not a security log.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_failed_authentication_reaches_the_security_log()
    {
        // Found by running the server rather than by the tests: events are buffered so they do
        // not deadlock a delivery transaction, and on the SMTP path NOTHING flushed them. Every
        // failure and every lockout was recorded, logged as recorded, and then discarded.
        await using (Client peer = await ConnectSecureAsync())
        {
            await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, "guess")}");
            await peer.SendAsync("QUIT");
        }

        await WaitForWritesAsync();

        _recorder.Written.ShouldContain(
            e => e.Type == SecurityEventType.MailboxAuthenticationFailed && e.Subject == Mailbox,
            "The failed authentication never reached storage.");
    }

    [Fact]
    public async Task A_successful_authentication_reaches_the_security_log()
    {
        // Recorded as well as the failures. A successful sign-in from an address the owner has
        // never used is the signal that a password has been stolen, and it is invisible if only
        // failures are kept.
        await using (Client peer = await ConnectSecureAsync())
        {
            await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, Password)}");
            await peer.SendAsync("QUIT");
        }

        await WaitForWritesAsync();

        _recorder.Written.ShouldContain(e => e.Type == SecurityEventType.MailboxAuthenticationSucceeded);
    }

    [Fact]
    public async Task A_session_dropped_without_quit_still_leaves_its_evidence()
    {
        // The flush is in a finally, so a session that ends the way an attacker's session ends
        // does not take the record of it along.
        Client peer = await ConnectSecureAsync();

        await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, "guess")}");

        await peer.DisposeAsync();

        await WaitForWritesAsync();

        _recorder.Written.ShouldContain(e => e.Type == SecurityEventType.MailboxAuthenticationFailed);
    }

    [Fact]
    public async Task The_security_log_does_not_distinguish_an_unknown_mailbox_from_a_wrong_password()
    {
        // The reply codes are careful not to offer that distinction. Writing it to the event log
        // would hand the same oracle to anyone who can read the log.
        await using (Client peer = await ConnectSecureAsync())
        {
            await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, "guess")}");
            await peer.SendAsync("QUIT");
        }

        await using (Client peer = await ConnectSecureAsync())
        {
            await peer.SendAsync($"AUTH PLAIN {Plain("nobody@example.com", Password)}");
            await peer.SendAsync("QUIT");
        }

        await WaitForWritesAsync(expected: 2);

        string[] descriptions =
        [
            .. _recorder.Written
                .Where(e => e.Type == SecurityEventType.MailboxAuthenticationFailed)
                .Select(e => e.Description)
                .Distinct()
        ];

        descriptions.ShouldHaveSingleItem();
    }

    [Fact]
    public async Task No_security_event_carries_the_attempted_password()
    {
        // Rule 77. The event log is read by operators and shipped to whatever collects logs; a
        // password in it is a password in all of those places.
        await using (Client peer = await ConnectSecureAsync())
        {
            await peer.SendAsync($"AUTH PLAIN {Plain(Mailbox, Password)}");
            await peer.SendAsync($"MAIL FROM:<{Mailbox}>");
            await peer.SendAsync("QUIT");
        }

        await WaitForWritesAsync();

        foreach ((SecurityEventType _, string? subject, string description) in _recorder.Written)
        {
            description.ShouldNotContain(Password);
            description.ShouldNotContain(Plain(Mailbox, Password));

            (subject ?? string.Empty).ShouldNotContain(Password);
        }
    }

    private async Task WaitForWritesAsync(int expected = 1)
    {
        for (int attempt = 0; attempt < 100 && _recorder.Written.Count < expected; attempt++)
        {
            await Task.Delay(20);
        }
    }
}
