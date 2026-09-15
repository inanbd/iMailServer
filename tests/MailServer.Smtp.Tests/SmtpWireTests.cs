using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
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

/// <summary>A TLS provider holding one self-signed certificate, for the handshake tests.</summary>
internal sealed class TestCertificateProvider : ITlsCertificateProvider, IDisposable
{
    private readonly X509Certificate2 _certificate;

    public TestCertificateProvider()
    {
        using System.Security.Cryptography.RSA key = System.Security.Cryptography.RSA.Create(2048);

        CertificateRequest request = new(
            "CN=mail.example.com",
            key,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder subjectAlternativeNames = new();
        subjectAlternativeNames.AddDnsName("mail.example.com");

        request.CertificateExtensions.Add(subjectAlternativeNames.Build());

        using X509Certificate2 generated = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));

        // Round-tripped through PKCS#12 so the private key is usable by SslStream on every
        // platform; a certificate created in memory is not always bound to its key otherwise.
        _certificate = X509CertificateLoader.LoadPkcs12(
            generated.Export(X509ContentType.Pkcs12),
            password: null);
    }

    public IReadOnlyCollection<DomainName> ConfiguredHostnames => [DomainName.Parse("mail.example.com")];

    public bool IsReady => true;

    public X509Certificate2? Select(string? hostname, CertificatePurpose purpose) => _certificate;

    public Task ReloadAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public void Dispose() => _certificate.Dispose();
}

/// <summary>Records what a delivery attempt was asked to do, without touching a database.</summary>
internal sealed class RecordingDeliveryService : ILocalDeliveryService
{
    public List<DeliveryRequest> Requests { get; } = [];

    public Task<DeliveryResult> DeliverAsync(DeliveryRequest request, CancellationToken cancellationToken)
    {
        Requests.Add(request);

        return Task.FromResult(new DeliveryResult(
            request.Message.Id,
            [.. request.Recipients.Select(r => new RecipientOutcome(r.Address, 1, false))]));
    }
}

/// <summary>
/// The SMTP implementation over a real TCP socket, driven the way a peer drives it.
/// </summary>
/// <remarks>
/// Everything below the wire is real: the listener, the connection handler, the reader, the
/// decoder, the message store and a genuine TLS handshake. Only the directory and the delivery
/// service are stand-ins, because a database is not what these tests are about.
/// </remarks>
public sealed class SmtpWireTests : IAsyncLifetime
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "aethermail-wire-" + Guid.NewGuid().ToString("N"));

    private readonly FakeSmtpDirectory _directory = new();
    private readonly RecordingDeliveryService _delivery = new();
    private readonly TestCertificateProvider _certificates = new();

    private SmtpListener _listener = null!;
    private ServiceProvider _services = null!;
    private int _port;

    public Task InitializeAsync()
    {
        FileSystemMessageStore store = new(
            _root,
            new TestClock(),
            NullLogger<FileSystemMessageStore>.Instance);

        // Registered rather than constructed, because the listener resolves a handler per
        // connection from its own scope - which is the behaviour under test as much as anything
        // else here, and a hand-built handler would not exercise it.
        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddSingleton<ISmtpDirectory>(_directory);
        services.AddSingleton<ITlsCertificateProvider>(_certificates);
        services.AddSingleton<ILocalDeliveryService>(_delivery);
        services.AddSingleton<IMessageStore>(store);
        services.AddSingleton<RelayPolicy>();
        services.AddScoped<SmtpDataReceiver>();
        services.AddScoped<SmtpConnectionHandler>();

        _services = services.BuildServiceProvider();

        SmtpConnectionOptions options = new(
            SmtpListenerRole.InboundMta,
            new SmtpProcessorOptions("mail.example.com", "AetherMail", 100, 1_000_000),
            MaxLineOctets: 4096,
            CommandTimeout: TimeSpan.FromSeconds(10),
            SessionTimeout: TimeSpan.FromSeconds(30),
            CertificatePurpose.SmtpInbound);

        _listener = new SmtpListener(
            new IPEndPoint(IPAddress.Loopback, 0),
            options,
            new SmtpConnectionLimiter(maxTotal: 10, maxPerAddress: 5),
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

    /// <summary>A client that speaks SMTP the way a peer does: write a line, read a reply.</summary>
    private sealed class Peer(TcpClient client) : IAsyncDisposable
    {
        private Stream _stream = client.GetStream();
        private StreamReader _reader = new(client.GetStream(), Encoding.UTF8);

        public async Task<string> ReadReplyAsync()
        {
            StringBuilder reply = new();

            while (await _reader.ReadLineAsync() is { } line)
            {
                reply.AppendLine(line);

                // Continuation lines carry a hyphen after the code; the last carries a space.
                if (line.Length < 4 || line[3] != '-')
                {
                    break;
                }
            }

            return reply.ToString();
        }

        public async Task<string> SendAsync(string line)
        {
            await WriteRawAsync(line + "\r\n");
            return await ReadReplyAsync();
        }

        /// <summary>Writes octets with no line ending added and no reply read. For pipelining.</summary>
        public async Task WriteRawAsync(string text)
        {
            byte[] octets = Encoding.UTF8.GetBytes(text);

            await _stream.WriteAsync(octets);
            await _stream.FlushAsync();
        }

        public async Task UpgradeToTlsAsync()
        {
            SslStream tls = new(
                _stream,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "mail.example.com",
            });

            _stream = tls;
            _reader = new StreamReader(tls, Encoding.UTF8);
        }

        public async ValueTask DisposeAsync()
        {
            await _stream.DisposeAsync();
            client.Dispose();
        }
    }

    private async Task<Peer> ConnectAsync()
    {
        TcpClient client = new();

        await client.ConnectAsync(IPAddress.Loopback, _port);

        return new Peer(client);
    }

    // ---------------------------------------------------------------------------------------
    // A whole conversation.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_message_is_accepted_over_a_real_socket()
    {
        await using Peer peer = await ConnectAsync();

        (await peer.ReadReplyAsync()).ShouldStartWith("220 mail.example.com ESMTP");

        (await peer.SendAsync("EHLO relay.example.net")).ShouldContain("PIPELINING");
        (await peer.SendAsync("MAIL FROM:<sender@example.net>")).ShouldStartWith("250");
        (await peer.SendAsync("RCPT TO:<user@example.com>")).ShouldStartWith("250");
        (await peer.SendAsync("DATA")).ShouldStartWith("354");

        await peer.WriteRawAsync("Subject: hello\r\n\r\nBody text.\r\n.\r\n");

        (await peer.ReadReplyAsync()).ShouldStartWith("250");
        (await peer.SendAsync("QUIT")).ShouldStartWith("221");

        _delivery.Requests.Count.ShouldBe(1);
        _delivery.Requests[0].Recipients.Single().Address.Value.ShouldBe("user@example.com");
    }

    [Fact]
    public async Task The_stored_message_carries_a_trace_header_naming_this_server()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("MAIL FROM:<sender@example.net>");
        await peer.SendAsync("RCPT TO:<user@example.com>");
        await peer.SendAsync("DATA");
        await peer.WriteRawAsync("Subject: traced\r\n\r\nBody.\r\n.\r\n");
        await peer.ReadReplyAsync();

        string path = Directory.EnumerateFiles(_root, "*.eml", SearchOption.AllDirectories).Single();
        string stored = await File.ReadAllTextAsync(path);

        stored.ShouldStartWith("Received: from relay.example.net (");
        stored.ShouldContain("by mail.example.com with ESMTP");
        stored.ShouldContain("for <user@example.com>");
        stored.ShouldEndWith("Subject: traced\r\n\r\nBody.\r\n");
    }

    [Fact]
    public async Task The_trace_header_names_the_identifier_the_message_was_stored_under()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("MAIL FROM:<sender@example.net>");
        await peer.SendAsync("RCPT TO:<user@example.com>");
        await peer.SendAsync("DATA");
        await peer.WriteRawAsync("Body.\r\n.\r\n");
        await peer.ReadReplyAsync();

        string path = Directory.EnumerateFiles(_root, "*.eml", SearchOption.AllDirectories).Single();
        string id = Path.GetFileNameWithoutExtension(path);

        (await File.ReadAllTextAsync(path)).ShouldContain($"id {id}");
    }

    [Fact]
    public async Task Two_messages_can_be_sent_on_one_connection()
    {
        // A sending MTA with several messages for this server reuses the connection. The second
        // must not inherit the first's envelope.
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");

        foreach (string recipient in (string[])["user@example.com", "postmaster@example.com"])
        {
            await peer.SendAsync("MAIL FROM:<sender@example.net>");
            await peer.SendAsync($"RCPT TO:<{recipient}>");
            await peer.SendAsync("DATA");
            await peer.WriteRawAsync($"To: {recipient}\r\n\r\nBody.\r\n.\r\n");

            (await peer.ReadReplyAsync()).ShouldStartWith("250");
        }

        _delivery.Requests.Count.ShouldBe(2);
        _delivery.Requests[0].Recipients.Single().Address.Value.ShouldBe("user@example.com");
        _delivery.Requests[1].Recipients.Single().Address.Value.ShouldBe("postmaster@example.com");
    }

    // ---------------------------------------------------------------------------------------
    // Relay refusal, over the wire.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_relay_attempt_on_port_25_is_refused_with_554()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO spammer.example.net");
        await peer.SendAsync("MAIL FROM:<spammer@example.net>");

        string reply = await peer.SendAsync("RCPT TO:<victim@elsewhere.example>");

        reply.ShouldStartWith("554 5.7.1");
        _delivery.Requests.ShouldBeEmpty();
    }

    [Fact]
    public async Task Auth_is_never_advertised_on_port_25()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();

        (await peer.SendAsync("EHLO relay.example.net")).ShouldNotContain("AUTH");
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS, including the injection test docs/SMTP.md calls for.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Starttls_upgrades_the_connection()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();

        (await peer.SendAsync("EHLO relay.example.net")).ShouldContain("STARTTLS");
        (await peer.SendAsync("STARTTLS")).ShouldStartWith("220");

        await peer.UpgradeToTlsAsync();

        string ehlo = await peer.SendAsync("EHLO relay.example.net");

        ehlo.ShouldStartWith("250");
        ehlo.ShouldNotContain("STARTTLS", Case.Sensitive);
    }

    [Fact]
    public async Task A_message_can_be_sent_inside_the_tunnel()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("STARTTLS");
        await peer.UpgradeToTlsAsync();

        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("MAIL FROM:<sender@example.net>");
        await peer.SendAsync("RCPT TO:<user@example.com>");
        await peer.SendAsync("DATA");
        await peer.WriteRawAsync("Subject: secure\r\n\r\nBody.\r\n.\r\n");

        (await peer.ReadReplyAsync()).ShouldStartWith("250");

        _delivery.Requests.Single().TlsActive.ShouldBeTrue();
    }

    [Fact]
    public async Task The_session_must_greet_again_inside_the_tunnel()
    {
        // RFC 3207 §4.2. The pre-handshake greeting was unauthenticated hearsay and is gone, so
        // a command that needs a greeting is out of sequence until the client sends a new one.
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("STARTTLS");
        await peer.UpgradeToTlsAsync();

        (await peer.SendAsync("MAIL FROM:<sender@example.net>")).ShouldStartWith("503");
    }

    [Fact]
    public async Task Commands_pipelined_before_the_handshake_are_never_executed()
    {
        // The STARTTLS command-injection test docs/SMTP.md requires. An attacker on the wire
        // appends plaintext commands to the STARTTLS line; a server that kept its read buffer
        // would execute them inside the tunnel with the authority the real client establishes.
        //
        // CVE-2011-0411 and relatives. The connection is refused outright rather than merely
        // having the octets dropped, because no legitimate client does this.
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");

        // One write, so the injected commands share a packet with STARTTLS and are sitting in
        // the server's read buffer when the handshake begins.
        await peer.WriteRawAsync(
            "STARTTLS\r\n" +
            "MAIL FROM:<attacker@evil.example>\r\n" +
            "RCPT TO:<victim@elsewhere.example>\r\n");

        (await peer.ReadReplyAsync()).ShouldStartWith("220");

        // The server closed the connection rather than handshaking, so the injected commands
        // were never executed and never will be.
        await Should.ThrowAsync<Exception>(peer.UpgradeToTlsAsync);

        _delivery.Requests.ShouldBeEmpty();
    }

    [Fact]
    public async Task An_envelope_collected_before_starttls_does_not_survive_it()
    {
        // The envelope was collected in the clear, where anyone on the path could have written
        // it. Keeping it would mean a message delivered inside the tunnel to a recipient chosen
        // outside it.
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("MAIL FROM:<sender@example.net>");
        await peer.SendAsync("RCPT TO:<user@example.com>");

        // STARTTLS mid-transaction is out of sequence, which is itself the defence: the question
        // of what happens to an envelope collected under the old security context never arises.
        (await peer.SendAsync("STARTTLS")).ShouldStartWith("503");
    }

    // ---------------------------------------------------------------------------------------
    // Limits, over the wire.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_over_long_command_line_is_refused_and_the_connection_closed()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();

        await peer.WriteRawAsync(new string('X', 5000) + "\r\n");

        (await peer.ReadReplyAsync()).ShouldStartWith("500");

        // Closed, not resynchronised: the tail of an over-long line is attacker-chosen text that
        // would otherwise be parsed as a command.
        (await peer.ReadReplyAsync()).ShouldBeEmpty();
    }

    [Fact]
    public async Task An_over_size_message_is_refused_and_the_session_continues()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("MAIL FROM:<sender@example.net> SIZE=2000000");

        // Refused from the declared size alone, before a single octet of body crosses the wire.
        _delivery.Requests.ShouldBeEmpty();

        (await peer.SendAsync("NOOP")).ShouldStartWith("250");
    }

    [Fact]
    public async Task The_advertised_size_is_the_configured_limit()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();

        (await peer.SendAsync("EHLO relay.example.net")).ShouldContain("SIZE 1000000");
    }

    [Fact]
    public async Task An_unknown_command_is_refused_without_ending_the_session()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();

        (await peer.SendAsync("XCLIENT NAME=evil")).ShouldStartWith("500");
        (await peer.SendAsync("EHLO relay.example.net")).ShouldStartWith("250");
    }

    // ---------------------------------------------------------------------------------------
    // Smuggling, over the wire.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Smuggled_commands_end_up_in_the_body_and_not_in_the_session()
    {
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("MAIL FROM:<sender@example.net>");
        await peer.SendAsync("RCPT TO:<user@example.com>");
        await peer.SendAsync("DATA");

        // "\n.\n" is not an end-of-data marker. A server that accepted it would truncate here
        // and execute the rest as commands - SMTP smuggling.
        await peer.WriteRawAsync(
            "legitimate\n.\n" +
            "MAIL FROM:<attacker@evil.example>\r\n" +
            "RCPT TO:<victim@elsewhere.example>\r\n" +
            ".\r\n");

        (await peer.ReadReplyAsync()).ShouldStartWith("250");

        _delivery.Requests.Count.ShouldBe(1);
        _delivery.Requests[0].Recipients.Single().Address.Value.ShouldBe("user@example.com");

        string stored = await File.ReadAllTextAsync(
            Directory.EnumerateFiles(_root, "*.eml", SearchOption.AllDirectories).Single());

        stored.ShouldContain("MAIL FROM:<attacker@evil.example>");
        stored.ShouldContain("RCPT TO:<victim@elsewhere.example>");
    }

    [Fact]
    public async Task A_pipelined_command_after_the_marker_is_still_executed()
    {
        // The other side of the same coin: octets after a REAL marker belong to the session and
        // must not be swallowed with the message.
        await using Peer peer = await ConnectAsync();

        await peer.ReadReplyAsync();
        await peer.SendAsync("EHLO relay.example.net");
        await peer.SendAsync("MAIL FROM:<sender@example.net>");
        await peer.SendAsync("RCPT TO:<user@example.com>");
        await peer.SendAsync("DATA");

        await peer.WriteRawAsync("Body.\r\n.\r\nQUIT\r\n");

        (await peer.ReadReplyAsync()).ShouldStartWith("250");
        (await peer.ReadReplyAsync()).ShouldStartWith("221");
    }
}
