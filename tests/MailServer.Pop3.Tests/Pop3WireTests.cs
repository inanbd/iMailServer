using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Domain.Enums;
using MailServer.Domain.Pop3;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Pop3;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Pop3.Tests;

/// <summary>A TLS provider holding one self-signed certificate, for the handshake tests.</summary>
internal sealed class Pop3TestCertificateProvider : ITlsCertificateProvider, IDisposable
{
    private readonly X509Certificate2 _certificate;

    public Pop3TestCertificateProvider()
    {
        using RSA key = RSA.Create(2048);

        CertificateRequest request = new(
            "CN=mail.example.com",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder names = new();
        names.AddDnsName("mail.example.com");
        request.CertificateExtensions.Add(names.Build());

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

/// <summary>
/// The POP3 connection handler driven over a real loopback socket.
/// </summary>
/// <remarks>
/// A socket rather than a memory stream, because the sequences this class is uniquely
/// responsible for — the <c>STLS</c> upgrade, the framing of a multi-line response, and what a
/// dropped connection does to a session's deletions — are exactly the ones a fake stream cannot
/// exercise honestly.
/// </remarks>
public sealed class Pop3WireTests : IDisposable
{
    private readonly Pop3TestCertificateProvider _certificates = new();

    public void Dispose() => _certificates.Dispose();

    private const string StoredMessage =
        "Subject: hello\r\nFrom: a@b.test\r\n\r\nHello there.\r\n.and a stuffed line\r\n";

    private static Pop3ConnectionOptions Options(
        Pop3ListenerRole role = Pop3ListenerRole.Cleartext,
        bool authAvailable = true,
        int maxLineOctets = 1_024,
        int preAuthSeconds = 30) =>
        new(
            role,
            new Pop3ProcessorOptions("AetherMail", role, authAvailable, MaxAuthenticationAttempts: 3),
            maxLineOctets,
            TimeSpan.FromSeconds(preAuthSeconds),
            TimeSpan.FromSeconds(600),
            CertificatePurpose.MailboxAccess);

    /// <summary>Accepts one connection, hands it to the handler, and returns the client end.</summary>
    private async Task<(TcpClient Client, Task Served, ScriptedPop3Mailboxes Mailboxes)> ConnectAsync(
        Pop3ConnectionOptions options,
        CancellationToken cancellationToken = default)
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();

        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        ValueTask<TcpClient> accepting = listener.AcceptTcpClientAsync(cancellationToken);

        TcpClient client = new();
        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);

        TcpClient accepted = await accepting;
        listener.Stop();

        ScriptedPop3Authenticator authenticator = new();
        ScriptedPop3Mailboxes mailboxes = new(authenticator.KnownMailboxId);

        mailboxes.Deliver(7, StoredMessage);

        Pop3ConnectionHandler handler = new(
            _certificates,
            authenticator,
            mailboxes,
            mailboxes,
            new ScriptedPop3MessageStore(mailboxes),
            new Pop3MaildropLocks(),
            NullLogger<Pop3ConnectionHandler>.Instance);

        Task served = Task.Run(
            async () =>
            {
                using TcpClient server = accepted;
                await using NetworkStream transport = server.GetStream();

                await handler.HandleAsync(
                    transport,
                    IpAddressValue.Parse("127.0.0.1"),
                    options,
                    DateTimeOffset.UtcNow,
                    cancellationToken);
            },
            cancellationToken);

        return (client, served, mailboxes);
    }

    /// <summary>Reads one CRLF-terminated line.</summary>
    private static async Task<string> ReadLineAsync(Stream stream)
    {
        StringBuilder line = new();
        byte[] one = new byte[1];

        while (true)
        {
            int read = await stream.ReadAsync(one);

            if (read == 0)
            {
                return line.ToString();
            }

            if (one[0] == (byte)'\n')
            {
                return line.ToString().TrimEnd('\r');
            }

            line.Append((char)one[0]);
        }
    }

    /// <summary>Reads lines until the terminating full stop, which is not returned.</summary>
    private static async Task<IReadOnlyList<string>> ReadMultiLineAsync(Stream stream)
    {
        List<string> lines = [];

        while (true)
        {
            string line = await ReadLineAsync(stream);

            if (line == ".")
            {
                return lines;
            }

            // A client "removes all byte-stuffed termination characters when it receives a
            // multi-line response" - RFC 1939 §11. These tests are a client.
            lines.Add(line.StartsWith('.') ? line[1..] : line);
        }
    }

    private static async Task WriteLineAsync(Stream stream, string line)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes(line + "\r\n"));
        await stream.FlushAsync();
    }

    // -------------------------------------------------------------------------------------------
    // The greeting and the upgrade.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 1939 §4: the server issues a one-line greeting. RFC 2449 §6 makes the absence of angle
    /// brackets the signal that APOP is not on offer.
    /// </summary>
    [Fact]
    public async Task The_greeting_arrives_and_offers_no_apop_challenge()
    {
        (TcpClient client, Task served, _) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream stream = client.GetStream();

            string greeting = await ReadLineAsync(stream);

            greeting.ShouldStartWith("+OK ");
            greeting.Contains('<', StringComparison.Ordinal).ShouldBeFalse();

            await WriteLineAsync(stream, "QUIT");
            (await ReadLineAsync(stream)).ShouldStartWith("+OK ");
        }

        await served;
    }

    /// <summary>
    /// RFC 2595 §4: "A TLS negotiation begins immediately after the CRLF at the end of the +OK
    /// response from the server." Everything after it is inside the tunnel.
    /// </summary>
    [Fact]
    public async Task Stls_upgrades_the_connection()
    {
        (TcpClient client, Task served, _) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream transport = client.GetStream();

            await ReadLineAsync(transport);
            await WriteLineAsync(transport, "STLS");
            (await ReadLineAsync(transport)).ShouldBe("+OK Begin TLS negotiation");

            await using SslStream tls = new(
                transport,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync("mail.example.com");

            // §4: "the client MUST discard cached information about server capabilities and
            // SHOULD re-issue the CAPA command." The USER capability appears only now.
            await WriteLineAsync(tls, "CAPA");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");

            IReadOnlyList<string> capabilities = await ReadMultiLineAsync(tls);

            capabilities.ShouldContain("USER");
            capabilities.ShouldNotContain("STLS");

            await WriteLineAsync(tls, "QUIT");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");
        }

        await served;
    }

    /// <summary>
    /// RFC 2595 §4: "Once a client issues a STLS command, it MUST NOT issue further commands
    /// until a server response is seen and the TLS negotiation is complete." A peer that does it
    /// anyway is attempting the command injection of CVE-2011-0411, and the connection ends.
    /// </summary>
    [Fact]
    public async Task Commands_pipelined_across_stls_close_the_connection()
    {
        (TcpClient client, Task served, _) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream transport = client.GetStream();

            await ReadLineAsync(transport);

            // Both in one write, so the second is in the reader's buffer when the upgrade runs.
            await transport.WriteAsync(Encoding.ASCII.GetBytes("STLS\r\nUSER mallory@example.com\r\n"));
            await transport.FlushAsync();

            (await ReadLineAsync(transport)).ShouldBe("+OK Begin TLS negotiation");

            // No handshake follows: the connection is gone.
            (await ReadLineAsync(transport)).ShouldBe(string.Empty);
        }

        await served;
    }

    // -------------------------------------------------------------------------------------------
    // A whole session.
    // -------------------------------------------------------------------------------------------

    /// <summary>Authenticates over the implicit-TLS port and returns the tunnel.</summary>
    private static async Task<SslStream> AuthenticatedAsync(NetworkStream transport)
    {
        SslStream tls = new(
            transport,
            leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, _, _, _) => true);

        await tls.AuthenticateAsClientAsync("mail.example.com");

        (await ReadLineAsync(tls)).ShouldStartWith("+OK ");

        await WriteLineAsync(tls, "USER alice@example.com");
        (await ReadLineAsync(tls)).ShouldStartWith("+OK ");

        await WriteLineAsync(tls, "PASS hunter2");
        (await ReadLineAsync(tls)).ShouldStartWith("+OK ");

        return tls;
    }

    /// <summary>
    /// The session a client actually runs: list, retrieve, delete, quit. The retrieved message
    /// is compared octet for octet after the client-side unstuffing RFC 1939 §3 describes.
    /// </summary>
    [Fact]
    public async Task A_whole_session_lists_retrieves_and_deletes()
    {
        (TcpClient client, Task served, ScriptedPop3Mailboxes mailboxes) =
            await ConnectAsync(Options(role: Pop3ListenerRole.ImplicitTls));

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "STAT");
            (await ReadLineAsync(tls)).ShouldBe($"+OK 1 {StoredMessage.Length}");

            await WriteLineAsync(tls, "LIST");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");
            (await ReadMultiLineAsync(tls)).ShouldBe([$"1 {StoredMessage.Length}"]);

            await WriteLineAsync(tls, "UIDL");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");
            (await ReadMultiLineAsync(tls)).ShouldBe(["1 3857529045.7"]);

            await WriteLineAsync(tls, "RETR 1");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");

            IReadOnlyList<string> body = await ReadMultiLineAsync(tls);

            string.Join("\r\n", body).ShouldBe(StoredMessage.TrimEnd('\r', '\n'));

            await WriteLineAsync(tls, "DELE 1");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");

            await WriteLineAsync(tls, "QUIT");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");
        }

        await served;

        mailboxes.Removed.ShouldBe([new long[] { 7 }]);
    }

    /// <summary>
    /// RFC 1939 §6: "If a session terminates for some reason other than a client-issued QUIT
    /// command, the POP3 session does NOT enter the UPDATE state and MUST not remove any messages
    /// from the maildrop." The client vanishes after its DELE.
    /// </summary>
    [Fact]
    public async Task A_dropped_connection_removes_nothing()
    {
        (TcpClient client, Task served, ScriptedPop3Mailboxes mailboxes) =
            await ConnectAsync(Options(role: Pop3ListenerRole.ImplicitTls));

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "DELE 1");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");
        }

        await served;

        mailboxes.Removed.ShouldBeEmpty();
    }

    /// <summary>
    /// RFC 2449 §6.6: "The PIPELINING capability indicates the server is capable of accepting
    /// multiple commands at a time […] If a server supports PIPELINING, it MUST process each
    /// command in turn." The capability is advertised, so this has to be true.
    /// </summary>
    [Fact]
    public async Task Pipelined_commands_are_answered_in_order()
    {
        (TcpClient client, Task served, _) =
            await ConnectAsync(Options(role: Pop3ListenerRole.ImplicitTls));

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await tls.WriteAsync(Encoding.ASCII.GetBytes("NOOP\r\nSTAT\r\nNOOP\r\nQUIT\r\n"));
            await tls.FlushAsync();

            (await ReadLineAsync(tls)).ShouldBe("+OK");
            (await ReadLineAsync(tls)).ShouldBe($"+OK 1 {StoredMessage.Length}");
            (await ReadLineAsync(tls)).ShouldBe("+OK");
            (await ReadLineAsync(tls)).ShouldStartWith("+OK ");
        }

        await served;
    }

    /// <summary>
    /// A line past the limit ends the connection with a negative status indicator. The reader has
    /// latched and cannot resynchronise, because the tail of an over-long line is attacker-chosen
    /// text that would parse as a fresh command.
    /// </summary>
    [Fact]
    public async Task An_over_long_line_ends_the_connection()
    {
        (TcpClient client, Task served, _) = await ConnectAsync(Options(maxLineOctets: 512));

        using (client)
        {
            NetworkStream stream = client.GetStream();

            await ReadLineAsync(stream);
            await WriteLineAsync(stream, "USER " + new string('x', 2_048));

            (await ReadLineAsync(stream)).ShouldBe("-ERR Command line too long");
            (await ReadLineAsync(stream)).ShouldBe(string.Empty);
        }

        await served;
    }

    /// <summary>
    /// RFC 1939 §3: "When the timer expires, the session does NOT enter the UPDATE state — the
    /// server should close the TCP connection without removing any messages or sending any
    /// response to the client." Unlike IMAP, POP3 asks for silence.
    /// </summary>
    [Fact]
    public async Task An_idle_connection_is_closed_without_a_farewell()
    {
        (TcpClient client, Task served, _) = await ConnectAsync(Options(preAuthSeconds: 1));

        using (client)
        {
            NetworkStream stream = client.GetStream();

            (await ReadLineAsync(stream)).ShouldStartWith("+OK ");

            // Nothing is sent. The next read completes when the server closes the socket.
            (await ReadLineAsync(stream)).ShouldBe(string.Empty);
        }

        await served;
    }
}
