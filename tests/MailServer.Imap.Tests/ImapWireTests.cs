using MailServer.Infrastructure.Time;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Imap;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Imap.Tests;

/// <summary>A TLS provider holding one self-signed certificate, for the handshake tests.</summary>
internal sealed class ImapTestCertificateProvider : ITlsCertificateProvider, IDisposable
{
    private readonly X509Certificate2 _certificate;

    public ImapTestCertificateProvider()
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

/// <summary>A provider with no certificate, for the handshake this server must refuse to attempt.</summary>
internal sealed class EmptyCertificateProvider : ITlsCertificateProvider
{
    public IReadOnlyCollection<DomainName> ConfiguredHostnames => [];

    public bool IsReady => false;

    public X509Certificate2? Select(string? hostname, CertificatePurpose purpose) => null;

    public Task ReloadAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>
/// The IMAP connection handler driven over a real loopback socket.
/// </summary>
/// <remarks>
/// A socket rather than a memory stream, because the two sequences this class is uniquely
/// responsible for — the <c>STARTTLS</c> upgrade and the idle timeouts — are exactly the ones a
/// fake stream cannot exercise honestly. A real <see cref="SslStream"/> handshake either happens
/// or it does not.
/// </remarks>
public sealed class ImapWireTests : IDisposable
{
    private readonly ImapTestCertificateProvider _certificates = new();

    public void Dispose() => _certificates.Dispose();

    private static ImapConnectionOptions Options(
        ImapListenerRole role = ImapListenerRole.Cleartext,
        bool authAvailable = true,
        int maxLineOctets = 8_000,
        long maxAppendOctets = 1_000_000,
        int preAuthSeconds = 30,
        int? idlePollMilliseconds = null) =>
        new(
            role,
            new ImapProcessorOptions("AetherMail", role, authAvailable, MaxAuthenticationAttempts: 3),
            maxAppendOctets,
            maxLineOctets,
            TimeSpan.FromSeconds(preAuthSeconds),
            TimeSpan.FromSeconds(60),

            // Both IMAP listeners present the same certificate: MailboxAccess is the purpose
            // for 143 and 993 alike, since a STARTTLS upgrade on 143 ends up serving exactly
            // what 993 serves from the first octet.
            CertificatePurpose.MailboxAccess,

            // The IDLE tests drive several polls, and at the production five seconds each one
            // would cost the suite a quarter of a minute of waiting for a timer.
            idlePollMilliseconds is null
                ? null
                : TimeSpan.FromMilliseconds(idlePollMilliseconds.Value));

    /// <summary>Accepts one connection, hands it to the handler, and returns the client end.</summary>
    private async Task<(TcpClient Client, Task Served)> ConnectAsync(
        ImapConnectionOptions options,
        ITlsCertificateProvider? certificates = null,
        ScriptedImapMailboxReader? mailboxes = null,
        IMailboxAuthenticator? authenticator = null,
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

        // One object for both interfaces, so a STORE over the wire is visible to the FETCH that
        // follows it - see ScriptedImapMailboxReader.StoreFlagsAsync.
        ScriptedImapMailboxReader store = mailboxes ?? new ScriptedImapMailboxReader();

        ImapConnectionHandler handler = new(
            certificates ?? _certificates,
            authenticator ?? new ScriptedImapAuthenticator(),
            store,
            store,
            new SystemClock(),
            new ScriptedMessageStore(store),
            NullLogger<ImapConnectionHandler>.Instance);

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

        return (client, served);
    }

    /// <summary>
    /// Waits until an idling connection has taken its opening look at the folder.
    /// </summary>
    /// <remarks>
    /// The continuation is written before the watch reads the folder, so a test that staged an
    /// external change the instant it saw <c>+</c> would be racing the seed — and losing that
    /// race means the change becomes the baseline and is never reported, which looks exactly
    /// like the bug these tests exist to catch.
    /// </remarks>
    private static async Task WatchStartedAsync(ScriptedImapMailboxReader mailboxes, int looks = 1)
    {
        for (int attempt = 0; attempt < 500 && mailboxes.FlagReads.Count < looks; attempt++)
        {
            await Task.Delay(10);
        }

        mailboxes.FlagReads.Count.ShouldBeGreaterThanOrEqualTo(looks);
    }

    /// <summary>Reads one CRLF-terminated line.</summary>
    private static async Task<string> ReadLineAsync(Stream stream)
    {
        StringBuilder line = new();
        byte[] one = new byte[1];

        while (true)
        {
            int read = await stream.ReadAsync(one, CancellationToken.None);

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

    private static async Task WriteLineAsync(Stream stream, string line)
    {
        byte[] octets = Encoding.ASCII.GetBytes(line + "\r\n");

        await stream.WriteAsync(octets, CancellationToken.None);
        await stream.FlushAsync(CancellationToken.None);
    }

    /// <summary>Reads until a line beginning with <paramref name="tag"/> arrives, or the peer closes.</summary>
    private static async Task<List<string>> ReadUntilTaggedAsync(Stream stream, string tag)
    {
        List<string> lines = [];

        while (true)
        {
            string line = await ReadLineAsync(stream);

            if (line.Length == 0)
            {
                return lines;
            }

            lines.Add(line);

            if (line.StartsWith(tag + " ", StringComparison.Ordinal))
            {
                return lines;
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // The greeting and a whole conversation.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_connection_is_greeted_with_an_untagged_ok()
    {
        (TcpClient client, Task served) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream stream = client.GetStream();

            string greeting = await ReadLineAsync(stream);

            greeting.ShouldStartWith("* OK [CAPABILITY IMAP4rev1");
            greeting.ShouldContain("LOGINDISABLED");
            greeting.ShouldContain("STARTTLS");

            await WriteLineAsync(stream, "a1 LOGOUT");
            await ReadUntilTaggedAsync(stream, "a1");
        }

        await served;
    }

    [Fact]
    public async Task A_client_can_hold_a_whole_conversation()
    {
        (TcpClient client, Task served) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream stream = client.GetStream();

            await ReadLineAsync(stream);

            await WriteLineAsync(stream, "a1 CAPABILITY");
            List<string> capability = await ReadUntilTaggedAsync(stream, "a1");

            capability[0].ShouldStartWith("* CAPABILITY IMAP4rev1");
            capability[^1].ShouldBe("a1 OK CAPABILITY completed");

            await WriteLineAsync(stream, "a2 NOOP");
            (await ReadLineAsync(stream)).ShouldBe("a2 OK NOOP completed");

            await WriteLineAsync(stream, "a3 FROBNICATE");
            (await ReadLineAsync(stream)).ShouldBe("a3 BAD Unrecognised command");

            await WriteLineAsync(stream, "a4 LOGOUT");
            List<string> logout = await ReadUntilTaggedAsync(stream, "a4");

            logout[0].ShouldStartWith("* BYE ");
            logout[^1].ShouldBe("a4 OK LOGOUT completed");
        }

        await served;
    }

    [Fact]
    public async Task Logout_closes_the_connection()
    {
        (TcpClient client, Task served) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream stream = client.GetStream();

            await ReadLineAsync(stream);
            await WriteLineAsync(stream, "a1 LOGOUT");
            await ReadUntilTaggedAsync(stream, "a1");

            // The peer has gone: the next read returns nothing rather than blocking.
            (await ReadLineAsync(stream)).ShouldBeEmpty();
        }

        await served;
    }

    [Fact]
    public async Task A_line_with_an_unusable_tag_is_answered_untagged_over_the_wire()
    {
        (TcpClient client, Task served) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream stream = client.GetStream();

            await ReadLineAsync(stream);

            await WriteLineAsync(stream, "* NOOP");
            (await ReadLineAsync(stream)).ShouldBe("* BAD Invalid tag");

            // Still usable afterwards: a bad tag is one bad line, not a poisoned session.
            await WriteLineAsync(stream, "a1 NOOP");
            (await ReadLineAsync(stream)).ShouldBe("a1 OK NOOP completed");

            await WriteLineAsync(stream, "a2 LOGOUT");
            await ReadUntilTaggedAsync(stream, "a2");
        }

        await served;
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Starttls_upgrades_the_connection_and_the_capabilities_change()
    {
        (TcpClient client, Task served) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream transport = client.GetStream();

            (await ReadLineAsync(transport)).ShouldContain("LOGINDISABLED");

            await WriteLineAsync(transport, "a1 STARTTLS");
            (await ReadLineAsync(transport)).ShouldBe("a1 OK Begin TLS negotiation now");

            await using SslStream tls = new(
                transport,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync("mail.example.com");

            tls.IsEncrypted.ShouldBeTrue();

            // RFC 3501 section 6.2.1 tells the client to discard its cached capabilities and
            // re-issue CAPABILITY, because a machine-in-the-middle may have altered the earlier
            // listing. This is what it finds when it does.
            await WriteLineAsync(tls, "a2 CAPABILITY");
            List<string> capability = await ReadUntilTaggedAsync(tls, "a2");

            capability[0].ShouldNotContain("LOGINDISABLED");
            capability[0].ShouldNotContain("STARTTLS");
            capability[0].ShouldContain("AUTH=PLAIN");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }

    [Fact]
    public async Task Login_then_select_works_inside_the_upgraded_tunnel()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(
                authenticator.KnownMailboxId,
                "INBOX",
                existsCount: 3,
                firstUnseen: 2,
                uidValidity: 3_857_529_045,
                nextUid: 12,
                specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 3, 7, 11);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            NetworkStream transport = client.GetStream();

            await ReadLineAsync(transport);
            await WriteLineAsync(transport, "a1 STARTTLS");
            await ReadLineAsync(transport);

            await using SslStream tls = new(
                transport,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync("mail.example.com");

            await WriteLineAsync(tls, "a2 LOGIN alice@example.com hunter2");
            string completion = (await ReadUntilTaggedAsync(tls, "a2"))[^1];

            completion.ShouldStartWith("a2 OK ");
            completion.ShouldContain("[CAPABILITY IMAP4rev1");

            // A whole SELECT, over a real TLS connection, in the order RFC 3501 section 6.3.1's
            // own example gives.
            await WriteLineAsync(tls, "a3 SELECT INBOX");
            List<string> select = await ReadUntilTaggedAsync(tls, "a3");

            select[0].ShouldBe("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)");
            select[1].ShouldBe("* 3 EXISTS");
            select[2].ShouldBe("* 0 RECENT");
            select[3].ShouldBe("* OK [UNSEEN 2] First unseen message");
            select[4].ShouldBe(
                "* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted");
            select[5].ShouldBe("* OK [UIDVALIDITY 3857529045] UIDs valid");
            select[6].ShouldBe("* OK [UIDNEXT 12] Predicted next UID");
            select[7].ShouldBe("a3 OK [READ-WRITE] SELECT completed");

            // Selected state now, so a whole FETCH runs - through the real connection handler,
            // the real line reader and the real TLS stream rather than the processor alone.
            await WriteLineAsync(tls, "a4 FETCH 1:* (UID FLAGS)");
            List<string> fetch = await ReadUntilTaggedAsync(tls, "a4");

            fetch[0].ShouldBe("* 1 FETCH (UID 3 FLAGS (\\Seen))");
            fetch[1].ShouldBe("* 2 FETCH (UID 7 FLAGS (\\Seen))");
            fetch[2].ShouldBe("* 3 FETCH (UID 11 FLAGS (\\Seen))");
            fetch[3].ShouldBe("a4 OK FETCH completed");

            // A whole LIST too, including the hierarchy-delimiter probe every client opens with.
            await WriteLineAsync(tls, "a4b LIST \"\" \"\"");
            List<string> probe = await ReadUntilTaggedAsync(tls, "a4b");

            probe[0].ShouldBe("* LIST (\\Noselect) \"/\" \"\"");
            probe[1].ShouldBe("a4b OK LIST completed");

            // And a STATUS, which must leave the selected mailbox alone.
            await WriteLineAsync(tls, "a4c STATUS INBOX (MESSAGES UIDNEXT)");
            List<string> status = await ReadUntilTaggedAsync(tls, "a4c");

            status[0].ShouldBe("* STATUS INBOX (MESSAGES 3 UIDNEXT 12)");
            status[1].ShouldBe("a4c OK STATUS completed");

            // Lower case reaches the same folder: RFC 3501 section 5.1 makes INBOX the one
            // case-insensitive mailbox name.
            await WriteLineAsync(tls, "a5 EXAMINE inbox");
            List<string> examine = await ReadUntilTaggedAsync(tls, "a5");

            examine.ShouldContain("* OK [PERMANENTFLAGS ()] Flags permitted");
            examine[^1].ShouldBe("a5 OK [READ-ONLY] EXAMINE completed");

            await WriteLineAsync(tls, "a6 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a6");
        }

        await served;
    }

    [Fact]
    public async Task Octets_pipelined_across_starttls_close_the_connection()
    {
        // The command-injection pattern RFC 3501 section 6.2.1 forbids: those octets would
        // otherwise be executed inside the tunnel with the authority the real client goes on to
        // establish. No legitimate client does this.
        (TcpClient client, Task served) = await ConnectAsync(Options());

        using (client)
        {
            NetworkStream transport = client.GetStream();

            await ReadLineAsync(transport);

            // The command and the smuggled command in one write, so both are in the reader's
            // buffer before the handler gets to the discard.
            byte[] octets = Encoding.ASCII.GetBytes("a1 STARTTLS\r\na2 LOGIN victim hunter2\r\n");

            await transport.WriteAsync(octets, CancellationToken.None);
            await transport.FlushAsync(CancellationToken.None);

            (await ReadLineAsync(transport)).ShouldBe("a1 OK Begin TLS negotiation now");

            // Closed rather than upgraded, and the smuggled command was never answered.
            (await ReadLineAsync(transport)).ShouldBeEmpty();
        }

        await served;
    }

    [Fact]
    public async Task Starttls_is_refused_when_no_certificate_is_configured()
    {
        // The handshake is not attempted at all. Attempting one without a certificate would
        // fail inside SslStream and give the peer a TLS-level error instead of a clean close.
        (TcpClient client, Task served) = await ConnectAsync(Options(), new EmptyCertificateProvider());

        using (client)
        {
            NetworkStream transport = client.GetStream();

            await ReadLineAsync(transport);
            await WriteLineAsync(transport, "a1 STARTTLS");

            (await ReadLineAsync(transport)).ShouldBe("a1 OK Begin TLS negotiation now");
            (await ReadLineAsync(transport)).ShouldBeEmpty();
        }

        await served;
    }

    // ---------------------------------------------------------------------------------------
    // Implicit TLS, port 993.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_implicit_tls_listener_handshakes_before_the_greeting()
    {
        // RFC 8314 section 3 prefers this over STARTTLS on 143: there is no cleartext phase for
        // a stripping attacker to interfere with, because the handshake precedes the protocol.
        (TcpClient client, Task served) = await ConnectAsync(Options(ImapListenerRole.ImplicitTls));

        using (client)
        {
            await using SslStream tls = new(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync("mail.example.com");

            string greeting = await ReadLineAsync(tls);

            greeting.ShouldStartWith("* OK [CAPABILITY IMAP4rev1");
            greeting.ShouldContain("AUTH=PLAIN");
            greeting.ShouldNotContain("STARTTLS");
            greeting.ShouldNotContain("LOGINDISABLED");

            await WriteLineAsync(tls, "a1 STARTTLS");
            (await ReadLineAsync(tls)).ShouldContain("not available on this listener");

            await WriteLineAsync(tls, "a2 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a2");
        }

        await served;
    }

    [Fact]
    public async Task Authenticate_plain_completes_over_two_lines()
    {
        (TcpClient client, Task served) = await ConnectAsync(Options(ImapListenerRole.ImplicitTls));

        using (client)
        {
            await using SslStream tls = new(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync("mail.example.com");
            await ReadLineAsync(tls);

            await WriteLineAsync(tls, "a1 AUTHENTICATE PLAIN");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            // The continuation line is a credential and never reaches the command parser.
            await WriteLineAsync(tls, "AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI=");
            (await ReadUntilTaggedAsync(tls, "a1"))[^1].ShouldStartWith("a1 OK ");

            await WriteLineAsync(tls, "a2 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a2");
        }

        await served;
    }

    // ---------------------------------------------------------------------------------------
    // Bounds.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_over_long_command_line_ends_the_connection_untagged()
    {
        // RFC 2683 section 3.2.1.5 asks for a BAD, and it must be untagged: the tag is somewhere
        // in the text that was discarded, so the command cannot be determined. The reader has
        // latched and will not resynchronise, because the tail of an over-long line is
        // attacker-chosen text that would parse as a fresh command.
        (TcpClient client, Task served) = await ConnectAsync(Options(maxLineOctets: 1_024));

        using (client)
        {
            NetworkStream stream = client.GetStream();

            await ReadLineAsync(stream);

            await WriteLineAsync(stream, "a1 NOOP " + new string('x', 4_096));

            (await ReadLineAsync(stream)).ShouldBe("* BAD Command line too long");
            (await ReadLineAsync(stream)).ShouldStartWith("* BYE ");
            (await ReadLineAsync(stream)).ShouldBeEmpty();
        }

        await served;
    }

    [Fact]
    public async Task An_idle_connection_is_logged_out_with_a_bye()
    {
        // RFC 3501 section 7.1.5: the untagged BYE is how a server says it is closing of its own
        // accord. Closing silently is indistinguishable from a network failure.
        (TcpClient client, Task served) = await ConnectAsync(Options(preAuthSeconds: 10));

        using (client)
        {
            NetworkStream stream = client.GetStream();

            await ReadLineAsync(stream);

            // Nothing sent. The pre-authentication timer is the slowloris bound, and RFC 3501
            // section 5.4's thirty-minute floor does not apply to a connection that has proven
            // nothing.
            string line = await ReadLineAsync(stream);

            line.ShouldStartWith("* BYE ");
            line.ShouldContain("Autologout");
        }

        await served;
    }

    [Fact]
    public async Task A_peer_that_disappears_does_not_fault_the_handler()
    {
        (TcpClient client, Task served) = await ConnectAsync(Options());

        NetworkStream stream = client.GetStream();
        await ReadLineAsync(stream);

        // Gone mid-session without a LOGOUT, which is how most real connections end.
        client.Close();

        await served;
        served.IsCompletedSuccessfully.ShouldBeTrue();
    }

    [Fact]
    public async Task Shutdown_ends_the_session_without_faulting()
    {
        using CancellationTokenSource shutdown = new();

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            cancellationToken: shutdown.Token);

        using (client)
        {
            await ReadLineAsync(client.GetStream());

            await shutdown.CancelAsync();

            await served;
            served.IsCompletedSuccessfully.ShouldBeTrue();
        }
    }

    [Fact]
    public async Task The_handler_rejects_null_arguments()
    {
        ScriptedImapMailboxReader store = new();

        ImapConnectionHandler handler = new(
            _certificates,
            new ScriptedImapAuthenticator(),
            store,
            store,
            new SystemClock(),
            new ScriptedMessageStore(store),
            NullLogger<ImapConnectionHandler>.Instance);

        await Should.ThrowAsync<ArgumentNullException>(async () => await handler.HandleAsync(
            null!,
            IpAddressValue.Parse("127.0.0.1"),
            Options(),
            DateTimeOffset.UtcNow,
            CancellationToken.None));

        await Should.ThrowAsync<ArgumentNullException>(async () => await handler.HandleAsync(
            Stream.Null,
            null!,
            Options(),
            DateTimeOffset.UtcNow,
            CancellationToken.None));

        await Should.ThrowAsync<ArgumentNullException>(async () => await handler.HandleAsync(
            Stream.Null,
            IpAddressValue.Parse("127.0.0.1"),
            null!,
            DateTimeOffset.UtcNow,
            CancellationToken.None));
    }
    /// <summary>
    /// Connects, upgrades with STARTTLS and logs in — the shortest route to an authenticated
    /// session, and the only one: LOGIN is refused in the clear, because
    /// <c>LOGINDISABLED</c> is advertised until the connection is protected.
    /// </summary>
    private async Task<SslStream> AuthenticatedAsync(NetworkStream transport)
    {
        await ReadLineAsync(transport);
        await WriteLineAsync(transport, "x1 STARTTLS");
        await ReadLineAsync(transport);

        SslStream tls = new(
            transport,
            leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, _, _, _) => true);

        await tls.AuthenticateAsClientAsync("mail.example.com");

        await WriteLineAsync(tls, "x2 LOGIN alice@example.com hunter2");
        (await ReadUntilTaggedAsync(tls, "x2"))[^1].ShouldStartWith("x2 OK ");

        return tls;
    }

    /// <summary>
    /// A whole APPEND over the wire, which is the only way to exercise the literal: RFC 3501
    /// §6.3.11's last argument is not on the command line, and only the connection loop owns the
    /// stream it arrives on.
    /// </summary>
    [Fact]
    public async Task Append_reads_a_synchronising_literal_and_files_the_message()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Add(authenticator.KnownMailboxId, "Drafts", specialUse: FolderSpecialUse.Drafts);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            const string Message =
                "From: alice@example.com\r\n" +
                "Subject: a draft\r\n" +
                "\r\n" +
                "Not finished yet.\r\n";

            await WriteLineAsync(
                tls,
                $"a2 APPEND Drafts (\\Draft) \"18-Sep-2026 10:00:00 +0000\" {{{Message.Length}}}");

            // §4.3: for a synchronising literal "the client MUST wait to receive a command
            // continuation request [...] before sending the octets of the literal".
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            await tls.WriteAsync(Encoding.ASCII.GetBytes(Message + "\r\n"));
            await tls.FlushAsync();

            (await ReadUntilTaggedAsync(tls, "a2"))[^1].ShouldStartWith("a2 OK ");

            await WriteLineAsync(tls, "a3 SELECT Drafts");
            await ReadUntilTaggedAsync(tls, "a3");

            await WriteLineAsync(tls, "a4 FETCH 1 (FLAGS INTERNALDATE RFC822.SIZE)");
            List<string> fetched = await ReadUntilTaggedAsync(tls, "a4");

            fetched[0].ShouldBe(
                "* 1 FETCH (FLAGS (\\Draft) INTERNALDATE \"18-Sep-2026 10:00:00 +0000\" " +
                $"RFC822.SIZE {Message.Length})");

            await WriteLineAsync(tls, "a5 FETCH 1 BODY.PEEK[]");
            (await ReadUntilTaggedAsync(tls, "a5"))[0]
                .ShouldBe($"* 1 FETCH (BODY[] {{{Message.Length}}}");

            await WriteLineAsync(tls, "a6 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a6");
        }

        await served;
    }

    /// <summary>
    /// §6.3.11's MUST: "If the destination mailbox does not exist, a server MUST return an error,
    /// and MUST NOT automatically create the mailbox. Unless it is certain that the destination
    /// mailbox can not be created, the server MUST send the response code "[TRYCREATE]"".
    /// </summary>
    [Fact]
    public async Task Append_to_a_missing_mailbox_earns_trycreate()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX");

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 APPEND Nowhere {5}");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            await tls.WriteAsync(Encoding.ASCII.GetBytes("hello\r\n"));
            await tls.FlushAsync();

            (await ReadUntilTaggedAsync(tls, "a2"))[^1].ShouldStartWith("a2 NO [TRYCREATE]");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }

    /// <summary>
    /// §6.3.11: "If the mailbox is currently selected […] the server SHOULD notify the client
    /// immediately via an untagged EXISTS response." Without it a client that appends to the
    /// folder it is reading does not see its own message until it polls.
    /// </summary>
    [Fact]
    public async Task Appending_to_the_selected_mailbox_reports_exists()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 APPEND INBOX {5}");
            await ReadLineAsync(tls);

            await tls.WriteAsync(Encoding.ASCII.GetBytes("hello\r\n"));
            await tls.FlushAsync();

            List<string> lines = await ReadUntilTaggedAsync(tls, "a3");

            lines[0].ShouldBe("* 1 EXISTS");
            lines[^1].ShouldStartWith("a3 OK ");

            await WriteLineAsync(tls, "a4 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a4");
        }

        await served;
    }

    /// <summary>
    /// RFC 7888's non-synchronising literal: the client has already sent the octets, so waiting
    /// for permission to receive what has arrived would deadlock.
    /// </summary>
    [Fact]
    public async Task A_non_synchronising_literal_gets_no_continuation()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            // The command line and its octets in one write, which is what {n+} is for.
            await tls.WriteAsync(Encoding.ASCII.GetBytes("a2 APPEND INBOX {5+}\r\nhello\r\n"));
            await tls.FlushAsync();

            (await ReadUntilTaggedAsync(tls, "a2"))[^1].ShouldStartWith("a2 OK ");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }

    /// <summary>
    /// A literal larger than the listener accepts is refused before a byte is read, so an
    /// oversized append costs the connection nothing.
    /// </summary>
    [Fact]
    public async Task An_oversized_append_is_refused_without_reading_it()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX");

        (TcpClient client, Task served) = await ConnectAsync(
            Options(maxAppendOctets: 100),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 APPEND INBOX {1000}");

            // No continuation: the refusal comes first, so the client never sends the octets.
            (await ReadUntilTaggedAsync(tls, "a2"))[^1].ShouldStartWith("a2 NO ");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }
    /// <summary>
    /// RFC 2177 §3: the server "requests a response to the IDLE command using the continuation
    /// ("+") response", and the command "is terminated by the receipt of a "DONE" continuation
    /// from the client" — after which the server "MUST immediately send the tagged response".
    /// </summary>
    [Fact]
    public async Task Idle_holds_the_connection_until_done()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            // The connection is usable again straight away.
            await WriteLineAsync(tls, "a4 NOOP");
            (await ReadUntilTaggedAsync(tls, "a4"))[^1].ShouldStartWith("a4 OK ");

            await WriteLineAsync(tls, "a5 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a5");
        }

        await served;
    }

    /// <summary>
    /// §3: "as long as an IDLE command is active, the server is now free to send untagged EXISTS,
    /// EXPUNGE, and other messages at any time." This is the whole point of the command — a
    /// client told it may stop polling and then told nothing would see new mail later than if it
    /// had kept polling.
    /// </summary>
    [Fact]
    public async Task Idle_pushes_an_exists_when_the_folder_grows()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 200),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            // Another delivery arrives while the client is idling.
            mailboxes.Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2);

            // The push arrives on the poll, without the client having said anything.
            (await ReadLineAsync(tls)).ShouldBe("* 2 EXISTS");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            await WriteLineAsync(tls, "a4 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a4");
        }

        await served;
    }

    /// <summary>
    /// The baseline an idling connection compares against is what the client was told, so a
    /// message that arrived between the SELECT and the IDLE is pushed rather than silently
    /// adopted as the starting point. A server that re-counted on entering IDLE would leave the
    /// client one message behind until it next sent a command — which is the poll IDLE exists to
    /// replace.
    /// </summary>
    [Fact]
    public async Task Idle_pushes_a_delivery_that_arrived_before_the_idle_began()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 200),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            // Delivered after the SELECT told the client "1", and before IDLE is even sent.
            mailboxes.Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2);

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");
            (await ReadLineAsync(tls)).ShouldBe("* 2 EXISTS");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            await WriteLineAsync(tls, "a4 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a4");
        }

        await served;
    }

    /// <summary>
    /// A folder that shrinks and grows back must not produce an <c>EXISTS</c> lower than the one
    /// the client already holds. RFC 2180 §4.1 shows a falling count being sent as the
    /// <c>EXPUNGE</c> lines first and the lower <c>EXISTS</c> after; a bare decrement would have
    /// the client renumber onto the wrong messages, which is how mail gets deleted on a client.
    /// So the poll absorbs the shrink without lowering what it compares against.
    /// </summary>
    [Fact]
    public async Task Idle_never_pushes_an_exists_below_what_the_client_was_told()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3);


        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 200),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            // Another session expunges one, which this connection was never told about.
            mailboxes.Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2);
            await Task.Delay(TimeSpan.FromMilliseconds(600));

            // The folder is back to three. The client already believes three, so there is
            // nothing to say - and saying "* 3 EXISTS" here would be a decrement in disguise.
            mailboxes.Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 4);
            await Task.Delay(TimeSpan.FromMilliseconds(600));

            // The fourth is news, and is the first thing the client hears.
            mailboxes.Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 4, 5);

            (await ReadLineAsync(tls)).ShouldBe("* 4 EXISTS");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            await WriteLineAsync(tls, "a4 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a4");
        }

        await served;
    }

    /// <summary>
    /// RFC 3501 §6.4.6: "Regardless of whether or not the <c>.SILENT</c> suffix was used, the
    /// server SHOULD send an untagged FETCH response if a change to a message's flags from an
    /// external source is observed. The intent is that the status of the flags is determinate
    /// without a race condition."
    /// </summary>
    /// <remarks>
    /// Two clients on one mailbox is the ordinary case — a phone and a desktop — and without
    /// this a message read on one shows as unread on the other until something else happens to
    /// make the second look.
    /// </remarks>
    [Fact]
    public async Task Idle_pushes_an_untagged_fetch_when_another_session_changes_flags()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 200),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");
            await WatchStartedAsync(mailboxes);

            // Another session flags the middle message. Nothing on this connection did it and
            // nothing on this connection asked about it.
            mailboxes.ChangeFlagsElsewhere(
                authenticator.KnownMailboxId,
                "INBOX",
                uid: 2,
                MessageFlags.Seen | MessageFlags.Flagged);

            // The position is the client's; the UID says which message it is whatever the
            // client's numbering has been through.
            (await ReadLineAsync(tls)).ShouldBe(@"* 2 FETCH (FLAGS (\Seen \Flagged) UID 2)");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            await WriteLineAsync(tls, "a4 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a4");
        }

        await served;
    }

    /// <summary>
    /// An arrival and a flag change in the same poll go out with the <c>EXISTS</c> first, so no
    /// <c>FETCH</c> ever names a position the client has not yet been told exists.
    /// </summary>
    [Fact]
    public async Task Idle_pushes_the_exists_before_the_flags()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 200),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");
            await WatchStartedAsync(mailboxes);

            // The delivery is staged first, so that a poll landing between the two statements
            // still produces these two lines in this order rather than making the test flaky.
            mailboxes
                .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3)
                .ChangeFlagsElsewhere(
                    authenticator.KnownMailboxId,
                    "INBOX",
                    uid: 1,
                    MessageFlags.Seen | MessageFlags.Answered);

            (await ReadLineAsync(tls)).ShouldBe("* 3 EXISTS");
            (await ReadLineAsync(tls)).ShouldBe(@"* 1 FETCH (FLAGS (\Seen \Answered) UID 1)");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            await WriteLineAsync(tls, "a4 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a4");
        }

        await served;
    }

    /// <summary>
    /// RFC 2177 §3 tells a client to re-issue <c>IDLE</c> "at least every 29 minutes to avoid
    /// being logged off", which it does with <c>DONE</c> followed by another <c>IDLE</c>. A
    /// watch that began again from the folder each time would take whatever changed in between
    /// as its starting point and never report it — which is precisely the race §6.4.6 is about.
    /// </summary>
    [Fact]
    public async Task A_change_between_two_idles_is_still_reported()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 200),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            // In the gap, with no command in flight to tell the client anything.
            mailboxes.ChangeFlagsElsewhere(
                authenticator.KnownMailboxId,
                "INBOX",
                uid: 1,
                MessageFlags.Seen | MessageFlags.Deleted);

            await WriteLineAsync(tls, "a4 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            (await ReadLineAsync(tls)).ShouldBe(@"* 1 FETCH (FLAGS (\Seen \Deleted) UID 1)");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a4 OK ");

            await WriteLineAsync(tls, "a5 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a5");
        }

        await served;
    }

    /// <summary>
    /// A flag this connection set itself is not pushed back at it on the next idle. §6.4.6's
    /// SHOULD is about "an external source"; the client already has the untagged <c>FETCH</c>
    /// its own <c>STORE</c> earned, and a bulk <c>STORE</c> echoed back a poll later would be
    /// thousands of responses about nothing.
    /// </summary>
    [Fact]
    public async Task A_flag_this_session_set_is_not_pushed_back_on_the_next_idle()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 200),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            await WriteLineAsync(tls, @"a4 STORE 1 +FLAGS (\Flagged)");
            await ReadUntilTaggedAsync(tls, "a4");

            await WriteLineAsync(tls, "a5 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            // Several polls' worth of silence, then something that genuinely is news. If the
            // STORE were being replayed it would arrive before this does.
            await Task.Delay(TimeSpan.FromMilliseconds(600));
            mailboxes.Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3);

            (await ReadLineAsync(tls)).ShouldBe("* 3 EXISTS");

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a5 OK ");

            await WriteLineAsync(tls, "a6 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a6");
        }

        await served;
    }

    /// <summary>
    /// A folder nothing has happened to is not read row by row on the poll timer. That is the
    /// whole reason <c>MailboxFolders.FlagsModSeq</c> exists, and a regression here would be
    /// invisible in behaviour and ruinous on a large mailbox.
    /// </summary>
    [Fact]
    public async Task An_idle_over_a_quiet_folder_reads_its_rows_once()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 100),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");
            await WatchStartedAsync(mailboxes);

            await Task.Delay(TimeSpan.FromMilliseconds(700));

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 OK ");

            // Once, to start the watch. Not once per poll.
            mailboxes.FlagReads.Count.ShouldBe(1);

            await WriteLineAsync(tls, "a4 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a4");
        }

        await served;
    }

    /// <summary>
    /// RFC 2177 §4 annotates its <c>command_auth</c> production ";; Valid only in Authenticated
    /// or Selected state", so idling with no mailbox open is legal. There is nothing to report
    /// to such a client, which is not the same as there being a reason to hang up on it.
    /// </summary>
    [Fact]
    public async Task Idle_with_no_mailbox_selected_is_held_open()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(idlePollMilliseconds: 100),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            // Several polls, every one of them with nothing to look at.
            await Task.Delay(TimeSpan.FromMilliseconds(500));

            await WriteLineAsync(tls, "DONE");
            (await ReadLineAsync(tls)).ShouldStartWith("a2 OK ");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }

    /// <summary>
    /// §3: "The client MUST NOT send a command while the server is waiting for the DONE, since
    /// the server will not be able to distinguish a command from a continuation." A client that
    /// does anyway gets its connection back with a tagged BAD rather than having the command
    /// silently swallowed.
    /// </summary>
    [Fact]
    public async Task Anything_but_done_ends_the_idle_with_a_bad()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT INBOX");
            await ReadUntilTaggedAsync(tls, "a2");

            await WriteLineAsync(tls, "a3 IDLE");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            await WriteLineAsync(tls, "a4 NOOP");
            (await ReadLineAsync(tls)).ShouldStartWith("a3 BAD ");

            await WriteLineAsync(tls, "a5 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a5");
        }

        await served;
    }

    /// <summary>
    /// §3 makes the capability the precondition: "If the server does not advertise the IDLE
    /// capability, the client MUST NOT use the IDLE command and must poll for mailbox updates."
    /// </summary>
    [Fact]
    public async Task Idle_is_advertised()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX");

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 CAPABILITY");
            List<string> lines = await ReadUntilTaggedAsync(tls, "a2");

            lines[0].ShouldContain("IDLE");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }

    // -----------------------------------------------------------------------------------------
    // Literals outside APPEND. RFC 3501 4.3 admits one wherever the grammar has an astring, and
    // only a real connection can exercise the continuation handshake they turn on.
    // -----------------------------------------------------------------------------------------

    /// <summary>
    /// A mailbox name sent as a synchronising literal: the server must ask for the octets, take
    /// them, and then read the rest of the command line that follows them.
    /// </summary>
    [Fact]
    public async Task Select_reads_a_mailbox_name_sent_as_a_literal()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 SELECT {5}");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            // The octets, then the CRLF that ends the (empty) remainder of the command line.
            await WriteLineAsync(tls, "INBOX");

            (await ReadUntilTaggedAsync(tls, "a2"))[^1].ShouldStartWith("a2 OK ");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }

    /// <summary>
    /// Two literals in one command, each with its own continuation — RFC 3501 §6.2.3's LOGIN is
    /// the case where getting the order wrong would hand the authenticator a swapped credential.
    /// </summary>
    [Fact]
    public async Task Login_reads_a_userid_and_password_sent_as_literals()
    {
        ScriptedImapAuthenticator authenticator = new();

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            authenticator: authenticator);

        using (client)
        {
            NetworkStream transport = client.GetStream();

            await ReadLineAsync(transport);
            await WriteLineAsync(transport, "x1 STARTTLS");
            await ReadLineAsync(transport);

            await using SslStream tls = new(
                transport,
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await tls.AuthenticateAsClientAsync("mail.example.com");

            await WriteLineAsync(tls, "a1 LOGIN {17}");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            // The userid's octets, then the rest of the line — which announces the next literal.
            await WriteLineAsync(tls, "alice@example.com {7}");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            await WriteLineAsync(tls, "hunter2");

            (await ReadUntilTaggedAsync(tls, "a1"))[^1].ShouldStartWith("a1 OK ");

            authenticator.SeenIdentities.ShouldBe(["alice@example.com"]);
            authenticator.SeenPasswords.ShouldBe(["hunter2"]);

            await WriteLineAsync(tls, "a2 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a2");
        }

        await served;
    }

    /// <summary>
    /// RFC 7888's <c>{n+}</c> outside APPEND: no continuation, because the octets are already
    /// on their way.
    /// </summary>
    [Fact]
    public async Task A_non_synchronising_literal_argument_gets_no_continuation()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await tls.WriteAsync(Encoding.ASCII.GetBytes("a2 SELECT {5+}\r\nINBOX\r\n"));
            await tls.FlushAsync();

            // The first line back is the tagged completion, not a continuation.
            (await ReadUntilTaggedAsync(tls, "a2"))[^1].ShouldStartWith("a2 OK ");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }

    /// <summary>
    /// An APPEND whose mailbox is a literal and whose message is another: the first is read into
    /// memory as an argument, the second still streams to the message store.
    /// </summary>
    [Fact]
    public async Task Append_reads_a_literal_mailbox_and_still_streams_its_message()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 APPEND {5}");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            // The mailbox's octets, then the rest of the line — which announces the message.
            await WriteLineAsync(tls, "INBOX {5}");
            (await ReadLineAsync(tls)).ShouldStartWith("+ ");

            await WriteLineAsync(tls, "hello");

            (await ReadUntilTaggedAsync(tls, "a2"))[^1].ShouldStartWith("a2 OK ");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }

    /// <summary>
    /// A synchronising literal over the cap is refused without a continuation, so its octets
    /// never leave the client — the whole point of the handshake, and why RFC 7888 §4 treats the
    /// two forms differently.
    /// </summary>
    [Fact]
    public async Task An_oversized_synchronising_literal_argument_is_refused_before_its_octets()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(
                tls,
                $"a2 SELECT {{{ImapConnectionHandler.MaxInlineLiteralOctets + 1}}}");

            // A refusal, not a continuation: nothing was asked for, so nothing is sent.
            string reply = await ReadLineAsync(tls);

            reply.ShouldStartWith("a2 BAD");
            reply.ShouldNotStartWith("+ ");

            // The session survives it, which is what distinguishes this from the {n+} case.
            await WriteLineAsync(tls, "a3 SELECT INBOX");
            (await ReadUntilTaggedAsync(tls, "a3"))[^1].ShouldStartWith("a3 OK ");

            await WriteLineAsync(tls, "a4 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a4");
        }

        await served;
    }

    /// <summary>
    /// A non-synchronising literal over the cap has already been sent, so RFC 7888 §4 leaves
    /// only the untagged BYE: there is no refusal that does not either read the octets or
    /// desynchronise the session.
    /// </summary>
    [Fact]
    public async Task An_oversized_non_synchronising_literal_ends_the_connection()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox);

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(
                tls,
                $"a2 SELECT {{{ImapConnectionHandler.MaxInlineLiteralOctets + 1}+}}");

            (await ReadLineAsync(tls)).ShouldStartWith("* BYE");
        }

        await served;
    }

    /// <summary>
    /// RFC 7888 §4 makes the atom a promise about the cap, so it is advertised only now that
    /// there is a cap to promise — and only as LITERAL-, never LITERAL+, which §5 forbids
    /// alongside it.
    /// </summary>
    [Fact]
    public async Task The_capability_listing_offers_literal_minus_and_never_literal_plus()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX");

        (TcpClient client, Task served) = await ConnectAsync(
            Options(),
            mailboxes: mailboxes,
            authenticator: authenticator);

        using (client)
        {
            await using SslStream tls = await AuthenticatedAsync(client.GetStream());

            await WriteLineAsync(tls, "a2 CAPABILITY");
            List<string> lines = await ReadUntilTaggedAsync(tls, "a2");

            lines[0].ShouldContain("LITERAL-");
            lines[0].ShouldNotContain("LITERAL+");

            await WriteLineAsync(tls, "a3 LOGOUT");
            await ReadUntilTaggedAsync(tls, "a3");
        }

        await served;
    }
}
