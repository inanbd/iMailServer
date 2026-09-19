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
        int preAuthSeconds = 30) =>
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
            CertificatePurpose.MailboxAccess);

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
}
