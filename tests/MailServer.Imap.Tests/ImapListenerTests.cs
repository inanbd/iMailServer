using System.Net;
using System.Net.Sockets;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Infrastructure.Imap;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Imap.Tests;

/// <summary>
/// The IMAP listener, bound to a real loopback port and driven by real clients.
/// </summary>
/// <remarks>
/// The handler's own behaviour is covered by <see cref="ImapWireTests"/>. What is left for the
/// listener is what only it does: binding, accepting more than one connection at once, admitting
/// or refusing them, and stopping cleanly — none of which a single-connection test can reach.
/// </remarks>
public sealed class ImapListenerTests : IAsyncDisposable
{
    private readonly ImapTestCertificateProvider _certificates = new();
    private readonly ServiceProvider _services;

    public ImapListenerTests()
    {
        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddSingleton<ITlsCertificateProvider>(_certificates);
        services.AddSingleton<IMailboxAuthenticator, ScriptedImapAuthenticator>();
        // One instance behind both interfaces, so a store is visible to a later read - the same
        // arrangement the processor and wire tests use.
        services.AddSingleton<ScriptedImapMailboxReader>();
        services.AddSingleton<IImapMailboxReader>(p => p.GetRequiredService<ScriptedImapMailboxReader>());
        services.AddSingleton<IImapMailboxWriter>(p => p.GetRequiredService<ScriptedImapMailboxReader>());
        services.AddScoped<ImapConnectionHandler>();

        _services = services.BuildServiceProvider();
    }

    public async ValueTask DisposeAsync()
    {
        await _services.DisposeAsync();
        _certificates.Dispose();
    }

    private static ImapConnectionOptions Options(
        ImapListenerRole role = ImapListenerRole.Cleartext,
        int preAuthSeconds = 30) =>
        new(
            role,
            new ImapProcessorOptions("AetherMail", role, IsAuthenticationAvailable: true),
            MaxLineOctets: 8_000,
            TimeSpan.FromSeconds(preAuthSeconds),
            TimeSpan.FromSeconds(60),
            CertificatePurpose.MailboxAccess);

    private ImapListener Listener(
        SmtpConnectionLimiter? limiter = null,
        ImapListenerRole role = ImapListenerRole.Cleartext) =>
        new(
            new IPEndPoint(IPAddress.Loopback, 0),
            Options(role),
            limiter ?? new SmtpConnectionLimiter(maxTotal: 10, maxPerAddress: 5),
            _services.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<ImapListener>.Instance);

    private static async Task<string> ReadLineAsync(Stream stream)
    {
        StringBuilder line = new();
        byte[] one = new byte[1];

        while (true)
        {
            if (await stream.ReadAsync(one, CancellationToken.None) == 0)
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

    private static async Task<TcpClient> ConnectAsync(int port)
    {
        TcpClient client = new();
        await client.ConnectAsync(IPAddress.Loopback, port, CancellationToken.None);
        return client;
    }

    // ---------------------------------------------------------------------------------------
    // Binding and accepting.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_bound_listener_reports_the_port_it_actually_got()
    {
        await using ImapListener listener = Listener();

        _ = listener.StartAsync(CancellationToken.None);

        // Port 0 asks the operating system to choose, which is what makes these tests able to
        // run concurrently without colliding.
        listener.BoundPort.ShouldBeGreaterThan(0);
        listener.Role.ShouldBe(ImapListenerRole.Cleartext);

        await listener.StopAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task An_accepted_connection_is_greeted_and_served()
    {
        await using ImapListener listener = Listener();

        _ = listener.StartAsync(CancellationToken.None);

        using TcpClient client = await ConnectAsync(listener.BoundPort);

        NetworkStream stream = client.GetStream();

        (await ReadLineAsync(stream)).ShouldStartWith("* OK [CAPABILITY IMAP4rev1");

        await WriteLineAsync(stream, "a1 NOOP");
        (await ReadLineAsync(stream)).ShouldBe("a1 OK NOOP completed");

        await WriteLineAsync(stream, "a2 LOGOUT");
        (await ReadLineAsync(stream)).ShouldStartWith("* BYE ");

        await listener.StopAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task Several_clients_are_served_at_once()
    {
        // The accept loop must not be waiting on a session: anything it waits on is a connection
        // nobody else can make in the meantime, which is a denial of service with extra steps.
        await using ImapListener listener = Listener();

        _ = listener.StartAsync(CancellationToken.None);

        List<TcpClient> clients = [];

        try
        {
            for (int i = 0; i < 5; i++)
            {
                clients.Add(await ConnectAsync(listener.BoundPort));
            }

            // Every one of them is greeted, and none is waiting on another.
            foreach (TcpClient client in clients)
            {
                (await ReadLineAsync(client.GetStream())).ShouldStartWith("* OK ");
            }

            // And every one can still hold a conversation.
            for (int i = 0; i < clients.Count; i++)
            {
                NetworkStream stream = clients[i].GetStream();

                await WriteLineAsync(stream, $"c{i} CAPABILITY");

                (await ReadLineAsync(stream)).ShouldStartWith("* CAPABILITY ");
                (await ReadLineAsync(stream)).ShouldBe($"c{i} OK CAPABILITY completed");
            }
        }
        finally
        {
            foreach (TcpClient client in clients)
            {
                client.Dispose();
            }
        }

        await listener.StopAsync(TimeSpan.FromSeconds(2));
    }

    // ---------------------------------------------------------------------------------------
    // Admission.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_connection_over_the_limit_is_refused_with_an_untagged_bye()
    {
        // RFC 3501 section 7.1.5 is the only way an IMAP server can say "not now" before a
        // client has sent anything: there is no tag to answer with and no equivalent of SMTP's
        // 421 greeting. Refusing politely matters - a client that is told backs off, and one
        // that sees a bare reset shows its user a connection error.
        await using ImapListener listener = Listener(new SmtpConnectionLimiter(maxTotal: 1, maxPerAddress: 1));

        _ = listener.StartAsync(CancellationToken.None);

        using TcpClient admitted = await ConnectAsync(listener.BoundPort);
        (await ReadLineAsync(admitted.GetStream())).ShouldStartWith("* OK ");

        using TcpClient refused = await ConnectAsync(listener.BoundPort);

        string greeting = await ReadLineAsync(refused.GetStream());

        greeting.ShouldStartWith("* BYE ");
        greeting.ShouldContain("Too many connections");

        // Refused, not merely warned: the socket is closed behind the BYE.
        (await ReadLineAsync(refused.GetStream())).ShouldBeEmpty();

        await listener.StopAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task A_slot_is_returned_when_its_session_ends()
    {
        // Otherwise the first burst of connections would permanently consume the budget, and a
        // server that had been busy once would stay refusing for ever.
        SmtpConnectionLimiter limiter = new(maxTotal: 1, maxPerAddress: 1);

        await using ImapListener listener = Listener(limiter);

        _ = listener.StartAsync(CancellationToken.None);

        using (TcpClient first = await ConnectAsync(listener.BoundPort))
        {
            NetworkStream stream = first.GetStream();

            await ReadLineAsync(stream);
            await WriteLineAsync(stream, "a1 LOGOUT");
            await ReadLineAsync(stream);
            await ReadLineAsync(stream);
        }

        // The session has to unwind before the slot is free, so this waits on the observable
        // consequence rather than on a sleep.
        for (int attempt = 0; attempt < 100 && limiter.CurrentTotal > 0; attempt++)
        {
            await Task.Delay(50, CancellationToken.None);
        }

        limiter.CurrentTotal.ShouldBe(0);

        using TcpClient second = await ConnectAsync(listener.BoundPort);
        (await ReadLineAsync(second.GetStream())).ShouldStartWith("* OK ");

        await listener.StopAsync(TimeSpan.FromSeconds(2));
    }

    // ---------------------------------------------------------------------------------------
    // Stopping.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Stopping_refuses_new_connections()
    {
        ImapListener listener = Listener();

        _ = listener.StartAsync(CancellationToken.None);

        int port = listener.BoundPort;

        await listener.StopAsync(TimeSpan.FromSeconds(1));
        await listener.DisposeAsync();

        using TcpClient client = new();

        await Should.ThrowAsync<SocketException>(
            async () => await client.ConnectAsync(IPAddress.Loopback, port, CancellationToken.None));
    }

    [Fact]
    public async Task Stopping_does_not_wait_out_an_idle_session()
    {
        // The grace means something different from the SMTP listener's. An abandoned SMTP
        // session mid-DATA risks a duplicate at the sending server, so a message in flight is
        // worth waiting for; an IMAP session has no such hazard and is idle by design, so
        // shutdown must not stall on connections that are doing nothing.
        await using ImapListener listener = Listener();

        _ = listener.StartAsync(CancellationToken.None);

        using TcpClient idle = await ConnectAsync(listener.BoundPort);
        (await ReadLineAsync(idle.GetStream())).ShouldStartWith("* OK ");

        DateTimeOffset before = DateTimeOffset.UtcNow;

        await listener.StopAsync(TimeSpan.FromSeconds(2));

        (DateTimeOffset.UtcNow - before).ShouldBeLessThan(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Host_shutdown_ends_the_accept_loop()
    {
        using CancellationTokenSource shutdown = new();

        await using ImapListener listener = Listener();

        Task accepting = listener.StartAsync(shutdown.Token);

        using (TcpClient client = await ConnectAsync(listener.BoundPort))
        {
            (await ReadLineAsync(client.GetStream())).ShouldStartWith("* OK ");
        }

        await shutdown.CancelAsync();

        await accepting;
        accepting.IsCompletedSuccessfully.ShouldBeTrue();
    }

    [Fact]
    public async Task A_client_that_connects_and_vanishes_does_not_stop_the_listener()
    {
        await using ImapListener listener = Listener();

        _ = listener.StartAsync(CancellationToken.None);

        // Connect and drop without reading the greeting, ten times over.
        for (int i = 0; i < 10; i++)
        {
            using TcpClient rude = await ConnectAsync(listener.BoundPort);
            rude.Close();
        }

        // Still accepting.
        using TcpClient client = await ConnectAsync(listener.BoundPort);
        (await ReadLineAsync(client.GetStream())).ShouldStartWith("* OK ");

        await listener.StopAsync(TimeSpan.FromSeconds(2));
    }
}
