using System.Net;
using System.Net.Sockets;
using System.Text;
using MailServer.Domain.Pop3;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Pop3;

/// <summary>
/// Accepts POP3 connections on one endpoint and hands each to a session.
/// </summary>
/// <remarks>
/// <para>
/// One listener per role, never one listener with a mode flag — the same rule
/// <see cref="Imap.ImapListener"/> and <see cref="SmtpListener"/> follow. Whether TLS precedes
/// the greeting is decided by which socket accepted the connection, never by anything the peer
/// says, so a peer cannot talk its way from port 110 into port 995's assumptions.
/// </para>
/// <para>
/// <b>The connection limiter is <see cref="SmtpConnectionLimiter"/> and this listener service
/// holds its own instance</b>, for the reason <see cref="Imap.ImapListener"/> gives: the type
/// counts connections per address and knows nothing about SMTP beyond its name, so a second
/// implementation would be the same arithmetic written twice with somewhere to drift. Separate
/// instances still matter — a flood of POP3 connections must not exhaust the budget inbound mail
/// delivery needs.
/// </para>
/// </remarks>
public sealed class Pop3Listener(
    IPEndPoint endpoint,
    Pop3ConnectionOptions options,
    SmtpConnectionLimiter limiter,
    IServiceScopeFactory scopeFactory,
    ILogger<Pop3Listener> logger) : IAsyncDisposable
{
    private readonly TcpListener _listener = new(endpoint);
    private readonly CancellationTokenSource _stopping = new();
    private readonly List<Task> _sessions = [];
    private readonly Lock _sessionGate = new();

    /// <summary>Where this listener is bound.</summary>
    public IPEndPoint EndPoint => endpoint;

    /// <summary>Which role it serves.</summary>
    public Pop3ListenerRole Role => options.Role;

    /// <summary>The port actually bound. Differs from the configured one only when port 0 was asked for.</summary>
    public int BoundPort => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>Binds and begins accepting.</summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (endpoint.Address.Equals(IPAddress.IPv6Any))
        {
            // One socket serving both families. Binding IPv4 and IPv6 separately on the same
            // port fails outright on some configurations and, worse, silently serves only one
            // family on others.
            _listener.Server.DualMode = true;
        }

        _listener.Start();

        logger.LogInformation(
            "POP3 {Role} listener bound to {EndPoint}.",
            options.Role,
            _listener.LocalEndpoint);

        return Task.Run(() => AcceptLoopAsync(cancellationToken), CancellationToken.None);
    }

    /// <summary>
    /// Stops accepting and gives in-flight sessions a moment to finish.
    /// </summary>
    /// <remarks>
    /// <b>The grace matters more here than it does for IMAP.</b> A POP3 session that is cut off
    /// between its last <c>DELE</c> and its <c>QUIT</c> removes nothing — RFC 1939 §6 requires
    /// that — so the client will download the same mail again on its next connection. That is
    /// the safe failure and not a harmful one, but it is a wasted transfer, so a session that is
    /// nearly done is worth a moment.
    /// </remarks>
    public async Task StopAsync(TimeSpan grace)
    {
        _listener.Stop();

        Task[] pending;

        lock (_sessionGate)
        {
            pending = [.. _sessions];
        }

        if (pending.Length > 0)
        {
            logger.LogInformation(
                "Waiting up to {Grace} for {Count} in-flight POP3 session(s) on {Role}.",
                grace,
                pending.Length,
                options.Role);

            await Task.WhenAny(Task.WhenAll(pending), Task.Delay(grace)).ConfigureAwait(false);
        }

        await _stopping.CancelAsync().ConfigureAwait(false);
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        using CancellationTokenSource linked =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stopping.Token);

        while (!linked.IsCancellationRequested)
        {
            TcpClient client;

            try
            {
                client = await _listener.AcceptTcpClientAsync(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                // Stop() raced the accept. Ordinary shutdown.
                return;
            }
            catch (SocketException ex)
            {
                // One failed accept must not end the listener.
                logger.LogWarning(ex, "Accepting a POP3 connection failed.");
                continue;
            }

            StartSession(client, linked.Token);
        }
    }

    private void StartSession(TcpClient client, CancellationToken cancellationToken)
    {
        IpAddressValue remoteAddress;

        try
        {
            remoteAddress = IpAddressValue.From(((IPEndPoint)client.Client.RemoteEndPoint!).Address);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or NullReferenceException)
        {
            // The peer vanished between accept and here.
            client.Dispose();
            return;
        }

        SmtpAdmission admission = limiter.TryAdmit(remoteAddress, out ISmtpConnectionSlot? slot);

        if (admission != SmtpAdmission.Admitted)
        {
            _ = RefuseAsync(client, admission, remoteAddress);
            return;
        }

        Task session = RunSessionAsync(client, slot!, remoteAddress, cancellationToken);

        lock (_sessionGate)
        {
            _sessions.Add(session);

            // Completed sessions are pruned here rather than by a timer: the list is only read
            // at shutdown, and an unpruned list of every session the process ever ran is a leak
            // on a server that stays up for months.
            _sessions.RemoveAll(t => t.IsCompleted);
        }
    }

    private async Task RunSessionAsync(
        TcpClient client,
        ISmtpConnectionSlot slot,
        IpAddressValue remoteAddress,
        CancellationToken cancellationToken)
    {
        // Yield so the accept loop is not waiting on this session's first await.
        await Task.Yield();

        try
        {
            using (client)
            using (slot)
            {
                // Nagle off. A POP3 client waits for each response before sending its next
                // command, so coalescing adds latency to a conversation that is round-trip bound.
                client.NoDelay = true;

                await using NetworkStream stream = client.GetStream();

                // A scope per connection, not per listener: the handler's dependencies reach
                // repositories, which hold a database connection, and one scope shared by every
                // session would have concurrent sessions sharing one.
                await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

                Pop3ConnectionHandler handler =
                    scope.ServiceProvider.GetRequiredService<Pop3ConnectionHandler>();

                await handler.HandleAsync(
                    stream,
                    remoteAddress,
                    options,
                    DateTimeOffset.UtcNow,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // The handler already catches everything it can name. This is the backstop that
            // keeps one session from taking the listener with it.
            logger.LogError(ex, "POP3 session from {RemoteAddress} ended unexpectedly.", remoteAddress.Value);
        }
    }

    /// <summary>
    /// Refuses a connection the limiter would not admit.
    /// </summary>
    /// <remarks>
    /// A negative status indicator and then the socket closes. RFC 1939 §4 makes the greeting
    /// "any positive response", so there is no positive greeting that could carry a refusal —
    /// and §3 makes <c>-ERR</c> the way a server says no. Refusing politely rather than dropping
    /// the socket matters because a client that is told will back off and reconnect, and one
    /// that sees a bare reset shows its user a connection error.
    /// </remarks>
    private async Task RefuseAsync(TcpClient client, SmtpAdmission admission, IpAddressValue remoteAddress)
    {
        logger.LogWarning(
            "Refusing POP3 connection from {RemoteAddress}: {Reason} (total {Total}/{MaxTotal}, this address {ForAddress}/{MaxPerAddress}).",
            remoteAddress.Value,
            admission,
            limiter.CurrentTotal,
            limiter.MaxTotal,
            limiter.CurrentFor(remoteAddress),
            limiter.MaxPerAddress);

        try
        {
            using (client)
            {
                await using NetworkStream stream = client.GetStream();

                byte[] octets = Encoding.ASCII.GetBytes(
                    Pop3Response.Error("Too many connections; please try again shortly").Format());

                await stream.WriteAsync(octets).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // The peer is being refused anyway; failing to tell it so changes nothing.
            logger.LogDebug(ex, "Could not deliver the refusal to {RemoteAddress}.", remoteAddress.Value);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);

        _stopping.Dispose();
        _listener.Dispose();
    }
}
