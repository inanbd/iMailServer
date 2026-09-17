using System.Net;
using System.Net.Sockets;
using System.Text;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Imap;

/// <summary>
/// Accepts IMAP connections on one endpoint and hands each to a session.
/// </summary>
/// <remarks>
/// <para>
/// One listener per role, never one listener with a mode flag — the same rule
/// <see cref="SmtpListener"/> follows and for the same reason. Whether TLS precedes the greeting
/// is decided by which socket accepted the connection, never by anything the peer says, so a
/// peer cannot talk its way from the cleartext port into the implicit-TLS one's assumptions.
/// </para>
/// <para>
/// The accept loop does as little as possible: take a slot, start a session, go back to
/// accepting. Anything it waits on is a connection nobody else can make in the meantime, which
/// is a denial of service with extra steps.
/// </para>
/// <para>
/// <b>The connection limiter is <see cref="SmtpConnectionLimiter"/>, and each listener service
/// holds its own instance.</b> The type counts connections per address and knows nothing about
/// SMTP beyond its name, so a second implementation would be the same arithmetic written twice
/// with somewhere to drift — the repository has already made that call once, where
/// <see cref="ImapCapabilities.SaslMechanisms"/> reads the SMTP list rather than forking it.
/// Separate <i>instances</i> matter though: a flood of IMAP connections must not exhaust the
/// budget inbound mail delivery needs, and one shared counter would let it.
/// </para>
/// </remarks>
public sealed class ImapListener(
    IPEndPoint endpoint,
    ImapConnectionOptions options,
    SmtpConnectionLimiter limiter,
    IServiceScopeFactory scopeFactory,
    ILogger<ImapListener> logger) : IAsyncDisposable
{
    private readonly TcpListener _listener = new(endpoint);
    private readonly CancellationTokenSource _stopping = new();
    private readonly List<Task> _sessions = [];
    private readonly Lock _sessionGate = new();

    /// <summary>Where this listener is bound.</summary>
    public IPEndPoint EndPoint => endpoint;

    /// <summary>Which role it serves.</summary>
    public ImapListenerRole Role => options.Role;

    /// <summary>The port actually bound. Differs from the configured one only when port 0 was asked for.</summary>
    public int BoundPort => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>Binds and begins accepting.</summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (endpoint.Address.Equals(IPAddress.IPv6Any))
        {
            // One socket serving both families. Binding IPv4 and IPv6 separately on the same
            // port fails outright on some configurations and, worse, silently serves only one
            // family on others - a mail server that quietly stopped accepting IPv4 would look
            // like a DNS problem for days.
            _listener.Server.DualMode = true;
        }

        _listener.Start();

        logger.LogInformation(
            "IMAP {Role} listener bound to {EndPoint}.",
            options.Role,
            _listener.LocalEndpoint);

        return Task.Run(() => AcceptLoopAsync(cancellationToken), CancellationToken.None);
    }

    /// <summary>
    /// Stops accepting and gives in-flight sessions a moment to finish.
    /// </summary>
    /// <remarks>
    /// <b>The grace here means something different from <see cref="SmtpListener.StopAsync"/>'s,
    /// and should be shorter.</b> Abandoning an SMTP session mid-<c>DATA</c> risks a duplicate
    /// at the sending server, which saw no reply and will retry, so a message already in flight
    /// is worth waiting for. An IMAP session has no such hazard: every command is idempotent
    /// from the client's point of view or has already been committed, and a client that loses
    /// its connection reconnects and re-reads. What it does have is sessions that are idle by
    /// design and may stay open for half an hour, so waiting on them would stall shutdown for
    /// nothing.
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
                "Waiting up to {Grace} for {Count} in-flight IMAP session(s) on {Role}.",
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
                // One failed accept must not end the listener: a peer that resets during the
                // handshake would otherwise take the whole port down with it.
                logger.LogWarning(ex, "Accepting an IMAP connection failed.");
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
                // Nagle off. A client waits for a tagged completion before sending its next
                // command, so coalescing adds latency to a conversation that is already
                // round-trip bound - and an IMAP client makes far more round trips than an SMTP
                // one does.
                client.NoDelay = true;

                await using NetworkStream stream = client.GetStream();

                // A scope per connection, not per listener. The handler's dependencies reach
                // repositories, which hold a database connection; one scope shared by every
                // session would have concurrent sessions sharing a connection, and an IMAP
                // session can outlive an SMTP one by hours.
                await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

                ImapConnectionHandler handler =
                    scope.ServiceProvider.GetRequiredService<ImapConnectionHandler>();

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
            logger.LogError(ex, "IMAP session from {RemoteAddress} ended unexpectedly.", remoteAddress.Value);
        }
    }

    /// <summary>
    /// Refuses a connection the limiter would not admit.
    /// </summary>
    /// <remarks>
    /// An untagged <c>BYE</c> and then the socket closes. RFC 3501 §7.1.5 is the only way an
    /// IMAP server can say "not now" before a client has sent anything — there is no tag to
    /// answer with and no equivalent of SMTP's 421 greeting. Refusing politely rather than
    /// dropping the socket matters for the same reason it does there: a client that is told will
    /// back off and reconnect, and one that sees a bare reset shows its user a connection error.
    /// </remarks>
    private async Task RefuseAsync(TcpClient client, SmtpAdmission admission, IpAddressValue remoteAddress)
    {
        logger.LogWarning(
            "Refusing IMAP connection from {RemoteAddress}: {Reason} (total {Total}/{MaxTotal}, this address {ForAddress}/{MaxPerAddress}).",
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

                byte[] octets = Encoding.UTF8.GetBytes(
                    ImapResponses.Bye("Too many connections; please try again shortly").Format());

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
