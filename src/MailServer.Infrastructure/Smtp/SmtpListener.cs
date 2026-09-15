using System.Net;
using System.Net.Sockets;
using System.Text;
using MailServer.Application.Abstractions.Security;
using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Smtp;

/// <summary>
/// Accepts connections on one endpoint and hands each to a session.
/// </summary>
/// <remarks>
/// <para>
/// One listener per role, never one listener with a mode flag. The role is decided by which
/// socket accepted the connection and is not derived from anything the peer says, so a peer
/// cannot talk its way from port 25 into submission privileges.
/// </para>
/// <para>
/// The accept loop does as little as possible: take a slot, start a session, go back to
/// accepting. Anything it waits on is a connection nobody else can make in the meantime, which
/// is a denial of service with extra steps.
/// </para>
/// </remarks>
public sealed class SmtpListener(
    IPEndPoint endpoint,
    SmtpConnectionOptions options,
    SmtpConnectionLimiter limiter,
    IServiceScopeFactory scopeFactory,
    ILogger<SmtpListener> logger) : IAsyncDisposable
{
    private readonly TcpListener _listener = new(endpoint);
    private readonly CancellationTokenSource _stopping = new();
    private readonly List<Task> _sessions = [];
    private readonly Lock _sessionGate = new();

    /// <summary>Where this listener is bound.</summary>
    public IPEndPoint EndPoint => endpoint;

    /// <summary>Which role it serves.</summary>
    public SmtpListenerRole Role => options.Role;

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
            "SMTP {Role} listener bound to {EndPoint}.",
            options.Role,
            _listener.LocalEndpoint);

        return Task.Run(() => AcceptLoopAsync(cancellationToken), CancellationToken.None);
    }

    /// <summary>
    /// Stops accepting and waits for in-flight sessions.
    /// </summary>
    /// <remarks>
    /// Accepting stops immediately; existing sessions are given until <paramref name="grace"/>.
    /// Abandoning a session mid-DATA risks a duplicate at the sending server, which saw no reply
    /// and will retry — so a message already in flight is worth waiting for.
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
                "Waiting up to {Grace} for {Count} in-flight SMTP session(s) on {Role}.",
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
                logger.LogWarning(ex, "Accepting an SMTP connection failed.");
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
            // Refused politely and transiently. 421 tells a legitimate sender to come back, which
            // it will; dropping the socket silently makes a busy server look broken.
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
                // Nagle off: SMTP is lock-step and every reply is small, so coalescing adds
                // latency to a conversation that is already round-trip bound.
                client.NoDelay = true;

                await using NetworkStream stream = client.GetStream();

                // A scope per connection, not per listener. The handler's dependencies reach
                // repositories, which hold a database connection and join the ambient
                // transaction; one scope shared by every session would have concurrent sessions
                // sharing a connection, and a session that outlived the process would hold one
                // for ever.
                await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

                SmtpConnectionHandler handler =
                    scope.ServiceProvider.GetRequiredService<SmtpConnectionHandler>();

                try
                {
                    await handler.HandleAsync(
                        stream,
                        remoteAddress,
                        options,
                        DateTimeOffset.UtcNow,
                        cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    // Security events are BUFFERED during the session and written here.
                    //
                    // They have to be buffered: writing one while a delivery transaction is open
                    // deadlocks SQLite (see addendum A2.2). They have to be flushed HERE because
                    // nothing else will - the pipeline behaviour that flushes them runs only for
                    // MediatR requests and the IPC dispatcher only for admin commands, and an
                    // SMTP session goes through neither. Without this the entire audit trail for
                    // mailbox authentication - every failure, every lockout, every forged sender
                    // - is recorded, logged as recorded, and silently discarded.
                    //
                    // In the finally, so a session that ended badly still leaves its evidence.
                    await FlushSecurityEventsAsync(scope.ServiceProvider).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex)
        {
            // The handler already catches everything it can name. This is the backstop that
            // keeps one session from taking the listener with it.
            logger.LogError(ex, "SMTP session from {RemoteAddress} ended unexpectedly.", remoteAddress.Value);
        }
    }

    /// <summary>Writes the session's buffered security events. Never throws.</summary>
    /// <remarks>
    /// A failure to record evidence must not also fail the thing it was evidence of, and by this
    /// point the session is over anyway. It is logged at error level because a security log that
    /// has stopped being written is worth waking somebody for.
    /// </remarks>
    private async Task FlushSecurityEventsAsync(IServiceProvider scopedServices)
    {
        try
        {
            ISecurityEventRecorder recorder =
                scopedServices.GetRequiredService<ISecurityEventRecorder>();

            if (!recorder.HasPendingEvents)
            {
                return;
            }

            await recorder.FlushAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to write the security events buffered during an SMTP session.");
        }
    }

    private async Task RefuseAsync(TcpClient client, SmtpAdmission admission, IpAddressValue remoteAddress)
    {
        SmtpReply reply = SmtpReplies.TooManyConnections();

        logger.LogWarning(
            "Refusing SMTP connection from {RemoteAddress}: {Reason} (total {Total}/{MaxTotal}, this address {ForAddress}/{MaxPerAddress}).",
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

                byte[] octets = Encoding.UTF8.GetBytes(reply.Format());

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
