using System.Net;
using System.Net.Sockets;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Domain.Enums;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Imap;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Service.Hosting;

/// <summary>
/// Owns the IMAP listeners for their whole lifetime.
/// </summary>
/// <remarks>
/// <para>
/// One listener per enabled role, each on its own socket, for the reason
/// <see cref="SmtpListenerService"/> gives: whether TLS precedes the greeting is fixed by which
/// socket accepted the connection and is never derived from anything the peer says.
/// </para>
/// <para>
/// <b>A listener that cannot bind is fatal to this worker and reported, not retried quietly.</b>
/// The usual cause is another process already on the port, or the service running without the
/// privilege to bind below 1024; neither fixes itself, and a server that silently serves no
/// mailboxes is worse than one that says why.
/// </para>
/// <para>
/// <b>Neither listener is enabled by default, so the ordinary healthy state of this worker is to
/// report that it is doing nothing.</b> That is deliberate rather than a gap: mailbox access
/// reaches a user's entire mail history, and it opens when an operator asks for it. The message
/// says so plainly instead of leaving an operator to wonder whether the port failed to bind.
/// </para>
/// </remarks>
public sealed class ImapListenerService : ResilientBackgroundService
{
    private readonly IServiceProvider _services;
    private readonly IOptionsMonitor<MailServerOptions> _options;
    private readonly List<ImapListener> _listeners = [];

    public ImapListenerService(
        IServiceProvider services,
        IOptionsMonitor<MailServerOptions> options,
        IHealthRegistry healthRegistry,
        ILogger<ImapListenerService> logger)
        : base(healthRegistry, logger)
    {
        _services = services;
        _options = options;
    }

    public override string ComponentName => "ImapListeners";

    /// <summary>Restarting a listener that failed to bind will not make the port free.</summary>
    protected override TimeSpan InitialRestartDelay => TimeSpan.FromSeconds(5);

    protected override TimeSpan MaximumRestartDelay => TimeSpan.FromMinutes(2);

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        MailServerOptions options = _options.CurrentValue;

        // Its own limiter instance, deliberately not shared with the SMTP listeners: a flood of
        // IMAP connections must not exhaust the budget inbound mail delivery needs, and one
        // shared counter would let it. See ImapListener's remarks.
        SmtpConnectionLimiter limiter = new(
            options.Limits.MaxConcurrentConnectionsTotal,
            options.Limits.MaxConcurrentConnectionsPerIp);

        try
        {
            StartListeners(options, limiter, stoppingToken);

            if (_listeners.Count == 0)
            {
                Health.Publish(
                    ComponentName,
                    HealthState.Healthy,
                    "No IMAP listener is enabled, so no mailbox access is being served.");

                Logger.LogInformation(
                    "No IMAP listener is enabled; mailbox access is not being served. " +
                    "Enable MailServer:Imap:ImplicitTls to serve it on port 993.");
            }
            else
            {
                Health.Publish(
                    ComponentName,
                    HealthState.Healthy,
                    $"Listening on {string.Join(", ", _listeners.Select(l => $"{l.Role}:{l.BoundPort}"))}.");
            }

            // The listeners run themselves; this worker exists to own them and to stop them.
            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        finally
        {
            await StopListenersAsync().ConfigureAwait(false);
        }
    }

    private void StartListeners(
        MailServerOptions options,
        SmtpConnectionLimiter limiter,
        CancellationToken stoppingToken)
    {
        foreach ((ImapListenerRole role, ImapListenerOptions listener) in
            ((ImapListenerRole, ImapListenerOptions)[])
            [
                (ImapListenerRole.Cleartext, options.Imap.Cleartext),
                (ImapListenerRole.ImplicitTls, options.Imap.ImplicitTls),
            ])
        {
            if (!listener.Enabled)
            {
                continue;
            }

            foreach (IPEndPoint endpoint in ResolveEndpoints(listener))
            {
                ImapListener started = new(
                    endpoint,
                    BuildConnectionOptions(options, role),
                    limiter,
                    _services.GetRequiredService<IServiceScopeFactory>(),
                    _services.GetRequiredService<ILogger<ImapListener>>());

                // Start before adding: a listener that throws on bind must not end up in the
                // list, where shutdown would then try to stop something that never started.
                _ = started.StartAsync(stoppingToken);

                _listeners.Add(started);
            }
        }
    }

    /// <summary>
    /// Both listeners present the same certificate.
    /// </summary>
    /// <remarks>
    /// <see cref="CertificatePurpose.MailboxAccess"/> covers 143 and 993 alike, because a
    /// <c>STARTTLS</c> upgrade on 143 ends up serving exactly what 993 serves from the first
    /// octet. Splitting them would be two names for one certificate and one more thing for an
    /// operator to get half-configured.
    /// </remarks>
    private static ImapConnectionOptions BuildConnectionOptions(
        MailServerOptions options,
        ImapListenerRole role) =>
        new(
            role,
            new ImapProcessorOptions(
                options.Server.ProductName,
                role,
                options.Imap.EnableAuthentication,
                options.Limits.MaxAuthAttemptsPerSession),

            // The same ceiling SMTP accepts, so a message a client could have sent itself is a
            // message it can also file with APPEND. A lower limit here would make "save to
            // Drafts" fail for mail the server would happily have relayed.
            options.Storage.MaxMessageSizeBytes,
            options.Limits.MaxImapLineBytes,
            TimeSpan.FromSeconds(options.Limits.ImapPreAuthenticationTimeoutSeconds),
            TimeSpan.FromSeconds(options.Limits.ImapInactivityTimeoutSeconds),
            CertificatePurpose.MailboxAccess);

    /// <summary>
    /// Stops the listeners, briefly.
    /// </summary>
    /// <remarks>
    /// A much shorter grace than <see cref="SmtpListenerService"/>'s, and for a reason worth
    /// stating: an abandoned SMTP session mid-<c>DATA</c> risks a duplicate at the sending
    /// server, so a message in flight is worth waiting for. An IMAP session has no such hazard —
    /// a client that loses its connection reconnects and re-reads — and IMAP sessions are idle
    /// by design, so waiting on them would stall shutdown on connections that are doing nothing.
    /// </remarks>
    private async Task StopListenersAsync()
    {
        foreach (ImapListener listener in _listeners)
        {
            try
            {
                await listener.StopAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                await listener.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Shutdown must complete. A listener that will not stop cleanly is logged and
                // left to the process exiting.
                Logger.LogWarning(ex, "Stopping the IMAP {Role} listener failed.", listener.Role);
            }
        }

        _listeners.Clear();
    }

    /// <summary>
    /// Resolves the addresses to bind.
    /// </summary>
    /// <remarks>
    /// An empty list means every interface, expressed as <see cref="IPAddress.IPv6Any"/> with
    /// dual-mode rather than as two sockets: binding IPv4 and IPv6 separately on the same port
    /// fails on some configurations and silently serves only one family on others.
    /// </remarks>
    private IEnumerable<IPEndPoint> ResolveEndpoints(ImapListenerOptions listener)
    {
        if (listener.BindAddresses.Count == 0)
        {
            yield return new IPEndPoint(
                Socket.OSSupportsIPv6 ? IPAddress.IPv6Any : IPAddress.Any,
                listener.Port);

            yield break;
        }

        foreach (string address in listener.BindAddresses)
        {
            if (IPAddress.TryParse(address, out IPAddress? parsed))
            {
                yield return new IPEndPoint(parsed, listener.Port);
            }
            else
            {
                // Named rather than ignored. A typo in a bind address silently narrows what the
                // server listens on, which looks exactly like a firewall problem.
                Logger.LogError(
                    "'{Address}' is not a valid IP address and was not bound for the IMAP listener on port {Port}.",
                    address,
                    listener.Port);
            }
        }
    }
}
