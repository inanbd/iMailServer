using System.Net;
using System.Net.Sockets;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Domain.Enums;
using MailServer.Domain.Pop3;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Pop3;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Service.Hosting;

/// <summary>
/// Owns the POP3 listeners for their whole lifetime.
/// </summary>
/// <remarks>
/// <para>
/// One listener per enabled role, each on its own socket, for the reason
/// <see cref="ImapListenerService"/> gives: whether TLS precedes the greeting is fixed by which
/// socket accepted the connection and is never derived from anything the peer says.
/// </para>
/// <para>
/// <b>Neither listener is enabled by default, so the ordinary healthy state of this worker is to
/// report that it is doing nothing.</b> POP3 is here for devices that cannot speak IMAP, and a
/// port nobody asked for is a port nobody is watching. The message says so plainly instead of
/// leaving an operator to wonder whether the port failed to bind.
/// </para>
/// </remarks>
public sealed class Pop3ListenerService : ResilientBackgroundService
{
    private readonly IServiceProvider _services;
    private readonly IOptionsMonitor<MailServerOptions> _options;
    private readonly List<Pop3Listener> _listeners = [];

    public Pop3ListenerService(
        IServiceProvider services,
        IOptionsMonitor<MailServerOptions> options,
        IHealthRegistry healthRegistry,
        ILogger<Pop3ListenerService> logger)
        : base(healthRegistry, logger)
    {
        _services = services;
        _options = options;
    }

    public override string ComponentName => "Pop3Listeners";

    /// <summary>Restarting a listener that failed to bind will not make the port free.</summary>
    protected override TimeSpan InitialRestartDelay => TimeSpan.FromSeconds(5);

    protected override TimeSpan MaximumRestartDelay => TimeSpan.FromMinutes(2);

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        MailServerOptions options = _options.CurrentValue;

        // Its own limiter instance, deliberately not shared with the SMTP or IMAP listeners: a
        // flood of POP3 connections must not exhaust the budget inbound mail delivery needs.
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
                    "No POP3 listener is enabled, so no POP3 access is being served.");

                Logger.LogInformation(
                    "No POP3 listener is enabled. Enable MailServer:Pop3:ImplicitTls to serve it " +
                    "on port 995; IMAP is the better choice for any client that can speak it.");
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
        foreach ((Pop3ListenerRole role, Pop3ListenerOptions listener) in
            ((Pop3ListenerRole, Pop3ListenerOptions)[])
            [
                (Pop3ListenerRole.Cleartext, options.Pop3.Cleartext),
                (Pop3ListenerRole.ImplicitTls, options.Pop3.ImplicitTls),
            ])
        {
            if (!listener.Enabled)
            {
                continue;
            }

            foreach (IPEndPoint endpoint in ResolveEndpoints(listener))
            {
                Pop3Listener started = new(
                    endpoint,
                    BuildConnectionOptions(options, role),
                    limiter,
                    _services.GetRequiredService<IServiceScopeFactory>(),
                    _services.GetRequiredService<ILogger<Pop3Listener>>());

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
    /// <see cref="CertificatePurpose.MailboxAccess"/> covers 110 and 995 as it covers 143 and
    /// 993: an <c>STLS</c> upgrade on 110 ends up serving exactly what 995 serves from the first
    /// octet, and both are mailbox access. A fourth purpose would be one more thing for an
    /// operator to get half-configured.
    /// </remarks>
    private static Pop3ConnectionOptions BuildConnectionOptions(
        MailServerOptions options,
        Pop3ListenerRole role) =>
        new(
            role,
            new Pop3ProcessorOptions(
                options.Server.ProductName,
                role,
                options.Pop3.EnableAuthentication,
                options.Limits.MaxAuthAttemptsPerSession),
            options.Limits.MaxPop3LineBytes,
            TimeSpan.FromSeconds(options.Limits.Pop3PreAuthenticationTimeoutSeconds),
            TimeSpan.FromSeconds(options.Limits.Pop3InactivityTimeoutSeconds),
            CertificatePurpose.MailboxAccess);

    /// <summary>
    /// Stops the listeners, briefly.
    /// </summary>
    /// <remarks>
    /// A session cut off before its <c>QUIT</c> removes nothing — RFC 1939 §6 requires that — so
    /// the failure is a repeated download rather than lost mail, and shutdown need not wait long
    /// for it.
    /// </remarks>
    private async Task StopListenersAsync()
    {
        foreach (Pop3Listener listener in _listeners)
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
                Logger.LogWarning(ex, "Stopping the POP3 {Role} listener failed.", listener.Role);
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
    private IEnumerable<IPEndPoint> ResolveEndpoints(Pop3ListenerOptions listener)
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
                    "'{Address}' is not a valid IP address and was not bound for the POP3 listener on port {Port}.",
                    address,
                    listener.Port);
            }
        }
    }
}
