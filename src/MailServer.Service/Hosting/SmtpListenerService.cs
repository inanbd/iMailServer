using System.Net.Sockets;
using System.Net;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Domain.Enums;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Service.Hosting;

/// <summary>
/// Owns the SMTP listeners for their whole lifetime.
/// </summary>
/// <remarks>
/// <para>
/// One listener per enabled role, each on its own socket. The role is fixed by which socket
/// accepted a connection and is never derived from anything the peer says, which is what makes
/// "port 25 cannot relay" a property of the deployment rather than of a runtime check somebody
/// could get wrong.
/// </para>
/// <para>
/// <b>A listener that cannot bind is fatal to this worker and reported, not retried quietly.</b>
/// The usual cause is another process already on the port, or the service running without the
/// privilege to bind below 1024; neither fixes itself, and a server that silently accepts no
/// mail is worse than one that says why.
/// </para>
/// </remarks>
public sealed class SmtpListenerService : ResilientBackgroundService
{
    private readonly IServiceProvider _services;
    private readonly IOptionsMonitor<MailServerOptions> _options;
    private readonly List<SmtpListener> _listeners = [];

    public SmtpListenerService(
        IServiceProvider services,
        IOptionsMonitor<MailServerOptions> options,
        IHealthRegistry healthRegistry,
        ILogger<SmtpListenerService> logger)
        : base(healthRegistry, logger)
    {
        _services = services;
        _options = options;
    }

    public override string ComponentName => "SmtpListeners";

    /// <summary>
    /// Restarting a listener that failed to bind will not make the port free.
    /// </summary>
    /// <remarks>
    /// The long ceiling is deliberate: the realistic recovery is an operator stopping whatever
    /// else holds the port, and retrying every second in the meantime only fills the log.
    /// </remarks>
    protected override TimeSpan InitialRestartDelay => TimeSpan.FromSeconds(5);

    protected override TimeSpan MaximumRestartDelay => TimeSpan.FromMinutes(2);

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        MailServerOptions options = _options.CurrentValue;

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
                    HealthState.Warning,
                    "No SMTP listener is enabled, so this server is not accepting mail.");

                Logger.LogWarning("No SMTP listener is enabled; this server is not accepting mail.");
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
            await StopListenersAsync(options).ConfigureAwait(false);
        }
    }

    private void StartListeners(
        MailServerOptions options,
        SmtpConnectionLimiter limiter,
        CancellationToken stoppingToken)
    {
        foreach ((SmtpListenerRole role, SmtpListenerOptions listener, CertificatePurpose purpose) in
            (( SmtpListenerRole, SmtpListenerOptions, CertificatePurpose )[])
            [
                (SmtpListenerRole.InboundMta, options.Smtp.InboundMta, CertificatePurpose.SmtpInbound),
                (SmtpListenerRole.Submission, options.Smtp.Submission, CertificatePurpose.SmtpSubmission),
                (SmtpListenerRole.ImplicitTlsSubmission, options.Smtp.ImplicitTlsSubmission, CertificatePurpose.SmtpSubmission),
            ])
        {
            if (!listener.Enabled)
            {
                continue;
            }

            foreach (IPEndPoint endpoint in ResolveEndpoints(listener))
            {
                SmtpListener started = new(
                    endpoint,
                    BuildConnectionOptions(options, role, purpose),
                    limiter,
                    _services.GetRequiredService<IServiceScopeFactory>(),
                    _services.GetRequiredService<ILogger<SmtpListener>>());

                // Start before adding: a listener that throws on bind must not end up in the
                // list, where shutdown would then try to stop something that never started.
                _ = started.StartAsync(stoppingToken);

                _listeners.Add(started);
            }
        }
    }

    private SmtpConnectionOptions BuildConnectionOptions(
        MailServerOptions options,
        SmtpListenerRole role,
        CertificatePurpose purpose) =>
        new(
            role,
            new SmtpProcessorOptions(
                options.Server.Hostname,
                options.Server.ProductName,
                options.Limits.MaxRecipientsPerMessage,
                options.Storage.MaxMessageSizeBytes,
                options.Smtp.EnableAuthentication,
                options.Smtp.EnableSmtpUtf8,
                options.Smtp.EnableChunking),
            options.Limits.MaxSmtpLineBytes,
            TimeSpan.FromSeconds(options.Limits.SmtpCommandTimeoutSeconds),
            TimeSpan.FromSeconds(options.Limits.SmtpSessionTimeoutSeconds),
            purpose);

    /// <summary>
    /// Resolves the addresses to bind.
    /// </summary>
    /// <remarks>
    /// An empty list means every interface, expressed as <see cref="IPAddress.IPv6Any"/> with
    /// dual-mode rather than as two sockets: one socket accepting both families is what a mail
    /// server wants, and binding IPv4 and IPv6 separately on the same port fails on some
    /// configurations and silently serves only one family on others.
    /// </remarks>
    private IEnumerable<IPEndPoint> ResolveEndpoints(SmtpListenerOptions listener)
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
                    "'{Address}' is not a valid IP address and was not bound for the SMTP listener on port {Port}.",
                    address,
                    listener.Port);
            }
        }
    }

    private async Task StopListenersAsync(MailServerOptions options)
    {
        TimeSpan grace = TimeSpan.FromSeconds(options.Smtp.ShutdownGraceSeconds);

        foreach (SmtpListener listener in _listeners)
        {
            try
            {
                await listener.StopAsync(grace).ConfigureAwait(false);
                await listener.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.LogWarning(ex, "Stopping the {Role} SMTP listener failed.", listener.Role);
            }
        }

        _listeners.Clear();
    }
}
