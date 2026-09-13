using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using MailServer.Domain.Enums;
using MailServer.Ipc.Protocol;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Ipc.Server;

/// <summary>Configuration for the IPC server.</summary>
public sealed class IpcServerOptions
{
    public string PipeName { get; set; } = "AetherMail.Admin";

    public int MaxFrameBytes { get; set; } = 4 * 1024 * 1024;

    public int MaxConcurrentConnections { get; set; } = 8;

    public int RequestTimeoutSeconds { get; set; } = 60;
}

/// <summary>
/// Accepts administration connections on an ACL-restricted named pipe.
/// </summary>
/// <remarks>
/// <para>
/// One accept loop per permitted concurrent connection. Named pipes are not sockets: a
/// server instance serves exactly one client for its lifetime, so concurrency comes from
/// running several instances of the same pipe rather than from accepting repeatedly on one.
/// </para>
/// <para>
/// A connection that violates the protocol is closed rather than argued with. There is no
/// legitimate client that sends a malformed frame, so the cheapest correct response is to
/// stop talking to it; a new connection costs the admin application a few milliseconds.
/// </para>
/// </remarks>
public sealed class IpcServerHostedService : BackgroundService
{
    private readonly IpcServerOptions _options;
    private readonly IpcRequestDispatcher _dispatcher;
    private readonly ILogger<IpcServerHostedService> _logger;

    internal IpcServerHostedService(
        IOptions<IpcServerOptions> options,
        IpcRequestDispatcher dispatcher,
        ILogger<IpcServerHostedService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
        _dispatcher = dispatcher;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "IPC server starting on pipe '{PipeName}' with {InstanceCount} concurrent " +
            "instance(s) and a {MaxFrameBytes}-byte frame limit.",
            _options.PipeName,
            _options.MaxConcurrentConnections,
            _options.MaxFrameBytes);

        Task[] loops = new Task[_options.MaxConcurrentConnections];

        for (int i = 0; i < loops.Length; i++)
        {
            int instanceIndex = i;
            loops[i] = RunAcceptLoopAsync(instanceIndex, stoppingToken);
        }

        await Task.WhenAll(loops).ConfigureAwait(false);

        _logger.LogInformation("IPC server stopped.");
    }

    private async Task RunAcceptLoopAsync(int instanceIndex, CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using NamedPipeServerStream pipe = IpcPipeSecurity.Create(
                    _options.PipeName,
                    _options.MaxConcurrentConnections,
                    _logger);

                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);

                IpcCallerIdentity caller = ResolveCaller(pipe);

                _logger.LogInformation(
                    "Administration client connected on instance {InstanceIndex} as {Caller}.",
                    instanceIndex,
                    caller.Name);

                await ServeConnectionAsync(pipe, caller, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                // Normal shutdown. Not a fault, and must not be logged as one.
                return;
            }
            catch (IpcFrameException ex)
            {
                _logger.LogWarning(
                    ex,
                    "Closed an administration connection on instance {InstanceIndex} after a " +
                    "protocol violation.",
                    instanceIndex);
            }
            catch (IOException ex)
            {
                // The client vanished mid-conversation. Routine; the admin application was
                // closed or the machine went to sleep.
                _logger.LogDebug(
                    ex,
                    "Administration connection on instance {InstanceIndex} ended unexpectedly.",
                    instanceIndex);
            }
            catch (Exception ex)
            {
                // Fault isolation: one poisoned connection must never stop the accept loop,
                // and certainly must never take down the mail server hosting it.
                _logger.LogError(
                    ex,
                    "Unhandled error on IPC instance {InstanceIndex}. The loop will continue.",
                    instanceIndex);

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    private async Task ServeConnectionAsync(
        NamedPipeServerStream pipe,
        IpcCallerIdentity caller,
        CancellationToken stoppingToken)
    {
        while (pipe.IsConnected && !stoppingToken.IsCancellationRequested)
        {
            IpcRequest? request = await IpcFrame
                .ReadAsync<IpcRequest>(pipe, _options.MaxFrameBytes, stoppingToken)
                .ConfigureAwait(false);

            if (request is null)
            {
                // Clean close between frames: the admin application exited.
                _logger.LogInformation("Administration client {Caller} disconnected.", caller.Name);
                return;
            }

            // Per-request timeout, linked to shutdown. An administrative operation that hangs
            // must not hold a pipe instance forever - with a small instance count, a handful
            // of hung requests would lock every administrator out of the server.
            using CancellationTokenSource timeout = CancellationTokenSource
                .CreateLinkedTokenSource(stoppingToken);

            timeout.CancelAfter(TimeSpan.FromSeconds(_options.RequestTimeoutSeconds));

            IpcResponse response = await _dispatcher
                .DispatchAsync(request, caller, timeout.Token)
                .ConfigureAwait(false);

            // Written with the shutdown token, not the timeout token: a response describing a
            // timeout still has to reach the client, and cancelling the write would leave the
            // admin application waiting forever for a reply that was never sent.
            await IpcFrame
                .WriteAsync(pipe, response, _options.MaxFrameBytes, stoppingToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Identifies the connecting process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two layers of access control apply, and this is the outer one. The pipe ACL has already
    /// restricted connections to local administrators; this records <i>which</i> one, so that a
    /// security event can be attributed to a Windows account even when the sign-in it describes
    /// failed.
    /// </para>
    /// <para>
    /// <b>It confers no permissions.</b> From Milestone 2, permissions come exclusively from an
    /// authenticated session validated by the dispatcher. Windows identity gets a caller as far
    /// as the sign-in screen and no further, which is why <see cref="AdminPermission.None"/> is
    /// passed here rather than <c>FullControl</c>.
    /// </para>
    /// </remarks>
    private IpcCallerIdentity ResolveCaller(NamedPipeServerStream pipe)
    {
        if (OperatingSystem.IsWindows())
        {
            return ResolveWindowsCaller(pipe);
        }

        return new IpcCallerIdentity(
            $"{Environment.UserName}@{Environment.MachineName} (development)",
            SessionIdentifier: null,
            AdminPermission.None);
    }

    [SupportedOSPlatform("windows")]
    private IpcCallerIdentity ResolveWindowsCaller(NamedPipeServerStream pipe)
    {
        try
        {
            string? userName = pipe.GetImpersonationUserName();

            return new IpcCallerIdentity(
                string.IsNullOrWhiteSpace(userName) ? "(unknown)" : userName,
                SessionIdentifier: null,

                // No permissions from transport identity alone. The session decides.
                AdminPermission.None);
        }
        catch (IOException ex)
        {
            // Identity is needed for the audit trail. Failing to obtain it is a genuine
            // problem, but the ACL has already done the access control, so the connection
            // proceeds with an explicit placeholder rather than being dropped.
            _logger.LogWarning(ex, "Could not determine the identity of the connecting client.");

            return new IpcCallerIdentity(
                $"(unidentified administrator on {Environment.MachineName})",
                SessionIdentifier: null,
                AdminPermission.None);
        }
    }
}
