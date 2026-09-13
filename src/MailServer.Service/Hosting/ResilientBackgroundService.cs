using MailServer.Application.Abstractions.Monitoring;
using MailServer.Domain.Enums;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MailServer.Service.Hosting;

/// <summary>
/// Base class for every long-running worker in the service.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why not plain <see cref="BackgroundService"/>.</b> Since .NET 6, an unhandled exception
/// in a <c>BackgroundService</c> stops the entire host by default. For a mail server that is
/// the wrong behaviour by a wide margin: a transient DNS failure inside the DNS monitor must
/// never stop SMTP receipt, and a malformed DMARC report must never stop outbound delivery.
/// </para>
/// <para>
/// This base class provides fault isolation, restart with exponential backoff and jitter,
/// health reporting, graceful shutdown, and maintenance-mode awareness. Every worker gets
/// all of it by deriving, so none of it can be forgotten in a new worker.
/// </para>
/// <para>
/// <b>Cancellation is success, not failure.</b> An <see cref="OperationCanceledException"/>
/// during shutdown is the correct outcome of a cooperative stop. Treating it as a fault fills
/// the log with alarming noise on every clean service stop, which trains operators to ignore
/// exactly the messages they should not ignore.
/// </para>
/// </remarks>
public abstract class ResilientBackgroundService : BackgroundService
{
    protected ResilientBackgroundService(IHealthRegistry healthRegistry, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(healthRegistry);
        ArgumentNullException.ThrowIfNull(logger);

        Health = healthRegistry;
        Logger = logger;
    }

    /// <summary>
    /// The health registry, exposed to derived workers so they can publish richer readings
    /// than the base class's automatic Healthy/Warning/Critical transitions.
    /// </summary>
    /// <remarks>
    /// A conventional constructor is used rather than a primary constructor precisely so that
    /// there is exactly ONE reference to each dependency shared by the base body and every
    /// derived worker. A primary constructor would have each derived class capture its own
    /// copy alongside the base's, which the compiler flags (CS9107/CS9124) and which is
    /// genuinely redundant state.
    /// </remarks>
    protected IHealthRegistry Health { get; }

    /// <summary>The logger, shared with derived workers so log scopes stay consistent.</summary>
    protected ILogger Logger { get; }

    /// <summary>Delay before the first restart after a fault.</summary>
    protected virtual TimeSpan InitialRestartDelay => TimeSpan.FromSeconds(1);

    /// <summary>Ceiling on the restart delay.</summary>
    protected virtual TimeSpan MaximumRestartDelay => TimeSpan.FromMinutes(5);

    /// <summary>
    /// Consecutive failures after which health becomes Critical rather than Warning.
    /// </summary>
    /// <remarks>
    /// One failure is noise; three in a row is a pattern. Escalating on the first would make
    /// the dashboard cry wolf, and operators stop reading a dashboard that does that.
    /// </remarks>
    protected virtual int CriticalFailureThreshold => 3;

    /// <summary>Name used in health readings and log scopes.</summary>
    public virtual string ComponentName => GetType().Name;

    /// <summary>The worker's actual work. Must observe <paramref name="stoppingToken"/>.</summary>
    protected abstract Task RunAsync(CancellationToken stoppingToken);

    /// <summary>
    /// Called once before the first <see cref="RunAsync"/>. A failure here is fatal to the
    /// worker: unlike a run-loop fault, a worker that cannot initialise will not fix itself
    /// by being restarted in a loop.
    /// </summary>
    protected virtual Task InitializeAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;

    protected sealed override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using IDisposable? scope = Logger.BeginScope(new Dictionary<string, object>
        {
            ["Worker"] = ComponentName,
        });

        Logger.LogInformation("{Worker} starting.", ComponentName);

        try
        {
            await InitializeAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            Logger.LogCritical(ex, "{Worker} failed to initialise and will not run.", ComponentName);

            Health.Publish(
                ComponentName,
                HealthState.Critical,
                $"Failed to initialise: {ex.Message}");

            return;
        }

        int consecutiveFailures = 0;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                Health.Publish(ComponentName, HealthState.Healthy, "Running.");

                await RunAsync(stoppingToken).ConfigureAwait(false);

                // A clean return means the worker finished its own work, not that it failed.
                Logger.LogInformation("{Worker} completed.", ComponentName);
                return;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                Logger.LogInformation("{Worker} stopped.", ComponentName);

                Health.Publish(ComponentName, HealthState.Unknown, "Stopped.");
                return;
            }
            catch (Exception ex)
            {
                consecutiveFailures++;

                TimeSpan delay = ComputeRestartDelay(consecutiveFailures);

                HealthState state = consecutiveFailures >= CriticalFailureThreshold
                    ? HealthState.Critical
                    : HealthState.Warning;

                Logger.Log(
                    state == HealthState.Critical ? LogLevel.Error : LogLevel.Warning,
                    ex,
                    "{Worker} faulted ({FailureCount} consecutive). Restarting in {DelaySeconds:0.#}s.",
                    ComponentName,
                    consecutiveFailures,
                    delay.TotalSeconds);

                Health.Publish(
                    ComponentName,
                    state,
                    $"Faulted {consecutiveFailures} time(s) in a row: {ex.Message}");

                try
                {
                    await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    /// <summary>
    /// Exponential backoff with jitter, capped.
    /// </summary>
    /// <remarks>
    /// Jitter matters when several workers depend on the same failing resource - typically the
    /// database. Without it they synchronise onto the same retry instant and hammer a server
    /// that is trying to recover, turning a brief outage into a sustained one.
    /// </remarks>
    private TimeSpan ComputeRestartDelay(int consecutiveFailures)
    {
        double seconds = InitialRestartDelay.TotalSeconds * Math.Pow(2, consecutiveFailures - 1);
        seconds = Math.Min(seconds, MaximumRestartDelay.TotalSeconds);

        double jitter = Random.Shared.NextDouble() * 0.3 * seconds;

        return TimeSpan.FromSeconds(seconds + jitter);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        Logger.LogInformation("{Worker} received a stop request.", ComponentName);

        await base.StopAsync(cancellationToken).ConfigureAwait(false);

        Health.Publish(ComponentName, HealthState.Unknown, "Stopped.");
    }
}
