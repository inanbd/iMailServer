using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Platform;
using MailServer.Domain.Enums;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Service.Hosting;

/// <summary>
/// Periodically re-evaluates the health signals that nothing else pushes.
/// </summary>
/// <remarks>
/// Most health comes from the workers themselves, which know their own state continuously.
/// A few conditions have no natural publisher because nothing in the product causes them -
/// disk filling up, the system clock drifting - so they are polled here.
/// </remarks>
public sealed class ServiceHealthMonitor(
    IHealthRegistry health,
    IServerPaths paths,
    IEnvironmentInfo environment,
    IOptions<MailServerOptions> options,
    ILogger<ServiceHealthMonitor> logger)
    : ResilientBackgroundService(health, logger)
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(1);

    public override string ComponentName => "HealthMonitor";

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(PollInterval);

        // Evaluate immediately rather than waiting a full interval: an operator starting the
        // service wants the dashboard populated now, not in sixty seconds.
        EvaluateDiskSpace();

        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            EvaluateDiskSpace();
        }
    }

    private void EvaluateDiskSpace()
    {
        long free = environment.GetAvailableFreeSpaceBytes(paths.DataRoot);
        long minimum = options.Value.Storage.MinimumFreeDiskBytes;

        // Two thresholds. Warning at twice the configured minimum gives an operator time to
        // act before mail is actually affected; by the time the minimum itself is breached,
        // inbound mail is already being deferred.
        HealthState state = free switch
        {
            _ when free < minimum => HealthState.Critical,
            _ when free < minimum * 2 => HealthState.Warning,
            _ => HealthState.Healthy,
        };

        Health.Publish(new HealthReading(
            "Disk",
            state,
            state switch
            {
                HealthState.Critical =>
                    $"Free space on the data volume has fallen below the configured minimum " +
                    $"({free:N0} < {minimum:N0} bytes). Inbound mail will be deferred.",
                HealthState.Warning =>
                    $"Free space on the data volume is getting low ({free:N0} bytes).",
                _ => $"{free:N0} bytes free on the data volume.",
            },
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["FreeBytes"] = free.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["MinimumBytes"] = minimum.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["DataRoot"] = paths.DataRoot,
            }));
    }
}
