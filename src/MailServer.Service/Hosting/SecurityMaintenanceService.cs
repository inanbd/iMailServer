using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Domain.Enums;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MailServer.Service.Hosting;

/// <summary>
/// Periodically drops expired administrative sessions and reports security readiness.
/// </summary>
/// <remarks>
/// <para>
/// Sessions expire lazily on validation — a token presented after its idle timeout is rejected
/// and removed there and then. This worker exists for the sessions that are simply
/// <i>abandoned</i>: a console closed without signing out leaves an entry nobody will ever
/// present again, and without a sweep those accumulate until the process restarts.
/// </para>
/// <para>
/// It also publishes the security health reading, which is what puts "setup has not been
/// completed" and "secrets are not production-protected" on the dashboard rather than leaving
/// them to be discovered.
/// </para>
/// </remarks>
public sealed class SecurityMaintenanceService(
    IServiceScopeFactory scopeFactory,
    IAdminSessionManager sessions,
    ISecretProtector secretProtector,
    IHealthRegistry health,
    ILogger<SecurityMaintenanceService> logger)
    : ResilientBackgroundService(health, logger)
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(5);

    public override string ComponentName => "Security";

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(SweepInterval);

        // Evaluate immediately: an operator starting the service wants to know straight away
        // that setup is outstanding, not in five minutes.
        await EvaluateAsync(stoppingToken).ConfigureAwait(false);

        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            int purged = await sessions.PurgeExpiredAsync(stoppingToken).ConfigureAwait(false);

            if (purged > 0)
            {
                Logger.LogDebug("Purged {SessionCount} expired administrative session(s).", purged);
            }

            await EvaluateAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task EvaluateAsync(CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        IAdminAccountRepository accounts =
            scope.ServiceProvider.GetRequiredService<IAdminAccountRepository>();

        bool configured = await accounts.AnyAsync(cancellationToken).ConfigureAwait(false);

        IReadOnlyList<AdminSession> active =
            await sessions.GetActiveAsync(cancellationToken).ConfigureAwait(false);

        // Two conditions worth surfacing, in priority order.
        (HealthState state, string message) = (configured, secretProtector.IsProductionGrade) switch
        {
            (false, _) => (
                HealthState.Warning,
                "First-run setup has not been completed. The administration console will " +
                "prompt for a master password on its next connection."),

            (true, false) => (
                HealthState.Warning,
                $"Secrets are protected with the {secretProtector.SchemeName} scheme, which is " +
                "not suitable for production. Set MailServer:Security:SecretProtection to " +
                "'Dpapi' on Windows Server."),

            _ => (
                HealthState.Healthy,
                $"Administrator configured; secrets protected with {secretProtector.SchemeName}; " +
                $"{active.Count} active session(s)."),
        };

        Health.Publish(new HealthReading(
            ComponentName,
            state,
            message,
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["SetupCompleted"] = configured.ToString(),
                ["ActiveSessions"] = active.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["SecretProtection"] = secretProtector.SchemeName,
            }));
    }
}
