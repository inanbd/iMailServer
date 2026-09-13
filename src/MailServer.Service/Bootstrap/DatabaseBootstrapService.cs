using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Exceptions;
using MailServer.Domain.Enums;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Monitoring;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Service.Bootstrap;

/// <summary>
/// Startup gate: verifies storage, applies schema migrations and loads the maintenance mode
/// before any listener opens.
/// </summary>
/// <remarks>
/// <para>
/// An <see cref="IHostedService"/> rather than a <c>BackgroundService</c>, and registered
/// first, because the host runs hosted services' <c>StartAsync</c> in registration order and
/// waits for each. That ordering is what makes this a genuine gate: a failure here aborts
/// startup, and nothing that follows ever runs against an unmigrated schema.
/// </para>
/// <para>
/// <b>Failing to start is the correct outcome.</b> A mail server that comes up against a
/// half-migrated schema accepts mail it cannot store and returns 250 for messages that are
/// then lost. Refusing to start is visible, diagnosable and loses nothing.
/// </para>
/// </remarks>
public sealed class DatabaseBootstrapService(
    IServiceScopeFactory scopeFactory,
    IServerPaths paths,
    IEnvironmentInfo environment,
    IHealthRegistry health,
    MaintenanceModeAccessor maintenanceMode,
    IOptions<MailServerOptions> options,
    ILogger<DatabaseBootstrapService> logger) : IHostedService
{
    private const string StorageComponent = "Storage";
    private const string DatabaseComponent = "Database";

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await PrepareStorageAsync(cancellationToken).ConfigureAwait(false);
        await MigrateAsync(cancellationToken).ConfigureAwait(false);

        await maintenanceMode.InitializeAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private Task PrepareStorageAsync(CancellationToken cancellationToken)
    {
        try
        {
            paths.EnsureCreated();

            long free = environment.GetAvailableFreeSpaceBytes(paths.DataRoot);
            long minimum = options.Value.Storage.MinimumFreeDiskBytes;

            if (free < minimum)
            {
                // A warning rather than a refusal to start: with the server running, an
                // operator can see the problem in the dashboard and clear space. Refusing to
                // start would take mail offline over a condition they can fix in a minute.
                logger.LogWarning(
                    "Only {FreeBytes} bytes are free on the volume holding {DataRoot}; the " +
                    "configured minimum is {MinimumBytes}. Inbound mail will be deferred if " +
                    "this is not resolved.",
                    free,
                    paths.DataRoot,
                    minimum);

                health.Publish(
                    StorageComponent,
                    HealthState.Warning,
                    $"Free disk space is below the configured minimum ({free} < {minimum} bytes).");
            }
            else
            {
                health.Publish(
                    StorageComponent,
                    HealthState.Healthy,
                    $"Data root {paths.DataRoot} is ready with {free} bytes free.");
            }

            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Message storage at {DataRoot} could not be prepared.", paths.DataRoot);

            health.Publish(
                StorageComponent,
                HealthState.Critical,
                $"Storage could not be prepared: {ex.Message}");

            // Unlike low disk space, this is not recoverable at runtime: the server cannot
            // accept a single message without somewhere to put it.
            throw;
        }
    }

    private async Task MigrateAsync(CancellationToken cancellationToken)
    {
        // A scope, because the migrator and connection factory are scoped services and this
        // hosted service is a singleton.
        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        IDatabaseMigrator migrator = scope.ServiceProvider.GetRequiredService<IDatabaseMigrator>();
        IDbConnectionFactory factory = scope.ServiceProvider.GetRequiredService<IDbConnectionFactory>();

        logger.LogInformation("Database target: {Target}.", factory.DescribeTarget());

        if (!options.Value.Database.Migrations.RunOnStartup)
        {
            MigrationStatus status = await migrator
                .GetStatusAsync(cancellationToken)
                .ConfigureAwait(false);

            if (!status.IsUpToDate)
            {
                logger.LogCritical(
                    "The database is at schema version {CurrentVersion} but version " +
                    "{TargetVersion} is required, and RunOnStartup is disabled. The service " +
                    "cannot start against an out-of-date schema.",
                    status.CurrentVersion,
                    status.TargetVersion);

                health.Publish(
                    DatabaseComponent,
                    HealthState.Critical,
                    $"Schema is at version {status.CurrentVersion}; {status.TargetVersion} is required.");

                throw new InvalidOperationException(
                    $"The database schema is at version {status.CurrentVersion} but this build " +
                    $"requires {status.TargetVersion}. Enable " +
                    "MailServer:Database:Migrations:RunOnStartup, or apply the migrations " +
                    "manually before starting the service.");
            }

            health.Publish(
                DatabaseComponent,
                HealthState.Healthy,
                $"Schema is up to date at version {status.CurrentVersion}.");

            return;
        }

        try
        {
            MigrationRunResult result = await migrator
                .MigrateAsync(cancellationToken)
                .ConfigureAwait(false);

            if (result.AnythingApplied)
            {
                logger.LogInformation(
                    "Applied {Count} migration(s) in {ElapsedMs} ms: schema is now at version " +
                    "{ToVersion}.",
                    result.AppliedScripts.Count,
                    (long)result.Duration.TotalMilliseconds,
                    result.ToVersion);
            }

            health.Publish(
                DatabaseComponent,
                HealthState.Healthy,
                $"Schema is up to date at version {result.ToVersion}.");
        }
        catch (SchemaDriftException ex)
        {
            // The most operationally important failure in this class. The message names the
            // script and explains the remedy, because an operator hitting this at 3am needs
            // to know that editing an applied migration is the cause, not a symptom.
            logger.LogCritical(ex, "Schema drift detected. The service will not start.");

            health.Publish(DatabaseComponent, HealthState.Critical, ex.Message);
            throw;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Database migration failed. The service will not start.");

            health.Publish(
                DatabaseComponent,
                HealthState.Critical,
                $"Migration failed: {ex.Message}");

            throw;
        }
    }
}
