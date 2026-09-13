using Dapper;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Enums;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Monitoring;

/// <summary>
/// Holds and persists the server's operating mode.
/// </summary>
/// <remarks>
/// <para>
/// Kept in memory for the read path, because every background worker consults it on each
/// iteration and a database round trip per iteration would be absurd. Persisted on write, so
/// the mode survives a restart: an operator who paused outbound delivery to investigate a
/// reputation problem would not thank the server for silently resuming it after a reboot.
/// </para>
/// <para>
/// Singleton. The configured mode is only a fallback for a fresh installation; the persisted
/// value always wins.
/// </para>
/// </remarks>
public sealed class MaintenanceModeAccessor(
    IDbConnectionFactory connectionFactory,
    IClock clock,
    IOptions<MailServerOptions> options,
    ILogger<MaintenanceModeAccessor> logger) : IMaintenanceModeAccessor
{
    private const string SettingKey = "Maintenance.Mode";

    private volatile int _current = (int)MaintenanceMode.Normal;

    public MaintenanceMode Current => (MaintenanceMode)_current;

    public bool IsInboundEnabled => Current is MaintenanceMode.Normal or MaintenanceMode.OutboundPaused;

    public bool IsOutboundEnabled => Current is MaintenanceMode.Normal
                                              or MaintenanceMode.InboundPaused
                                              or MaintenanceMode.QueueOnly;

    public bool AreAdministrativeWritesEnabled =>
        Current is not (MaintenanceMode.ReadOnly or MaintenanceMode.FullMaintenance);

    /// <summary>
    /// Loads the persisted mode at startup, falling back to configuration on a fresh install.
    /// </summary>
    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        MaintenanceMode configured =
            Enum.TryParse(options.Value.Maintenance.Mode, ignoreCase: true, out MaintenanceMode parsed)
                ? parsed
                : MaintenanceMode.Normal;

        try
        {
            await using System.Data.Common.DbConnection connection = await connectionFactory
                .OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);

            string? stored = await connection.ExecuteScalarAsync<string?>(new CommandDefinition(
                "SELECT SettingValue FROM ServerSettings WHERE SettingKey = @Key",
                new { Key = SettingKey },
                cancellationToken: cancellationToken)).ConfigureAwait(false);

            if (stored is not null &&
                Enum.TryParse(stored, ignoreCase: true, out MaintenanceMode persisted))
            {
                _current = (int)persisted;

                if (persisted != MaintenanceMode.Normal)
                {
                    // Loud on purpose: an operator seeing mail not flowing after a restart
                    // must find the reason in the first page of the log.
                    logger.LogWarning(
                        "Server started in {MaintenanceMode} mode, restored from the previous " +
                        "session. Mail flow is restricted until the mode is set back to Normal.",
                        persisted);
                }

                return;
            }

            _current = (int)configured;

            await PersistAsync(configured, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Falling back to the configured mode is correct here: refusing to start because
            // a settings row could not be read would be a worse outcome than starting in the
            // administrator's declared default.
            logger.LogError(
                ex,
                "Could not read the persisted maintenance mode; falling back to the configured " +
                "value {ConfiguredMode}.",
                configured);

            _current = (int)configured;
        }
    }

    public async Task SetAsync(MaintenanceMode mode, CancellationToken cancellationToken)
    {
        MaintenanceMode previous = Current;
        _current = (int)mode;

        await PersistAsync(mode, cancellationToken).ConfigureAwait(false);

        logger.LogWarning(
            "Maintenance mode changed from {PreviousMode} to {NewMode}.",
            previous,
            mode);
    }

    private async Task PersistAsync(MaintenanceMode mode, CancellationToken cancellationToken)
    {
        await using System.Data.Common.DbConnection connection = await connectionFactory
            .OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        // UPDATE-then-INSERT rather than a provider-specific upsert. Two short statements
        // are portable between SQLite and SQL Server, and this runs at most a handful of
        // times per server lifetime, so the extra round trip costs nothing worth optimising.
        int updated = await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE ServerSettings SET SettingValue = @Value, ModifiedUtc = @Now WHERE SettingKey = @Key",
            new { Key = SettingKey, Value = mode.ToString(), Now = clock.UtcNow },
            cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (updated == 0)
        {
            await connection.ExecuteAsync(new CommandDefinition(
                "INSERT INTO ServerSettings (SettingKey, SettingValue, ModifiedUtc) VALUES (@Key, @Value, @Now)",
                new { Key = SettingKey, Value = mode.ToString(), Now = clock.UtcNow },
                cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
    }
}
