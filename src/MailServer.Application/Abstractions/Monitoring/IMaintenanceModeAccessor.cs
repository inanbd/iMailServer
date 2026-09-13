using MailServer.Domain.Enums;

namespace MailServer.Application.Abstractions.Monitoring;

/// <summary>
/// The server's current operating mode.
/// </summary>
/// <remarks>
/// Read by every background worker on each iteration so that pausing outbound delivery takes
/// effect without restarting the service. Held in memory and persisted, so the mode survives
/// a restart - an operator who paused outbound delivery to investigate a reputation problem
/// would not thank the server for resuming it on its own after a reboot.
/// </remarks>
public interface IMaintenanceModeAccessor
{
    /// <summary>The current mode.</summary>
    MaintenanceMode Current { get; }

    /// <summary>True when inbound listeners should accept mail.</summary>
    bool IsInboundEnabled { get; }

    /// <summary>True when the queue should attempt outbound delivery.</summary>
    bool IsOutboundEnabled { get; }

    /// <summary>True when administrative writes are permitted.</summary>
    bool AreAdministrativeWritesEnabled { get; }

    /// <summary>Changes the mode. Audited by the caller.</summary>
    Task SetAsync(MaintenanceMode mode, CancellationToken cancellationToken);
}
