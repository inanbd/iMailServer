namespace MailServer.Domain.Enums;

/// <summary>
/// Coarse operating mode for the whole server, surfaced prominently in the admin UI.
/// </summary>
public enum MaintenanceMode
{
    /// <summary>All subsystems operating.</summary>
    Normal = 0,

    /// <summary>
    /// Inbound receipt continues; outbound delivery is paused and queued. Used while
    /// investigating a reputation problem or a misconfiguration, so that nothing further
    /// leaves the server.
    /// </summary>
    OutboundPaused = 1,

    /// <summary>
    /// Outbound delivery continues; inbound listeners return a temporary failure so that
    /// senders retry rather than bounce. Used during storage maintenance.
    /// </summary>
    InboundPaused = 2,

    /// <summary>Only the queue processor runs. Listeners are stopped.</summary>
    QueueOnly = 3,

    /// <summary>
    /// Mail is served for reading but nothing mutates: no delivery, no submission,
    /// no administrative writes. Used while a backup is verified.
    /// </summary>
    ReadOnly = 4,

    /// <summary>
    /// Everything except administration is stopped. Used for database migration and
    /// restore operations.
    /// </summary>
    FullMaintenance = 5,
}
