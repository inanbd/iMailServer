namespace MailServer.Domain.Enums;

/// <summary>Lifecycle state of a hosted mail domain.</summary>
/// <remarks>
/// Explicit numeric values are assigned throughout the Enums namespace because these are
/// persisted. Reordering members must never silently change the meaning of stored data.
/// </remarks>
public enum DomainStatus
{
    /// <summary>Created but not yet serving mail. DNS is typically still propagating.</summary>
    Pending = 0,

    /// <summary>Accepting inbound mail and permitting submission.</summary>
    Active = 1,

    /// <summary>
    /// Administratively disabled. Inbound mail is rejected with a permanent failure and
    /// submission is refused, but all mailboxes and stored mail are retained.
    /// </summary>
    Disabled = 2,

    /// <summary>
    /// Scheduled for removal. Retained so that queued mail can drain and so that an
    /// accidental deletion is recoverable within the retention window.
    /// </summary>
    PendingDeletion = 3,
}
