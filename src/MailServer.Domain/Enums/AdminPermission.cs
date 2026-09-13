namespace MailServer.Domain.Enums;

/// <summary>
/// Permissions that an administrative session may hold.
/// </summary>
/// <remarks>
/// <para>
/// Every IPC-reachable request declares the permission it requires, and
/// <c>AuthorizationBehavior</c> enforces it. Milestone 1 ships a single administrator
/// identity holding <see cref="FullControl"/>; the enumeration exists from the start so that
/// Milestone 2 fills in identity rather than retrofitting enforcement onto handlers that
/// never had it.
/// </para>
/// <para>
/// Flags rather than a role hierarchy, because a future delegated-administration model
/// ("this operator may manage mailboxes but not certificates") is a permission set, not a
/// rank.
/// </para>
/// </remarks>
[Flags]
public enum AdminPermission
{
    None = 0,

    /// <summary>Read dashboards, listings and diagnostics.</summary>
    ViewServerState = 1 << 0,

    /// <summary>Create, modify and remove hosted domains.</summary>
    ManageDomains = 1 << 1,

    /// <summary>Create, modify and remove mailboxes and aliases.</summary>
    ManageMailboxes = 1 << 2,

    /// <summary>Reset mailbox passwords.</summary>
    ManageCredentials = 1 << 3,

    /// <summary>Retry, pause and cancel queued mail.</summary>
    ManageQueue = 1 << 4,

    /// <summary>Generate, import, renew and bind TLS certificates.</summary>
    ManageCertificates = 1 << 5,

    /// <summary>Generate and rotate DKIM keys.</summary>
    ManageDkim = 1 << 6,

    /// <summary>Change server configuration, listeners and limits.</summary>
    ManageServerConfiguration = 1 << 7,

    /// <summary>Manage IP rules, rate limits and anti-abuse policy.</summary>
    ManageSecurity = 1 << 8,

    /// <summary>Read the audit trail and security events.</summary>
    ViewAuditLog = 1 << 9,

    /// <summary>Create, restore and verify backups.</summary>
    ManageBackups = 1 << 10,

    /// <summary>Run database migrations and provider changes.</summary>
    ManageDatabase = 1 << 11,

    /// <summary>Read the content of quarantined and stored messages.</summary>
    ReadMessageContent = 1 << 12,

    /// <summary>Every permission. Held by the built-in administrator.</summary>
    FullControl = ViewServerState | ManageDomains | ManageMailboxes | ManageCredentials |
                  ManageQueue | ManageCertificates | ManageDkim | ManageServerConfiguration |
                  ManageSecurity | ViewAuditLog | ManageBackups | ManageDatabase |
                  ReadMessageContent,
}
