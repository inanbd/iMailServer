using MailServer.Application.Abstractions.Security;
using MailServer.Domain.Enums;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// The identity used by work the service initiates itself: migrations at startup, queue
/// processing, certificate renewal, scheduled backups.
/// </summary>
/// <remarks>
/// Holds <see cref="AdminPermission.FullControl"/> because these operations genuinely need
/// it, but reports <see cref="IsSystem"/> so the audit trail distinguishes "the scheduler
/// renewed a certificate" from "a human renewed a certificate". Conflating the two makes an
/// audit trail far less useful during an incident review.
/// </remarks>
public sealed class SystemAdminContext : IAdminContext
{
    /// <summary>The name recorded in the audit trail for service-initiated work.</summary>
    public const string SystemAdministratorName = "SYSTEM (AetherMail Service)";

    public string Administrator => SystemAdministratorName;

    public string? SessionIdentifier => null;

    public bool IsSystem => true;

    public bool IsAuthenticated => true;

    public AdminPermission Permissions => AdminPermission.FullControl;

    /// <summary>Always false: service-initiated work never owes a password change.</summary>
    public bool MustChangePassword => false;

    public bool HasPermission(AdminPermission permission) =>
        (Permissions & permission) == permission;
}

/// <summary>
/// A scoped admin context whose identity is supplied by the IPC layer once the caller has
/// been authenticated.
/// </summary>
/// <remarks>
/// <para>
/// Starts <b>unauthenticated with no permissions</b>. That default matters: if the IPC layer
/// ever fails to call <see cref="Assign"/> - a bug, a new code path, a refactor - the
/// authorization behavior denies every request rather than granting them. The failure mode
/// of forgetting to authenticate is "nothing works", not "everything is permitted".
/// </para>
/// <para>
/// Milestone 1 populates this from the authenticated Windows identity on the far end of the
/// named pipe. Milestone 2 replaces that with a master-password session, without any handler
/// changing.
/// </para>
/// </remarks>
public sealed class MutableAdminContext : IAdminContext, IAdminContextInitializer
{
    public string Administrator { get; private set; } = "(unauthenticated)";

    public string? SessionIdentifier { get; private set; }

    public bool IsSystem { get; private set; }

    public bool IsAuthenticated { get; private set; }

    public AdminPermission Permissions { get; private set; } = AdminPermission.None;

    /// <summary>
    /// True when this identity must change its password before anything else is permitted.
    /// </summary>
    /// <remarks>
    /// Carried from the session rather than re-read from the account on every request, so a
    /// single database read at sign-in decides it for the session's lifetime.
    /// </remarks>
    public bool MustChangePassword { get; private set; }

    /// <summary>Populates the context after the caller has been authenticated.</summary>
    public void Assign(
        string administrator,
        string? sessionIdentifier,
        AdminPermission permissions,
        bool isSystem = false,
        bool mustChangePassword = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(administrator);

        Administrator = administrator;
        SessionIdentifier = sessionIdentifier;
        Permissions = permissions;
        IsSystem = isSystem;
        MustChangePassword = mustChangePassword;
        IsAuthenticated = true;
    }

    public bool HasPermission(AdminPermission permission) =>
        IsAuthenticated && (Permissions & permission) == permission;
}
