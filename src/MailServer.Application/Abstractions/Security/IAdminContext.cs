using MailServer.Domain.Enums;

namespace MailServer.Application.Abstractions.Security;

/// <summary>
/// The administrative identity on whose behalf the current request is running.
/// </summary>
/// <remarks>
/// <para>
/// Milestone 1 supplies this from the authenticated Windows identity on the far end of the
/// named pipe. Milestone 2 replaces it with a master-password session, without any handler
/// changing: handlers depend on this interface, never on how identity was established.
/// </para>
/// <para>
/// Requests originating inside the service itself (background workers, the migration
/// bootstrapper) run as the system context, which holds <see cref="AdminPermission.FullControl"/>
/// but is recorded distinctly in the audit trail so that a human action and a scheduled one
/// are never confused.
/// </para>
/// </remarks>
public interface IAdminContext
{
    /// <summary>Display name of the acting administrator, or the system identity.</summary>
    string Administrator { get; }

    /// <summary>Administrative session identifier, if the action came from an interactive session.</summary>
    string? SessionIdentifier { get; }

    /// <summary>True when this is an internal system action rather than a human one.</summary>
    bool IsSystem { get; }

    /// <summary>True when the session is authenticated and not locked.</summary>
    bool IsAuthenticated { get; }

    /// <summary>Permissions held by this identity.</summary>
    AdminPermission Permissions { get; }

    /// <summary>
    /// True when this identity must change its password before doing anything else.
    /// </summary>
    /// <remarks>
    /// Set after a recovery-key reset. The authorization behavior refuses every request except
    /// those marked <see cref="Messaging.IAllowedWhenPasswordChangeRequired"/>, so a recovery
    /// key grants a path back in rather than a standing bypass of the password.
    /// </remarks>
    bool MustChangePassword { get; }

    /// <summary>True when every bit in <paramref name="permission"/> is held.</summary>
    bool HasPermission(AdminPermission permission);
}
