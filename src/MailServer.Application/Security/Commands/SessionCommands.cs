using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Security;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Security.Commands;

/// <summary>
/// Ends the calling session.
/// </summary>
/// <remarks>
/// Permitted while a password change is outstanding: an administrator who reset with a
/// recovery key and then thought better of it must be able to leave.
/// </remarks>
public sealed record SignOutCommand : ICommand<Unit>,
                                      IAuthorizedRequest,
                                      IAllowedWhenPasswordChangeRequired
{
    /// <summary>
    /// True when the console is locking rather than signing out.
    /// </summary>
    /// <remarks>
    /// The server-side effect is identical — the session is revoked either way. It is recorded
    /// because "locked by idle timeout" and "deliberately signed out" tell an operator
    /// different things when reading the security log.
    /// </remarks>
    public bool IsAutoLock { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.None;
}

internal sealed class SignOutCommandHandler(
    IAdminSessionManager sessions,
    ISecurityEventRecorder securityEvents,
    IAdminContext adminContext,
    ILogger<SignOutCommandHandler> logger) : IRequestHandler<SignOutCommand, Unit>
{
    public async Task<Unit> Handle(SignOutCommand request, CancellationToken cancellationToken)
    {
        if (AdminSessionId.TryParseIdentifier(adminContext.SessionIdentifier, out AdminSessionId id))
        {
            await sessions.RevokeAsync(id, cancellationToken).ConfigureAwait(false);
        }

        await securityEvents.RecordAsync(
            request.IsAutoLock
                ? SecurityEventType.AdminSessionExpired
                : SecurityEventType.AdminSignedOut,
            adminContext.Administrator,
            adminContext.SessionIdentifier,
            request.IsAutoLock
                ? "The console locked itself after a period of inactivity."
                : "Signed out.",
            cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "{Administrator} {Action}.",
            adminContext.Administrator,
            request.IsAutoLock ? "was locked out by inactivity" : "signed out");

        return Unit.Value;
    }
}

/// <summary>Revokes another administrative session.</summary>
public sealed record RevokeSessionCommand : ICommand<Unit>,
                                            IAuditableRequest,
                                            IAuthorizedRequest
{
    public required Guid SessionId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageSecurity;

    public AuditDescriptor DescribeForAudit() =>
        new("Security.RevokeSession", "AdminSession", SessionId.ToString());
}

internal sealed class RevokeSessionCommandHandler(
    IAdminSessionManager sessions,
    ISecurityEventRecorder securityEvents,
    IAdminContext adminContext) : IRequestHandler<RevokeSessionCommand, Unit>
{
    public async Task<Unit> Handle(RevokeSessionCommand request, CancellationToken cancellationToken)
    {
        bool revoked = await sessions
            .RevokeAsync(new AdminSessionId(request.SessionId), cancellationToken)
            .ConfigureAwait(false);

        await securityEvents.RecordAsync(
            SecurityEventType.AdminSessionRevoked,
            adminContext.Administrator,
            adminContext.SessionIdentifier,
            revoked
                ? $"Session {request.SessionId:D} was revoked."
                : $"Revocation was requested for session {request.SessionId:D}, which was not active.",
            cancellationToken).ConfigureAwait(false);

        return Unit.Value;
    }
}
