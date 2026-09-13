using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Exceptions;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Security.Commands;

/// <summary>
/// Changes the master password, re-proving knowledge of the current one.
/// </summary>
/// <remarks>
/// Permitted while a password change is outstanding — that is the whole point of the
/// <see cref="IAllowedWhenPasswordChangeRequired"/> marker.
/// </remarks>
public sealed record ChangeMasterPasswordCommand : ICommand<Unit>,
                                                   ITransactionalRequest,
                                                   IAuditableRequest,
                                                   IAuthorizedRequest,
                                                   IAllowedWhenPasswordChangeRequired
{
    /// <summary>The current password, re-entered.</summary>
    public required string CurrentPassword { get; init; }

    public required string NewPassword { get; init; }

    public required string ConfirmNewPassword { get; init; }

    /// <summary>
    /// When true, other sessions are left alone.
    /// </summary>
    /// <remarks>
    /// Defaults to false so that every other session is revoked, which is what an
    /// administrator changing a password after a suspected compromise actually wants. Offered
    /// as an opt-out rather than an opt-in for exactly that reason.
    /// </remarks>
    public bool KeepOtherSessions { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCredentials;

    public AuditDescriptor DescribeForAudit() =>
        new("Security.ChangeMasterPassword",
            nameof(AdminAccount),
            AdminAccount.BuiltInAdministratorName,
            // Records that it happened and what it implied. Never any part of either password.
            "The master password was changed.");
}

internal sealed class ChangeMasterPasswordCommandHandler(
    IAdminAccountRepository accounts,
    IPasswordHasher passwordHasher,
    IAdminSessionManager sessions,
    ISecurityEventRecorder securityEvents,
    IAdminContext adminContext,
    ISecuritySettings settings,
    IClock clock,
    ILogger<ChangeMasterPasswordCommandHandler> logger)
    : IRequestHandler<ChangeMasterPasswordCommand, Unit>
{
    public async Task<Unit> Handle(
        ChangeMasterPasswordCommand request,
        CancellationToken cancellationToken)
    {
        AdminAccount account = await accounts
            .GetBuiltInAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new EntityNotFoundException(
                nameof(AdminAccount),
                AdminAccount.BuiltInAdministratorName);

        // Re-proving the current password matters even though the caller already holds a valid
        // session: it is what stops an unattended, unlocked console from being used to lock
        // the real administrator out of their own server.
        if (!passwordHasher.Verify(request.CurrentPassword, account.PasswordHash).IsValid)
        {
            await securityEvents.RecordAsync(
                SecurityEventType.AdminSignInFailed,
                account.Name,
                adminContext.SessionIdentifier,
                "A password change was refused: the current password was not correct.",
                cancellationToken).ConfigureAwait(false);

            throw new AuthenticationFailedException("The current password is not correct.");
        }

        PasswordEvaluation evaluation =
            new PasswordPolicy(settings.MinimumPasswordLength).Evaluate(request.NewPassword);

        if (!evaluation.IsAcceptable)
        {
            throw new DomainRuleViolationException(
                "security.password.unacceptable",
                string.Join(" ", evaluation.Failures));
        }

        // Compared in plaintext here rather than by hash: Argon2 salts each hash, so two
        // hashes of the same password never match. The aggregate's own verifier-equality check
        // catches the degenerate case where an identical hash is somehow supplied.
        if (string.Equals(request.CurrentPassword, request.NewPassword, StringComparison.Ordinal))
        {
            throw new DomainRuleViolationException(
                "admin.password.unchanged",
                "The new password must differ from the current one.");
        }

        account.ChangePassword(passwordHasher.Hash(request.NewPassword), clock.UtcNow);

        await accounts.UpdateAsync(account, cancellationToken).ConfigureAwait(false);

        if (!request.KeepOtherSessions)
        {
            // Every session, including this one. The client re-authenticates immediately with
            // the new password. Leaving the current session alive would require carving an
            // exception into the revoke path, and an exception in a "revoke everything" path
            // is exactly where a lingering intruder session would survive.
            int revoked = await sessions.RevokeAllAsync(cancellationToken).ConfigureAwait(false);

            logger.LogInformation(
                "Revoked {SessionCount} session(s) following a master password change.",
                revoked);
        }

        await securityEvents.RecordAsync(
            SecurityEventType.MasterPasswordChanged,
            account.Name,
            adminContext.SessionIdentifier,
            request.KeepOtherSessions
                ? "The master password was changed; other sessions were left active."
                : "The master password was changed and all sessions were revoked.",
            cancellationToken).ConfigureAwait(false);

        logger.LogWarning("The master password was changed by {Administrator}.", account.Name);

        return Unit.Value;
    }
}
