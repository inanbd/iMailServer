using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Exceptions;
using MailServer.Application.Security.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Security.Commands;

/// <summary>
/// Resets the master password using the recovery key, for an administrator who has lost it.
/// </summary>
/// <remarks>
/// <para>
/// Anonymous by necessity — the whole point is that the password is unavailable. The recovery
/// key is the credential, and it is verified with the same Argon2id cost as a password.
/// </para>
/// <para>
/// <b>Bypasses lockout deliberately.</b> An attacker who has locked the account out must not
/// thereby also deny the legitimate administrator their recovery route. The recovery key is
/// 25 characters of cryptographic randomness, so guessing it is not a realistic threat, and a
/// failed attempt is recorded as alarming.
/// </para>
/// <para>
/// The key is single-use. A replacement is issued in the same transaction, so the installation
/// is never left without one.
/// </para>
/// </remarks>
public sealed record ResetPasswordWithRecoveryKeyCommand : ICommand<RecoveryKeyDto>,
                                                           ITransactionalRequest,
                                                           IAuditableRequest,
                                                           IAuthorizedRequest,
                                                           IAnonymousRequest
{
    /// <summary>The recovery key, with or without its display hyphens.</summary>
    public required string RecoveryKey { get; init; }

    public required string NewPassword { get; init; }

    public required string ConfirmNewPassword { get; init; }

    public string? Origin { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.None;

    public AuditDescriptor DescribeForAudit() =>
        new("Security.ResetPasswordWithRecoveryKey",
            nameof(AdminAccount),
            AdminAccount.BuiltInAdministratorName,
            "The master password was reset using the recovery key.");
}

internal sealed class ResetPasswordWithRecoveryKeyCommandHandler(
    IAdminAccountRepository accounts,
    IPasswordHasher passwordHasher,
    IAdminSessionManager sessions,
    ISecurityEventRecorder securityEvents,
    IRecoveryKeyGenerator recoveryKeys,
    ISecuritySettings settings,
    IClock clock,
    ILogger<ResetPasswordWithRecoveryKeyCommandHandler> logger)
    : IRequestHandler<ResetPasswordWithRecoveryKeyCommand, RecoveryKeyDto>
{
    private const string GenericFailureMessage = "The recovery key is not correct.";

    public async Task<RecoveryKeyDto> Handle(
        ResetPasswordWithRecoveryKeyCommand request,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;

        AdminAccount? account = await accounts
            .GetBuiltInAsync(cancellationToken)
            .ConfigureAwait(false);

        if (account?.RecoveryKeyHash is null)
        {
            // Equal cost whether the account is missing or has no key, so the two cannot be
            // distinguished by timing.
            passwordHasher.VerifyAgainstDummy(request.RecoveryKey);

            await securityEvents.RecordAsync(
                SecurityEventType.RecoveryKeyRejected,
                account?.Name,
                request.Origin,
                "A recovery key was presented but none is available for this server.",
                cancellationToken).ConfigureAwait(false);

            throw new AuthenticationFailedException(GenericFailureMessage);
        }

        // Normalised so that a key typed with the display hyphens, without them, or in the
        // wrong case all verify. The hash was computed over the normalised form.
        string normalized = PasswordPolicy.NormalizeRecoveryKey(request.RecoveryKey);

        if (!passwordHasher.Verify(normalized, account.RecoveryKeyHash).IsValid)
        {
            await securityEvents.RecordAsync(
                SecurityEventType.RecoveryKeyRejected,
                account.Name,
                request.Origin,
                "A recovery key was presented and rejected.",
                cancellationToken).ConfigureAwait(false);

            logger.LogWarning(
                "A recovery key was presented and rejected from {Origin}.",
                request.Origin ?? "(unknown origin)");

            throw new AuthenticationFailedException(GenericFailureMessage);
        }

        PasswordEvaluation evaluation =
            new PasswordPolicy(settings.MinimumPasswordLength).Evaluate(request.NewPassword);

        if (!evaluation.IsAcceptable)
        {
            throw new DomainRuleViolationException(
                "security.password.unacceptable",
                string.Join(" ", evaluation.Failures));
        }

        // Consumes the key, clears the lockout and sets MustChangePassword.
        account.ResetPasswordWithRecoveryKey(passwordHasher.Hash(request.NewPassword), now);

        // Issue the replacement in the same transaction, so the server is never left with no
        // recovery route.
        string replacement = recoveryKeys.Generate();

        account.IssueRecoveryKey(
            passwordHasher.Hash(PasswordPolicy.NormalizeRecoveryKey(replacement)),
            now);

        await accounts.UpdateAsync(account, cancellationToken).ConfigureAwait(false);

        // Anyone holding a session at this point predates the recovery. If the reset is
        // happening because of a compromise, those are exactly the sessions to destroy.
        int revoked = await sessions.RevokeAllAsync(cancellationToken).ConfigureAwait(false);

        await securityEvents.RecordAsync(
            SecurityEventType.MasterPasswordResetWithRecoveryKey,
            account.Name,
            request.Origin,
            $"The master password was reset with the recovery key; {revoked} session(s) were " +
            "revoked and a replacement recovery key was issued.",
            cancellationToken).ConfigureAwait(false);

        logger.LogWarning(
            "The master password was reset using the recovery key from {Origin}. " +
            "{SessionCount} session(s) were revoked.",
            request.Origin ?? "(unknown origin)",
            revoked);

        return new RecoveryKeyDto
        {
            RecoveryKey = PasswordPolicy.FormatRecoveryKey(replacement),
            IssuedUtc = now,
        };
    }
}
