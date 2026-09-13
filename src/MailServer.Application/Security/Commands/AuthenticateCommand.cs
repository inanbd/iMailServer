using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Exceptions;
using MailServer.Application.Security.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Security.Commands;

/// <summary>
/// Authenticates an administrator and issues a session.
/// </summary>
/// <remarks>
/// <para>
/// <b>Deliberately not <c>ITransactionalRequest</c>, and this is a security property rather
/// than an optimisation.</b> A failed attempt increments the persisted failure counter and
/// then throws, and <c>TransactionBehavior</c> rolls back on exception — so wrapping this
/// command in a transaction would discard the very increment that drives lockout. The counter
/// would never reach the threshold, and brute-force protection would be silently inert while
/// appearing, in code and in configuration, to be present.
/// </para>
/// <para>
/// Nothing here needs a transaction anyway: every path performs at most one row update. The
/// session lives in memory and security events are buffered and flushed outside the request,
/// so there is no second write to stay consistent with.
/// </para>
/// </remarks>
public sealed record AuthenticateCommand : ICommand<AuthenticationResultDto>,
                                           IAuthorizedRequest,
                                           IAnonymousRequest
{
    /// <summary>The master password. Never logged, never audited, never echoed.</summary>
    public required string Password { get; init; }

    public string? Origin { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.None;

    // Deliberately NOT IAuditableRequest. Sign-in attempts belong in the security event log,
    // which is written out of band and therefore survives the rollback of a failed attempt.
    // An audit record inside this transaction would be rolled back along with the failure it
    // was recording.
}

internal sealed class AuthenticateCommandHandler(
    IAdminAccountRepository accounts,
    IPasswordHasher passwordHasher,
    IAdminSessionManager sessions,
    ISecurityEventRecorder securityEvents,
    ISecuritySettings settings,
    IClock clock,
    ILogger<AuthenticateCommandHandler> logger)
    : IRequestHandler<AuthenticateCommand, AuthenticationResultDto>
{
    /// <summary>
    /// The single message returned for every authentication failure.
    /// </summary>
    /// <remarks>
    /// Identical whether the account does not exist, the password is wrong, or the stored hash
    /// is corrupt. Distinguishable messages are an enumeration oracle — the caller learns which
    /// of those three is true, and "the account exists but the password is wrong" is exactly
    /// what an attacker wants confirmed.
    /// </remarks>
    private const string GenericFailureMessage =
        "The master password is not correct.";

    public async Task<AuthenticationResultDto> Handle(
        AuthenticateCommand request,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;

        AdminAccount? account = await accounts
            .GetBuiltInAsync(cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            // No account: still spend the Argon2 cost, so "not set up" and "wrong password"
            // cannot be told apart by how long the call took.
            passwordHasher.VerifyAgainstDummy(request.Password);

            await RecordFailureAsync(
                request,
                subject: null,
                "A sign-in was attempted before setup had been completed.",
                cancellationToken).ConfigureAwait(false);

            throw new AuthenticationFailedException(GenericFailureMessage);
        }

        // Checked BEFORE verifying, so a locked-out attacker cannot keep the server busy
        // doing Argon2 work. This does make a locked-out attempt observably faster, which is
        // acceptable: lockout state is not a secret, and the setup-status query reports it.
        if (account.IsLockedOut(now))
        {
            TimeSpan remaining = account.GetRemainingLockout(now);

            await securityEvents.RecordAsync(
                SecurityEventType.AdminSignInBlockedByLockout,
                account.Name,
                request.Origin,
                $"A sign-in was refused: the account is locked for a further " +
                $"{(int)remaining.TotalMinutes} minute(s).",
                cancellationToken).ConfigureAwait(false);

            throw new AccountLockedOutException(remaining);
        }

        PasswordVerificationResult verification =
            passwordHasher.Verify(request.Password, account.PasswordHash);

        if (!verification.IsValid)
        {
            bool nowLocked = account.RecordFailedSignIn(settings.LockoutPolicy, now);

            await accounts.UpdateAsync(account, cancellationToken).ConfigureAwait(false);

            await RecordFailureAsync(
                request,
                account.Name,
                nowLocked
                    ? $"Sign-in failed and the account is now locked after " +
                      $"{account.ConsecutiveFailures} consecutive failures."
                    : "Sign-in failed: the password did not match.",
                cancellationToken).ConfigureAwait(false);

            if (nowLocked)
            {
                logger.LogWarning(
                    "Administrator account locked after {FailureCount} consecutive failures.",
                    account.ConsecutiveFailures);

                await securityEvents.RecordAsync(
                    SecurityEventType.AdminAccountLockedOut,
                    account.Name,
                    request.Origin,
                    $"The account was locked until {account.LockedOutUntilUtc:u} after " +
                    $"{account.ConsecutiveFailures} consecutive failures.",
                    cancellationToken).ConfigureAwait(false);

                throw new AccountLockedOutException(account.GetRemainingLockout(now));
            }

            throw new AuthenticationFailedException(GenericFailureMessage);
        }

        // Successful. Upgrade the stored verifier if the work factors have since been raised —
        // this is the only moment the plaintext is available to rehash with.
        if (verification.NeedsRehash)
        {
            account.UpgradePasswordHash(passwordHasher.Hash(request.Password));

            logger.LogInformation(
                "The stored password verifier was upgraded to current work factors.");
        }

        account.RecordSuccessfulSignIn(now);
        await accounts.UpdateAsync(account, cancellationToken).ConfigureAwait(false);

        (AdminSession session, string token) = await sessions.CreateAsync(
            account.Name,
            account.Permissions,
            request.Origin,
            account.MustChangePassword,
            cancellationToken).ConfigureAwait(false);

        await securityEvents.RecordAsync(
            SecurityEventType.AdminSignInSucceeded,
            account.Name,
            request.Origin,
            "Signed in successfully.",
            cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Administrator {Administrator} signed in.", account.Name);

        return new AuthenticationResultDto
        {
            SessionToken = token,
            SessionId = session.Id.Value,
            Administrator = session.Administrator,
            Permissions = session.Permissions,
            ExpiresUtc = session.AbsoluteExpiryUtc,
            IdleTimeoutSeconds = (int)settings.SessionIdleTimeout.TotalSeconds,
            MustChangePassword = account.MustChangePassword,
        };
    }

    private Task RecordFailureAsync(
        AuthenticateCommand request,
        string? subject,
        string description,
        CancellationToken cancellationToken) =>
        securityEvents.RecordAsync(
            SecurityEventType.AdminSignInFailed,
            subject,
            request.Origin,
            description,
            cancellationToken);
}
