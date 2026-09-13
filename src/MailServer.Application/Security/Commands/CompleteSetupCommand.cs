using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
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
/// Creates the master password on first run and returns a signed-in session plus the recovery
/// key.
/// </summary>
/// <remarks>
/// <para>
/// Anonymous by necessity: there is no account to authenticate against yet. The safety comes
/// from the handler refusing outright once an account exists, so this cannot be replayed later
/// to seize the server.
/// </para>
/// <para>
/// The recovery key is generated here, shown once, and stored only as an Argon2id hash.
/// Nothing in the product can display it again.
/// </para>
/// </remarks>
public sealed record CompleteSetupCommand : ICommand<SetupResultDto>,
                                            ITransactionalRequest,
                                            IAuditableRequest,
                                            IAuthorizedRequest,
                                            IAnonymousRequest
{
    /// <summary>The master password. Never logged, never audited, never echoed.</summary>
    public required string Password { get; init; }

    /// <summary>Repeat of the password, checked by the validator.</summary>
    public required string ConfirmPassword { get; init; }

    /// <summary>Where the request came from, for the security event.</summary>
    public string? Origin { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.None;

    /// <summary>
    /// Records that setup happened, and nothing about what was chosen.
    /// </summary>
    /// <remarks>
    /// The descriptor is hand-written precisely so that adding <see cref="Password"/> to this
    /// record could never start writing it to the audit table.
    /// </remarks>
    public AuditDescriptor DescribeForAudit() =>
        new("Security.CompleteSetup",
            nameof(AdminAccount),
            AdminAccount.BuiltInAdministratorName,
            "Master password created and recovery key issued.");
}

internal sealed class CompleteSetupCommandHandler(
    IAdminAccountRepository accounts,
    IPasswordHasher passwordHasher,
    IAdminSessionManager sessions,
    ISecurityEventRecorder securityEvents,
    IRecoveryKeyGenerator recoveryKeys,
    ISecuritySettings settings,
    IClock clock,
    ILogger<CompleteSetupCommandHandler> logger)
    : IRequestHandler<CompleteSetupCommand, SetupResultDto>
{
    public async Task<SetupResultDto> Handle(
        CompleteSetupCommand request,
        CancellationToken cancellationToken)
    {
        // The gate that makes an anonymous command safe. Without it, anyone reaching the pipe
        // could re-run setup and take ownership of a configured server.
        if (await accounts.AnyAsync(cancellationToken).ConfigureAwait(false))
        {
            await securityEvents.RecordAsync(
                SecurityEventType.AuthorizationDenied,
                subject: null,
                request.Origin,
                "Setup was attempted but an administrator account already exists.",
                cancellationToken).ConfigureAwait(false);

            throw new DomainRuleViolationException(
                "security.setup.already_completed",
                "Setup has already been completed for this server. Sign in with the existing " +
                "master password, or use the recovery key if it has been lost.");
        }

        PasswordEvaluation evaluation = new PasswordPolicy(
            PasswordPolicy.MinimumMasterPasswordLength).Evaluate(request.Password);

        if (!evaluation.IsAcceptable)
        {
            throw new DomainRuleViolationException(
                "security.password.unacceptable",
                string.Join(" ", evaluation.Failures));
        }

        string recoveryKey = recoveryKeys.Generate();

        DateTimeOffset now = clock.UtcNow;

        AdminAccount account = AdminAccount.Create(
            AdminAccountId.New(),
            AdminAccount.BuiltInAdministratorName,
            passwordHasher.Hash(request.Password),
            passwordHasher.Hash(PasswordPolicy.NormalizeRecoveryKey(recoveryKey)),
            now);

        await accounts.AddAsync(account, cancellationToken).ConfigureAwait(false);

        (AdminSession session, string token) = await sessions.CreateAsync(
            account.Name,
            account.Permissions,
            request.Origin,
            mustChangePassword: false,
            cancellationToken).ConfigureAwait(false);

        await securityEvents.RecordAsync(
            SecurityEventType.MasterPasswordCreated,
            account.Name,
            request.Origin,
            "The master password was created and a recovery key was issued.",
            cancellationToken).ConfigureAwait(false);

        logger.LogWarning(
            "First-run setup completed: the master password was created for {Administrator}.",
            account.Name);

        return new SetupResultDto
        {
            Authentication = new AuthenticationResultDto
            {
                SessionToken = token,
                SessionId = session.Id.Value,
                Administrator = session.Administrator,
                Permissions = session.Permissions,
                ExpiresUtc = session.AbsoluteExpiryUtc,
                IdleTimeoutSeconds = (int)settings.SessionIdleTimeout.TotalSeconds,
                MustChangePassword = false,
            },
            RecoveryKey = new RecoveryKeyDto
            {
                // The only moment this exists in plaintext outside the administrator's head.
                RecoveryKey = PasswordPolicy.FormatRecoveryKey(recoveryKey),
                IssuedUtc = now,
            },
        };
    }
}
