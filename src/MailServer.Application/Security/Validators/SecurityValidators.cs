using FluentValidation;
using MailServer.Application.Common;
using MailServer.Application.Security.Commands;
using MailServer.Application.Security.Queries;
using MailServer.Domain.Policies;

namespace MailServer.Application.Security.Validators;

/// <summary>
/// Shape checks only.
/// </summary>
/// <remarks>
/// <para>
/// Password <i>strength</i> is evaluated in the handler by <see cref="PasswordPolicy"/>, not
/// here. That is deliberate: a validation failure travels to the client as a per-field error,
/// and pushing strength rules through it would encourage the UI to re-implement them for live
/// feedback — producing two definitions of an acceptable password that will eventually
/// disagree.
/// </para>
/// <para>
/// What these validators do enforce is the bound on input length, which must happen
/// <b>before</b> the handler, because an unbounded field would let an unauthenticated caller
/// spend the server's Argon2 budget on a megabyte-long "password".
/// </para>
/// </remarks>
public sealed class CompleteSetupCommandValidator : AbstractValidator<CompleteSetupCommand>
{
    public CompleteSetupCommandValidator()
    {
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("A master password is required.")
            .MaximumLength(PasswordPolicy.MaximumLength)
            .WithMessage($"The password must be no more than {PasswordPolicy.MaximumLength} characters.");

        RuleFor(x => x.ConfirmPassword)
            .Equal(x => x.Password)
            .WithMessage("The passwords do not match.");
    }
}

public sealed class AuthenticateCommandValidator : AbstractValidator<AuthenticateCommand>
{
    public AuthenticateCommandValidator() =>
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("A password is required.")

            // Bounds the Argon2 work an unauthenticated caller can request. Deliberately not a
            // strength rule: rejecting a wrong password for being too short would confirm that
            // the real one is longer.
            .MaximumLength(PasswordPolicy.MaximumLength)
            .WithMessage("The password is too long.");
}

public sealed class ChangeMasterPasswordCommandValidator
    : AbstractValidator<ChangeMasterPasswordCommand>
{
    public ChangeMasterPasswordCommandValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage("The current password is required.")
            .MaximumLength(PasswordPolicy.MaximumLength);

        RuleFor(x => x.NewPassword)
            .NotEmpty().WithMessage("A new password is required.")
            .MaximumLength(PasswordPolicy.MaximumLength);

        RuleFor(x => x.ConfirmNewPassword)
            .Equal(x => x.NewPassword)
            .WithMessage("The new passwords do not match.");
    }
}

public sealed class ResetPasswordWithRecoveryKeyCommandValidator
    : AbstractValidator<ResetPasswordWithRecoveryKeyCommand>
{
    public ResetPasswordWithRecoveryKeyCommandValidator()
    {
        RuleFor(x => x.RecoveryKey)
            .NotEmpty().WithMessage("The recovery key is required.")
            .MaximumLength(128).WithMessage("That is not a recovery key.");

        RuleFor(x => x.NewPassword)
            .NotEmpty().WithMessage("A new password is required.")
            .MaximumLength(PasswordPolicy.MaximumLength);

        RuleFor(x => x.ConfirmNewPassword)
            .Equal(x => x.NewPassword)
            .WithMessage("The new passwords do not match.");
    }
}

public sealed class RevokeSessionCommandValidator : AbstractValidator<RevokeSessionCommand>
{
    public RevokeSessionCommandValidator() => RuleFor(x => x.SessionId).NotEmpty();
}

public sealed class GetAuditLogQueryValidator : AbstractValidator<GetAuditLogQuery>
{
    public GetAuditLogQueryValidator()
    {
        RuleFor(x => x.Page).GreaterThanOrEqualTo(0);

        RuleFor(x => x.PageSize)
            .InclusiveBetween(1, PagedRequest.MaxPageSize)
            .WithMessage($"The page size must be between 1 and {PagedRequest.MaxPageSize}.");

        RuleFor(x => x.Action).MaximumLength(128);
        RuleFor(x => x.Administrator).MaximumLength(256);
        RuleFor(x => x.CorrelationId).MaximumLength(64);

        RuleFor(x => x.ToUtc)
            .GreaterThanOrEqualTo(x => x.FromUtc!.Value)
            .When(x => x.FromUtc.HasValue && x.ToUtc.HasValue)
            .WithMessage("The end of the range must not precede its start.");
    }
}

public sealed class GetSecurityEventsQueryValidator : AbstractValidator<GetSecurityEventsQuery>
{
    public GetSecurityEventsQueryValidator()
    {
        RuleFor(x => x.Page).GreaterThanOrEqualTo(0);

        RuleFor(x => x.PageSize)
            .InclusiveBetween(1, PagedRequest.MaxPageSize);

        RuleForEach(x => x.EventTypes)
            .IsInEnum()
            .WithMessage("Unknown security event type.")
            .When(x => x.EventTypes is { Count: > 0 });

        RuleFor(x => x.ToUtc)
            .GreaterThanOrEqualTo(x => x.FromUtc!.Value)
            .When(x => x.FromUtc.HasValue && x.ToUtc.HasValue)
            .WithMessage("The end of the range must not precede its start.");
    }
}
