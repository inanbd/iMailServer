using FluentValidation;
using MailServer.Application.Mailboxes.Commands;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Mailboxes.Validators;

/// <summary>Shape checks for mailbox creation.</summary>
/// <remarks>
/// Syntax only. Whether the address is already taken needs a database read and belongs in the
/// handler; validation runs before the transaction precisely so it does no I/O.
/// </remarks>
internal sealed class CreateMailboxCommandValidator : AbstractValidator<CreateMailboxCommand>
{
    public CreateMailboxCommandValidator()
    {
        RuleFor(c => c.DomainId).NotEmpty();

        RuleFor(c => c.LocalPart)
            .NotEmpty()
            .MaximumLength(EmailAddress.MaxLocalPartLength)
            .WithMessage(
                $"A local-part may be at most {EmailAddress.MaxLocalPartLength} characters, " +
                "which is the RFC 5321 limit.")
            .Must(static l => IsUsableLocalPart(l))
            .WithMessage(
                "'{PropertyValue}' is not a usable local-part. Use letters, digits and the " +
                "punctuation RFC 5321 permits unquoted.");

        RuleFor(c => c.QuotaBytes)
            .GreaterThanOrEqualTo(0)
            .WithMessage("A quota cannot be negative. Use 0 to inherit the domain's default.");

        RuleFor(c => c.Password!)
            .MinimumLength(PasswordPolicy.MinimumMailboxPasswordLength)
            .MaximumLength(PasswordPolicy.MaximumLength)
            .When(c => c.Password is not null)
            .WithMessage(
                $"A mailbox password must be at least " +
                $"{PasswordPolicy.MinimumMailboxPasswordLength} characters.");
    }

    /// <summary>
    /// True when the local-part parses as an unquoted RFC 5321 address.
    /// </summary>
    /// <remarks>
    /// Quoted local-parts — <c>"weird name"@example.com</c> — are legal and are deliberately
    /// not offered here. They are accepted on inbound mail because the standard requires it,
    /// but creating one is asking for an address half the world's software mishandles, and an
    /// administrator typing it almost certainly meant something else.
    /// </remarks>
    private static bool IsUsableLocalPart(string localPart) =>
        !string.IsNullOrWhiteSpace(localPart) &&
        EmailAddress.TryParse($"{localPart}@example.com", out EmailAddress? parsed) &&
        !parsed.IsQuoted;
}

internal sealed class SetMailboxPasswordCommandValidator
    : AbstractValidator<SetMailboxPasswordCommand>
{
    public SetMailboxPasswordCommandValidator()
    {
        RuleFor(c => c.MailboxId).NotEmpty();

        RuleFor(c => c.Password)
            .NotEmpty()
            .MinimumLength(PasswordPolicy.MinimumMailboxPasswordLength)
            .MaximumLength(PasswordPolicy.MaximumLength)
            .WithMessage(
                $"A mailbox password must be between " +
                $"{PasswordPolicy.MinimumMailboxPasswordLength} and " +
                $"{PasswordPolicy.MaximumLength} characters.");
    }
}

internal sealed class UpdateMailboxCommandValidator : AbstractValidator<UpdateMailboxCommand>
{
    public UpdateMailboxCommandValidator()
    {
        RuleFor(c => c.MailboxId).NotEmpty();

        RuleFor(c => c.QuotaBytes!.Value)
            .GreaterThanOrEqualTo(0)
            .When(c => c.QuotaBytes is not null);

        RuleFor(c => c.MaxMessageSizeBytes!.Value)
            .GreaterThanOrEqualTo(0)
            .When(c => c.MaxMessageSizeBytes is not null);
    }
}

internal sealed class DeleteMailboxCommandValidator : AbstractValidator<DeleteMailboxCommand>
{
    public DeleteMailboxCommandValidator() => RuleFor(c => c.MailboxId).NotEmpty();
}

internal sealed class CreateAliasCommandValidator : AbstractValidator<CreateAliasCommand>
{
    /// <summary>
    /// Targets permitted on one alias.
    /// </summary>
    /// <remarks>
    /// Below the expansion policy's recipient limit on purpose: an alias that alone exhausts
    /// the delivery-time bound would be accepted here and then silently truncated at the first
    /// message, which is the failure mode worth preventing at the point of entry.
    /// </remarks>
    private const int MaxTargets = 50;

    public CreateAliasCommandValidator()
    {
        RuleFor(c => c.DomainId).NotEmpty();

        RuleFor(c => c.LocalPart)
            .NotEmpty()
            .MaximumLength(EmailAddress.MaxLocalPartLength);

        RuleFor(c => c.Targets)
            .NotEmpty()
            .WithMessage(
                "An alias must forward to at least one address, or it would accept mail and " +
                "discard it silently.")
            .Must(t => t.Count <= MaxTargets)
            .WithMessage($"An alias may have at most {MaxTargets} targets.");

        RuleForEach(c => c.Targets)
            .Must(static t => EmailAddress.TryParse(t, out _))
            .WithMessage("'{PropertyValue}' is not a valid email address.");
    }
}

internal sealed class UpdateAliasCommandValidator : AbstractValidator<UpdateAliasCommand>
{
    public UpdateAliasCommandValidator()
    {
        RuleFor(c => c.AliasId).NotEmpty();

        RuleFor(c => c.Targets!)
            .NotEmpty()
            .When(c => c.Targets is not null)
            .WithMessage("An alias must forward to at least one address.");

        RuleForEach(c => c.Targets!)
            .Must(static t => EmailAddress.TryParse(t, out _))
            .When(c => c.Targets is not null)
            .WithMessage("'{PropertyValue}' is not a valid email address.");
    }
}

internal sealed class DeleteAliasCommandValidator : AbstractValidator<DeleteAliasCommand>
{
    public DeleteAliasCommandValidator() => RuleFor(c => c.AliasId).NotEmpty();
}
