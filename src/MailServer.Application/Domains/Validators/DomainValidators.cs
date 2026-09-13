using FluentValidation;
using MailServer.Application.Common;
using MailServer.Application.Domains.Commands;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Domains.Validators;

/// <summary>
/// Shared rules, so that "is this a valid domain name" has exactly one definition.
/// </summary>
/// <remarks>
/// The validators delegate to the value objects' own <c>TryParse</c> rather than
/// re-implementing the grammar with a regular expression. Two independent definitions of a
/// valid domain name would eventually disagree, and the one that matters is the one the
/// aggregate enforces.
/// </remarks>
internal static class DomainValidationRules
{
    public static IRuleBuilderOptions<T, string?> MustBeValidDomainName<T>(
        this IRuleBuilder<T, string?> rule) =>
        rule.Must(value => value is null || DomainName.TryParse(value, out _))
            .WithMessage(
                "'{PropertyValue}' is not a valid fully-qualified domain name. " +
                "Use a name such as example.com.");

    public static IRuleBuilderOptions<T, string?> MustBeValidEmailAddress<T>(
        this IRuleBuilder<T, string?> rule) =>
        rule.Must(value => value is null || EmailAddress.TryParse(value, out _))
            .WithMessage("'{PropertyValue}' is not a valid email address.");
}

public sealed class CreateDomainCommandValidator : AbstractValidator<CreateDomainCommand>
{
    public CreateDomainCommandValidator()
    {
        RuleFor(x => x.Name)
            .NotEmpty().WithMessage("A domain name is required.")
            .MaximumLength(DomainName.MaxLength)
            .MustBeValidDomainName();

        RuleFor(x => x.MailHostname)
            .MaximumLength(DomainName.MaxLength)
            .MustBeValidDomainName()
            .When(x => !string.IsNullOrWhiteSpace(x.MailHostname));

        RuleFor(x => x.DefaultMailboxQuotaBytes)
            .GreaterThanOrEqualTo(0)
            .WithMessage("A quota cannot be negative. Use 0 for unlimited.");

        RuleFor(x => x.MaxMessageSizeBytes)
            .GreaterThanOrEqualTo(MailDomain.MinimumMaxMessageSizeBytes)
            .WithMessage(
                $"The maximum message size must be at least " +
                $"{QuotaBytes.FormatBytes(MailDomain.MinimumMaxMessageSizeBytes)}; a smaller " +
                "limit would reject ordinary mail with attachments.");
    }
}

public sealed class UpdateDomainCommandValidator : AbstractValidator<UpdateDomainCommand>
{
    public UpdateDomainCommandValidator()
    {
        RuleFor(x => x.DomainId).NotEmpty();

        RuleFor(x => x.MailHostname)
            .MaximumLength(DomainName.MaxLength)
            .MustBeValidDomainName()
            .When(x => !string.IsNullOrWhiteSpace(x.MailHostname));

        RuleFor(x => x.CatchAllMailbox)
            .NotEmpty()
            .WithMessage("A catch-all destination mailbox is required for this policy.")
            .MustBeValidEmailAddress()
            .When(x => x.CatchAllPolicy == CatchAllPolicy.DeliverToCatchAll);

        RuleFor(x => x.DefaultMailboxQuotaBytes)
            .GreaterThanOrEqualTo(0)
            .WithMessage("A quota cannot be negative. Use 0 for unlimited.");

        RuleFor(x => x.DomainQuotaBytes)
            .GreaterThanOrEqualTo(0)
            .WithMessage("A quota cannot be negative. Use 0 for unlimited.");

        RuleFor(x => x.MaxMessageSizeBytes)
            .GreaterThanOrEqualTo(MailDomain.MinimumMaxMessageSizeBytes);
    }
}

public sealed class SetDomainStatusCommandValidator : AbstractValidator<SetDomainStatusCommand>
{
    public SetDomainStatusCommandValidator() => RuleFor(x => x.DomainId).NotEmpty();
}

public sealed class DeleteDomainCommandValidator : AbstractValidator<DeleteDomainCommand>
{
    public DeleteDomainCommandValidator() => RuleFor(x => x.DomainId).NotEmpty();
}

public sealed class GetDomainsQueryValidator : AbstractValidator<Queries.GetDomainsQuery>
{
    public GetDomainsQueryValidator()
    {
        RuleFor(x => x.Page).GreaterThanOrEqualTo(0);

        RuleFor(x => x.PageSize)
            .InclusiveBetween(1, PagedRequest.MaxPageSize)
            .WithMessage($"The page size must be between 1 and {PagedRequest.MaxPageSize}.");

        RuleFor(x => x.NameContains).MaximumLength(DomainName.MaxLength);

        // A sort column arriving as a free-text string would be an injection vector, because
        // identifiers cannot be parameterised. The enum is the defence; this check closes
        // the remaining gap of an out-of-range integer cast onto it.
        RuleFor(x => x.SortBy)
            .IsInEnum()
            .WithMessage("Unknown sort column.");
    }
}
