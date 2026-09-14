using FluentValidation;
using MailServer.Application.Acme.Commands;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Acme.Validators;

/// <summary>
/// Shape checks for certificate requests.
/// </summary>
/// <remarks>
/// Hostname syntax only. Whether a name resolves, points here, or would breach a rate limit are
/// all questions the pre-flight and the limiter answer, because they need I/O and validation
/// runs before the transaction precisely so it does none.
/// </remarks>
internal sealed class RequestCertificateCommandValidator
    : AbstractValidator<RequestCertificateCommand>
{
    /// <summary>
    /// Identifiers permitted in one order.
    /// </summary>
    /// <remarks>
    /// Let's Encrypt's own limit. Refusing locally turns a CA rejection — which costs a
    /// rate-limit slot — into a message that costs nothing.
    /// </remarks>
    private const int MaxIdentifiers = 100;

    public RequestCertificateCommandValidator()
    {
        RuleFor(c => c.Hostnames)
            .NotEmpty()
            .WithMessage("A certificate must cover at least one hostname.")
            .Must(h => h.Count <= MaxIdentifiers)
            .WithMessage(
                $"A certificate may cover at most {MaxIdentifiers} hostnames, which is the " +
                "certificate authority's own limit.");

        // Wildcards get their own rule and their own message. "Not a valid hostname" would be
        // both wrong and unhelpful: a wildcard is a perfectly valid ACME identifier, and an
        // operator told it is malformed will waste time checking the spelling.
        RuleForEach(c => c.Hostnames)
            .Must(static h => !h.StartsWith("*.", StringComparison.Ordinal))
            .WithMessage(
                "Wildcard certificates are not supported yet. A wildcard can be obtained — it " +
                "needs DNS-01, which this server supports — but it could not then be " +
                "presented: the TLS layer selects a certificate by exact SNI hostname, so one " +
                "bound to '{PropertyValue}' would never be chosen for any name it covers. " +
                "List the hostnames explicitly instead.");

        RuleForEach(c => c.Hostnames)
            .Must(static h => h.StartsWith("*.", StringComparison.Ordinal) ||
                              DomainName.TryParse(h, out _))
            .WithMessage("'{PropertyValue}' is not a valid hostname.");
    }
}

internal sealed class CheckIssuanceReadinessCommandValidator
    : AbstractValidator<CheckIssuanceReadinessCommand>
{
    public CheckIssuanceReadinessCommandValidator() =>
        RuleFor(c => c.Hostnames).NotEmpty();
}
