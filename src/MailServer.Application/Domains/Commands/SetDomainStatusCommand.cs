using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Domains.Commands;

/// <summary>
/// Enables or disables a domain.
/// </summary>
/// <remarks>
/// One command with an intent flag rather than two near-identical commands, because the
/// audit descriptor, permission and validation are identical and the only difference is
/// which aggregate method is called.
/// </remarks>
public sealed record SetDomainStatusCommand : ICommand<Unit>,
                                              ITransactionalRequest,
                                              IAuditableRequest,
                                              IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    /// <summary>True to bring the domain into service, false to take it out.</summary>
    public required bool Enabled { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageDomains;

    public AuditDescriptor DescribeForAudit() =>
        new(Enabled ? "Domain.Enable" : "Domain.Disable",
            nameof(MailDomain),
            DomainId.ToString());
}

internal sealed class SetDomainStatusCommandHandler(
    IDomainRepository domains,
    IClock clock,
    ILogger<SetDomainStatusCommandHandler> logger)
    : IRequestHandler<SetDomainStatusCommand, Unit>
{
    public async Task<Unit> Handle(SetDomainStatusCommand request, CancellationToken cancellationToken)
    {
        DomainId id = new(request.DomainId);

        MailDomain domain = await domains.GetByIdAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(MailDomain), id.ToString());

        if (request.Enabled)
        {
            // Throws if the domain has no mail hostname - a domain with no outbound identity
            // sends mail that fails SPF, DKIM alignment and reverse-DNS checks everywhere.
            domain.Enable(clock.UtcNow);
        }
        else
        {
            domain.Disable(clock.UtcNow);
        }

        await domains.UpdateAsync(domain, cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "Domain {DomainName} is now {DomainStatus}.",
            domain.Name.Value,
            domain.Status);

        return Unit.Value;
    }
}
