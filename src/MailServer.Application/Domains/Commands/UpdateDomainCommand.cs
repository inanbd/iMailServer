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
/// Updates a domain's mutable settings.
/// </summary>
/// <remarks>
/// There is deliberately no way to change the domain <i>name</i>. Every mailbox address,
/// DKIM DNS record, SPF record and already-delivered message refers to it; a rename would
/// silently strand all of them. The supported path is add-new, migrate, remove-old.
/// </remarks>
public sealed record UpdateDomainCommand : ICommand<Unit>,
                                           ITransactionalRequest,
                                           IAuditableRequest,
                                           IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    /// <summary>Outbound identity. Changing it requires re-checking DNS and the certificate.</summary>
    public string? MailHostname { get; init; }

    public CatchAllPolicy CatchAllPolicy { get; init; } = CatchAllPolicy.Reject;

    /// <summary>Required when <see cref="CatchAllPolicy"/> is DeliverToCatchAll.</summary>
    public string? CatchAllMailbox { get; init; }

    /// <summary>Zero means unlimited.</summary>
    public long DefaultMailboxQuotaBytes { get; init; }

    /// <summary>Zero means unlimited.</summary>
    public long DomainQuotaBytes { get; init; }

    public long MaxMessageSizeBytes { get; init; } = MailDomain.DefaultMaxMessageSizeBytes;

    public bool RequireTlsForOutbound { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageDomains;

    public AuditDescriptor DescribeForAudit() =>
        new("Domain.Update", nameof(MailDomain), DomainId.ToString());
}

internal sealed class UpdateDomainCommandHandler(
    IDomainRepository domains,
    IClock clock,
    ILogger<UpdateDomainCommandHandler> logger)
    : IRequestHandler<UpdateDomainCommand, Unit>
{
    public async Task<Unit> Handle(UpdateDomainCommand request, CancellationToken cancellationToken)
    {
        DomainId id = new(request.DomainId);

        MailDomain domain = await domains.GetByIdAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(MailDomain), id.ToString());

        DateTimeOffset now = clock.UtcNow;

        if (request.MailHostname is not null)
        {
            domain.SetMailHostname(DomainName.Parse(request.MailHostname), now);
        }

        EmailAddress? catchAll = request.CatchAllMailbox is null
            ? null
            : EmailAddress.Parse(request.CatchAllMailbox);

        // Each of these calls enforces its own invariant and throws a DomainRuleViolation-
        // Exception on breach. The handler deliberately does not duplicate those checks:
        // a rule implemented in two places is a rule that will eventually disagree with
        // itself, and the aggregate is the copy that counts.
        domain.SetCatchAllPolicy(request.CatchAllPolicy, catchAll, now);

        domain.SetQuotas(
            QuotaBytes.FromBytes(request.DefaultMailboxQuotaBytes),
            QuotaBytes.FromBytes(request.DomainQuotaBytes),
            now);

        domain.SetMaxMessageSize(request.MaxMessageSizeBytes, now);
        domain.SetRequireTlsForOutbound(request.RequireTlsForOutbound, now);

        await domains.UpdateAsync(domain, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Updated domain {DomainName}.", domain.Name.Value);

        return Unit.Value;
    }
}
