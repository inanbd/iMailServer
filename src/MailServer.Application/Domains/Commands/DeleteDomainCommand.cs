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
/// Removes a domain from the server.
/// </summary>
/// <remarks>
/// <para>
/// Two-stage by default. The first call marks the domain <see cref="DomainStatus.PendingDeletion"/>,
/// which stops mail flow while retaining everything, so that queued mail drains and an
/// accidental deletion is recoverable. Only a second call with
/// <see cref="PermanentlyDelete"/> actually removes the row.
/// </para>
/// <para>
/// Permanent deletion is refused while mailboxes remain. Removing the domain first would
/// orphan every message in the store: the rows would be gone and the files would not, and
/// nothing would ever reclaim them.
/// </para>
/// </remarks>
public sealed record DeleteDomainCommand : ICommand<Unit>,
                                           ITransactionalRequest,
                                           IAuditableRequest,
                                           IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    /// <summary>
    /// When true, removes the domain outright instead of marking it for deletion. The admin
    /// application requires the administrator to type the domain name before sending this.
    /// </summary>
    public bool PermanentlyDelete { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageDomains;

    public AuditDescriptor DescribeForAudit() =>
        new(PermanentlyDelete ? "Domain.Delete" : "Domain.MarkForDeletion",
            nameof(MailDomain),
            DomainId.ToString());
}

internal sealed class DeleteDomainCommandHandler(
    IDomainRepository domains,
    IClock clock,
    ILogger<DeleteDomainCommandHandler> logger)
    : IRequestHandler<DeleteDomainCommand, Unit>
{
    public async Task<Unit> Handle(DeleteDomainCommand request, CancellationToken cancellationToken)
    {
        DomainId id = new(request.DomainId);

        MailDomain domain = await domains.GetByIdAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(MailDomain), id.ToString());

        if (!request.PermanentlyDelete)
        {
            domain.MarkForDeletion(clock.UtcNow);
            await domains.UpdateAsync(domain, cancellationToken).ConfigureAwait(false);

            logger.LogWarning(
                "Domain {DomainName} marked for deletion. Mail flow has stopped; data is retained.",
                domain.Name.Value);

            return Unit.Value;
        }

        int mailboxCount = await domains
            .CountMailboxesAsync(id, cancellationToken)
            .ConfigureAwait(false);

        if (mailboxCount > 0)
        {
            throw new DomainRuleViolationException(
                "domain.delete.has_mailboxes",
                $"Domain '{domain.Name}' still has {mailboxCount} mailbox(es). Deleting it " +
                "now would orphan every stored message belonging to them. Remove the " +
                "mailboxes first.");
        }

        await domains.RemoveAsync(id, cancellationToken).ConfigureAwait(false);

        logger.LogWarning("Domain {DomainName} was permanently deleted.", domain.Name.Value);

        return Unit.Value;
    }
}
