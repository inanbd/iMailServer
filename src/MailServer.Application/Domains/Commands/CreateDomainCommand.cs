using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Domains.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Domains.Commands;

/// <summary>
/// Adds a mail domain to the server.
/// </summary>
/// <remarks>
/// The domain is created in <see cref="DomainStatus.Pending"/>. It does not accept mail
/// until DKIM is generated, DNS is published and an administrator enables it - see
/// <see cref="MailDomain.Create"/> for why starting active would damage the sending IP's
/// reputation.
/// </remarks>
public sealed record CreateDomainCommand : ICommand<DomainSummaryDto>,
                                           ITransactionalRequest,
                                           IAuditableRequest,
                                           IAuthorizedRequest
{
    /// <summary>The domain name, e.g. <c>example.com</c>. Unicode is accepted and normalised.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// Outbound identity, e.g. <c>mail.example.com</c>. Optional at creation; required
    /// before the domain can be enabled.
    /// </summary>
    public string? MailHostname { get; init; }

    /// <summary>Default quota for new mailboxes, in bytes. Zero means unlimited.</summary>
    public long DefaultMailboxQuotaBytes { get; init; } = 5L * 1024 * 1024 * 1024;

    /// <summary>Largest message accepted for this domain, in bytes.</summary>
    public long MaxMessageSizeBytes { get; init; } = MailDomain.DefaultMaxMessageSizeBytes;

    public AdminPermission RequiredPermission => AdminPermission.ManageDomains;

    public AuditDescriptor DescribeForAudit() =>
        new("Domain.Create",
            nameof(MailDomain),
            Name,
            MailHostname is null ? null : $"Mail hostname: {MailHostname}");
}

internal sealed class CreateDomainCommandHandler(
    IDomainRepository domains,
    IClock clock,
    ILogger<CreateDomainCommandHandler> logger)
    : IRequestHandler<CreateDomainCommand, DomainSummaryDto>
{
    public async Task<DomainSummaryDto> Handle(
        CreateDomainCommand request,
        CancellationToken cancellationToken)
    {
        // The validator has already checked the format, so parsing here cannot fail on
        // well-formed input. Parse (not TryParse) is correct: a failure at this point is a
        // bug in the validator, and should be loud.
        DomainName name = DomainName.Parse(request.Name);

        // A friendly pre-check for a good error message. The database's unique index is what
        // actually guarantees correctness under concurrency - two administrators creating the
        // same domain simultaneously both pass this check, and one of them then hits the
        // constraint, which the persistence layer maps to the same exception type.
        if (await domains.ExistsAsync(name, cancellationToken).ConfigureAwait(false))
        {
            throw new DuplicateEntityException(nameof(MailDomain), name.Value);
        }

        DomainName? mailHostname = request.MailHostname is null
            ? null
            : DomainName.Parse(request.MailHostname);

        MailDomain domain = MailDomain.Create(
            DomainId.New(),
            name,
            clock.UtcNow,
            mailHostname,
            QuotaBytes.FromBytes(request.DefaultMailboxQuotaBytes),
            request.MaxMessageSizeBytes);

        await domains.AddAsync(domain, cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "Created domain {DomainName} in {DomainStatus} state.",
            domain.Name.Value,
            domain.Status);

        return new DomainSummaryDto
        {
            Id = domain.Id.Value,
            Name = domain.Name.Value,
            DisplayName = domain.Name.UnicodeValue,
            Status = domain.Status,
            MailHostname = domain.MailHostname?.Value,
            ActiveDkimSelector = domain.ActiveDkimSelector?.Value,
            MailboxCount = 0,
            StorageUsedBytes = 0,
            CreatedUtc = domain.CreatedUtc,
        };
    }
}
