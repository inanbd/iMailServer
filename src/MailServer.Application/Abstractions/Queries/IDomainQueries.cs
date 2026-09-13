using MailServer.Application.Common;
using MailServer.Application.Domains.Dtos;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Queries;

/// <summary>
/// Read models for domain screens.
/// </summary>
/// <remarks>
/// The read side of CQRS. Hand-tuned SQL returning flat DTOs shaped for a specific screen,
/// with paging and filtering pushed into the database. No aggregate is rehydrated, no
/// invariant is evaluated, nothing is tracked.
/// </remarks>
public interface IDomainQueries
{
    Task<PagedResult<DomainSummaryDto>> SearchAsync(
        DomainSearchRequest request,
        CancellationToken cancellationToken);

    Task<DomainDetailDto?> GetDetailAsync(DomainId id, CancellationToken cancellationToken);
}
