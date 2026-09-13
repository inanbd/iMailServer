using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Common;
using MailServer.Application.Domains.Dtos;
using MailServer.Domain.Enums;
using MediatR;

namespace MailServer.Application.Domains.Queries;

/// <summary>
/// Returns a page of domains for the grid.
/// </summary>
/// <remarks>
/// A query, so it carries no <c>ITransactionalRequest</c> marker and never opens a
/// transaction. It goes to <see cref="IDomainQueries"/>, not to the repository: this is the
/// read side, and rehydrating aggregates to project them back to flat rows would be pure
/// waste.
/// </remarks>
public sealed record GetDomainsQuery : IQuery<PagedResult<DomainSummaryDto>>, IAuthorizedRequest
{
    public string? NameContains { get; init; }

    public IReadOnlyList<DomainStatus>? Statuses { get; init; }

    public int Page { get; init; }

    public int PageSize { get; init; } = PagedRequest.DefaultPageSize;

    public DomainSortField SortBy { get; init; } = DomainSortField.Name;

    public bool SortDescending { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetDomainsQueryHandler(IDomainQueries queries)
    : IRequestHandler<GetDomainsQuery, PagedResult<DomainSummaryDto>>
{
    public Task<PagedResult<DomainSummaryDto>> Handle(
        GetDomainsQuery request,
        CancellationToken cancellationToken)
    {
        DomainSearchRequest search = new()
        {
            NameContains = request.NameContains,
            Statuses = request.Statuses,
            Page = request.Page,
            PageSize = request.PageSize,
            SortBy = request.SortBy,
            SortDescending = request.SortDescending,
        };

        return queries.SearchAsync(search, cancellationToken);
    }
}
