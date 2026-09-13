using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Domains.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Domains.Queries;

/// <summary>Returns everything shown on the domain details screen.</summary>
public sealed record GetDomainDetailsQuery : IQuery<DomainDetailDto>, IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetDomainDetailsQueryHandler(IDomainQueries queries)
    : IRequestHandler<GetDomainDetailsQuery, DomainDetailDto>
{
    public async Task<DomainDetailDto> Handle(
        GetDomainDetailsQuery request,
        CancellationToken cancellationToken)
    {
        DomainId id = new(request.DomainId);

        return await queries.GetDetailAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(MailDomain), id.ToString());
    }
}
