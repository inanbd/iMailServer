using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Filtering.Dtos;
using MailServer.Domain.Enums;
using MailServer.Domain.Filtering;
using MediatR;

namespace MailServer.Application.Filtering.Queries;

/// <summary>
/// Lists what the filter is holding.
/// </summary>
/// <remarks>
/// <b><see cref="AdminPermission.ViewServerState"/>, not
/// <see cref="AdminPermission.ReadMessageContent"/>.</b> The listing carries verdicts and
/// reasons, never message content — that is what makes it readable by whoever watches the
/// server without also giving them the ability to read everybody's mail. Reading a held
/// message's content is a separate request with the stronger permission.
/// </remarks>
public sealed record GetQuarantineQuery : IQuery<IReadOnlyList<QuarantinedMessageDto>>, IAuthorizedRequest
{
    /// <summary>The most rows to return.</summary>
    public int Limit { get; init; } = 100;

    /// <summary>Whether to include messages that have already been resolved.</summary>
    public bool IncludeResolved { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetQuarantineQueryHandler(IQuarantineRepository quarantine)
    : IRequestHandler<GetQuarantineQuery, IReadOnlyList<QuarantinedMessageDto>>
{
    /// <summary>The most rows one call will return, however many were asked for.</summary>
    /// <remarks>
    /// A quarantine grows without bound on a server under sustained attack, and a caller that
    /// asked for everything would be asking this server to materialise all of it.
    /// </remarks>
    public const int MaxLimit = 500;

    public async Task<IReadOnlyList<QuarantinedMessageDto>> Handle(
        GetQuarantineQuery request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        int limit = Math.Clamp(request.Limit, 1, MaxLimit);

        IReadOnlyList<QuarantinedMessage> held = await quarantine
            .ListAsync(
                request.IncludeResolved ? QuarantineFilter.All : QuarantineFilter.Held,
                limit,
                cancellationToken)
            .ConfigureAwait(false);

        return [.. held.Select(QuarantineMapping.ToDto)];
    }
}

/// <summary>Turns a held message into its wire shape.</summary>
internal static class QuarantineMapping
{
    public static QuarantinedMessageDto ToDto(QuarantinedMessage message) => new()
    {
        Id = message.Id.Value,
        MessageId = message.MessageId.Value,
        Sender = message.ReversePath?.Value,
        RemoteAddress = message.RemoteAddress.ToString(),
        Score = message.Score,
        Summary = message.Summary,
        Status = message.Status.ToString(),
        QuarantinedUtc = message.QuarantinedUtc,
        ExpiresUtc = message.ExpiresUtc,
        ResolvedUtc = message.ResolvedUtc,
        ResolvedBy = message.ResolvedBy,
        Signals =
        [
            .. message.Signals.Select(s => new FilterSignalDto
            {
                Name = s.Name,
                Score = s.Score,
                Detail = s.Detail,
            }),
        ],
    };
}
