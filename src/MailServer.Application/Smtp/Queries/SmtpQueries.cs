using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Common;
using MailServer.Application.Smtp.Dtos;
using MailServer.Domain.Enums;
using MediatR;

namespace MailServer.Application.Smtp.Queries;

/// <summary>A page of the received-mail log, newest first.</summary>
/// <remarks>
/// <b>Envelopes, not bodies.</b> There is no query anywhere in this slice that returns message
/// content. Reading customers' mail is not an administrative function, and an interface that
/// offered it would be used — by an administrator with a grievance, or by whoever compromises
/// one. What an operator actually needs to diagnose delivery is the envelope, and that is what
/// this returns.
/// </remarks>
public sealed record GetReceivedMessagesQuery : IQuery<PagedResult<ReceivedMessageDto>>, IAuthorizedRequest
{
    public int Page { get; init; }

    public int PageSize { get; init; } = 50;

    /// <summary>Matches the sender, a recipient, or the peer address.</summary>
    public string? Search { get; init; }

    /// <summary>Earliest arrival time to include.</summary>
    public DateTimeOffset? SinceUtc { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetReceivedMessagesQueryHandler(ISmtpQueries queries)
    : IRequestHandler<GetReceivedMessagesQuery, PagedResult<ReceivedMessageDto>>
{
    public Task<PagedResult<ReceivedMessageDto>> Handle(
        GetReceivedMessagesQuery request,
        CancellationToken cancellationToken) =>
        queries.SearchReceivedAsync(
            new ReceivedMessageSearchRequest(
                request.Page,
                request.PageSize,
                request.Search,
                request.SinceUtc),
            cancellationToken);
}

/// <summary>What the SMTP subsystem is doing.</summary>
public sealed record GetSmtpStatusQuery : IQuery<SmtpStatusDto>, IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetSmtpStatusQueryHandler(
    ISmtpQueries queries,
    ISmtpConfigurationView configuration,
    IClock clock)
    : IRequestHandler<GetSmtpStatusQuery, SmtpStatusDto>
{
    public async Task<SmtpStatusDto> Handle(
        GetSmtpStatusQuery request,
        CancellationToken cancellationToken)
    {
        (long lastDay, long lastHour, long storedBytes) = await queries
            .GetThroughputAsync(clock.UtcNow, cancellationToken)
            .ConfigureAwait(false);

        return new SmtpStatusDto
        {
            Listeners = configuration.DescribeListeners(),
            MessagesLastDay = lastDay,
            MessagesLastHour = lastHour,
            StoredBytes = storedBytes,
            AuthenticationAvailable = configuration.IsAuthenticationAvailable,
            AuthorizedRelayAddresses = configuration.AuthorizedRelayAddresses,
        };
    }
}
