using MailServer.Application.Common;
using MailServer.Application.Smtp.Dtos;

namespace MailServer.Application.Abstractions.Queries;

/// <summary>What to search for in the received-mail log.</summary>
/// <param name="Page">Zero-based page index.</param>
/// <param name="PageSize">Rows per page.</param>
/// <param name="Search">Matches the sender, a recipient, or the peer address. Null matches everything.</param>
/// <param name="SinceUtc">Earliest arrival time to include.</param>
public sealed record ReceivedMessageSearchRequest(
    int Page = 0,
    int PageSize = 50,
    string? Search = null,
    DateTimeOffset? SinceUtc = null);

/// <summary>
/// Read models for the SMTP screens.
/// </summary>
/// <remarks>
/// The read side of CQRS: flat DTOs shaped for one screen, with paging and filtering pushed into
/// the database. No aggregate is rehydrated and no invariant is evaluated.
/// </remarks>
public interface ISmtpQueries
{
    /// <summary>A page of received messages, newest first.</summary>
    Task<PagedResult<ReceivedMessageDto>> SearchReceivedAsync(
        ReceivedMessageSearchRequest request,
        CancellationToken cancellationToken);

    /// <summary>Counts and totals for the SMTP status panel.</summary>
    Task<(long LastDay, long LastHour, long StoredBytes)> GetThroughputAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken);
}
