using MailServer.Application.Monitoring.Dtos;

namespace MailServer.Application.Abstractions.Queries;

/// <summary>Read models for the dashboard and server status screens.</summary>
public interface IServerStatusQueries
{
    /// <summary>
    /// Aggregated counters for the dashboard.
    /// </summary>
    /// <remarks>
    /// From Milestone 8 these are served from rolled-up metrics tables rather than by
    /// scanning the queue and message tables. Counting rows in a multi-million-row queue on
    /// every dashboard refresh is precisely the query that takes a busy mail server down.
    /// </remarks>
    Task<ServerCountersDto> GetCountersAsync(CancellationToken cancellationToken);
}
