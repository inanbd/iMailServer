using MailServer.Domain.Enums;

namespace MailServer.Application.Monitoring.Dtos;

/// <summary>Aggregated counters for the dashboard.</summary>
/// <remarks>
/// From Milestone 8 these come from rolled-up metrics tables. Counting rows in a
/// multi-million-row queue table on every dashboard refresh is exactly the query that takes
/// a busy mail server down, so the read model is designed for pre-aggregation from the start.
/// </remarks>
public sealed record ServerCountersDto
{
    public required int DomainCount { get; init; }

    public required int ActiveDomainCount { get; init; }

    public required int MailboxCount { get; init; }

    public required int QueuedMessageCount { get; init; }

    public required int DeferredMessageCount { get; init; }

    public required long StorageUsedBytes { get; init; }
}

/// <summary>The health of one subsystem, as shown on the dashboard.</summary>
public sealed record HealthComponentDto
{
    public required string Component { get; init; }

    public required HealthState State { get; init; }

    public required string Message { get; init; }

    public required DateTimeOffset ObservedUtc { get; init; }
}

/// <summary>Everything the dashboard needs, in one round trip.</summary>
/// <remarks>
/// One aggregate DTO rather than five separate queries, because each round trip over the
/// named pipe costs a full request cycle, and a dashboard that refreshes on a timer would
/// multiply that by every open admin console.
/// </remarks>
public sealed record DashboardDto
{
    public required ServerCountersDto Counters { get; init; }

    public required IReadOnlyList<HealthComponentDto> Health { get; init; }

    public required HealthState OverallHealth { get; init; }

    public required MaintenanceMode MaintenanceMode { get; init; }

    public required string ServerHostname { get; init; }

    public required string DatabaseProvider { get; init; }

    public required string ProductVersion { get; init; }

    public required DateTimeOffset GeneratedUtc { get; init; }
}
