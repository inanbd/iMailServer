using MailServer.Application.Common;
using MailServer.Domain.Enums;

namespace MailServer.Application.Domains.Dtos;

/// <summary>One row in the domains grid.</summary>
/// <remarks>
/// Flat and primitive-typed on purpose. This crosses the IPC boundary to the WPF admin
/// application, and a serialisable read model must not drag domain value objects or
/// aggregates across a process boundary where their invariants cannot be honoured.
/// </remarks>
public sealed record DomainSummaryDto
{
    public required Guid Id { get; init; }

    /// <summary>ASCII (A-label) name. The canonical form.</summary>
    public required string Name { get; init; }

    /// <summary>Unicode form for display; equals <see cref="Name"/> for non-IDN domains.</summary>
    public required string DisplayName { get; init; }

    public required DomainStatus Status { get; init; }

    public string? MailHostname { get; init; }

    public string? ActiveDkimSelector { get; init; }

    public required int MailboxCount { get; init; }

    public required long StorageUsedBytes { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }
}

/// <summary>Everything shown on the domain details screen.</summary>
public sealed record DomainDetailDto
{
    public required Guid Id { get; init; }

    public required string Name { get; init; }

    public required string DisplayName { get; init; }

    public required DomainStatus Status { get; init; }

    public string? MailHostname { get; init; }

    public string? ActiveDkimSelector { get; init; }

    public required CatchAllPolicy CatchAllPolicy { get; init; }

    public string? CatchAllMailbox { get; init; }

    /// <summary>Zero means unlimited.</summary>
    public required long DefaultMailboxQuotaBytes { get; init; }

    /// <summary>Zero means unlimited.</summary>
    public required long DomainQuotaBytes { get; init; }

    public required long MaxMessageSizeBytes { get; init; }

    public required bool RequireTlsForOutbound { get; init; }

    public required int MailboxCount { get; init; }

    public required int AliasCount { get; init; }

    public required long StorageUsedBytes { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }

    public DateTimeOffset? ModifiedUtc { get; init; }
}

/// <summary>Filter, sort and page parameters for the domains grid.</summary>
public sealed record DomainSearchRequest : PagedRequest
{
    /// <summary>Case-insensitive substring match on the domain name. Null matches everything.</summary>
    public string? NameContains { get; init; }

    /// <summary>Restricts to these statuses. Empty or null matches everything.</summary>
    public IReadOnlyList<DomainStatus>? Statuses { get; init; }

    /// <summary>
    /// Sort column. A closed enum rather than a free-text column name, because a
    /// caller-supplied ORDER BY string is an SQL injection vector that parameters cannot
    /// defend against - identifiers cannot be parameterised.
    /// </summary>
    public DomainSortField SortBy { get; init; } = DomainSortField.Name;

    public bool SortDescending { get; init; }
}

/// <summary>Sortable columns on the domains grid.</summary>
public enum DomainSortField
{
    Name = 0,
    Status = 1,
    CreatedUtc = 2,
    MailboxCount = 3,
}
