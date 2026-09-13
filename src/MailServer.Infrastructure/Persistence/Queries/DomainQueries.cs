using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Common;
using MailServer.Application.Domains.Dtos;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Queries;

/// <summary>
/// The read side for domain screens.
/// </summary>
/// <remarks>
/// <para>
/// Hand-written SQL returning flat DTOs, with filtering, sorting and paging pushed into the
/// database. No aggregate is rehydrated. Mailbox counts and storage totals are computed in
/// the same statement rather than with a query per row, which is the classic N+1 that makes
/// a grid unusable at a few hundred domains.
/// </para>
/// <para>
/// <b>The ORDER BY column comes from a closed enum, never from caller text.</b> Identifiers
/// cannot be parameterised, so a free-text sort column would be a genuine SQL injection
/// vector that no amount of parameter binding could defend. The switch below is the defence.
/// </para>
/// </remarks>
internal sealed class DomainQueries(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IDomainQueries
{
    public Task<PagedResult<DomainSummaryDto>> SearchAsync(
        DomainSearchRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        return ExecuteAsync(async (session, ct) =>
        {
            List<string> conditions = [];
            DynamicParameters parameters = new();

            if (!string.IsNullOrWhiteSpace(request.NameContains))
            {
                // Escaped and parameterised. The wildcards are ours; the value is bound.
                conditions.Add("d.Name LIKE @NamePattern");
                parameters.Add("NamePattern", $"%{EscapeLikePattern(request.NameContains)}%");
            }

            if (request.Statuses is { Count: > 0 })
            {
                // Dapper expands a collection parameter into a parameterised IN list; the
                // values never touch the SQL text.
                conditions.Add("d.Status IN @Statuses");
                parameters.Add("Statuses", request.Statuses.Select(s => (int)s).ToArray());
            }

            string where = conditions.Count == 0
                ? string.Empty
                : "WHERE " + string.Join(" AND ", conditions);

            string orderBy = BuildOrderBy(request.SortBy, request.SortDescending);
            string paging = Dialect.PagingClause(request.PageSize, request.Skip);

            string sql = $"""
                SELECT  d.Id                                      AS Id,
                        d.Name                                    AS Name,
                        d.UnicodeName                             AS DisplayName,
                        d.Status                                  AS Status,
                        d.MailHostname                            AS MailHostname,
                        d.ActiveDkimSelector                      AS ActiveDkimSelector,
                        COALESCE(m.MailboxCount, 0)               AS MailboxCount,
                        COALESCE(m.StorageUsedBytes, 0)           AS StorageUsedBytes,
                        d.CreatedUtc                              AS CreatedUtc
                FROM    Domains d
                LEFT JOIN (
                        SELECT  DomainId,
                                COUNT(1)                AS MailboxCount,
                                SUM(StorageUsedBytes)   AS StorageUsedBytes
                        FROM    Mailboxes
                        GROUP BY DomainId
                ) m ON m.DomainId = d.Id
                {where}
                {orderBy}
                {paging}
                """;

            IEnumerable<DomainSummaryRow> rows = await session.Connection
                .QueryAsync<DomainSummaryRow>(Command(session, sql, parameters, ct))
                .ConfigureAwait(false);

            IReadOnlyList<DomainSummaryDto> items = [.. rows.Select(r => r.ToDto())];

            long? total = null;
            if (request.IncludeTotalCount)
            {
                string countSql = $"SELECT COUNT(1) FROM Domains d {where}";
                total = await session.Connection
                    .ExecuteScalarAsync<long>(Command(session, countSql, parameters, ct))
                    .ConfigureAwait(false);
            }

            return new PagedResult<DomainSummaryDto>(items, request.Page, request.PageSize, total);
        }, cancellationToken);
    }

    public Task<DomainDetailDto?> GetDetailAsync(DomainId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            const string Sql = """
                SELECT  d.Id                            AS Id,
                        d.Name                          AS Name,
                        d.UnicodeName                   AS DisplayName,
                        d.Status                        AS Status,
                        d.MailHostname                  AS MailHostname,
                        d.ActiveDkimSelector            AS ActiveDkimSelector,
                        d.CatchAllPolicy                AS CatchAllPolicy,
                        d.CatchAllMailbox               AS CatchAllMailbox,
                        d.DefaultMailboxQuotaBytes      AS DefaultMailboxQuotaBytes,
                        d.DomainQuotaBytes              AS DomainQuotaBytes,
                        d.MaxMessageSizeBytes           AS MaxMessageSizeBytes,
                        d.RequireTlsForOutbound         AS RequireTlsForOutbound,
                        COALESCE(m.MailboxCount, 0)     AS MailboxCount,
                        COALESCE(m.StorageUsedBytes, 0) AS StorageUsedBytes,
                        d.CreatedUtc                    AS CreatedUtc,
                        d.ModifiedUtc                   AS ModifiedUtc
                FROM    Domains d
                LEFT JOIN (
                        SELECT  DomainId,
                                COUNT(1)              AS MailboxCount,
                                SUM(StorageUsedBytes) AS StorageUsedBytes
                        FROM    Mailboxes
                        GROUP BY DomainId
                ) m ON m.DomainId = d.Id
                WHERE   d.Id = @Id
                """;

            DomainDetailRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<DomainDetailRow>(
                    Command(session, Sql, new { Id = id.Value }, ct))
                .ConfigureAwait(false);

            return row?.ToDto();
        }, cancellationToken);

    /// <summary>
    /// Maps the sort enum onto a literal ORDER BY clause.
    /// </summary>
    /// <remarks>
    /// Every branch returns a compile-time constant. No caller-supplied text reaches the SQL
    /// text under any input, including a cast of an out-of-range integer onto the enum, which
    /// falls into the default branch.
    /// </remarks>
    private static string BuildOrderBy(DomainSortField sortBy, bool descending)
    {
        string direction = descending ? "DESC" : "ASC";

        string column = sortBy switch
        {
            DomainSortField.Status => "d.Status",
            DomainSortField.CreatedUtc => "d.CreatedUtc",
            DomainSortField.MailboxCount => "COALESCE(m.MailboxCount, 0)",
            DomainSortField.Name => "d.Name",
            _ => "d.Name",
        };

        // The tie-break on Name keeps paging stable. Without a total order, two pages of an
        // unstably sorted result can show the same row twice and omit another entirely.
        return sortBy == DomainSortField.Name
            ? $"ORDER BY {column} {direction}"
            : $"ORDER BY {column} {direction}, d.Name ASC";
    }

    /// <summary>Escapes LIKE metacharacters so a search for "a_b" does not match "axb".</summary>
    private static string EscapeLikePattern(string value) =>
        value.Replace("[", "[[]", StringComparison.Ordinal)
             .Replace("%", "[%]", StringComparison.Ordinal)
             .Replace("_", "[_]", StringComparison.Ordinal);

    private sealed class DomainSummaryRow
    {
        public Guid Id { get; set; }

        public string Name { get; set; } = string.Empty;

        public string DisplayName { get; set; } = string.Empty;

        public int Status { get; set; }

        public string? MailHostname { get; set; }

        public string? ActiveDkimSelector { get; set; }

        public int MailboxCount { get; set; }

        public long StorageUsedBytes { get; set; }

        public DateTimeOffset CreatedUtc { get; set; }

        public DomainSummaryDto ToDto() => new()
        {
            Id = Id,
            Name = Name,
            DisplayName = DisplayName,
            Status = (Domain.Enums.DomainStatus)Status,
            MailHostname = MailHostname,
            ActiveDkimSelector = ActiveDkimSelector,
            MailboxCount = MailboxCount,
            StorageUsedBytes = StorageUsedBytes,
            CreatedUtc = CreatedUtc,
        };
    }

    private sealed class DomainDetailRow
    {
        public Guid Id { get; set; }

        public string Name { get; set; } = string.Empty;

        public string DisplayName { get; set; } = string.Empty;

        public int Status { get; set; }

        public string? MailHostname { get; set; }

        public string? ActiveDkimSelector { get; set; }

        public int CatchAllPolicy { get; set; }

        public string? CatchAllMailbox { get; set; }

        public long DefaultMailboxQuotaBytes { get; set; }

        public long DomainQuotaBytes { get; set; }

        public long MaxMessageSizeBytes { get; set; }

        public bool RequireTlsForOutbound { get; set; }

        public int MailboxCount { get; set; }

        public long StorageUsedBytes { get; set; }

        public DateTimeOffset CreatedUtc { get; set; }

        public DateTimeOffset? ModifiedUtc { get; set; }

        public DomainDetailDto ToDto() => new()
        {
            Id = Id,
            Name = Name,
            DisplayName = DisplayName,
            Status = (Domain.Enums.DomainStatus)Status,
            MailHostname = MailHostname,
            ActiveDkimSelector = ActiveDkimSelector,
            CatchAllPolicy = (Domain.Enums.CatchAllPolicy)CatchAllPolicy,
            CatchAllMailbox = CatchAllMailbox,
            DefaultMailboxQuotaBytes = DefaultMailboxQuotaBytes,
            DomainQuotaBytes = DomainQuotaBytes,
            MaxMessageSizeBytes = MaxMessageSizeBytes,
            RequireTlsForOutbound = RequireTlsForOutbound,
            MailboxCount = MailboxCount,

            // Aliases arrive with mailbox management in Milestone 5. Reported as zero rather
            // than omitted, so the DTO contract does not change when the table appears.
            AliasCount = 0,

            StorageUsedBytes = StorageUsedBytes,
            CreatedUtc = CreatedUtc,
            ModifiedUtc = ModifiedUtc,
        };
    }
}
