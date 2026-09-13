using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Common;
using MailServer.Application.Security.Dtos;
using MailServer.Domain.Enums;

namespace MailServer.Infrastructure.Persistence.Queries;

/// <summary>Read side for the audit trail.</summary>
internal sealed class AuditQueries(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IAuditQueries
{
    public Task<PagedResult<AuditRecordDto>> SearchAsync(
        AuditSearchRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        return ExecuteAsync(async (session, ct) =>
        {
            List<string> conditions = [];
            DynamicParameters parameters = new();

            if (request.FromUtc is { } from)
            {
                conditions.Add("TimestampUtc >= @FromUtc");
                parameters.Add("FromUtc", from);
            }

            if (request.ToUtc is { } to)
            {
                conditions.Add("TimestampUtc <= @ToUtc");
                parameters.Add("ToUtc", to);
            }

            if (!string.IsNullOrWhiteSpace(request.Action))
            {
                conditions.Add("Action = @Action");
                parameters.Add("Action", request.Action);
            }

            if (!string.IsNullOrWhiteSpace(request.Administrator))
            {
                conditions.Add("Administrator = @Administrator");
                parameters.Add("Administrator", request.Administrator);
            }

            if (request.Result is { } result)
            {
                conditions.Add("Result = @Result");
                parameters.Add("Result", (int)result);
            }

            if (!string.IsNullOrWhiteSpace(request.CorrelationId))
            {
                conditions.Add("CorrelationId = @CorrelationId");
                parameters.Add("CorrelationId", request.CorrelationId);
            }

            string where = conditions.Count == 0
                ? string.Empty
                : "WHERE " + string.Join(" AND ", conditions);

            // Newest first, with the id as a tie-break so paging is stable when several rows
            // share a timestamp - which happens routinely, because one operation can write
            // several audit records inside a single transaction.
            string sql = $"""
                SELECT  Id, TimestampUtc, Administrator, Action, TargetType, TargetIdentifier,
                        Result, Detail, MachineName, CorrelationId
                FROM    AuditRecords
                {where}
                ORDER BY TimestampUtc DESC, Id DESC
                {Dialect.PagingClause(request.PageSize, request.Skip)}
                """;

            IEnumerable<AuditRow> rows = await session.Connection
                .QueryAsync<AuditRow>(Command(session, sql, parameters, ct))
                .ConfigureAwait(false);

            IReadOnlyList<AuditRecordDto> items = [.. rows.Select(r => r.ToDto())];

            long? total = null;
            if (request.IncludeTotalCount)
            {
                total = await session.Connection
                    .ExecuteScalarAsync<long>(Command(
                        session,
                        $"SELECT COUNT(1) FROM AuditRecords {where}",
                        parameters,
                        ct))
                    .ConfigureAwait(false);
            }

            return new PagedResult<AuditRecordDto>(items, request.Page, request.PageSize, total);
        }, cancellationToken);
    }

    private sealed class AuditRow
    {
        public Guid Id { get; set; }

        public DateTimeOffset TimestampUtc { get; set; }

        public string Administrator { get; set; } = string.Empty;

        public string Action { get; set; } = string.Empty;

        public string TargetType { get; set; } = string.Empty;

        public string? TargetIdentifier { get; set; }

        public int Result { get; set; }

        public string? Detail { get; set; }

        public string MachineName { get; set; } = string.Empty;

        public string CorrelationId { get; set; } = string.Empty;

        public AuditRecordDto ToDto() => new()
        {
            Id = Id,
            TimestampUtc = TimestampUtc,
            Administrator = Administrator,
            Action = Action,
            TargetType = TargetType,
            TargetIdentifier = TargetIdentifier,
            Result = (AuditResult)Result,
            Detail = Detail,
            MachineName = MachineName,
            CorrelationId = CorrelationId,
        };
    }
}

/// <summary>Read side for the security event log.</summary>
internal sealed class SecurityEventQueries(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), ISecurityEventQueries
{
    public Task<PagedResult<SecurityEventDto>> SearchAsync(
        SecurityEventSearchRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        return ExecuteAsync(async (session, ct) =>
        {
            List<string> conditions = [];
            DynamicParameters parameters = new();

            if (request.FromUtc is { } from)
            {
                conditions.Add("TimestampUtc >= @FromUtc");
                parameters.Add("FromUtc", from);
            }

            if (request.ToUtc is { } to)
            {
                conditions.Add("TimestampUtc <= @ToUtc");
                parameters.Add("ToUtc", to);
            }

            if (request.EventTypes is { Count: > 0 })
            {
                // Dapper expands this into a parameterised IN list; the values never touch
                // the SQL text.
                conditions.Add("EventType IN @EventTypes");
                parameters.Add("EventTypes", request.EventTypes.Select(t => (int)t).ToArray());
            }

            if (request.AlarmingOnly)
            {
                conditions.Add("IsAlarming = @Alarming");
                parameters.Add("Alarming", true);
            }

            string where = conditions.Count == 0
                ? string.Empty
                : "WHERE " + string.Join(" AND ", conditions);

            string sql = $"""
                SELECT  Id, TimestampUtc, EventType, Subject, Origin, Description,
                        CorrelationId, IsAlarming
                FROM    SecurityEvents
                {where}
                ORDER BY TimestampUtc DESC, Id DESC
                {Dialect.PagingClause(request.PageSize, request.Skip)}
                """;

            IEnumerable<SecurityEventRow> rows = await session.Connection
                .QueryAsync<SecurityEventRow>(Command(session, sql, parameters, ct))
                .ConfigureAwait(false);

            IReadOnlyList<SecurityEventDto> items = [.. rows.Select(r => r.ToDto())];

            long? total = null;
            if (request.IncludeTotalCount)
            {
                total = await session.Connection
                    .ExecuteScalarAsync<long>(Command(
                        session,
                        $"SELECT COUNT(1) FROM SecurityEvents {where}",
                        parameters,
                        ct))
                    .ConfigureAwait(false);
            }

            return new PagedResult<SecurityEventDto>(items, request.Page, request.PageSize, total);
        }, cancellationToken);
    }

    public Task<int> CountFailedSignInsSinceAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken) =>
        ExecuteAsync((session, ct) => session.Connection.ExecuteScalarAsync<int>(Command(
            session,
            """
            SELECT COUNT(1)
            FROM   SecurityEvents
            WHERE  TimestampUtc >= @SinceUtc
              AND  EventType IN @FailureTypes
            """,
            new
            {
                SinceUtc = sinceUtc,
                FailureTypes = new[]
                {
                    (int)SecurityEventType.AdminSignInFailed,
                    (int)SecurityEventType.AdminSignInBlockedByLockout,
                    (int)SecurityEventType.RecoveryKeyRejected,
                },
            },
            ct)), cancellationToken);

    private sealed class SecurityEventRow
    {
        public Guid Id { get; set; }

        public DateTimeOffset TimestampUtc { get; set; }

        public int EventType { get; set; }

        public string? Subject { get; set; }

        public string? Origin { get; set; }

        public string Description { get; set; } = string.Empty;

        public string CorrelationId { get; set; } = string.Empty;

        public bool IsAlarming { get; set; }

        public SecurityEventDto ToDto() => new()
        {
            Id = Id,
            TimestampUtc = TimestampUtc,
            EventType = (SecurityEventType)EventType,
            Subject = Subject,
            Origin = Origin,
            Description = Description,
            CorrelationId = CorrelationId,
            IsAlarming = IsAlarming,
        };
    }
}
