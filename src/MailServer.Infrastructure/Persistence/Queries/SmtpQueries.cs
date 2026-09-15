using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Common;
using MailServer.Application.Smtp.Dtos;
using MailServer.Domain.Enums;

namespace MailServer.Infrastructure.Persistence.Queries;

/// <summary>Flat shape of one received-message row.</summary>
internal sealed class ReceivedMessageRow
{
    public Guid Id { get; set; }

    public long SizeBytes { get; set; }

    public string ContentSha256 { get; set; } = string.Empty;

    public string? ReversePath { get; set; }

    public string RemoteAddress { get; set; } = string.Empty;

    public string? GreetedName { get; set; }

    public int ListenerRole { get; set; }

    public bool TlsActive { get; set; }

    public string? AuthenticatedAs { get; set; }

    public DateTimeOffset ReceivedUtc { get; set; }

    public DateTimeOffset? ContentRemovedUtc { get; set; }

    public int DeliveryCount { get; set; }
}

/// <summary>Flat shape of one recipient row.</summary>
internal sealed class ReceivedRecipientRow
{
    public Guid MessageId { get; set; }

    public string Address { get; set; } = string.Empty;

    public int RelayDecision { get; set; }
}

/// <summary>Read models for the SMTP screens.</summary>
/// <remarks>
/// <b>No query here selects message content, and there is no column it could select it from:</b>
/// the body is a file outside the database. That is a happy consequence of the storage design
/// rather than a rule this class has to remember.
/// </remarks>
internal sealed class SmtpQueries(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), ISmtpQueries
{
    public Task<PagedResult<ReceivedMessageDto>> SearchReceivedAsync(
        ReceivedMessageSearchRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Bounded here rather than trusted from the caller. The page size arrives over IPC, and
        // an administration client asking for a million rows would materialise a million rows.
        int pageSize = Math.Clamp(request.PageSize, 1, 500);
        int page = Math.Max(request.Page, 0);

        return ExecuteAsync(async (session, ct) =>
        {
            string search = string.IsNullOrWhiteSpace(request.Search)
                ? string.Empty
                : $"%{request.Search.Trim()}%";

            // Parameterised throughout. The search text comes from an administrator, but an
            // administrator is not a reason to concatenate SQL.
            const string Filter = """
                WHERE  (@Since IS NULL OR m.ReceivedUtc >= @Since)
                AND    (@HasSearch = 0
                        OR m.ReversePath   LIKE @Search
                        OR m.RemoteAddress LIKE @Search
                        OR EXISTS (SELECT 1 FROM MessageRecipients r
                                   WHERE r.MessageId = m.Id AND r.Address LIKE @Search))
                """;

            object parameters = new
            {
                Since = request.SinceUtc,
                HasSearch = search.Length == 0 ? 0 : 1,
                Search = search,
            };

            long total = await session.Connection.ExecuteScalarAsync<long>(Command(
                session,
                $"SELECT COUNT(*) FROM Messages m {Filter}",
                parameters,
                ct)).ConfigureAwait(false);

            string sql = $"""
                SELECT  m.Id, m.SizeBytes, m.ContentSha256, m.ReversePath, m.RemoteAddress,
                        m.GreetedName, m.ListenerRole, m.TlsActive, m.AuthenticatedAs,
                        m.ReceivedUtc, m.ContentRemovedUtc,
                        (SELECT COUNT(*) FROM Deliveries d WHERE d.MessageId = m.Id) AS DeliveryCount
                FROM    Messages m
                {Filter}
                ORDER BY m.ReceivedUtc DESC
                {Dialect.PagingClause(pageSize, page * pageSize)}
                """;

            ReceivedMessageRow[] rows =
            [
                .. await session.Connection
                    .QueryAsync<ReceivedMessageRow>(Command(session, sql, parameters, ct))
                    .ConfigureAwait(false)
            ];

            if (rows.Length == 0)
            {
                return new PagedResult<ReceivedMessageDto>([], page, pageSize, total);
            }

            // One extra round trip for the whole page's recipients, rather than one per row.
            // A page of fifty messages would otherwise be fifty-one queries, on a screen an
            // operator refreshes while chasing a delivery problem.
            Guid[] ids = [.. rows.Select(r => r.Id)];

            ReceivedRecipientRow[] recipientRows =
            [
                .. await session.Connection
                    .QueryAsync<ReceivedRecipientRow>(Command(
                        session,
                        """
                        SELECT MessageId, Address, RelayDecision
                        FROM   MessageRecipients
                        WHERE  MessageId IN @Ids
                        ORDER BY Address
                        """,
                        new { Ids = ids },
                        ct))
                    .ConfigureAwait(false)
            ];

            ILookup<Guid, ReceivedRecipientRow> byMessage = recipientRows.ToLookup(r => r.MessageId);

            ReceivedMessageDto[] items =
            [
                .. rows.Select(row => new ReceivedMessageDto
                {
                    Id = row.Id,
                    SizeBytes = row.SizeBytes,
                    ContentSha256 = row.ContentSha256,
                    ReversePath = row.ReversePath,
                    RemoteAddress = row.RemoteAddress,
                    GreetedName = row.GreetedName,
                    ListenerRole = (SmtpListenerRole)row.ListenerRole,
                    TlsActive = row.TlsActive,
                    AuthenticatedAs = row.AuthenticatedAs,
                    ReceivedUtc = row.ReceivedUtc,
                    ContentRemovedUtc = row.ContentRemovedUtc,
                    DeliveryCount = row.DeliveryCount,
                    Recipients =
                    [
                        .. byMessage[row.Id].Select(r =>
                            new ReceivedRecipientDto(r.Address, (RelayDecision)r.RelayDecision)),
                    ],
                })
            ];

            return new PagedResult<ReceivedMessageDto>(items, page, pageSize, total);
        }, cancellationToken);
    }

    public Task<(long LastDay, long LastHour, long StoredBytes)> GetThroughputAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            long lastDay = await session.Connection.ExecuteScalarAsync<long>(Command(
                session,
                "SELECT COUNT(*) FROM Messages WHERE ReceivedUtc >= @Since",
                new { Since = now.AddDays(-1) },
                ct)).ConfigureAwait(false);

            long lastHour = await session.Connection.ExecuteScalarAsync<long>(Command(
                session,
                "SELECT COUNT(*) FROM Messages WHERE ReceivedUtc >= @Since",
                new { Since = now.AddHours(-1) },
                ct)).ConfigureAwait(false);

            // Only messages whose content is still on disk. Counting the rest would report
            // storage that retention has already reclaimed.
            long storedBytes = await session.Connection.ExecuteScalarAsync<long?>(Command(
                session,
                "SELECT SUM(SizeBytes) FROM Messages WHERE ContentRemovedUtc IS NULL",
                null,
                ct)).ConfigureAwait(false) ?? 0;

            return (lastDay, lastHour, storedBytes);
        }, cancellationToken);
}
