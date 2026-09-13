using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Monitoring.Dtos;
using MailServer.Domain.Enums;

namespace MailServer.Infrastructure.Persistence.Queries;

/// <summary>
/// Dashboard counters.
/// </summary>
/// <remarks>
/// One round trip returning every counter, rather than six separate queries. The dashboard
/// refreshes on a timer in every open admin console, so its cost is multiplied by the number
/// of operators watching.
/// </remarks>
internal sealed class ServerStatusQueries(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IServerStatusQueries
{
    public Task<ServerCountersDto> GetCountersAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            // Scalar subqueries in one statement. From Milestone 8, when the queue table can
            // hold millions of rows, the queue counters move to a rolled-up metrics table -
            // COUNT(*) over a large queue on every dashboard refresh is exactly the query
            // that takes a busy mail server down.
            const string Sql = """
                SELECT
                    (SELECT COUNT(1) FROM Domains)                              AS DomainCount,
                    (SELECT COUNT(1) FROM Domains WHERE Status = @ActiveStatus) AS ActiveDomainCount,
                    (SELECT COUNT(1) FROM Mailboxes)                            AS MailboxCount,
                    (SELECT COALESCE(SUM(StorageUsedBytes), 0) FROM Mailboxes)  AS StorageUsedBytes
                """;

            CounterRow row = await session.Connection
                .QuerySingleAsync<CounterRow>(Command(
                    session,
                    Sql,
                    new { ActiveStatus = (int)DomainStatus.Active },
                    ct))
                .ConfigureAwait(false);

            return new ServerCountersDto
            {
                DomainCount = row.DomainCount,
                ActiveDomainCount = row.ActiveDomainCount,
                MailboxCount = row.MailboxCount,

                // The outbound queue arrives in Milestone 8. Reported as zero rather than
                // omitted, so the DTO contract does not change when the table appears.
                QueuedMessageCount = 0,
                DeferredMessageCount = 0,

                StorageUsedBytes = row.StorageUsedBytes,
            };
        }, cancellationToken);

    private sealed class CounterRow
    {
        public int DomainCount { get; set; }

        public int ActiveDomainCount { get; set; }

        public int MailboxCount { get; set; }

        public long StorageUsedBytes { get; set; }
    }
}
