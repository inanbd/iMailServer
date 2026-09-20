using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of a <c>TlsReports</c> row.</summary>
internal sealed class TlsReportRow
{
    public Guid Id { get; set; }

    public string PolicyDomain { get; set; } = string.Empty;

    public string? OrganizationName { get; set; }

    public string? ContactInfo { get; set; }

    public string? ReportId { get; set; }

    public DateTimeOffset? StartUtc { get; set; }

    public DateTimeOffset? EndUtc { get; set; }

    public long SuccessfulSessionCount { get; set; }

    public long FailedSessionCount { get; set; }

    public string Summary { get; set; } = string.Empty;

    public DateTimeOffset CollectedUtc { get; set; }
}

/// <summary>Flat shape of a <c>TlsReportFailures</c> row.</summary>
internal sealed class TlsReportFailureRow
{
    public Guid TlsReportId { get; set; }

    public string ResultType { get; set; } = string.Empty;

    public long FailedSessionCount { get; set; }

    public string? ReceivingMxHostnames { get; set; }
}

/// <summary>
/// Stores collected TLS reports and remembers which messages have been looked at.
/// </summary>
/// <remarks>
/// <b>The domain is lower-cased on the way in.</b> The unique index folds reports from one
/// sender about one domain together, and leaving the folding to the column's collation would
/// make it happen on a default-collation SQL Server and not on SQLite — the divergence
/// <c>docs/IMAP.md</c> records for folder names, reappearing where it would silently split one
/// sender's history in two. Normalising here makes both providers agree.
/// </remarks>
internal sealed class TlsReportRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), ITlsReportRepository
{
    public Task<IReadOnlyList<StoredMessageId>> ListUnexaminedAsync(
        MailboxId mailboxId,
        int limit,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);

        return ExecuteAsync(async (session, ct) =>
        {
            // Oldest first, so a backlog is worked through in the order it arrived and a
            // bounded pass makes progress rather than re-reading the same newest few.
            string sql = $"""
                SELECT   d.MessageId
                FROM     Deliveries d
                LEFT JOIN TlsReportSources s ON s.MessageId = d.MessageId
                WHERE    d.MailboxId = @MailboxId
                AND      s.MessageId IS NULL
                ORDER BY d.InternalDate ASC
                {Dialect.PagingClause(limit, 0)}
                """;

            IEnumerable<Guid> ids = await session.Connection
                .QueryAsync<Guid>(Command(session, sql, new { MailboxId = mailboxId.Value }, ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<StoredMessageId>)[.. ids.Select(id => new StoredMessageId(id))];
        }, cancellationToken);
    }

    public Task<bool> RecordAsync(
        StoredMessageId messageId,
        string policyDomain,
        TlsReport report,
        DateTimeOffset collectedUtc,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyDomain);
        ArgumentNullException.ThrowIfNull(report);

        return ExecuteAsync(async (session, ct) =>
        {
            string domain = policyDomain.Trim().ToLowerInvariant();

            // Asked before inserting rather than caught afterwards, because the answer changes
            // what is written: a duplicate report still marks its message examined, so the
            // message is not opened again on the next pass.
            bool alreadyHeld = report.ReportId is { Length: > 0 } && await session.Connection
                .ExecuteScalarAsync<int>(Command(
                    session,
                    """
                    SELECT COUNT(1)
                    FROM   TlsReports
                    WHERE  PolicyDomain = @PolicyDomain
                    AND    ReportId = @ReportId
                    AND    ((OrganizationName IS NULL AND @OrganizationName IS NULL)
                            OR OrganizationName = @OrganizationName)
                    """,
                    new
                    {
                        PolicyDomain = domain,
                        report.ReportId,
                        report.OrganizationName,
                    },
                    ct))
                .ConfigureAwait(false) > 0;

            Guid? reportRowId = null;

            if (!alreadyHeld)
            {
                reportRowId = Guid.NewGuid();

                await session.Connection.ExecuteAsync(Command(
                    session,
                    """
                    INSERT INTO TlsReports
                        (Id, PolicyDomain, OrganizationName, ContactInfo, ReportId,
                         StartUtc, EndUtc, SuccessfulSessionCount, FailedSessionCount,
                         Summary, CollectedUtc)
                    VALUES
                        (@Id, @PolicyDomain, @OrganizationName, @ContactInfo, @ReportId,
                         @StartUtc, @EndUtc, @SuccessfulSessionCount, @FailedSessionCount,
                         @Summary, @CollectedUtc)
                    """,
                    new
                    {
                        Id = reportRowId,
                        PolicyDomain = domain,
                        report.OrganizationName,
                        report.ContactInfo,
                        report.ReportId,
                        StartUtc = report.StartDate,
                        EndUtc = report.EndDate,
                        report.SuccessfulSessionCount,
                        report.FailedSessionCount,
                        Summary = report.Summarise(),
                        CollectedUtc = collectedUtc,
                    },
                    ct)).ConfigureAwait(false);

                foreach (TlsFailureSummary failure in report.FailuresByImpact())
                {
                    await session.Connection.ExecuteAsync(Command(
                        session,
                        """
                        INSERT INTO TlsReportFailures
                            (Id, TlsReportId, ResultType, FailedSessionCount, ReceivingMxHostnames)
                        VALUES
                            (@Id, @TlsReportId, @ResultType, @FailedSessionCount, @ReceivingMxHostnames)
                        """,
                        new
                        {
                            Id = Guid.NewGuid(),
                            TlsReportId = reportRowId,
                            ResultType = TlsReport.NameOf(failure.Result),
                            failure.FailedSessionCount,
                            ReceivingMxHostnames = failure.ReceivingMxHostnames.Count == 0
                                ? null
                                : string.Join(", ", failure.ReceivingMxHostnames),
                        },
                        ct)).ConfigureAwait(false);
                }
            }

            await MarkExaminedAsync(session, messageId, reportRowId, null, collectedUtc, ct)
                .ConfigureAwait(false);

            return !alreadyHeld;
        }, cancellationToken);
    }

    public Task RecordFailureAsync(
        StoredMessageId messageId,
        string error,
        DateTimeOffset examinedUtc,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            await MarkExaminedAsync(session, messageId, null, error, examinedUtc, ct)
                .ConfigureAwait(false);

            return true;
        }, cancellationToken);

    public Task<IReadOnlyList<CollectedTlsReport>> ListRecentAsync(
        string policyDomain,
        int limit,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyDomain);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);

        return ExecuteAsync(async (session, ct) =>
        {
            string domain = policyDomain.Trim().ToLowerInvariant();

            string sql = $"""
                SELECT   Id, PolicyDomain, OrganizationName, ContactInfo, ReportId,
                         StartUtc, EndUtc, SuccessfulSessionCount, FailedSessionCount,
                         Summary, CollectedUtc
                FROM     TlsReports
                WHERE    PolicyDomain = @PolicyDomain
                ORDER BY CollectedUtc DESC
                {Dialect.PagingClause(limit, 0)}
                """;

            List<TlsReportRow> rows = [.. await session.Connection
                .QueryAsync<TlsReportRow>(Command(session, sql, new { PolicyDomain = domain }, ct))
                .ConfigureAwait(false)];

            if (rows.Count == 0)
            {
                return (IReadOnlyList<CollectedTlsReport>)[];
            }

            // One query for every report's failures rather than one per report: a listing of
            // twenty reports would otherwise be twenty-one round trips to render one page.
            IEnumerable<TlsReportFailureRow> failures = await session.Connection
                .QueryAsync<TlsReportFailureRow>(Command(
                    session,
                    """
                    SELECT   TlsReportId, ResultType, FailedSessionCount, ReceivingMxHostnames
                    FROM     TlsReportFailures
                    WHERE    TlsReportId IN @Ids
                    ORDER BY FailedSessionCount DESC
                    """,
                    new { Ids = rows.Select(r => r.Id).ToArray() },
                    ct))
                .ConfigureAwait(false);

            ILookup<Guid, TlsReportFailureRow> byReport = failures.ToLookup(f => f.TlsReportId);

            return (IReadOnlyList<CollectedTlsReport>)
            [
                .. rows.Select(r => new CollectedTlsReport(
                    r.Id,
                    r.PolicyDomain,
                    r.OrganizationName,
                    r.ContactInfo,
                    r.ReportId,
                    r.StartUtc,
                    r.EndUtc,
                    r.SuccessfulSessionCount,
                    r.FailedSessionCount,
                    r.Summary,
                    r.CollectedUtc,
                    [
                        .. byReport[r.Id].Select(f => new TlsFailureSummary(
                            TlsReport.ReadResult(f.ResultType),
                            f.FailedSessionCount,
                            Hostnames(f.ReceivingMxHostnames))),
                    ])),
            ];
        }, cancellationToken);
    }

    private static IReadOnlyList<string> Hostnames(string? packed) =>
        string.IsNullOrWhiteSpace(packed)
            ? []
            : [.. packed.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    /// <summary>
    /// Records that a message has been looked at, whatever came of it.
    /// </summary>
    /// <remarks>
    /// An upsert rather than an insert, because a pass interrupted between writing the report
    /// and marking the message would otherwise leave a row that a later pass could not write
    /// over — and would then re-collect a report it already holds on every pass.
    /// </remarks>
    private static async Task MarkExaminedAsync(
        IDbSession session,
        StoredMessageId messageId,
        Guid? reportId,
        string? error,
        DateTimeOffset examinedUtc,
        CancellationToken cancellationToken)
    {
        int updated = await session.Connection.ExecuteAsync(Command(
            session,
            """
            UPDATE TlsReportSources
            SET    TlsReportId = @TlsReportId, Error = @Error, ExaminedUtc = @ExaminedUtc
            WHERE  MessageId = @MessageId
            """,
            new
            {
                MessageId = messageId.Value,
                TlsReportId = reportId,
                Error = error,
                ExaminedUtc = examinedUtc,
            },
            cancellationToken)).ConfigureAwait(false);

        if (updated > 0)
        {
            return;
        }

        await session.Connection.ExecuteAsync(Command(
            session,
            """
            INSERT INTO TlsReportSources (MessageId, TlsReportId, Error, ExaminedUtc)
            VALUES (@MessageId, @TlsReportId, @Error, @ExaminedUtc)
            """,
            new
            {
                MessageId = messageId.Value,
                TlsReportId = reportId,
                Error = error,
                ExaminedUtc = examinedUtc,
            },
            cancellationToken)).ConfigureAwait(false);
    }
}
