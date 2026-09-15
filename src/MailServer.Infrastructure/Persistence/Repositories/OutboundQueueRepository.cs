using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of an <c>OutboundQueueItems</c> row.</summary>
internal sealed class QueueItemRow
{
    public Guid Id { get; set; }

    public Guid MessageId { get; set; }

    public Guid RecipientId { get; set; }

    public string DestinationAddress { get; set; } = string.Empty;

    public string? ReversePath { get; set; }

    public bool RequireTls { get; set; }

    public bool IsDsn { get; set; }

    public int Priority { get; set; }

    public int Status { get; set; }

    public int AttemptCount { get; set; }

    public DateTimeOffset FirstQueuedUtc { get; set; }

    public DateTimeOffset NextAttemptUtc { get; set; }

    public string? LeaseOwner { get; set; }

    public DateTimeOffset? LeaseExpiresUtc { get; set; }

    public DateTimeOffset? DelayWarningSentUtc { get; set; }

    public string? LastFailureReason { get; set; }

    public DateTimeOffset ModifiedUtc { get; set; }
}

/// <summary>Persists the outbound queue and its delivery attempt history.</summary>
internal sealed class OutboundQueueRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IOutboundQueueRepository
{
    // The updatable-CTE form of the canonical SQL Server queue-claim pattern: TOP + ORDER BY
    // inside the CTE selects which rows are in scope, READPAST/UPDLOCK/ROWLOCK let concurrent
    // workers skip each other's in-flight rows rather than block on them, and OUTPUT returns
    // the post-update row in the same statement.
    private const string SqlServerClaimSql = """
        WITH Candidates AS (
            SELECT TOP (@MaxItems) *
            FROM OutboundQueueItems WITH (READPAST, UPDLOCK, ROWLOCK)
            WHERE (Status IN (0, 2) AND NextAttemptUtc <= @NowUtc)
               OR (Status = 1 AND LeaseExpiresUtc <= @NowUtc)
            ORDER BY Priority, NextAttemptUtc
        )
        UPDATE Candidates
        SET Status = 1,
            AttemptCount = AttemptCount + 1,
            LeaseOwner = @LeaseOwner,
            LeaseExpiresUtc = @LeaseExpiresUtc,
            ModifiedUtc = @NowUtc
        OUTPUT inserted.*;
        """;

    // SQLite's UPDATE ... RETURNING form. A single statement, not select-then-update: two
    // workers racing for the same row cannot both win, because there is no gap between reading
    // "is this due" and writing "I claimed it" for another connection to land in.
    private const string SqliteClaimSql = """
        UPDATE OutboundQueueItems
        SET Status = 1,
            AttemptCount = AttemptCount + 1,
            LeaseOwner = @LeaseOwner,
            LeaseExpiresUtc = @LeaseExpiresUtc,
            ModifiedUtc = @NowUtc
        WHERE Id IN (
            SELECT Id FROM OutboundQueueItems
            WHERE (Status IN (0, 2) AND NextAttemptUtc <= @NowUtc)
               OR (Status = 1 AND LeaseExpiresUtc <= @NowUtc)
            ORDER BY Priority, NextAttemptUtc
            LIMIT @MaxItems
        )
        RETURNING *;
        """;

    public Task AddAsync(OutboundQueueItem item, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(item);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO OutboundQueueItems
                    (Id, MessageId, RecipientId, DestinationAddress, DestinationDomain,
                     ReversePath, RequireTls, IsDsn, Priority, Status, AttemptCount,
                     FirstQueuedUtc, NextAttemptUtc, LeaseOwner, LeaseExpiresUtc,
                     DelayWarningSentUtc, LastFailureReason, CreatedUtc, ModifiedUtc)
                VALUES
                    (@Id, @MessageId, @RecipientId, @DestinationAddress, @DestinationDomain,
                     @ReversePath, @RequireTls, @IsDsn, @Priority, @Status, @AttemptCount,
                     @FirstQueuedUtc, @NextAttemptUtc, @LeaseOwner, @LeaseExpiresUtc,
                     @DelayWarningSentUtc, @LastFailureReason, @CreatedUtc, @ModifiedUtc)
                """,
                new
                {
                    Id = item.Id.Value,
                    MessageId = item.MessageId.Value,
                    item.RecipientId,
                    DestinationAddress = item.DestinationAddress.NormalizedValue,
                    DestinationDomain = item.DestinationDomain.Value,

                    // Null here is the null reverse path: a real and meaningful sender, kept so
                    // this item can never be mistaken for one that should generate a DSN.
                    ReversePath = item.ReversePath?.NormalizedValue,

                    item.RequireTls,
                    item.IsDsn,
                    item.Priority,
                    Status = (int)item.Status,
                    item.AttemptCount,
                    item.FirstQueuedUtc,
                    item.NextAttemptUtc,
                    item.LeaseOwner,
                    item.LeaseExpiresUtc,
                    item.DelayWarningSentUtc,
                    item.LastFailureReason,
                    CreatedUtc = item.ModifiedUtc,
                    item.ModifiedUtc,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task<IReadOnlyList<OutboundQueueItem>> ClaimDueAsync(
        string leaseOwner,
        int maxItems,
        TimeSpan leaseDuration,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(leaseOwner);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxItems, 0);

        string sql = Dialect.Name switch
        {
            "Sqlite" => SqliteClaimSql,
            "SqlServer" => SqlServerClaimSql,
            _ => throw new NotSupportedException(
                $"No outbound queue claim statement is defined for dialect '{Dialect.Name}'."),
        };

        return ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<QueueItemRow> rows = await session.Connection.QueryAsync<QueueItemRow>(Command(
                session,
                sql,
                new
                {
                    LeaseOwner = leaseOwner,
                    MaxItems = maxItems,
                    LeaseExpiresUtc = nowUtc + leaseDuration,
                    NowUtc = nowUtc,
                },
                ct)).ConfigureAwait(false);

            return (IReadOnlyList<OutboundQueueItem>)[.. rows.Select(ToEntity)];
        }, cancellationToken);
    }

    public Task UpdateAsync(OutboundQueueItem item, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(item);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE OutboundQueueItems
                SET Status              = @Status,
                    AttemptCount        = @AttemptCount,
                    NextAttemptUtc      = @NextAttemptUtc,
                    LeaseOwner          = @LeaseOwner,
                    LeaseExpiresUtc     = @LeaseExpiresUtc,
                    DelayWarningSentUtc = @DelayWarningSentUtc,
                    LastFailureReason   = @LastFailureReason,
                    ModifiedUtc         = @ModifiedUtc
                WHERE Id = @Id
                """,
                new
                {
                    Id = item.Id.Value,
                    Status = (int)item.Status,
                    item.AttemptCount,
                    item.NextAttemptUtc,
                    item.LeaseOwner,
                    item.LeaseExpiresUtc,
                    item.DelayWarningSentUtc,
                    item.LastFailureReason,
                    item.ModifiedUtc,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task AddAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attempt);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO DeliveryAttempts
                    (Id, QueueItemId, AttemptNumber, StartedUtc, CompletedUtc, MxHostname,
                     RemoteAddress, TlsActive, TlsProtocol, TlsCipher, PeerCertificateSubject,
                     PeerCertificateIssuer, ReplyCode, EnhancedStatus, ReplyText, Outcome,
                     FailureClassification, ErrorDetail, CreatedUtc)
                VALUES
                    (@Id, @QueueItemId, @AttemptNumber, @StartedUtc, @CompletedUtc, @MxHostname,
                     @RemoteAddress, @TlsActive, @TlsProtocol, @TlsCipher, @PeerCertificateSubject,
                     @PeerCertificateIssuer, @ReplyCode, @EnhancedStatus, @ReplyText, @Outcome,
                     @FailureClassification, @ErrorDetail, @CreatedUtc)
                """,
                new
                {
                    attempt.Id,
                    QueueItemId = attempt.QueueItemId.Value,
                    attempt.AttemptNumber,
                    attempt.StartedUtc,
                    attempt.CompletedUtc,
                    attempt.MxHostname,
                    RemoteAddress = attempt.RemoteAddress?.Value,
                    attempt.TlsActive,
                    TlsProtocol = attempt.TlsProtocol,
                    attempt.TlsCipher,
                    attempt.PeerCertificateSubject,
                    attempt.PeerCertificateIssuer,
                    attempt.ReplyCode,
                    attempt.EnhancedStatus,
                    attempt.ReplyText,
                    Outcome = (int)attempt.Outcome,
                    FailureClassification = (int)attempt.Classification,
                    attempt.ErrorDetail,
                    CreatedUtc = attempt.CompletedUtc,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task ReleaseLeaseAsync(string leaseOwner, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(leaseOwner);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE OutboundQueueItems
                SET Status = 0,
                    LeaseOwner = NULL,
                    LeaseExpiresUtc = NULL,
                    NextAttemptUtc = @NowUtc,
                    ModifiedUtc = @NowUtc
                WHERE LeaseOwner = @LeaseOwner AND Status = 1
                """,
                new { LeaseOwner = leaseOwner, NowUtc = nowUtc },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task<QueueDepth> GetDepthAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            DepthRow row = await session.Connection.QuerySingleAsync<DepthRow>(Command(
                session,
                """
                SELECT
                    COALESCE(SUM(CASE WHEN Status IN (0, 2) THEN 1 ELSE 0 END), 0) AS Pending,
                    COALESCE(SUM(CASE WHEN Status = 1 THEN 1 ELSE 0 END), 0)       AS Processing,
                    MIN(CASE WHEN Status IN (0, 2) THEN FirstQueuedUtc ELSE NULL END) AS OldestPendingUtc
                FROM OutboundQueueItems
                """,
                null,
                ct)).ConfigureAwait(false);

            return new QueueDepth(row.Pending, row.Processing, row.OldestPendingUtc);
        }, cancellationToken);

    private static OutboundQueueItem ToEntity(QueueItemRow row) =>
        OutboundQueueItem.Rehydrate(
            new QueueId(row.Id),
            new StoredMessageId(row.MessageId),
            row.RecipientId,
            EmailAddress.Parse(row.DestinationAddress),
            row.ReversePath is null ? null : EmailAddress.Parse(row.ReversePath),
            row.RequireTls,
            row.IsDsn,
            row.Priority,
            (QueueStatus)row.Status,
            row.AttemptCount,
            row.FirstQueuedUtc,
            row.NextAttemptUtc,
            row.LeaseOwner,
            row.LeaseExpiresUtc,
            row.DelayWarningSentUtc,
            row.LastFailureReason,
            row.ModifiedUtc);

    private sealed class DepthRow
    {
        public int Pending { get; set; }

        public int Processing { get; set; }

        public DateTimeOffset? OldestPendingUtc { get; set; }
    }
}
