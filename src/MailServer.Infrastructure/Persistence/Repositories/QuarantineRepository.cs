using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Filtering;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of a <c>QuarantinedMessages</c> row.</summary>
internal sealed class QuarantinedMessageRow
{
    public Guid Id { get; set; }

    public Guid MessageId { get; set; }

    public string? ReversePath { get; set; }

    public string RemoteAddress { get; set; } = string.Empty;

    public double Score { get; set; }

    public string Summary { get; set; } = string.Empty;

    public int Status { get; set; }

    public DateTimeOffset QuarantinedUtc { get; set; }

    public DateTimeOffset? ResolvedUtc { get; set; }

    public string? ResolvedBy { get; set; }

    public DateTimeOffset ExpiresUtc { get; set; }
}

/// <summary>The two columns the retention sweep reads.</summary>
/// <remarks>
/// A named type rather than a value tuple because Dapper maps by column name onto settable
/// members, and a tuple's <c>Item1</c>/<c>Item2</c> are neither.
/// </remarks>
internal sealed class ExpiredQuarantineRow
{
    public Guid Id { get; set; }

    public Guid MessageId { get; set; }
}

/// <summary>Flat shape of a <c>QuarantineSignals</c> row.</summary>
internal sealed class QuarantineSignalRow
{
    public Guid QuarantinedMessageId { get; set; }

    public string Name { get; set; } = string.Empty;

    public double Score { get; set; }

    public string Detail { get; set; } = string.Empty;
}

/// <summary>
/// Stores held messages and their reasons.
/// </summary>
/// <remarks>
/// <para>
/// <b>Resolution is a conditional update, not a read followed by a write.</b> Two
/// administrators looking at the same quarantine at the same time is the ordinary case, not a
/// race worth ignoring: whoever clicks second must be told it was already handled rather than
/// delivering the message a second time. <c>WHERE Status = 0</c> and the affected-row count are
/// what make that a fact about the database rather than a hope about timing.
/// </para>
/// <para>
/// <b>Signals are read in one query per listing, not one per message.</b> A quarantine of two
/// hundred messages would otherwise be two hundred and one round trips to render a grid.
/// </para>
/// </remarks>
internal sealed class QuarantineRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IQuarantineRepository
{
    public Task AddAsync(QuarantinedMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO QuarantinedMessages
                    (Id, MessageId, ReversePath, RemoteAddress, Score, Summary,
                     Status, QuarantinedUtc, ResolvedUtc, ResolvedBy, ExpiresUtc)
                VALUES
                    (@Id, @MessageId, @ReversePath, @RemoteAddress, @Score, @Summary,
                     @Status, @QuarantinedUtc, NULL, NULL, @ExpiresUtc)
                """,
                new
                {
                    Id = message.Id.Value,
                    MessageId = message.MessageId.Value,
                    ReversePath = message.ReversePath?.Value,
                    RemoteAddress = message.RemoteAddress.ToString(),
                    message.Score,
                    message.Summary,
                    Status = (int)message.Status,
                    message.QuarantinedUtc,
                    message.ExpiresUtc,
                },
                ct)).ConfigureAwait(false);

            int ordinal = 0;

            foreach (FilterSignal signal in message.Signals)
            {
                await session.Connection.ExecuteAsync(Command(
                    session,
                    """
                    INSERT INTO QuarantineSignals
                        (Id, QuarantinedMessageId, Name, Score, Detail, Ordinal)
                    VALUES
                        (@Id, @QuarantinedMessageId, @Name, @Score, @Detail, @Ordinal)
                    """,
                    new
                    {
                        Id = Guid.CreateVersion7(),
                        QuarantinedMessageId = message.Id.Value,
                        signal.Name,
                        signal.Score,
                        signal.Detail,
                        Ordinal = ordinal++,
                    },
                    ct)).ConfigureAwait(false);
            }

            return true;
        }, cancellationToken);
    }

    public Task<QuarantinedMessage?> GetAsync(
        QuarantinedMessageId id,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            QuarantinedMessageRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<QuarantinedMessageRow>(Command(
                    session,
                    """
                    SELECT Id, MessageId, ReversePath, RemoteAddress, Score, Summary,
                           Status, QuarantinedUtc, ResolvedUtc, ResolvedBy, ExpiresUtc
                    FROM   QuarantinedMessages
                    WHERE  Id = @Id
                    """,
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            if (row is null)
            {
                return null;
            }

            IEnumerable<QuarantineSignalRow> signals = await session.Connection
                .QueryAsync<QuarantineSignalRow>(Command(
                    session,
                    """
                    SELECT QuarantinedMessageId, Name, Score, Detail
                    FROM   QuarantineSignals
                    WHERE  QuarantinedMessageId = @Id
                    ORDER BY Ordinal
                    """,
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return Rehydrate(row, [.. signals]);
        }, cancellationToken);

    public Task<IReadOnlyList<QuarantinedMessage>> ListAsync(
        QuarantineFilter filter,
        int limit,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);

        return ExecuteAsync(async (session, ct) =>
        {
            string where = filter == QuarantineFilter.Held ? "WHERE Status = 0" : string.Empty;

            string sql = $"""
                SELECT Id, MessageId, ReversePath, RemoteAddress, Score, Summary,
                       Status, QuarantinedUtc, ResolvedUtc, ResolvedBy, ExpiresUtc
                FROM   QuarantinedMessages
                {where}
                ORDER BY QuarantinedUtc DESC
                {Dialect.PagingClause(limit, 0)}
                """;

            List<QuarantinedMessageRow> rows = [.. await session.Connection
                .QueryAsync<QuarantinedMessageRow>(Command(session, sql, null, ct))
                .ConfigureAwait(false)];

            if (rows.Count == 0)
            {
                return (IReadOnlyList<QuarantinedMessage>)[];
            }

            // One query for every signal on the page rather than one per row: a quarantine of
            // two hundred messages would otherwise be two hundred and one round trips.
            IEnumerable<QuarantineSignalRow> signals = await session.Connection
                .QueryAsync<QuarantineSignalRow>(Command(
                    session,
                    """
                    SELECT QuarantinedMessageId, Name, Score, Detail
                    FROM   QuarantineSignals
                    WHERE  QuarantinedMessageId IN @Ids
                    ORDER BY QuarantinedMessageId, Ordinal
                    """,
                    new { Ids = rows.Select(r => r.Id).ToArray() },
                    ct))
                .ConfigureAwait(false);

            ILookup<Guid, QuarantineSignalRow> byMessage = signals.ToLookup(s => s.QuarantinedMessageId);

            return (IReadOnlyList<QuarantinedMessage>)
                [.. rows.Select(r => Rehydrate(r, [.. byMessage[r.Id]]))];
        }, cancellationToken);
    }

    public Task<int> CountHeldAsync(CancellationToken cancellationToken) =>
        ExecuteAsync((session, ct) => session.Connection.ExecuteScalarAsync<int>(Command(
            session,
            "SELECT COUNT(1) FROM QuarantinedMessages WHERE Status = 0",
            null,
            ct)), cancellationToken);

    public Task<bool> TryResolveAsync(QuarantinedMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        return ExecuteAsync(async (session, ct) =>
        {
            // WHERE Status = 0 is what makes this safe against two administrators resolving the
            // same message at once. The row count is the answer to "was it me who resolved it",
            // and the caller delivers only when it was.
            int affected = await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE QuarantinedMessages
                SET    Status = @Status,
                       ResolvedUtc = @ResolvedUtc,
                       ResolvedBy = @ResolvedBy
                WHERE  Id = @Id
                AND    Status = 0
                """,
                new
                {
                    Id = message.Id.Value,
                    Status = (int)message.Status,
                    message.ResolvedUtc,
                    message.ResolvedBy,
                },
                ct)).ConfigureAwait(false);

            return affected == 1;
        }, cancellationToken);
    }

    public Task<IReadOnlyList<StoredMessageId>> PurgeExpiredAsync(
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);

        return ExecuteAsync(async (session, ct) =>
        {
            // Read first, delete second, and report what was deleted: the caller removes the
            // content, and a sweep that deleted the rows without saying which messages they
            // named would leave those files behind with nothing pointing at them.
            string select = $"""
                SELECT Id, MessageId
                FROM   QuarantinedMessages
                WHERE  Status = 0
                AND    ExpiresUtc <= @Now
                ORDER BY ExpiresUtc
                {Dialect.PagingClause(limit, 0)}
                """;

            List<ExpiredQuarantineRow> expired = [.. await session.Connection
                .QueryAsync<ExpiredQuarantineRow>(Command(session, select, new { Now = now }, ct))
                .ConfigureAwait(false)];

            if (expired.Count == 0)
            {
                return (IReadOnlyList<StoredMessageId>)[];
            }

            await session.Connection.ExecuteAsync(Command(
                session,
                "DELETE FROM QuarantinedMessages WHERE Id IN @Ids",
                new { Ids = expired.Select(e => e.Id).ToArray() },
                ct)).ConfigureAwait(false);

            return (IReadOnlyList<StoredMessageId>)
                [.. expired.Select(e => new StoredMessageId(e.MessageId))];
        }, cancellationToken);
    }

    private static QuarantinedMessage Rehydrate(
        QuarantinedMessageRow row,
        IReadOnlyList<QuarantineSignalRow> signals) =>
        QuarantinedMessage.Rehydrate(
            new QuarantinedMessageId(row.Id),
            new StoredMessageId(row.MessageId),
            row.ReversePath is { Length: > 0 } sender && EmailAddress.TryParse(sender, out EmailAddress? parsed)
                ? parsed
                : null,
            IpAddressValue.Parse(row.RemoteAddress),
            row.Score,
            row.Summary,
            [.. signals.Select(s => new FilterSignal(s.Name, s.Score, s.Detail))],
            row.QuarantinedUtc,
            row.ExpiresUtc,
            (QuarantineStatus)row.Status,
            row.ResolvedUtc,
            row.ResolvedBy);
}
