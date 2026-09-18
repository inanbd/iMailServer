using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of the two aggregates <c>SELECT</c> needs over a folder's deliveries.</summary>
internal sealed class FolderAggregateRow
{
    public long ExistsCount { get; set; }

    /// <summary>Null when every message in the folder has been read.</summary>
    public long? FirstUnseen { get; set; }
}

/// <summary>The three columns a <c>LIST</c> or <c>LSUB</c> line is built from.</summary>
internal sealed class FolderPathRow
{
    public string Path { get; set; } = string.Empty;

    public int SpecialUse { get; set; }

    public bool IsSubscribed { get; set; }
}

/// <summary>Flat shape of the two counts <c>STATUS</c> needs over a folder's deliveries.</summary>
internal sealed class FolderStatusRow
{
    public long MessageCount { get; set; }

    public long UnseenCount { get; set; }
}

/// <summary>Flat shape of one message's stored facts, as <c>FETCH</c> reports them.</summary>
internal sealed class MessageSummaryRow
{
    public long Seq { get; set; }

    public long Uid { get; set; }

    public int Flags { get; set; }

    public DateTimeOffset InternalDate { get; set; }

    public long SizeBytes { get; set; }
}

/// <summary>Reads a mailbox for IMAP.</summary>
internal sealed class ImapMailboxReader(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IImapMailboxReader
{
    /// <summary>
    /// The folder, scoped to its owner.
    /// </summary>
    /// <remarks>
    /// <c>MailboxId</c> is in the <c>WHERE</c> clause rather than checked afterwards. The unique
    /// index is on <c>(MailboxId, Path)</c>, so this is the index's own shape as well as the
    /// authorisation boundary — a session cannot name another mailbox's folder and get a row
    /// back, however it came by the name.
    /// </remarks>
    private const string SelectFolder = """
        SELECT  Id, MailboxId, Path, SpecialUse, UidValidity, NextUid, IsSubscribed,
                CreatedUtc, ModifiedUtc
        FROM    MailboxFolders
        WHERE   MailboxId = @MailboxId
          AND   Path = @Path
        """;

    /// <summary>
    /// The message count and the first unseen message's sequence number, in one statement.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Sequence numbers are positions, not stored values.</b> RFC 3501 §2.3.1.2: a message
    /// sequence number is "the relative position from 1 to the number of messages in the
    /// mailbox", ordered by UID. So the first unseen message's sequence number cannot be looked
    /// up — it has to be counted — and <c>ROW_NUMBER() OVER (ORDER BY Uid)</c> is that count
    /// expressed where the index already provides the ordering. Both providers have supported
    /// the window function for years; nothing here needs a dialect of its own.
    /// </para>
    /// <para>
    /// One statement, not two, because the two numbers must describe the same instant — see
    /// <see cref="ImapFolderSnapshot"/>'s remarks on what a client does when they disagree.
    /// </para>
    /// <para>
    /// <c>\Seen</c> is passed as a parameter rather than written as the literal <c>1</c>, so the
    /// bit and <see cref="MessageFlags.Seen"/> cannot drift apart without the compiler noticing.
    /// </para>
    /// </remarks>
    private const string SelectFolderAggregates = """
        SELECT
            (SELECT COUNT(*)
             FROM   Deliveries
             WHERE  FolderId = @FolderId) AS ExistsCount,
            (SELECT MIN(Ordered.Seq)
             FROM   (SELECT ROW_NUMBER() OVER (ORDER BY Uid) AS Seq, Flags
                     FROM   Deliveries
                     WHERE  FolderId = @FolderId) AS Ordered
             WHERE  (Ordered.Flags & @SeenFlag) = 0) AS FirstUnseen
        """;

    public Task<ImapFolderSnapshot?> OpenFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);

        return ExecuteAsync(async (session, ct) =>
        {
            MailboxFolderRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<MailboxFolderRow>(Command(
                    session,
                    SelectFolder,
                    new { MailboxId = mailboxId.Value, Path = ImapMailboxPath.Canonical(path) },
                    ct))
                .ConfigureAwait(false);

            if (row is null)
            {
                // Not an error and not an exception: a client asking for a folder that is not
                // there is ordinary, and RFC 3501 §6.3.1 has the server answer a tagged NO.
                return null;
            }

            MailboxFolder folder = new(
                new MailboxFolderId(row.Id),
                new MailboxId(row.MailboxId),
                row.Path,
                (FolderSpecialUse)row.SpecialUse,
                row.UidValidity,
                row.NextUid,
                row.IsSubscribed,
                row.CreatedUtc,
                row.ModifiedUtc);

            FolderAggregateRow aggregates = await session.Connection
                .QuerySingleAsync<FolderAggregateRow>(Command(
                    session,
                    SelectFolderAggregates,
                    new { FolderId = row.Id, SeenFlag = (int)MessageFlags.Seen },
                    ct))
                .ConfigureAwait(false);

            return new ImapFolderSnapshot(folder, aggregates.ExistsCount, aggregates.FirstUnseen);
        }, cancellationToken);
    }

    /// <summary>
    /// Every folder path in a mailbox, with its role and subscription.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No <c>ORDER BY</c>, deliberately. Ordering happens in memory under
    /// <see cref="StringComparer.Ordinal"/>, because no database guarantees that collation:
    /// SQLite's default for <c>TEXT</c> is binary, SQL Server's is whatever the column was
    /// created with — commonly case-insensitive — and the two disagree about where
    /// <c>Projects/2026</c> sits relative to <c>projects</c>. Two providers returning a client's
    /// folder tree in two different orders is the kind of difference that only shows up in
    /// production.
    /// </para>
    /// <para>
    /// <c>NextUid</c>, <c>UidValidity</c> and the timestamps are not selected. A listing must not
    /// report them — see <see cref="ImapFolderListing"/> — and a column not read cannot be
    /// reported by mistake.
    /// </para>
    /// </remarks>
    private const string SelectFolderPaths = """
        SELECT  Path, SpecialUse, IsSubscribed
        FROM    MailboxFolders
        WHERE   MailboxId = @MailboxId
        """;

    public Task<IReadOnlyList<ImapFolderListing>> ListFoldersAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken)
    {
        return ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<FolderPathRow> rows = await session.Connection
                .QueryAsync<FolderPathRow>(Command(
                    session,
                    SelectFolderPaths,
                    new { MailboxId = mailboxId.Value },
                    ct))
                .ConfigureAwait(false);

            return Listings(rows);
        }, cancellationToken);
    }

    /// <summary>Turns folder rows into listings, deciding <c>\HasChildren</c> for the whole set.</summary>
    /// <remarks>
    /// The child question is answered by <see cref="ImapMailboxPattern.ParentsAmong"/>, whose own
    /// remarks explain why it is asked of the set rather than of each folder — and why the
    /// obvious faster version is wrong.
    /// </remarks>
    private static IReadOnlyList<ImapFolderListing> Listings(IEnumerable<FolderPathRow> rows)
    {
        List<FolderPathRow> ordered = [.. rows];

        ordered.Sort(static (left, right) => string.CompareOrdinal(left.Path, right.Path));

        IReadOnlySet<string> parents = ImapMailboxPattern.ParentsAmong(ordered.Select(r => r.Path));

        List<ImapFolderListing> listings = new(ordered.Count);

        foreach (FolderPathRow row in ordered)
        {
            listings.Add(new ImapFolderListing(
                row.Path,
                (FolderSpecialUse)row.SpecialUse,
                row.IsSubscribed,
                parents.Contains(row.Path)));
        }

        return listings;
    }

    /// <summary>
    /// How many messages a folder holds and how many are unread, in one statement.
    /// </summary>
    /// <remarks>
    /// Two counts over the same predicate rather than a count and a position, which is the whole
    /// difference between this and <see cref="SelectFolderAggregates"/> — and the reason there is
    /// no window function here. Both are plain counts over
    /// <c>IX_Deliveries_Folder_Uid</c>'s leading column.
    /// </remarks>
    private const string SelectFolderCounts = """
        SELECT
            (SELECT COUNT(*)
             FROM   Deliveries
             WHERE  FolderId = @FolderId) AS MessageCount,
            (SELECT COUNT(*)
             FROM   Deliveries
             WHERE  FolderId = @FolderId
               AND  (Flags & @SeenFlag) = 0) AS UnseenCount
        """;

    public Task<ImapFolderStatus?> ReadStatusAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);

        return ExecuteAsync(async (session, ct) =>
        {
            MailboxFolderRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<MailboxFolderRow>(Command(
                    session,
                    SelectFolder,
                    new { MailboxId = mailboxId.Value, Path = ImapMailboxPath.Canonical(path) },
                    ct))
                .ConfigureAwait(false);

            if (row is null)
            {
                return null;
            }

            MailboxFolder folder = new(
                new MailboxFolderId(row.Id),
                new MailboxId(row.MailboxId),
                row.Path,
                (FolderSpecialUse)row.SpecialUse,
                row.UidValidity,
                row.NextUid,
                row.IsSubscribed,
                row.CreatedUtc,
                row.ModifiedUtc);

            FolderStatusRow counts = await session.Connection
                .QuerySingleAsync<FolderStatusRow>(Command(
                    session,
                    SelectFolderCounts,
                    new { FolderId = row.Id, SeenFlag = (int)MessageFlags.Seen },
                    ct))
                .ConfigureAwait(false);

            return new ImapFolderStatus(folder, counts.MessageCount, counts.UnseenCount);
        }, cancellationToken);
    }

    /// <summary>
    /// Every message in a folder, numbered, optionally narrowed to a span.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ROW_NUMBER() OVER (ORDER BY Uid)</c> is the sequence number, for the reason
    /// <see cref="SelectFolderAggregates"/> gives: RFC 3501 §2.3.1.2 makes it "the relative
    /// position from 1 to the number of messages in the mailbox", so it is counted rather than
    /// looked up. The window runs over the whole folder and the narrowing is applied outside it,
    /// which is what keeps a narrowed read's numbers the same as an unnarrowed one's.
    /// </para>
    /// <para>
    /// The size comes from <c>Messages</c> because a message stored once and delivered to two
    /// folders has one size; the flags and the internal date come from <c>Deliveries</c> because
    /// each copy carries its own.
    /// </para>
    /// <para>
    /// <c>@Lowest</c> and <c>@Highest</c> are a single span rather than the set's own ranges. A
    /// set may hold up to <see cref="ImapSequenceSet.MaxSegments"/> of them, and turning those
    /// into a predicate would build a SQL string a client controls the length of — so the query
    /// narrows to the one span that contains them all and the exact filtering happens in memory,
    /// where the matcher is <see cref="ImapSequenceSet.Contains"/> and has tests. A null span
    /// means no narrowing at all, which is what a <c>*</c> requires.
    /// </para>
    /// </remarks>
    private const string SelectSummaries = """
        SELECT  Ordered.Seq, Ordered.Uid, Ordered.Flags, Ordered.InternalDate, Ordered.SizeBytes
        FROM    (SELECT ROW_NUMBER() OVER (ORDER BY d.Uid) AS Seq,
                        d.Uid, d.Flags, d.InternalDate, m.SizeBytes
                 FROM   Deliveries d
                 JOIN   Messages m ON m.Id = d.MessageId
                 WHERE  d.FolderId = @FolderId
                   AND  d.MailboxId = @MailboxId) AS Ordered
        WHERE   (@Lowest IS NULL OR @Highest IS NULL)
             OR (CASE WHEN @ByUid = 1 THEN Ordered.Uid ELSE Ordered.Seq END
                 BETWEEN @Lowest AND @Highest)
        ORDER BY Ordered.Seq
        """;

    public Task<IReadOnlyList<ImapMessageSummary>> ReadSummariesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(set);

        // A '*' means "the largest in use", which is not known until the folder has been read -
        // and narrowing on the literals anyway would be wrong rather than merely unhelpful, as
        // ImapSequenceSet.HasWildcard's own remarks work through.
        (long Lowest, long Highest)? span = set.HasWildcard ? null : set.LiteralBounds;

        return ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<MessageSummaryRow> rows = await session.Connection
                .QueryAsync<MessageSummaryRow>(Command(
                    session,
                    SelectSummaries,
                    new
                    {
                        FolderId = folderId.Value,
                        MailboxId = mailboxId.Value,
                        ByUid = byUid ? 1 : 0,
                        Lowest = span?.Lowest,
                        Highest = span?.Highest,
                    },
                    ct))
                .ConfigureAwait(false);

            return Summaries([.. rows], set, byUid);
        }, cancellationToken);
    }

    /// <summary>
    /// Filters the rows a span returned down to the ones the set actually names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What <c>*</c> resolves to is read off the rows, not queried for separately.</b> The
    /// window ran over the whole folder, so with no narrowing the last row's sequence number is
    /// the message count and its UID is the largest UID — the two things §9's <c>*</c> can mean,
    /// both true of the same instant as everything else here. A second query for either would
    /// let a delivery land between them.
    /// </para>
    /// <para>
    /// When the query <i>was</i> narrowed, the last row's number is not the folder's maximum —
    /// and nothing reads it as one, because narrowing only happens when the set holds no
    /// <c>*</c>, and a set with no <c>*</c> resolves without consulting a maximum at all.
    /// </para>
    /// <para>
    /// Zero is the right maximum for an empty folder: a set resolved against it selects nothing,
    /// which is what an empty folder should return, and §6.4.8 is explicit that finding nothing
    /// is not an error.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<ImapMessageSummary> Summaries(
        IReadOnlyList<MessageSummaryRow> rows,
        ImapSequenceSet set,
        bool byUid)
    {
        if (rows.Count == 0)
        {
            return [];
        }

        MessageSummaryRow last = rows[^1];
        long maxValue = byUid ? last.Uid : last.Seq;

        List<ImapMessageSummary> summaries = [];

        foreach (MessageSummaryRow row in rows)
        {
            if (set.Contains(byUid ? row.Uid : row.Seq, maxValue))
            {
                summaries.Add(new ImapMessageSummary(
                    row.Seq,
                    row.Uid,
                    (MessageFlags)row.Flags,
                    row.InternalDate,
                    row.SizeBytes));
            }
        }

        return summaries;
    }
}
