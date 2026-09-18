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
}
