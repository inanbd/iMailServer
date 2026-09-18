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
}
