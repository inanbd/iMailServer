using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Writes a mailbox for IMAP.</summary>
/// <remarks>
/// Depends on the reader rather than repeating its SQL. The rows a <c>STORE</c> updates are
/// exactly the rows a <c>FETCH</c> of the same sequence set would return, including how <c>*</c>
/// resolves and how a reversed wildcard range behaves — and two implementations of that would be
/// two chances to disagree about which messages a client just changed.
/// </remarks>
internal sealed class ImapMailboxWriter(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect,
    ITransactionManager transactions,
    IImapMailboxReader reader)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IImapMailboxWriter
{
    /// <summary>
    /// How many UIDs go into one <c>UPDATE</c>.
    /// </summary>
    /// <remarks>
    /// Every UID in the batch becomes a bound parameter, and both providers cap those: SQLite's
    /// historical limit is 999 and SQL Server's is 2,100. Five hundred sits below both with room
    /// for the statement's own parameters, and a client that stores over a larger set simply gets
    /// more statements inside the one transaction rather than an error from the driver.
    /// </remarks>
    private const int UidBatchSize = 500;

    /// <summary>
    /// Sets one flag mask on a batch of messages.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The new value is computed in C# and written as a literal rather than derived in SQL with
    /// <c>|</c> and <c>&amp;~</c>. Not because the operators are unavailable — both providers have
    /// them — but because there is nothing left for the database to work out:
    /// <see cref="ImapStoreRequest.Apply"/> has already produced each message's final value, and
    /// that value is what <c>STORE</c> must report back. Deriving it a second time in SQL would be
    /// a second implementation of the one rule that must not differ, in a dialect where it could.
    /// </para>
    /// <para>
    /// <c>MailboxId</c> is in the <c>WHERE</c> clause beside <c>FolderId</c>, as in every read:
    /// the authorisation boundary does not weaken because the statement writes.
    /// </para>
    /// </remarks>
    private const string UpdateFlags = """
        UPDATE  Deliveries
        SET     Flags = @Flags
        WHERE   FolderId = @FolderId
          AND   MailboxId = @MailboxId
          AND   Uid IN @Uids
        """;

    public Task<IReadOnlyList<ImapMessageSummary>> StoreFlagsAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        ImapStoreRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(set);
        ArgumentNullException.ThrowIfNull(request);

        // One transaction around the read and the write, so the values reported back are the
        // values written - see IImapMailboxWriter's remarks on the race this closes.
        return transactions.ExecuteScopedAsync(
            async ct =>
            {
                IReadOnlyList<ImapMessageSummary> before = await reader
                    .ReadSummariesAsync(mailboxId, folderId, set, byUid, ct)
                    .ConfigureAwait(false);

                if (before.Count == 0)
                {
                    return before;
                }

                List<ImapMessageSummary> after = [];

                // Grouped by the value each message ends up with, because that is what makes one
                // statement per distinct outcome rather than one per message: a '+FLAGS (\Seen)'
                // over ten thousand messages has at most a handful of outcomes, however many
                // messages share each.
                Dictionary<MessageFlags, List<long>> byOutcome = [];

                foreach (ImapMessageSummary summary in before)
                {
                    MessageFlags updated = request.Apply(summary.Flags);

                    after.Add(summary with { Flags = updated });

                    if (updated == summary.Flags)
                    {
                        // Already in the requested state. Skipped for the write and still
                        // reported: RFC 3501 §6.4.6 returns "the new value of the flags", not
                        // "the flags that changed".
                        continue;
                    }

                    if (!byOutcome.TryGetValue(updated, out List<long>? uids))
                    {
                        uids = [];
                        byOutcome[updated] = uids;
                    }

                    uids.Add(summary.Uid);
                }

                await ExecuteAsync(
                    async (session, inner) =>
                    {
                        foreach ((MessageFlags flags, List<long> uids) in byOutcome)
                        {
                            for (int offset = 0; offset < uids.Count; offset += UidBatchSize)
                            {
                                long[] batch = [.. uids.Skip(offset).Take(UidBatchSize)];

                                await session.Connection
                                    .ExecuteAsync(Command(
                                        session,
                                        UpdateFlags,
                                        new
                                        {
                                            Flags = (int)flags,
                                            FolderId = folderId.Value,
                                            MailboxId = mailboxId.Value,
                                            Uids = batch,
                                        },
                                        inner))
                                    .ConfigureAwait(false);
                            }
                        }

                        return true;
                    },
                    ct).ConfigureAwait(false);

                return (IReadOnlyList<ImapMessageSummary>)after;
            },
            cancellationToken);
    }

    /// <summary>
    /// The positions and UIDs of every message carrying <c>\Deleted</c>, highest position first.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The position is computed by <c>ROW_NUMBER() OVER (ORDER BY Uid)</c> over the whole folder,
    /// exactly as the reader does, because RFC 3501 §2.3.1.2 makes a sequence number a position
    /// rather than a stored value. The <c>\Deleted</c> filter is applied outside that window, so
    /// the numbers are positions in the folder as the client sees it rather than positions among
    /// the deleted.
    /// </para>
    /// <para>
    /// <c>ORDER BY Seq DESC</c> is the response order, and it is the query's job rather than the
    /// caller's so that the rows arrive already in the order they must be reported — see
    /// <see cref="IImapMailboxWriter.ExpungeAsync"/> for why descending removes the arithmetic
    /// entirely.
    /// </para>
    /// </remarks>
    private const string SelectDeleted = """
        SELECT  Ordered.Seq, Ordered.Uid
        FROM    (SELECT ROW_NUMBER() OVER (ORDER BY Uid) AS Seq, Uid, Flags
                 FROM   Deliveries
                 WHERE  FolderId = @FolderId
                   AND  MailboxId = @MailboxId) AS Ordered
        WHERE   (Ordered.Flags & @DeletedFlag) <> 0
        ORDER BY Ordered.Seq DESC
        """;

    /// <summary>Removes a batch of deliveries by UID.</summary>
    /// <remarks>
    /// Only the <c>Deliveries</c> rows. The <c>Messages</c> row and its stored file survive by
    /// design — see <see cref="IImapMailboxWriter.ExpungeAsync"/>.
    /// </remarks>
    private const string DeleteDeliveries = """
        DELETE  FROM Deliveries
        WHERE   FolderId = @FolderId
          AND   MailboxId = @MailboxId
          AND   Uid IN @Uids
        """;

    /// <summary>Flat shape of one message marked for removal.</summary>
    private sealed class DeletedRow
    {
        public long Seq { get; set; }

        public long Uid { get; set; }
    }

    public Task<IReadOnlyList<long>> ExpungeAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        CancellationToken cancellationToken)
    {
        // One transaction around the read and the delete: a position computed against one state
        // of the folder and reported against another is how a client renumbers onto the wrong
        // message.
        return transactions.ExecuteScopedAsync(
            async ct =>
            {
                return await ExecuteAsync(
                    async (session, inner) =>
                    {
                        IEnumerable<DeletedRow> rows = await session.Connection
                            .QueryAsync<DeletedRow>(Command(
                                session,
                                SelectDeleted,
                                new
                                {
                                    FolderId = folderId.Value,
                                    MailboxId = mailboxId.Value,
                                    DeletedFlag = (int)MessageFlags.Deleted,
                                },
                                inner))
                            .ConfigureAwait(false);

                        List<DeletedRow> deleted = [.. rows];

                        if (deleted.Count == 0)
                        {
                            return (IReadOnlyList<long>)[];
                        }

                        long[] uids = [.. deleted.Select(r => r.Uid)];

                        for (int offset = 0; offset < uids.Length; offset += UidBatchSize)
                        {
                            long[] batch = [.. uids.Skip(offset).Take(UidBatchSize)];

                            await session.Connection
                                .ExecuteAsync(Command(
                                    session,
                                    DeleteDeliveries,
                                    new
                                    {
                                        FolderId = folderId.Value,
                                        MailboxId = mailboxId.Value,
                                        Uids = batch,
                                    },
                                    inner))
                                .ConfigureAwait(false);
                        }

                        return (IReadOnlyList<long>)[.. deleted.Select(r => r.Seq)];
                    },
                    ct).ConfigureAwait(false);
            },
            cancellationToken);
    }
}
