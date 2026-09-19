using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
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

    private const string SelectFolderIdByPath = """
        SELECT  Id
        FROM    MailboxFolders
        WHERE   MailboxId = @MailboxId
          AND   Path = @Path
        """;

    private const string SelectSubtreePaths = """
        SELECT  Id, Path
        FROM    MailboxFolders
        WHERE   MailboxId = @MailboxId
        """;

    private const string InsertFolder = """
        INSERT INTO MailboxFolders
                    (Id, MailboxId, Path, SpecialUse, UidValidity, NextUid, IsSubscribed,
                     CreatedUtc)
        VALUES      (@Id, @MailboxId, @Path, 0, @UidValidity, 1, 0, @Now)
        """;

    private const string UpdateFolderPath = """
        UPDATE  MailboxFolders
        SET     Path = @Path, ModifiedUtc = @Now
        WHERE   Id = @Id
          AND   MailboxId = @MailboxId
        """;

    private const string DeleteFolderRow = """
        DELETE  FROM MailboxFolders
        WHERE   Id = @Id
          AND   MailboxId = @MailboxId
        """;

    private const string DeleteFolderDeliveries = """
        DELETE  FROM Deliveries
        WHERE   FolderId = @FolderId
          AND   MailboxId = @MailboxId
        """;

    private const string MoveDeliveries = """
        UPDATE  Deliveries
        SET     FolderId = @ToFolderId
        WHERE   FolderId = @FromFolderId
          AND   MailboxId = @MailboxId
        """;

    /// <summary>One folder's identity and name, for the subtree walks below.</summary>
    private sealed class FolderIdentityRow
    {
        public Guid Id { get; set; }

        public string Path { get; set; } = string.Empty;
    }

    public Task<ImapFolderMutation> CreateFolderAsync(
        MailboxId mailboxId,
        string path,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);

        // §6.3.3: "In any case, the name created is without the trailing hierarchy delimiter."
        // The suffix is a declaration of intent, not part of the name, and the RFC tells a server
        // that does not need the declaration to "MUST ignore" it.
        string wanted = path.TrimEnd(MailboxFolder.PathSeparator);

        if (ImapMailboxPath.IsInbox(wanted))
        {
            return Task.FromResult(ImapFolderMutation.Reserved);
        }

        return transactions.ExecuteScopedAsync(
            ct => ExecuteAsync(
                async (session, inner) =>
                {
                    HashSet<string> existing = await ExistingPathsAsync(session, mailboxId, inner)
                        .ConfigureAwait(false);

                    if (existing.Contains(wanted))
                    {
                        return ImapFolderMutation.AlreadyExists;
                    }

                    long uidValidity = await NextUidValidityAsync(session, inner, mailboxId, now)
                        .ConfigureAwait(false);

                    // Every level from the outermost inwards, so a parent is always inserted
                    // before its child - §6.3.3's "SHOULD create any superior hierarchical names".
                    List<string> levels = [.. ImapMailboxPattern.HierarchyLevelsOf(wanted), wanted];

                    foreach (string level in levels)
                    {
                        if (existing.Contains(level))
                        {
                            continue;
                        }

                        MailboxFolder folder;

                        try
                        {
                            // Constructed through the entity so its own validation runs: path
                            // length, depth and control characters are refused in one place.
                            folder = MailboxFolder.Create(
                                mailboxId,
                                level,
                                FolderSpecialUse.None,
                                uidValidity,
                                now);
                        }
                        catch (DomainRuleViolationException)
                        {
                            return ImapFolderMutation.Invalid;
                        }

                        await session.Connection.ExecuteAsync(Command(
                            session,
                            InsertFolder,
                            new
                            {
                                Id = folder.Id.Value,
                                MailboxId = mailboxId.Value,
                                Path = folder.Path,
                                UidValidity = folder.UidValidity,
                                Now = now,
                            },
                            inner)).ConfigureAwait(false);
                    }

                    return ImapFolderMutation.Done;
                },
                ct),
            cancellationToken);
    }

    public Task<ImapFolderMutation> DeleteFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (ImapMailboxPath.IsInbox(path))
        {
            return Task.FromResult(ImapFolderMutation.Reserved);
        }

        return transactions.ExecuteScopedAsync(
            ct => ExecuteAsync(
                async (session, inner) =>
                {
                    Guid? folderId = await session.Connection
                        .QuerySingleOrDefaultAsync<Guid?>(Command(
                            session,
                            SelectFolderIdByPath,
                            new { MailboxId = mailboxId.Value, Path = path },
                            inner))
                        .ConfigureAwait(false);

                    if (folderId is null)
                    {
                        return ImapFolderMutation.NotFound;
                    }

                    // The deliveries first, then the row. Nothing nested beneath the name is
                    // touched - §6.3.4's "MUST NOT remove inferior hierarchical names" - and
                    // nothing in MailboxSubscriptions is touched either, per §6.3.6.
                    await session.Connection.ExecuteAsync(Command(
                        session,
                        DeleteFolderDeliveries,
                        new { FolderId = folderId.Value, MailboxId = mailboxId.Value },
                        inner)).ConfigureAwait(false);

                    await session.Connection.ExecuteAsync(Command(
                        session,
                        DeleteFolderRow,
                        new { Id = folderId.Value, MailboxId = mailboxId.Value },
                        inner)).ConfigureAwait(false);

                    return ImapFolderMutation.Done;
                },
                ct),
            cancellationToken);
    }

    public Task<ImapFolderMutation> RenameFolderAsync(
        MailboxId mailboxId,
        string from,
        string to,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(from);
        ArgumentNullException.ThrowIfNull(to);

        string target = to.TrimEnd(MailboxFolder.PathSeparator);

        if (ImapMailboxPath.IsInbox(target))
        {
            // The destination is the one reserved name, so this would be a create of INBOX.
            return Task.FromResult(ImapFolderMutation.AlreadyExists);
        }

        return transactions.ExecuteScopedAsync(
            ct => ExecuteAsync(
                async (session, inner) =>
                {
                    IEnumerable<FolderIdentityRow> rows = await session.Connection
                        .QueryAsync<FolderIdentityRow>(Command(
                            session,
                            SelectSubtreePaths,
                            new { MailboxId = mailboxId.Value },
                            inner))
                        .ConfigureAwait(false);

                    List<FolderIdentityRow> all = [.. rows];

                    if (all.Exists(r => string.Equals(r.Path, target, StringComparison.Ordinal)))
                    {
                        return ImapFolderMutation.AlreadyExists;
                    }

                    FolderIdentityRow? source = all.Find(
                        r => string.Equals(r.Path, ImapMailboxPath.Canonical(from), StringComparison.Ordinal));

                    if (source is null)
                    {
                        return ImapFolderMutation.NotFound;
                    }

                    if (ImapMailboxPath.IsInbox(from))
                    {
                        return await RenameInboxAsync(
                            session, inner, mailboxId, source, target, now).ConfigureAwait(false);
                    }

                    // The subtree: the folder itself and everything strictly beneath it. The
                    // prefix is path + separator, so a sibling whose name merely starts the same
                    // way is untouched - the distinction ImapMailboxPattern.ParentsAmong makes.
                    string prefix = source.Path + MailboxFolder.PathSeparator;

                    List<FolderIdentityRow> subtree =
                    [
                        source,
                        .. all.Where(r => r.Path.StartsWith(prefix, StringComparison.Ordinal)),
                    ];

                    // Superior levels of the destination, per §6.3.5's SHOULD.
                    ImapFolderMutation parents = await EnsureParentsAsync(
                        session, inner, mailboxId, all, target, now).ConfigureAwait(false);

                    if (parents != ImapFolderMutation.Done)
                    {
                        return parents;
                    }

                    foreach (FolderIdentityRow row in subtree)
                    {
                        string renamed = target + row.Path[source.Path.Length..];

                        if (renamed.Length > MailboxFolder.MaxPathLength)
                        {
                            return ImapFolderMutation.Invalid;
                        }

                        await session.Connection.ExecuteAsync(Command(
                            session,
                            UpdateFolderPath,
                            new
                            {
                                Id = row.Id,
                                MailboxId = mailboxId.Value,
                                Path = renamed,
                                Now = now,
                            },
                            inner)).ConfigureAwait(false);
                    }

                    return ImapFolderMutation.Done;
                },
                ct),
            cancellationToken);
    }

    /// <summary>
    /// RFC 3501 §6.3.5's special case: the inbox stays, its messages leave, its children stay.
    /// </summary>
    /// <remarks>
    /// "It moves all messages in INBOX to a new mailbox with the given name, leaving INBOX empty.
    /// If the server implementation supports inferior hierarchical names of INBOX, these are
    /// unaffected by a rename of INBOX." Three departures from an ordinary rename, which is why
    /// this is a separate method rather than a branch inside one.
    /// </remarks>
    private async Task<ImapFolderMutation> RenameInboxAsync(
        IDbSession session,
        CancellationToken cancellationToken,
        MailboxId mailboxId,
        FolderIdentityRow inbox,
        string target,
        DateTimeOffset now)
    {
        MailboxFolder created;

        try
        {
            created = MailboxFolder.Create(
                mailboxId,
                target,
                FolderSpecialUse.None,
                await NextUidValidityAsync(session, cancellationToken, mailboxId, now)
                    .ConfigureAwait(false),
                now);
        }
        catch (DomainRuleViolationException)
        {
            return ImapFolderMutation.Invalid;
        }

        await session.Connection.ExecuteAsync(Command(
            session,
            InsertFolder,
            new
            {
                Id = created.Id.Value,
                MailboxId = mailboxId.Value,
                Path = created.Path,
                UidValidity = created.UidValidity,
                Now = now,
            },
            cancellationToken)).ConfigureAwait(false);

        // The messages move; the inbox row and its children stay exactly where they are.
        await session.Connection.ExecuteAsync(Command(
            session,
            MoveDeliveries,
            new
            {
                ToFolderId = created.Id.Value,
                FromFolderId = inbox.Id,
                MailboxId = mailboxId.Value,
            },
            cancellationToken)).ConfigureAwait(false);

        return ImapFolderMutation.Done;
    }

    /// <summary>Creates any superior level of <paramref name="target"/> that is missing.</summary>
    private async Task<ImapFolderMutation> EnsureParentsAsync(
        IDbSession session,
        CancellationToken cancellationToken,
        MailboxId mailboxId,
        IReadOnlyList<FolderIdentityRow> existing,
        string target,
        DateTimeOffset now)
    {
        HashSet<string> present = new(existing.Select(r => r.Path), StringComparer.Ordinal);

        foreach (string level in ImapMailboxPattern.HierarchyLevelsOf(target))
        {
            if (present.Contains(level))
            {
                continue;
            }

            MailboxFolder folder;

            try
            {
                folder = MailboxFolder.Create(
                    mailboxId,
                    level,
                    FolderSpecialUse.None,
                    await NextUidValidityAsync(session, cancellationToken, mailboxId, now)
                        .ConfigureAwait(false),
                    now);
            }
            catch (DomainRuleViolationException)
            {
                return ImapFolderMutation.Invalid;
            }

            await session.Connection.ExecuteAsync(Command(
                session,
                InsertFolder,
                new
                {
                    Id = folder.Id.Value,
                    MailboxId = mailboxId.Value,
                    Path = folder.Path,
                    UidValidity = folder.UidValidity,
                    Now = now,
                },
                cancellationToken)).ConfigureAwait(false);

            present.Add(level);
        }

        return ImapFolderMutation.Done;
    }

    /// <summary>
    /// A UIDVALIDITY for a folder about to be created.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The clock, floored to one above the highest value this mailbox has ever issued. The clock
    /// alone is what
    /// <c>MailboxCommands.CreateStandardFoldersAsync</c> uses and it is fine for provisioning,
    /// where the folders are new; it is not fine here, where a name can be deleted and created
    /// again. RFC 3501 §6.3.3 requires a recreated mailbox's UIDs to exceed the previous
    /// incarnation's "UNLESS the new incarnation has a different unique identifier validity
    /// value", and this server takes the exception — so the value must actually differ, or a
    /// client serves cached mail under UIDs that now name different messages.
    /// </para>
    /// <para>
    /// <b>A value derived only from surviving folders would not be enough, and the gap is not
    /// narrow.</b> The deleted folder's UIDVALIDITY leaves with its row, so a delete and an
    /// immediate recreate would reissue whatever the clock says — the same number, with UIDs
    /// restarting at 1. That is why <c>MailboxUidValidity</c> exists: a per-mailbox high-water
    /// mark that outlives the folder, in the same shape and for the same reason as the
    /// subscription list.
    /// </para>
    /// </remarks>
    private static async Task<long> NextUidValidityAsync(
        IDbSession session,
        CancellationToken cancellationToken,
        MailboxId mailboxId,
        DateTimeOffset now)
    {
        // Two sources, because neither alone is enough. The high-water mark remembers values
        // whose folders have been deleted; the folder maximum covers a mailbox that predates the
        // mark or was written by an older build. The clock keeps the numbers meaningful.
        long stored = await session.Connection
            .ExecuteScalarAsync<long?>(Command(
                session,
                "SELECT Highest FROM MailboxUidValidity WHERE MailboxId = @MailboxId",
                new { MailboxId = mailboxId.Value },
                cancellationToken))
            .ConfigureAwait(false) ?? 0;

        long inUse = await session.Connection
            .ExecuteScalarAsync<long?>(Command(
                session,
                "SELECT MAX(UidValidity) FROM MailboxFolders WHERE MailboxId = @MailboxId",
                new { MailboxId = mailboxId.Value },
                cancellationToken))
            .ConfigureAwait(false) ?? 0;

        long next = Math.Max(now.ToUnixTimeSeconds(), Math.Max(stored, inUse) + 1);

        // Delete-then-insert rather than an UPSERT, which SQLite and SQL Server spell
        // differently. Inside the caller's transaction, so the mark and the folder that used it
        // are written together or not at all.
        await session.Connection.ExecuteAsync(Command(
            session,
            "DELETE FROM MailboxUidValidity WHERE MailboxId = @MailboxId",
            new { MailboxId = mailboxId.Value },
            cancellationToken)).ConfigureAwait(false);

        await session.Connection.ExecuteAsync(Command(
            session,
            "INSERT INTO MailboxUidValidity (MailboxId, Highest) VALUES (@MailboxId, @Highest)",
            new { MailboxId = mailboxId.Value, Highest = next },
            cancellationToken)).ConfigureAwait(false);

        return next;
    }

    private static async Task<HashSet<string>> ExistingPathsAsync(
        IDbSession session,
        MailboxId mailboxId,
        CancellationToken cancellationToken)
    {
        IEnumerable<string> paths = await session.Connection
            .QueryAsync<string>(Command(
                session,
                "SELECT Path FROM MailboxFolders WHERE MailboxId = @MailboxId",
                new { MailboxId = mailboxId.Value },
                cancellationToken))
            .ConfigureAwait(false);

        return new HashSet<string>(paths, StringComparer.Ordinal);
    }

    /// <summary>The columns a copy carries over, for the source messages a set names.</summary>
    /// <remarks>
    /// <c>MessageId</c> is the point: a copy is a second <c>Deliveries</c> row against the same
    /// <c>Messages</c> row, so the stored content is never duplicated however large it is.
    /// </remarks>
    private const string SelectDeliveriesForCopy = """
        SELECT  Uid, MessageId, Flags, InternalDate
        FROM    Deliveries
        WHERE   FolderId = @FolderId
          AND   MailboxId = @MailboxId
          AND   Uid IN @Uids
        ORDER BY Uid
        """;

    private const string InsertDelivery = """
        INSERT INTO Deliveries
                    (Id, MessageId, MailboxId, FolderId, Uid, Flags, InternalDate, CreatedUtc)
        VALUES      (@Id, @MessageId, @MailboxId, @FolderId, @Uid, @Flags, @InternalDate, @Now)
        """;

    private const string SelectFolderNextUid = """
        SELECT  NextUid
        FROM    MailboxFolders
        WHERE   MailboxId = @MailboxId
          AND   Path = @Path
        """;

    private const string UpdateFolderNextUid = """
        UPDATE  MailboxFolders
        SET     NextUid = @NextUid, ModifiedUtc = @Now
        WHERE   Id = @Id
          AND   MailboxId = @MailboxId
        """;

    /// <summary>One source delivery, as a copy needs to see it.</summary>
    private sealed class CopySourceRow
    {
        public long Uid { get; set; }

        public Guid MessageId { get; set; }

        public int Flags { get; set; }

        public DateTimeOffset InternalDate { get; set; }
    }

    public Task<ImapCopyResult> CopyAsync(
        MailboxId mailboxId,
        MailboxFolderId sourceFolderId,
        ImapSequenceSet set,
        bool byUid,
        string targetPath,
        bool removeFromSource,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(set);
        ArgumentNullException.ThrowIfNull(targetPath);

        string canonical = ImapMailboxPath.Canonical(targetPath);

        return transactions.ExecuteScopedAsync(
            async ct =>
            {
                IReadOnlyList<ImapMessageSummary> selected = await reader
                    .ReadSummariesAsync(mailboxId, sourceFolderId, set, byUid, ct)
                    .ConfigureAwait(false);

                return await ExecuteAsync(
                    async (session, inner) =>
                    {
                        Guid? targetId = await session.Connection
                            .QuerySingleOrDefaultAsync<Guid?>(Command(
                                session,
                                SelectFolderIdByPath,
                                new { MailboxId = mailboxId.Value, Path = canonical },
                                inner))
                            .ConfigureAwait(false);

                        if (targetId is null)
                        {
                            // Checked before anything is written, so the destination is untouched
                            // - RFC 3501 §6.4.7's "MUST restore the destination mailbox to its
                            // state before the COPY attempt" is trivially satisfied by never
                            // having started. The handler turns this into [TRYCREATE].
                            return new ImapCopyResult(ImapFolderMutation.NotFound, [], 0);
                        }

                        if (selected.Count == 0)
                        {
                            // §6.4.8: a set naming nothing that exists "is ignored without any
                            // error message generated".
                            return new ImapCopyResult(ImapFolderMutation.Done, [], 0);
                        }

                        long[] uids = [.. selected.Select(m => m.Uid)];

                        IEnumerable<CopySourceRow> rows = await session.Connection
                            .QueryAsync<CopySourceRow>(Command(
                                session,
                                SelectDeliveriesForCopy,
                                new
                                {
                                    FolderId = sourceFolderId.Value,
                                    MailboxId = mailboxId.Value,
                                    Uids = uids,
                                },
                                inner))
                            .ConfigureAwait(false);

                        List<CopySourceRow> sources = [.. rows];

                        long nextUid = await session.Connection
                            .ExecuteScalarAsync<long>(Command(
                                session,
                                SelectFolderNextUid,
                                new { MailboxId = mailboxId.Value, Path = canonical },
                                inner))
                            .ConfigureAwait(false);

                        foreach (CopySourceRow source in sources)
                        {
                            await session.Connection.ExecuteAsync(Command(
                                session,
                                InsertDelivery,
                                new
                                {
                                    Id = Guid.NewGuid(),
                                    source.MessageId,
                                    MailboxId = mailboxId.Value,
                                    FolderId = targetId.Value,
                                    Uid = nextUid++,

                                    // Flags and internal date preserved, per §6.4.7's SHOULD.
                                    // \Recent is not set: this server never sets it, and a copy
                                    // is no place to start claiming otherwise.
                                    source.Flags,
                                    source.InternalDate,
                                    Now = now,
                                },
                                inner)).ConfigureAwait(false);
                        }

                        // UIDs are never reused, so the counter moves even though the messages
                        // are copies - the destination's UID space is its own.
                        await session.Connection.ExecuteAsync(Command(
                            session,
                            UpdateFolderNextUid,
                            new
                            {
                                Id = targetId.Value,
                                MailboxId = mailboxId.Value,
                                NextUid = nextUid,
                                Now = now,
                            },
                            inner)).ConfigureAwait(false);

                        if (!removeFromSource)
                        {
                            return new ImapCopyResult(ImapFolderMutation.Done, [], sources.Count);
                        }

                        for (int offset = 0; offset < uids.Length; offset += UidBatchSize)
                        {
                            long[] batch = [.. uids.Skip(offset).Take(UidBatchSize)];

                            await session.Connection.ExecuteAsync(Command(
                                session,
                                DeleteDeliveries,
                                new
                                {
                                    FolderId = sourceFolderId.Value,
                                    MailboxId = mailboxId.Value,
                                    Uids = batch,
                                },
                                inner)).ConfigureAwait(false);
                        }

                        // Descending, as EXPUNGE reports them - every number still valid when
                        // sent, because only higher positions have gone.
                        List<long> removed =
                            [.. selected.Select(m => m.SequenceNumber).OrderByDescending(n => n)];

                        return new ImapCopyResult(ImapFolderMutation.Done, removed, sources.Count);
                    },
                    ct).ConfigureAwait(false);
            },
            cancellationToken);
    }

    private const string InsertMessageRow = """
        INSERT INTO Messages
                    (Id, SizeBytes, ContentSha256, ReversePath, RemoteAddress, GreetedName,
                     ListenerRole, TlsActive, AuthenticatedAs, ReceivedUtc)
        VALUES      (@Id, @SizeBytes, @Hash, NULL, @RemoteAddress, NULL, @ListenerRole, 1, NULL,
                     @Now)
        """;

    private const string CountFolderDeliveries = """
        SELECT  COUNT(*)
        FROM    Deliveries
        WHERE   FolderId = @FolderId
          AND   MailboxId = @MailboxId
        """;

    public Task<ImapAppendResult> AppendAsync(
        MailboxId mailboxId,
        string path,
        StoredMessage stored,
        MessageFlags flags,
        DateTimeOffset internalDate,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);

        string canonical = ImapMailboxPath.Canonical(path);

        return transactions.ExecuteScopedAsync(
            ct => ExecuteAsync(
                async (session, inner) =>
                {
                    Guid? folderId = await session.Connection
                        .QuerySingleOrDefaultAsync<Guid?>(Command(
                            session,
                            SelectFolderIdByPath,
                            new { MailboxId = mailboxId.Value, Path = canonical },
                            inner))
                        .ConfigureAwait(false);

                    if (folderId is null)
                    {
                        // Detected before anything is written, so §6.3.11's "the mailbox MUST be
                        // restored to its state before the APPEND attempt" is satisfied by never
                        // having started. The handler answers [TRYCREATE].
                        return new ImapAppendResult(ImapFolderMutation.NotFound, null, 0);
                    }

                    // The Messages row, written after the octets were committed to the store -
                    // the order the schema's own comment insists on, so a crash leaves an
                    // unreferenced file rather than a row naming a file that is not there.
                    await session.Connection.ExecuteAsync(Command(
                        session,
                        InsertMessageRow,
                        new
                        {
                            Id = stored.Id.Value,
                            SizeBytes = stored.SizeBytes,

                            // The digest the store computed at commit, so the schema's
                            // truncated-or-altered check works for an appended message as it
                            // does for a received one.
                            Hash = stored.ContentHash.ToString(),

                            // APPEND has no SMTP envelope: no reverse path, no peer, no EHLO
                            // name. The loopback address records that the message was submitted
                            // by the account's own client rather than pretending a peer sent it.
                            RemoteAddress = "127.0.0.1",
                            ListenerRole = (int)SmtpListenerRole.Submission,
                            Now = now,
                        },
                        inner)).ConfigureAwait(false);

                    long nextUid = await session.Connection
                        .ExecuteScalarAsync<long>(Command(
                            session,
                            SelectFolderNextUid,
                            new { MailboxId = mailboxId.Value, Path = canonical },
                            inner))
                        .ConfigureAwait(false);

                    await session.Connection.ExecuteAsync(Command(
                        session,
                        InsertDelivery,
                        new
                        {
                            Id = Guid.NewGuid(),
                            MessageId = stored.Id.Value,
                            MailboxId = mailboxId.Value,
                            FolderId = folderId.Value,
                            Uid = nextUid,
                            Flags = (int)flags,
                            InternalDate = internalDate,
                            Now = now,
                        },
                        inner)).ConfigureAwait(false);

                    await session.Connection.ExecuteAsync(Command(
                        session,
                        UpdateFolderNextUid,
                        new
                        {
                            Id = folderId.Value,
                            MailboxId = mailboxId.Value,
                            NextUid = nextUid + 1,
                            Now = now,
                        },
                        inner)).ConfigureAwait(false);

                    long exists = await session.Connection
                        .ExecuteScalarAsync<long>(Command(
                            session,
                            CountFolderDeliveries,
                            new { FolderId = folderId.Value, MailboxId = mailboxId.Value },
                            inner))
                        .ConfigureAwait(false);

                    return new ImapAppendResult(
                        ImapFolderMutation.Done,
                        new MailboxFolderId(folderId.Value),
                        exists);
                },
                ct),
            cancellationToken);
    }

    private const string InsertSubscription = """
        INSERT INTO MailboxSubscriptions (MailboxId, Path, CreatedUtc)
        VALUES (@MailboxId, @Path, @Now)
        """;

    private const string DeleteSubscription = """
        DELETE FROM MailboxSubscriptions
        WHERE  MailboxId = @MailboxId AND Path = @Path
        """;

    public Task<ImapFolderMutation> SetSubscriptionAsync(
        MailboxId mailboxId,
        string path,
        bool subscribed,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);

        string canonical = ImapMailboxPath.Canonical(path);

        return transactions.ExecuteScopedAsync(
            ct => ExecuteAsync(
                async (session, inner) =>
                {
                    if (subscribed)
                    {
                        // §6.3.6's permitted validation. Unsubscribing deliberately skips it:
                        // the list must be able to name something that is gone.
                        Guid? folderId = await session.Connection
                            .QuerySingleOrDefaultAsync<Guid?>(Command(
                                session,
                                SelectFolderIdByPath,
                                new { MailboxId = mailboxId.Value, Path = canonical },
                                inner))
                            .ConfigureAwait(false);

                        if (folderId is null)
                        {
                            return ImapFolderMutation.NotFound;
                        }
                    }

                    // Idempotent in both directions: delete first, then insert if wanted, so a
                    // repeat subscribe cannot violate the primary key.
                    await session.Connection.ExecuteAsync(Command(
                        session,
                        DeleteSubscription,
                        new { MailboxId = mailboxId.Value, Path = canonical },
                        inner)).ConfigureAwait(false);

                    if (subscribed)
                    {
                        await session.Connection.ExecuteAsync(Command(
                            session,
                            InsertSubscription,
                            new { MailboxId = mailboxId.Value, Path = canonical, Now = now },
                            inner)).ConfigureAwait(false);
                    }

                    return ImapFolderMutation.Done;
                },
                ct),
            cancellationToken);
    }

    /// <summary>
    /// Removes named deliveries, whatever their flags.
    /// </summary>
    /// <remarks>
    /// The same statement <see cref="ExpungeAsync"/> uses to remove the rows it selected, driven
    /// by the caller's list instead of by a flag — see
    /// <see cref="IImapMailboxWriter.DeleteMessagesAsync"/> for why POP3 cannot use the flag.
    /// </remarks>
    public Task<long> DeleteMessagesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        IReadOnlyList<long> uids,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(uids);

        if (uids.Count == 0)
        {
            return Task.FromResult(0L);
        }

        // One transaction around every batch: a QUIT that removed half its messages and then
        // failed would leave a client believing all of them were gone, because RFC 1939 §6 gives
        // it one answer for the whole operation.
        return transactions.ExecuteScopedAsync(
            async ct => await ExecuteAsync(
                async (session, inner) =>
                {
                    long removed = 0;

                    for (int offset = 0; offset < uids.Count; offset += UidBatchSize)
                    {
                        long[] batch = [.. uids.Skip(offset).Take(UidBatchSize)];

                        removed += await session.Connection
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

                    return removed;
                },
                ct),
            cancellationToken);
    }
}
