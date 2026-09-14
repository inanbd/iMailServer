using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of a <c>Mailboxes</c> row.</summary>
internal sealed class MailboxRow
{
    public Guid Id { get; set; }

    public Guid DomainId { get; set; }

    public string LocalPart { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    public string? DisplayName { get; set; }

    public int Status { get; set; }

    public long QuotaBytes { get; set; }

    public long StorageUsedBytes { get; set; }

    public long MaxMessageSizeBytes { get; set; }

    public int AccessFlags { get; set; }

    // Kept in step with AccessFlags on every write. They are the columns migration 0001
    // created and are what a hand-written query or an older tool would read.
    public bool ImapEnabled { get; set; }

    public bool Pop3Enabled { get; set; }

    public bool SubmissionEnabled { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }

    public DateTimeOffset? LastLoginUtc { get; set; }
}

/// <summary>Flat shape of a <c>MailboxCredentials</c> row.</summary>
internal sealed class MailboxCredentialRow
{
    public Guid Id { get; set; }

    public Guid MailboxId { get; set; }

    public string PasswordHash { get; set; } = string.Empty;

    public bool MustChangePassword { get; set; }

    public int ConsecutiveFailures { get; set; }

    public DateTimeOffset? LastFailureUtc { get; set; }

    public DateTimeOffset? LockedOutUntilUtc { get; set; }

    public DateTimeOffset? LastSuccessUtc { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? PasswordChangedUtc { get; set; }
}

/// <summary>Flat shape of a <c>MailboxFolders</c> row.</summary>
internal sealed class MailboxFolderRow
{
    public Guid Id { get; set; }

    public Guid MailboxId { get; set; }

    public string Path { get; set; } = string.Empty;

    public int SpecialUse { get; set; }

    public long UidValidity { get; set; }

    public long NextUid { get; set; }

    public bool IsSubscribed { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }
}

/// <summary>Persists mailboxes, their credentials and their folders.</summary>
internal sealed class MailboxRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IMailboxRepository
{
    private const string SelectColumns = """
        SELECT  Id, DomainId, LocalPart, Address, DisplayName, Status, QuotaBytes,
                StorageUsedBytes, MaxMessageSizeBytes, AccessFlags, ImapEnabled, Pop3Enabled,
                SubmissionEnabled, CreatedUtc, ModifiedUtc, LastLoginUtc
        FROM    Mailboxes
        """;

    private const string SelectCredentialColumns = """
        SELECT  Id, MailboxId, PasswordHash, MustChangePassword, ConsecutiveFailures,
                LastFailureUtc, LockedOutUntilUtc, LastSuccessUtc, CreatedUtc,
                PasswordChangedUtc
        FROM    MailboxCredentials
        """;

    private const string SelectFolderColumns = """
        SELECT  Id, MailboxId, Path, SpecialUse, UidValidity, NextUid, IsSubscribed,
                CreatedUtc, ModifiedUtc
        FROM    MailboxFolders
        """;

    public Task<Mailbox?> GetAsync(MailboxId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            MailboxRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<MailboxRow>(Command(
                    session,
                    SelectColumns + " WHERE Id = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);

    /// <remarks>
    /// Matches on the normalised address, which is what the unique index stores and what
    /// <c>EmailAddress.NormalizedValue</c> produces. Matching on the display form would make
    /// <c>J.Smith@</c> and <c>j.smith@</c> different mailboxes.
    /// </remarks>
    public Task<Mailbox?> GetByAddressAsync(
        EmailAddress address,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        return ExecuteAsync(async (session, ct) =>
        {
            MailboxRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<MailboxRow>(Command(
                    session,
                    SelectColumns + " WHERE Address = @Address",
                    new { Address = address.NormalizedValue },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);
    }

    public Task<bool> AddressExistsAsync(
        EmailAddress address,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        return ExecuteAsync(async (session, ct) =>
            await session.Connection.ExecuteScalarAsync<int>(Command(
                session,
                "SELECT COUNT(1) FROM Mailboxes WHERE Address = @Address",
                new { Address = address.NormalizedValue },
                ct)).ConfigureAwait(false) > 0,
            cancellationToken);
    }

    public Task<IReadOnlyList<Mailbox>> GetByDomainAsync(
        DomainId domainId,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<MailboxRow> rows = await session.Connection
                .QueryAsync<MailboxRow>(Command(
                    session,
                    SelectColumns + " WHERE DomainId = @DomainId ORDER BY Address",
                    new { DomainId = domainId.Value },
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<Mailbox>)rows.Select(Map).ToList();
        }, cancellationToken);

    public Task<int> CountByDomainAsync(DomainId domainId, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
            await session.Connection.ExecuteScalarAsync<int>(Command(
                session,
                "SELECT COUNT(1) FROM Mailboxes WHERE DomainId = @DomainId",
                new { DomainId = domainId.Value },
                ct)).ConfigureAwait(false),
            cancellationToken);

    public Task AddAsync(Mailbox mailbox, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mailbox);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO Mailboxes
                    (Id, DomainId, LocalPart, Address, DisplayName, Status, QuotaBytes,
                     StorageUsedBytes, MaxMessageSizeBytes, AccessFlags, ImapEnabled,
                     Pop3Enabled, SubmissionEnabled, CreatedUtc, ModifiedUtc, LastLoginUtc)
                VALUES
                    (@Id, @DomainId, @LocalPart, @Address, @DisplayName, @Status, @QuotaBytes,
                     @StorageUsedBytes, @MaxMessageSizeBytes, @AccessFlags, @ImapEnabled,
                     @Pop3Enabled, @SubmissionEnabled, @CreatedUtc, @ModifiedUtc, @LastLoginUtc)
                """,
                ToRow(mailbox),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateAsync(Mailbox mailbox, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mailbox);

        return ExecuteAsync(async (session, ct) =>
        {
            // Address, LocalPart and DomainId are absent deliberately: the address is
            // immutable, and a mailbox cannot move between domains. An UPDATE that could
            // change them would be a rename, which strands every message already delivered.
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  Mailboxes
                SET     DisplayName = @DisplayName,
                        Status = @Status,
                        QuotaBytes = @QuotaBytes,
                        StorageUsedBytes = @StorageUsedBytes,
                        MaxMessageSizeBytes = @MaxMessageSizeBytes,
                        AccessFlags = @AccessFlags,
                        ImapEnabled = @ImapEnabled,
                        Pop3Enabled = @Pop3Enabled,
                        SubmissionEnabled = @SubmissionEnabled,
                        ModifiedUtc = @ModifiedUtc,
                        LastLoginUtc = @LastLoginUtc
                WHERE   Id = @Id
                """,
                ToRow(mailbox),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task RemoveAsync(MailboxId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            // Folders are ON DELETE RESTRICT, so this fails while any folder remains. That is
            // the intent: folders hold messages, and messages are files on disk. The delete
            // handler removes them in order.
            await session.Connection.ExecuteAsync(Command(
                session,
                "DELETE FROM Mailboxes WHERE Id = @Id",
                new { Id = id.Value },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);

    // ---- Credentials --------------------------------------------------------------------

    public Task<MailboxCredential?> GetCredentialAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            MailboxCredentialRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<MailboxCredentialRow>(Command(
                    session,
                    SelectCredentialColumns + " WHERE MailboxId = @MailboxId",
                    new { MailboxId = mailboxId.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : MapCredential(row);
        }, cancellationToken);

    public Task AddCredentialAsync(
        MailboxCredential credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO MailboxCredentials
                    (Id, MailboxId, PasswordHash, MustChangePassword, ConsecutiveFailures,
                     LastFailureUtc, LockedOutUntilUtc, LastSuccessUtc, CreatedUtc,
                     PasswordChangedUtc)
                VALUES
                    (@Id, @MailboxId, @PasswordHash, @MustChangePassword, @ConsecutiveFailures,
                     @LastFailureUtc, @LockedOutUntilUtc, @LastSuccessUtc, @CreatedUtc,
                     @PasswordChangedUtc)
                """,
                ToCredentialRow(credential),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateCredentialAsync(
        MailboxCredential credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  MailboxCredentials
                SET     PasswordHash = @PasswordHash,
                        MustChangePassword = @MustChangePassword,
                        ConsecutiveFailures = @ConsecutiveFailures,
                        LastFailureUtc = @LastFailureUtc,
                        LockedOutUntilUtc = @LockedOutUntilUtc,
                        LastSuccessUtc = @LastSuccessUtc,
                        PasswordChangedUtc = @PasswordChangedUtc
                WHERE   Id = @Id
                """,
                ToCredentialRow(credential),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    // ---- Folders ------------------------------------------------------------------------

    public Task<IReadOnlyList<MailboxFolder>> GetFoldersAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<MailboxFolderRow> rows = await session.Connection
                .QueryAsync<MailboxFolderRow>(Command(
                    session,
                    SelectFolderColumns + " WHERE MailboxId = @MailboxId ORDER BY Path",
                    new { MailboxId = mailboxId.Value },
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<MailboxFolder>)rows.Select(MapFolder).ToList();
        }, cancellationToken);

    public Task AddFolderAsync(MailboxFolder folder, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(folder);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO MailboxFolders
                    (Id, MailboxId, Path, SpecialUse, UidValidity, NextUid, IsSubscribed,
                     CreatedUtc, ModifiedUtc)
                VALUES
                    (@Id, @MailboxId, @Path, @SpecialUse, @UidValidity, @NextUid,
                     @IsSubscribed, @CreatedUtc, @ModifiedUtc)
                """,
                ToFolderRow(folder),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateFolderAsync(MailboxFolder folder, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(folder);

        return ExecuteAsync(async (session, ct) =>
        {
            // UidValidity is not updatable. It is the promise to a client that its cached UIDs
            // still name the same messages; an UPDATE that could change it would let a bug
            // force every client to resynchronise, repeatedly and silently.
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  MailboxFolders
                SET     Path = @Path,
                        SpecialUse = @SpecialUse,
                        NextUid = @NextUid,
                        IsSubscribed = @IsSubscribed,
                        ModifiedUtc = @ModifiedUtc
                WHERE   Id = @Id
                """,
                ToFolderRow(folder),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task RemoveFolderAsync(MailboxFolderId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                "DELETE FROM MailboxFolders WHERE Id = @Id",
                new { Id = id.Value },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);

    // ---- Mapping ------------------------------------------------------------------------

    private static Mailbox Map(MailboxRow row) =>
        new(
            new MailboxId(row.Id),
            new DomainId(row.DomainId),
            EmailAddress.Parse(row.Address),
            row.LocalPart,
            row.DisplayName,
            (MailboxStatus)row.Status,
            QuotaBytes.FromBytes(row.QuotaBytes),
            row.StorageUsedBytes,
            row.MaxMessageSizeBytes,
            (MailboxAccess)row.AccessFlags,
            row.CreatedUtc,
            row.ModifiedUtc,
            row.LastLoginUtc);

    private static MailboxRow ToRow(Mailbox mailbox) => new()
    {
        Id = mailbox.Id.Value,
        DomainId = mailbox.DomainId.Value,
        LocalPart = mailbox.LocalPart,
        Address = mailbox.Address.NormalizedValue,
        DisplayName = mailbox.DisplayName,
        Status = (int)mailbox.Status,
        QuotaBytes = mailbox.Quota.Bytes,
        StorageUsedBytes = mailbox.StorageUsedBytes,
        MaxMessageSizeBytes = mailbox.MaxMessageSizeBytes,
        AccessFlags = (int)mailbox.Access,

        // Written from the same source as AccessFlags on every write, so the two cannot drift.
        ImapEnabled = mailbox.Access.HasFlag(MailboxAccess.Imap),
        Pop3Enabled = mailbox.Access.HasFlag(MailboxAccess.Pop3),
        SubmissionEnabled = mailbox.Access.HasFlag(MailboxAccess.Submission),
        CreatedUtc = mailbox.CreatedUtc,
        ModifiedUtc = mailbox.ModifiedUtc,
        LastLoginUtc = mailbox.LastLoginUtc,
    };

    private static MailboxCredential MapCredential(MailboxCredentialRow row) =>
        new(
            new MailboxCredentialId(row.Id),
            new MailboxId(row.MailboxId),
            PasswordHash.Parse(row.PasswordHash),
            row.MustChangePassword,
            row.ConsecutiveFailures,
            row.LastFailureUtc,
            row.LockedOutUntilUtc,
            row.LastSuccessUtc,
            row.CreatedUtc,
            row.PasswordChangedUtc);

    private static MailboxCredentialRow ToCredentialRow(MailboxCredential credential) => new()
    {
        Id = credential.Id.Value,
        MailboxId = credential.MailboxId.Value,
        PasswordHash = credential.PasswordHash.Encoded,
        MustChangePassword = credential.MustChangePassword,
        ConsecutiveFailures = credential.ConsecutiveFailures,
        LastFailureUtc = credential.LastFailureUtc,
        LockedOutUntilUtc = credential.LockedOutUntilUtc,
        LastSuccessUtc = credential.LastSuccessUtc,
        CreatedUtc = credential.CreatedUtc,
        PasswordChangedUtc = credential.PasswordChangedUtc,
    };

    private static MailboxFolder MapFolder(MailboxFolderRow row) =>
        new(
            new MailboxFolderId(row.Id),
            new MailboxId(row.MailboxId),
            row.Path,
            (FolderSpecialUse)row.SpecialUse,
            row.UidValidity,
            row.NextUid,
            row.IsSubscribed,
            row.CreatedUtc,
            row.ModifiedUtc);

    private static MailboxFolderRow ToFolderRow(MailboxFolder folder) => new()
    {
        Id = folder.Id.Value,
        MailboxId = folder.MailboxId.Value,
        Path = folder.Path,
        SpecialUse = (int)folder.SpecialUse,
        UidValidity = folder.UidValidity,
        NextUid = folder.NextUid,
        IsSubscribed = folder.IsSubscribed,
        CreatedUtc = folder.CreatedUtc,
        ModifiedUtc = folder.ModifiedUtc,
    };
}
