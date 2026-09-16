using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of a <c>Messages</c> row.</summary>
internal sealed class MessageRow
{
    public Guid Id { get; set; }

    public long SizeBytes { get; set; }

    public string ContentSha256 { get; set; } = string.Empty;

    public string? ReversePath { get; set; }

    public string RemoteAddress { get; set; } = string.Empty;

    public string? GreetedName { get; set; }

    public int ListenerRole { get; set; }

    public bool TlsActive { get; set; }

    public string? AuthenticatedAs { get; set; }

    public DateTimeOffset ReceivedUtc { get; set; }

    public DateTimeOffset? ContentRemovedUtc { get; set; }
}

/// <summary>Persists accepted messages and where they were delivered.</summary>
internal sealed class DeliveryRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IDeliveryRepository
{
    private const string SelectFolderColumns = """
        SELECT  Id, MailboxId, Path, SpecialUse, UidValidity, NextUid, IsSubscribed,
                CreatedUtc, ModifiedUtc
        FROM    MailboxFolders
        """;

    public Task AddMessageAsync(MessageRecord message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO Messages
                    (Id, SizeBytes, ContentSha256, ReversePath, RemoteAddress, GreetedName,
                     ListenerRole, TlsActive, AuthenticatedAs, ReceivedUtc, ContentRemovedUtc)
                VALUES
                    (@Id, @SizeBytes, @ContentSha256, @ReversePath, @RemoteAddress, @GreetedName,
                     @ListenerRole, @TlsActive, @AuthenticatedAs, @ReceivedUtc, @ContentRemovedUtc)
                """,
                new
                {
                    Id = message.Id.Value,
                    message.SizeBytes,
                    ContentSha256 = message.ContentHash.Value,

                    // Null here is the null reverse path, which is a sender, not a missing
                    // value. The column is nullable for exactly this reason.
                    ReversePath = message.ReversePath?.NormalizedValue,

                    RemoteAddress = message.RemoteAddress.Value,
                    message.GreetedName,
                    ListenerRole = (int)message.ListenerRole,
                    message.TlsActive,
                    AuthenticatedAs = message.AuthenticatedAs?.NormalizedValue,
                    message.ReceivedUtc,
                    message.ContentRemovedUtc,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task AddRecipientAsync(MessageRecipient recipient, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipient);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO MessageRecipients (Id, MessageId, Address, RelayDecision, CreatedUtc)
                VALUES (@Id, @MessageId, @Address, @RelayDecision, @CreatedUtc)
                """,
                new
                {
                    recipient.Id,
                    MessageId = recipient.MessageId.Value,

                    // The address as the sender wrote it, normalised for lookup but not
                    // resolved: a bounce has to name this, not the mailbox behind it.
                    Address = recipient.Address.NormalizedValue,

                    RelayDecision = (int)recipient.Decision,
                    CreatedUtc = DateTimeOffset.UtcNow,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    /// <remarks>
    /// <para>
    /// One statement. A read of <c>NextUid</c> followed by a write of <c>NextUid + 1</c> lets two
    /// concurrent deliveries into the same folder take the same UID; the unique index then
    /// rejects the second, turning an ordinary concurrent delivery into a failed one. The
    /// <c>UPDATE ... WHERE</c> is atomic under both providers.
    /// </para>
    /// <para>
    /// Deliberately not <c>OUTPUT</c> / <c>RETURNING</c>: the two providers spell those
    /// differently, and this repository is written once against <c>ISqlDialect</c>. Reading back
    /// inside the same statement's transaction is correct on both.
    /// </para>
    /// </remarks>
    public Task<long> AllocateUidAsync(MailboxFolderId folderId, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            int updated = await session.Connection.ExecuteAsync(Command(
                session,
                "UPDATE MailboxFolders SET NextUid = NextUid + 1 WHERE Id = @Id",
                new { Id = folderId.Value },
                ct)).ConfigureAwait(false);

            if (updated == 0)
            {
                throw new InvalidOperationException(
                    $"Folder {folderId.Value} does not exist, so no UID can be allocated for it.");
            }

            long next = await session.Connection.ExecuteScalarAsync<long>(Command(
                session,
                "SELECT NextUid FROM MailboxFolders WHERE Id = @Id",
                new { Id = folderId.Value },
                ct)).ConfigureAwait(false);

            // The counter now points past the UID just taken.
            return next - 1;
        }, cancellationToken);

    public Task AddDeliveryAsync(Delivery delivery, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(delivery);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO Deliveries
                    (Id, MessageId, MailboxId, FolderId, Uid, Flags, RecipientId, InternalDate, CreatedUtc)
                VALUES
                    (@Id, @MessageId, @MailboxId, @FolderId, @Uid, 0, @RecipientId, @InternalDate, @CreatedUtc)
                """,
                new
                {
                    delivery.Id,
                    MessageId = delivery.MessageId.Value,
                    MailboxId = delivery.MailboxId.Value,
                    FolderId = delivery.FolderId.Value,
                    delivery.Uid,
                    delivery.RecipientId,
                    delivery.InternalDate,
                    CreatedUtc = delivery.InternalDate,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    /// <remarks>
    /// A relative update. Read-add-write would lose an increment whenever two deliveries landed
    /// at once, and a quota that drifts below the truth reports a full mailbox as having room.
    /// </remarks>
    public Task AddStorageUsedAsync(MailboxId mailboxId, long bytes, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                "UPDATE Mailboxes SET StorageUsedBytes = StorageUsedBytes + @Bytes WHERE Id = @Id",
                new { Id = mailboxId.Value, Bytes = bytes },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task<MailboxFolder?> GetFolderAsync(
        MailboxId mailboxId,
        FolderSpecialUse specialUse,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            MailboxFolderRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<MailboxFolderRow>(Command(
                    session,
                    SelectFolderColumns + " WHERE MailboxId = @MailboxId AND SpecialUse = @SpecialUse",
                    new { MailboxId = mailboxId.Value, SpecialUse = (int)specialUse },
                    ct))
                .ConfigureAwait(false);

            return row is null
                ? null
                : new MailboxFolder(
                    new MailboxFolderId(row.Id),
                    new MailboxId(row.MailboxId),
                    row.Path,
                    (FolderSpecialUse)row.SpecialUse,
                    row.UidValidity,
                    row.NextUid,
                    row.IsSubscribed,
                    row.CreatedUtc,
                    row.ModifiedUtc);
        }, cancellationToken);

    public Task AddDkimVerificationAsync(DkimVerificationRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO DkimVerificationResults
                    (Id, MessageId, SignatureIndex, Result, SigningDomain, Diagnostic, CreatedUtc)
                VALUES
                    (@Id, @MessageId, @SignatureIndex, @Result, @SigningDomain, @Diagnostic, @CreatedUtc)
                """,
                new
                {
                    record.Id,
                    MessageId = record.MessageId.Value,
                    record.SignatureIndex,
                    Result = (int)record.Result,
                    SigningDomain = record.SigningDomain?.Value,
                    record.Diagnostic,
                    record.CreatedUtc,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task AddDmarcVerificationAsync(DmarcVerificationRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO DmarcVerificationResults
                    (Id, MessageId, Result, Disposition, AlignedMechanisms, FromDomain, PolicyDomain, Diagnostic, CreatedUtc)
                VALUES
                    (@Id, @MessageId, @Result, @Disposition, @AlignedMechanisms, @FromDomain, @PolicyDomain, @Diagnostic, @CreatedUtc)
                """,
                new
                {
                    record.Id,
                    MessageId = record.MessageId.Value,
                    Result = (int?)record.Result,
                    Disposition = (int)record.Disposition,
                    AlignedMechanisms = (int)record.AlignedMechanisms,
                    FromDomain = record.FromDomain?.Value,
                    PolicyDomain = record.PolicyDomain?.Value,
                    record.Diagnostic,
                    record.CreatedUtc,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }
}
