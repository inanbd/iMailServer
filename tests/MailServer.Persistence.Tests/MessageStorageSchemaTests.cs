using System.Data.Common;
using Dapper;

namespace MailServer.Persistence.Tests;

/// <summary>
/// Migration 0006. The tests assert the invariants the schema is supposed to enforce, by
/// trying to violate them — a constraint that is declared but not enforced looks identical to
/// one that is, until the day it matters.
/// </summary>
public sealed class MessageStorageSchemaTests
{
    private static async Task<DbConnection> MigratedAsync(SqliteTestDatabase database)
    {
        await database.MigrateAsync(CancellationToken.None);

        return await database.ConnectionFactory.OpenConnectionAsync(CancellationToken.None);
    }

    [Fact]
    public async Task The_message_storage_tables_exist()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        string[] tables =
        [
            .. await connection.QueryAsync<string>(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        ];

        tables.ShouldContain("Messages");
        tables.ShouldContain("MessageRecipients");
        tables.ShouldContain("Deliveries");
    }

    [Fact]
    public async Task The_delivery_indexes_exist()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        string[] indexes =
        [
            .. await connection.QueryAsync<string>(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name IS NOT NULL")
        ];

        indexes.ShouldContain("UX_Deliveries_Folder_Uid");
        indexes.ShouldContain("UX_Deliveries_Folder_Message");
        indexes.ShouldContain("IX_Messages_Retained");
    }

    /// <summary>Creates a domain, mailbox, folder and message so a delivery can be inserted.</summary>
    private static async Task<(string MessageId, string MailboxId, string FolderId)> SeedAsync(
        DbConnection connection)
    {
        string domainId = Guid.NewGuid().ToString();
        string mailboxId = Guid.NewGuid().ToString();
        string folderId = Guid.NewGuid().ToString();
        string messageId = Guid.NewGuid().ToString();

        const string Now = "2026-03-01T09:00:00+00:00";

        await connection.ExecuteAsync(
            """
            INSERT INTO Domains (Id, Name, UnicodeName, Status, CreatedUtc)
            VALUES (@Id, 'example.com', 'example.com', 1, @Now)
            """,
            new { Id = domainId, Now });

        await connection.ExecuteAsync(
            """
            INSERT INTO Mailboxes (Id, DomainId, LocalPart, Address, Status, CreatedUtc)
            VALUES (@Id, @DomainId, 'user', 'user@example.com', 1, @Now)
            """,
            new { Id = mailboxId, DomainId = domainId, Now });

        await connection.ExecuteAsync(
            """
            INSERT INTO MailboxFolders (Id, MailboxId, Path, SpecialUse, UidValidity, CreatedUtc)
            VALUES (@Id, @MailboxId, 'INBOX', 1, 1, @Now)
            """,
            new { Id = folderId, MailboxId = mailboxId, Now });

        await connection.ExecuteAsync(
            """
            INSERT INTO Messages
                (Id, SizeBytes, ContentSha256, ReversePath, RemoteAddress, ListenerRole, TlsActive, ReceivedUtc)
            VALUES
                (@Id, 100, @Hash, 'sender@example.net', '198.51.100.20', 0, 0, @Now)
            """,
            new { Id = messageId, Hash = new string('a', 64), Now });

        return (messageId, mailboxId, folderId);
    }

    private static Task<int> InsertDeliveryAsync(
        DbConnection connection,
        string messageId,
        string mailboxId,
        string folderId,
        long uid) =>
        connection.ExecuteAsync(
            """
            INSERT INTO Deliveries (Id, MessageId, MailboxId, FolderId, Uid, Flags, InternalDate, CreatedUtc)
            VALUES (@Id, @MessageId, @MailboxId, @FolderId, @Uid, 0, @Now, @Now)
            """,
            new
            {
                Id = Guid.NewGuid().ToString(),
                MessageId = messageId,
                MailboxId = mailboxId,
                FolderId = folderId,
                Uid = uid,
                Now = "2026-03-01T09:00:00+00:00",
            });

    [Fact]
    public async Task A_delivery_can_be_recorded()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (string messageId, string mailboxId, string folderId) = await SeedAsync(connection);

        await InsertDeliveryAsync(connection, messageId, mailboxId, folderId, uid: 1);

        (await connection.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(1);
    }

    [Fact]
    public async Task A_uid_cannot_be_reused_within_a_folder()
    {
        // The IMAP promise, enforced by the database rather than by whichever code path
        // happened to assign it. A reused UID makes a client's cache serve the wrong message,
        // silently and without any error the user could report.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (string messageId, string mailboxId, string folderId) = await SeedAsync(connection);

        await InsertDeliveryAsync(connection, messageId, mailboxId, folderId, uid: 1);

        string second = Guid.NewGuid().ToString();

        await connection.ExecuteAsync(
            """
            INSERT INTO Messages
                (Id, SizeBytes, ContentSha256, RemoteAddress, ListenerRole, TlsActive, ReceivedUtc)
            VALUES (@Id, 50, @Hash, '198.51.100.21', 0, 0, '2026-03-01T09:00:00+00:00')
            """,
            new { Id = second, Hash = new string('b', 64) });

        await Should.ThrowAsync<Exception>(
            async () => await InsertDeliveryAsync(connection, second, mailboxId, folderId, uid: 1));
    }

    [Fact]
    public async Task The_same_message_cannot_be_delivered_to_the_same_folder_twice()
    {
        // Without this, a delivery retried after a partial failure silently duplicates mail -
        // which the recipient sees and the operator cannot explain.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (string messageId, string mailboxId, string folderId) = await SeedAsync(connection);

        await InsertDeliveryAsync(connection, messageId, mailboxId, folderId, uid: 1);

        await Should.ThrowAsync<Exception>(
            async () => await InsertDeliveryAsync(connection, messageId, mailboxId, folderId, uid: 2));
    }

    [Fact]
    public async Task A_denied_recipient_cannot_be_recorded_at_all()
    {
        // RelayDecision 0 is Deny. A denied recipient is refused at RCPT TO and never becomes a
        // row, and the check constraint makes that unrepresentable rather than merely unusual.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (string messageId, _, _) = await SeedAsync(connection);

        await Should.ThrowAsync<Exception>(
            async () => await connection.ExecuteAsync(
                """
                INSERT INTO MessageRecipients (Id, MessageId, Address, RelayDecision, CreatedUtc)
                VALUES (@Id, @MessageId, 'victim@elsewhere.example', 0, '2026-03-01T09:00:00+00:00')
                """,
                new { Id = Guid.NewGuid().ToString(), MessageId = messageId }));
    }

    [Fact]
    public async Task A_message_with_a_delivery_cannot_be_deleted_out_from_under_it()
    {
        // RESTRICT, not CASCADE. Removing a message row would leave IMAP clients with cached
        // UIDs pointing at nothing; expunging is a deliberate operation, not a side effect of
        // tidying the Messages table.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (string messageId, string mailboxId, string folderId) = await SeedAsync(connection);

        await InsertDeliveryAsync(connection, messageId, mailboxId, folderId, uid: 1);

        await Should.ThrowAsync<Exception>(
            async () => await connection.ExecuteAsync(
                "DELETE FROM Messages WHERE Id = @Id",
                new { Id = messageId }));
    }

    [Fact]
    public async Task The_null_reverse_path_is_storable()
    {
        // A bounce's sender. A schema that required a sender would make every delivery status
        // notification unstorable.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        await connection.ExecuteAsync(
            """
            INSERT INTO Messages
                (Id, SizeBytes, ContentSha256, ReversePath, RemoteAddress, ListenerRole, TlsActive, ReceivedUtc)
            VALUES (@Id, 10, @Hash, NULL, '198.51.100.20', 0, 0, '2026-03-01T09:00:00+00:00')
            """,
            new { Id = Guid.NewGuid().ToString(), Hash = new string('c', 64) });

        (await connection.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM Messages WHERE ReversePath IS NULL")).ShouldBe(1);
    }
}
