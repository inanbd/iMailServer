using System.Data.Common;
using Dapper;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Persistence.Tests;

/// <summary>
/// The IMAP read side, against a real SQLite database.
/// </summary>
/// <remarks>
/// <para>
/// A real database rather than a fake, because the two things worth proving here are both
/// properties of the SQL. The first-unseen position is computed with
/// <c>ROW_NUMBER() OVER (ORDER BY Uid)</c> — sequence numbers are positions rather than stored
/// values, so nothing can look one up — and a hand-rolled fake would simply agree with whatever
/// the test expected. The second is the authorisation boundary: <c>MailboxId</c> is in the
/// <c>WHERE</c> clause, and the only way to know it is still there is to ask the database for
/// another mailbox's folder and be told no.
/// </para>
/// <para>
/// The scenarios that matter are the boundary ones: an empty folder, a folder where everything
/// has been read, a folder where the unseen message is not the first one, and a folder with a
/// gap in its UIDs — because UIDs are never reused, so gaps are the normal state of any folder
/// that has ever been expunged, and a sequence number is a position in what remains rather than
/// a UID.
/// </para>
/// </remarks>
public sealed class ImapMailboxReaderTests
{
    private const string Now = "2026-09-18T12:00:00+00:00";

    /// <summary>Migrates and returns an open connection for the raw seeding below.</summary>
    private static async Task<DbConnection> MigratedAsync(SqliteTestDatabase database)
    {
        await database.MigrateAsync(CancellationToken.None);

        return await database.ConnectionFactory.OpenConnectionAsync(CancellationToken.None);
    }

    /// <summary>Creates a domain, a mailbox and one folder, and returns the two ids.</summary>
    /// <remarks>
    /// Written in as raw SQL rather than through the mailbox repository, because this test is
    /// about the reader's own SQL: going through another repository would make a failure here
    /// ambiguous between the two.
    /// </remarks>
    private static async Task<(MailboxId Mailbox, MailboxFolderId Folder)> SeedFolderAsync(
        DbConnection connection,
        string path = "INBOX",
        FolderSpecialUse specialUse = FolderSpecialUse.Inbox,
        long uidValidity = 3_857_529_045,
        string address = "alice@example.com")
    {
        Guid domainId = Guid.NewGuid();
        Guid mailboxId = Guid.NewGuid();
        Guid folderId = Guid.NewGuid();

        string domain = address.Split('@')[1];

        await connection.ExecuteAsync(
            """
            INSERT INTO Domains (Id, Name, UnicodeName, Status, CreatedUtc)
            VALUES (@DomainId, @Domain, @Domain, 1, @Now)
            """,
            new { DomainId = domainId, Domain = domain, Now });

        await connection.ExecuteAsync(
            """
            INSERT INTO Mailboxes (Id, DomainId, LocalPart, Address, Status, CreatedUtc)
            VALUES (@MailboxId, @DomainId, @LocalPart, @Address, 1, @Now)
            """,
            new
            {
                MailboxId = mailboxId,
                DomainId = domainId,
                LocalPart = address.Split('@')[0],
                Address = address,
                Now,
            });

        await connection.ExecuteAsync(
            """
            INSERT INTO MailboxFolders (Id, MailboxId, Path, SpecialUse, UidValidity, NextUid,
                                        IsSubscribed, CreatedUtc)
            VALUES (@FolderId, @MailboxId, @Path, @SpecialUse, @UidValidity, 1, 1, @Now)
            """,
            new
            {
                FolderId = folderId,
                MailboxId = mailboxId,
                Path = path,
                SpecialUse = (int)specialUse,
                UidValidity = uidValidity,
                Now,
            });

        return (new MailboxId(mailboxId), new MailboxFolderId(folderId));
    }

    /// <summary>Puts one delivery in a folder at a given UID, with given flags.</summary>
    private static async Task DeliverAsync(
        DbConnection connection,
        MailboxId mailboxId,
        MailboxFolderId folderId,
        long uid,
        MessageFlags flags = MessageFlags.None)
    {
        Guid messageId = Guid.NewGuid();

        await connection.ExecuteAsync(
            """
            INSERT INTO Messages
                (Id, SizeBytes, ContentSha256, RemoteAddress, ListenerRole, TlsActive, ReceivedUtc)
            VALUES (@MessageId, 100, @Hash, '198.51.100.7', 0, 1, @Now)
            """,
            new { MessageId = messageId, Hash = new string('c', 64), Now });

        await connection.ExecuteAsync(
            """
            INSERT INTO Deliveries
                (Id, MessageId, MailboxId, FolderId, Uid, Flags, InternalDate, CreatedUtc)
            VALUES (@DeliveryId, @MessageId, @MailboxId, @FolderId, @Uid, @Flags, @Now, @Now)
            """,
            new
            {
                DeliveryId = Guid.NewGuid(),
                MessageId = messageId,
                MailboxId = mailboxId.Value,
                FolderId = folderId.Value,
                Uid = uid,
                Flags = (int)flags,
                Now,
            });
    }

    // ---------------------------------------------------------------------------------------
    // Finding the folder.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_empty_folder_reads_as_zero_messages_and_nothing_unseen()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection, uidValidity: 12345);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot.ShouldNotBeNull();
        snapshot.ExistsCount.ShouldBe(0);
        snapshot.FirstUnseenSequenceNumber.ShouldBeNull();
        snapshot.HasUnseen.ShouldBeFalse();
        snapshot.UidValidity.ShouldBe(12345);
        snapshot.UidNext.ShouldBe(1);
        snapshot.Folder.Path.ShouldBe("INBOX");
    }

    [Fact]
    public async Task A_folder_this_mailbox_does_not_have_reads_as_null()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "Archive", CancellationToken.None);

        snapshot.ShouldBeNull();
    }

    [Theory]
    [InlineData("INBOX")]
    [InlineData("inbox")]
    [InlineData("Inbox")]
    [InlineData("InBoX")]
    public async Task The_inbox_is_found_whatever_case_the_client_asks_in(string asked)
    {
        // RFC 3501 section 5.1: "The case-insensitive mailbox name INBOX is a special name
        // reserved to mean the primary mailbox for this user on this server."
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, asked, CancellationToken.None);

        snapshot.ShouldNotBeNull();
        snapshot.Folder.SpecialUse.ShouldBe(FolderSpecialUse.Inbox);
    }

    [Theory]
    [InlineData("Receipts", "receipts")]
    [InlineData("Receipts", "RECEIPTS")]
    [InlineData("Projects/2026", "projects/2026")]
    public async Task Every_other_folder_name_is_case_sensitive(string stored, string asked)
    {
        // The other half of section 5.1: "Other mailbox names are case-sensitive." A server that
        // folded every name would merge two folders a user deliberately made different.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection, stored, FolderSpecialUse.None);

        (await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, stored, CancellationToken.None)).ShouldNotBeNull();

        (await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, asked, CancellationToken.None)).ShouldBeNull();
    }

    [Fact]
    public async Task One_mailbox_cannot_read_another_mailboxs_folder()
    {
        // The authorisation boundary, and the reason MailboxId is in the WHERE clause rather
        // than checked afterwards: a session that had somehow acquired another mailbox's folder
        // name must not be able to read it, and there is no query here that could.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId alice, MailboxFolderId aliceInbox) = await SeedFolderAsync(connection);

        (MailboxId mallory, _) = await SeedFolderAsync(
            connection,
            "INBOX",
            address: "mallory@evil.example");

        await DeliverAsync(connection, alice, aliceInbox, uid: 1);

        // Mallory's own inbox is there and is empty.
        ImapFolderSnapshot? own = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mallory, "INBOX", CancellationToken.None);

        own.ShouldNotBeNull();
        own.ExistsCount.ShouldBe(0);

        // Alice's is not reachable at all, and the message in it is not counted anywhere.
        own.FolderId.ShouldNotBe(aliceInbox);
    }

    // ---------------------------------------------------------------------------------------
    // EXISTS and the first unseen position. These are why the test uses a real database.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Messages_are_counted()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        for (long uid = 1; uid <= 4; uid++)
        {
            await DeliverAsync(connection, mailbox, folder, uid);
        }

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot!.ExistsCount.ShouldBe(4);
    }

    [Fact]
    public async Task The_first_unseen_message_is_reported_as_its_sequence_number()
    {
        // A sequence number is a position, not a UID. Messages 1 and 2 have been read, so the
        // first unseen one is at position 3.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(connection, mailbox, folder, uid: 1, flags: MessageFlags.Seen);
        await DeliverAsync(connection, mailbox, folder, uid: 2, flags: MessageFlags.Seen);
        await DeliverAsync(connection, mailbox, folder, uid: 3);
        await DeliverAsync(connection, mailbox, folder, uid: 4);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot!.ExistsCount.ShouldBe(4);
        snapshot.FirstUnseenSequenceNumber.ShouldBe(3);
        snapshot.HasUnseen.ShouldBeTrue();
    }

    [Fact]
    public async Task A_sequence_number_counts_positions_rather_than_uids()
    {
        // The case a naive implementation gets wrong by reporting the UID. UIDs are never
        // reused, so a gap is the normal state of any folder that has ever been expunged: these
        // four messages sit at UIDs 10, 20, 30 and 40, and the unseen one at UID 30 is at
        // sequence number 3.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(connection, mailbox, folder, uid: 10, flags: MessageFlags.Seen);
        await DeliverAsync(connection, mailbox, folder, uid: 20, flags: MessageFlags.Seen);
        await DeliverAsync(connection, mailbox, folder, uid: 30);
        await DeliverAsync(connection, mailbox, folder, uid: 40, flags: MessageFlags.Seen);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot!.FirstUnseenSequenceNumber.ShouldBe(3, "the unseen message is third, not UID 30.");
    }

    [Fact]
    public async Task The_first_message_being_unseen_reports_sequence_number_one()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(connection, mailbox, folder, uid: 1);
        await DeliverAsync(connection, mailbox, folder, uid: 2, flags: MessageFlags.Seen);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot!.FirstUnseenSequenceNumber.ShouldBe(1);
    }

    [Fact]
    public async Task A_folder_where_everything_has_been_read_reports_nothing_unseen()
    {
        // The case that must produce null rather than 0: RFC 3501 section 9 types the UNSEEN
        // code's argument as an nz-number, so a folder with nothing unseen omits the whole line
        // rather than sending an ungrammatical [UNSEEN 0].
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(connection, mailbox, folder, uid: 1, flags: MessageFlags.Seen);
        await DeliverAsync(connection, mailbox, folder, uid: 2, flags: MessageFlags.Seen);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot!.ExistsCount.ShouldBe(2);
        snapshot.FirstUnseenSequenceNumber.ShouldBeNull();
        snapshot.HasUnseen.ShouldBeFalse();
    }

    [Fact]
    public async Task Only_the_seen_bit_decides_whether_a_message_is_unseen()
    {
        // A message can carry several flags. \Answered, \Flagged, \Deleted and \Draft say
        // nothing about whether it has been read, and a mask that tested the whole column rather
        // than the one bit would report a flagged-but-unread message as read.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(
            connection,
            mailbox,
            folder,
            uid: 1,
            flags: MessageFlags.Flagged | MessageFlags.Answered | MessageFlags.Draft);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot!.FirstUnseenSequenceNumber.ShouldBe(1, "only \\Seen makes a message seen.");
    }

    [Fact]
    public async Task A_seen_message_carrying_other_flags_is_still_seen()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(
            connection,
            mailbox,
            folder,
            uid: 1,
            flags: MessageFlags.Seen | MessageFlags.Flagged | MessageFlags.Deleted);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot!.FirstUnseenSequenceNumber.ShouldBeNull();
    }

    [Fact]
    public async Task Another_folders_messages_are_not_counted()
    {
        // The count is scoped by FolderId, so a busy inbox must not make an empty Archive look
        // full - which is what a client would act on by asking to fetch messages that are not
        // there.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId inbox) = await SeedFolderAsync(connection);

        MailboxFolderId archive = new(Guid.NewGuid());

        await connection.ExecuteAsync(
            """
            INSERT INTO MailboxFolders (Id, MailboxId, Path, SpecialUse, UidValidity, NextUid,
                                        IsSubscribed, CreatedUtc)
            VALUES (@FolderId, @MailboxId, 'Archive', 6, 999, 1, 1, @Now)
            """,
            new { FolderId = archive.Value, MailboxId = mailbox.Value, Now });

        await DeliverAsync(connection, mailbox, inbox, uid: 1);
        await DeliverAsync(connection, mailbox, inbox, uid: 2);

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "Archive", CancellationToken.None);

        snapshot!.ExistsCount.ShouldBe(0);
        snapshot.FirstUnseenSequenceNumber.ShouldBeNull();
        snapshot.UidValidity.ShouldBe(999);
    }

    [Fact]
    public async Task Uidnext_comes_from_the_folders_stored_counter()
    {
        // Never derived from the highest UID present: UIDs are never reused, so a folder whose
        // last message was expunged still owes the next delivery a UID above it.
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await connection.ExecuteAsync(
            "UPDATE MailboxFolders SET NextUid = 4392 WHERE Id = @Id",
            new { Id = folder.Value });

        ImapFolderSnapshot? snapshot = await database.CreateScope().ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        snapshot!.UidNext.ShouldBe(4392);
        snapshot.ExistsCount.ShouldBe(0, "an empty folder can still have a high UIDNEXT.");
    }

    [Fact]
    public async Task The_reader_refuses_a_null_path()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        await Should.ThrowAsync<ArgumentNullException>(
            async () => await database.CreateScope().ImapMailboxes.OpenFolderAsync(
                new MailboxId(Guid.NewGuid()),
                null!,
                CancellationToken.None));
    }
}
