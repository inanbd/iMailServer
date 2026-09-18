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

    /// <summary>Adds another folder to a mailbox that already exists.</summary>
    private static async Task<MailboxFolderId> AddFolderAsync(
        DbConnection connection,
        MailboxId mailboxId,
        string path,
        FolderSpecialUse specialUse = FolderSpecialUse.None,
        bool subscribed = true)
    {
        Guid folderId = Guid.NewGuid();

        await connection.ExecuteAsync(
            """
            INSERT INTO MailboxFolders (Id, MailboxId, Path, SpecialUse, UidValidity, NextUid,
                                        IsSubscribed, CreatedUtc)
            VALUES (@FolderId, @MailboxId, @Path, @SpecialUse, 1, 1, @Subscribed, @Now)
            """,
            new
            {
                FolderId = folderId,
                MailboxId = mailboxId.Value,
                Path = path,
                SpecialUse = (int)specialUse,
                Subscribed = subscribed,
                Now,
            });

        return new MailboxFolderId(folderId);
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
        // Section 5.1 takes no position on non-INBOX names - "The interpretation of all other
        // names is implementation-dependent" - and this server matches them exactly, which is one
        // of the three dispositions it lists. A server that
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
    // ---------------------------------------------------------------------------------------
    // Enumerating the folders.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Every_folder_in_the_mailbox_is_listed_in_path_order()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection);

        await AddFolderAsync(connection, mailbox, "Sent", FolderSpecialUse.Sent);
        await AddFolderAsync(connection, mailbox, "Archive", FolderSpecialUse.Archive);

        IReadOnlyList<ImapFolderListing> listings = await database.CreateScope().ImapMailboxes
            .ListFoldersAsync(mailbox, CancellationToken.None);

        listings.Select(l => l.Path).ShouldBe(["Archive", "INBOX", "Sent"]);
        listings.Select(l => l.SpecialUse).ShouldBe(
        [
            FolderSpecialUse.Archive,
            FolderSpecialUse.Inbox,
            FolderSpecialUse.Sent,
        ]);
    }

    /// <summary>
    /// The one thing the SQL cannot answer on its own, so it is derived from the set — and the
    /// derivation is what this proves against real rows rather than a hand-built list.
    /// </summary>
    [Fact]
    public async Task A_folder_with_something_nested_beneath_it_reports_children()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection);

        await AddFolderAsync(connection, mailbox, "Projects");
        await AddFolderAsync(connection, mailbox, "Projects/2026");
        await AddFolderAsync(connection, mailbox, "Projects/2026/Q1");

        IReadOnlyList<ImapFolderListing> listings = await database.CreateScope().ImapMailboxes
            .ListFoldersAsync(mailbox, CancellationToken.None);

        listings.Single(l => l.Path == "Projects").HasChildren.ShouldBeTrue();
        listings.Single(l => l.Path == "Projects/2026").HasChildren.ShouldBeTrue();
        listings.Single(l => l.Path == "Projects/2026/Q1").HasChildren.ShouldBeFalse();
        listings.Single(l => l.Path == "INBOX").HasChildren.ShouldBeFalse();
    }

    /// <summary>
    /// A sibling whose name merely starts the same way is not a child, and a sibling sorting
    /// between a parent and its child does not hide the child. '.' is 0x2E and the separator is
    /// 0x2F, so ordered ordinally these rows are Work, Work.old, Work/Q1 — the case that rules
    /// out a neighbour comparison. Proved here against the real query's real ordering.
    /// </summary>
    [Fact]
    public async Task A_sibling_is_neither_a_child_nor_a_way_to_hide_one()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection);

        await AddFolderAsync(connection, mailbox, "Work");
        await AddFolderAsync(connection, mailbox, "Work.old");
        await AddFolderAsync(connection, mailbox, "Workshop");
        await AddFolderAsync(connection, mailbox, "Work/Q1");

        IReadOnlyList<ImapFolderListing> listings = await database.CreateScope().ImapMailboxes
            .ListFoldersAsync(mailbox, CancellationToken.None);

        listings.Single(l => l.Path == "Work").HasChildren.ShouldBeTrue();
        listings.Single(l => l.Path == "Work.old").HasChildren.ShouldBeFalse();
        listings.Single(l => l.Path == "Workshop").HasChildren.ShouldBeFalse();
    }

    [Fact]
    public async Task A_folders_subscription_is_reported_as_stored()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection);

        await AddFolderAsync(connection, mailbox, "Quiet", subscribed: false);

        IReadOnlyList<ImapFolderListing> listings = await database.CreateScope().ImapMailboxes
            .ListFoldersAsync(mailbox, CancellationToken.None);

        listings.Single(l => l.Path == "Quiet").IsSubscribed.ShouldBeFalse();
        listings.Single(l => l.Path == "INBOX").IsSubscribed.ShouldBeTrue();
    }

    /// <summary>
    /// The authorisation boundary again, and for the command that would leak the most: a folder
    /// listing names every folder the caller has, so a missing MailboxId here would hand one
    /// mailbox the shape of every other.
    /// </summary>
    [Fact]
    public async Task Another_mailboxs_folders_are_never_enumerated()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId alice, _) = await SeedFolderAsync(connection);

        (MailboxId bob, _) = await SeedFolderAsync(
            connection,
            address: "bob@example.net");

        await AddFolderAsync(connection, bob, "Payroll");

        IReadOnlyList<ImapFolderListing> listings = await database.CreateScope().ImapMailboxes
            .ListFoldersAsync(alice, CancellationToken.None);

        listings.Select(l => l.Path).ShouldBe(["INBOX"]);
    }

    // ---------------------------------------------------------------------------------------
    // STATUS.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Status_counts_the_messages_and_the_unread_ones()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(
            connection,
            uidValidity: 999);

        await DeliverAsync(connection, mailbox, folder, uid: 1, flags: MessageFlags.Seen);
        await DeliverAsync(connection, mailbox, folder, uid: 2, flags: MessageFlags.Seen);
        await DeliverAsync(connection, mailbox, folder, uid: 7);
        await DeliverAsync(connection, mailbox, folder, uid: 9);

        ImapFolderStatus? status = await database.CreateScope().ImapMailboxes
            .ReadStatusAsync(mailbox, "INBOX", CancellationToken.None);

        status.ShouldNotBeNull();
        status.MessageCount.ShouldBe(4);
        status.UnseenCount.ShouldBe(2);
        status.RecentCount.ShouldBe(0);
        status.UidValidity.ShouldBe(999);
    }

    /// <summary>
    /// The distinction the two commands bury under one word: STATUS's UNSEEN counts and
    /// SELECT's [UNSEEN n] points. Read from the same folder by the two real queries, so a
    /// future change that made one serve the other would fail here.
    /// </summary>
    [Fact]
    public async Task Status_counts_unread_where_select_locates_the_first_one()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        for (long uid = 1; uid <= 11; uid++)
        {
            await DeliverAsync(connection, mailbox, folder, uid, MessageFlags.Seen);
        }

        await DeliverAsync(connection, mailbox, folder, uid: 12);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        ImapFolderStatus? status = await scope.ImapMailboxes
            .ReadStatusAsync(mailbox, "INBOX", CancellationToken.None);

        ImapFolderSnapshot? snapshot = await scope.ImapMailboxes
            .OpenFolderAsync(mailbox, "INBOX", CancellationToken.None);

        status!.UnseenCount.ShouldBe(1);
        snapshot!.FirstUnseenSequenceNumber.ShouldBe(12);
    }

    [Fact]
    public async Task Status_for_an_empty_folder_is_zeroes_rather_than_null()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, _) = await SeedFolderAsync(connection);

        ImapFolderStatus? status = await database.CreateScope().ImapMailboxes
            .ReadStatusAsync(mailbox, "INBOX", CancellationToken.None);

        status.ShouldNotBeNull();
        status.MessageCount.ShouldBe(0);
        status.UnseenCount.ShouldBe(0);
    }

    [Fact]
    public async Task Status_for_a_folder_this_mailbox_does_not_have_reads_as_null()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId alice, _) = await SeedFolderAsync(connection);

        (MailboxId bob, _) = await SeedFolderAsync(connection, address: "bob@example.net");

        await AddFolderAsync(connection, bob, "Payroll");

        (await database.CreateScope().ImapMailboxes
            .ReadStatusAsync(alice, "Payroll", CancellationToken.None))
            .ShouldBeNull();
    }

    /// <summary>
    /// The inbox is the one name RFC 3501 §5.1 reserves and folds, and STATUS must apply the
    /// rule the same way SELECT does — a client that opened "inbox" and then asked STATUS for
    /// "INBOX" is asking about the same folder.
    /// </summary>
    [Theory]
    [InlineData("INBOX")]
    [InlineData("inbox")]
    [InlineData("InBoX")]
    public async Task Status_folds_the_inbox_name_the_way_select_does(string name)
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(connection, mailbox, folder, uid: 1);

        ImapFolderStatus? status = await database.CreateScope().ImapMailboxes
            .ReadStatusAsync(mailbox, name, CancellationToken.None);

        status.ShouldNotBeNull();
        status.MessageCount.ShouldBe(1);
    }
    // ---------------------------------------------------------------------------------------
    // FETCH.
    // ---------------------------------------------------------------------------------------

    private static ImapSequenceSet Set(string text)
    {
        ImapSequenceSet.TryParse(text, out ImapSequenceSet? set)
            .ShouldBeTrue($"could not parse sequence set [{text}]");

        return set!;
    }

    /// <summary>
    /// A folder with gaps in its UIDs, because UIDs are never reused and any folder that has been
    /// expunged has them. Sequence numbers are positions in what remains.
    /// </summary>
    private static async Task<(SqliteTestDatabase Database, MailboxId Mailbox, MailboxFolderId Folder)>
        SeedMessagesAsync(SqliteTestDatabase database, DbConnection connection)
    {
        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(connection, mailbox, folder, uid: 3, flags: MessageFlags.Seen);
        await DeliverAsync(connection, mailbox, folder, uid: 7);
        await DeliverAsync(connection, mailbox, folder, uid: 11, flags: MessageFlags.Flagged);
        await DeliverAsync(connection, mailbox, folder, uid: 19);

        return (database, mailbox, folder);
    }

    [Fact]
    public async Task Sequence_numbers_are_positions_in_uid_order()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        IReadOnlyList<ImapMessageSummary> summaries = await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("1:*"), byUid: false, CancellationToken.None);

        summaries.Select(s => s.SequenceNumber).ShouldBe([1, 2, 3, 4]);
        summaries.Select(s => s.Uid).ShouldBe([3, 7, 11, 19]);
    }

    [Fact]
    public async Task A_narrowed_read_numbers_its_rows_the_same_way_an_unnarrowed_one_does()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        IReadOnlyList<ImapMessageSummary> summaries = await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("3"), byUid: false, CancellationToken.None);

        summaries.Count.ShouldBe(1);
        summaries[0].SequenceNumber.ShouldBe(3);
        summaries[0].Uid.ShouldBe(11);
    }

    [Fact]
    public async Task Uid_reads_select_by_uid_and_still_report_the_sequence_number()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        IReadOnlyList<ImapMessageSummary> summaries = await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("11"), byUid: true, CancellationToken.None);

        summaries.Count.ShouldBe(1);
        summaries[0].Uid.ShouldBe(11);
        summaries[0].SequenceNumber.ShouldBe(3);
    }

    /// <summary>
    /// RFC 3501 §9's own note that 5:3 and 3:5 are the same range, applied through the wildcard:
    /// a folder holding four messages answers 6:* as 6:4, which is 4:6, which includes message 4.
    /// A read that narrowed to "from 6 upwards" because 6 was written first would return nothing.
    /// </summary>
    [Fact]
    public async Task A_reversed_wildcard_range_still_finds_the_messages_below_it()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        IReadOnlyList<ImapMessageSummary> summaries = await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("6:*"), byUid: false, CancellationToken.None);

        summaries.Select(s => s.SequenceNumber).ShouldBe([4]);
    }

    /// <summary>The wildcard means the largest UID under UID FETCH, not the message count.</summary>
    [Fact]
    public async Task The_wildcard_resolves_against_uids_for_a_uid_read()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        IReadOnlyList<ImapMessageSummary> summaries = await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("*"), byUid: true, CancellationToken.None);

        summaries.Select(s => s.Uid).ShouldBe([19]);
    }

    /// <summary>The same star under a plain FETCH means the last position, which is a different row.</summary>
    [Fact]
    public async Task The_wildcard_resolves_against_positions_for_a_plain_read()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        IReadOnlyList<ImapMessageSummary> summaries = await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("*"), byUid: false, CancellationToken.None);

        summaries.Select(s => s.SequenceNumber).ShouldBe([4]);
        summaries.Select(s => s.Uid).ShouldBe([19]);
    }

    [Fact]
    public async Task A_disjoint_set_selects_only_what_it_names()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        IReadOnlyList<ImapMessageSummary> summaries = await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("1,4"), byUid: false, CancellationToken.None);

        summaries.Select(s => s.Uid).ShouldBe([3, 19]);
    }

    /// <summary>
    /// §6.4.8: "A non-existent unique identifier is ignored without any error message generated."
    /// </summary>
    [Theory]
    [InlineData("5", true)]
    [InlineData("100:200", true)]
    [InlineData("99", false)]
    public async Task A_number_naming_no_message_returns_nothing_rather_than_failing(
        string text,
        bool byUid)
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        (await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set(text), byUid, CancellationToken.None))
            .ShouldBeEmpty();
    }

    [Fact]
    public async Task An_empty_folder_returns_nothing_for_any_set()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        (await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("1:*"), byUid: false, CancellationToken.None))
            .ShouldBeEmpty();
    }

    [Fact]
    public async Task The_stored_flags_and_size_come_back_with_the_message()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        IReadOnlyList<ImapMessageSummary> summaries = await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(mailbox, folder, Set("1:*"), byUid: false, CancellationToken.None);

        summaries[0].Flags.ShouldBe(MessageFlags.Seen);
        summaries[1].Flags.ShouldBe(MessageFlags.None);
        summaries[2].Flags.ShouldBe(MessageFlags.Flagged);

        // Every seeded message is 100 octets; the size is read from Messages, not Deliveries,
        // because one stored message delivered to two folders has one size.
        summaries.ShouldAllBe(s => s.SizeBytes == 100);
    }

    /// <summary>
    /// The authorisation boundary on the command that returns actual mail. A folder id is a value
    /// an authenticated session hands back, so it must not be enough on its own.
    /// </summary>
    [Fact]
    public async Task Another_mailboxs_folder_id_reads_no_messages()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId alice, _) = await SeedFolderAsync(connection);

        (MailboxId bob, MailboxFolderId bobsFolder) = await SeedFolderAsync(
            connection,
            address: "bob@example.net");

        await DeliverAsync(connection, bob, bobsFolder, uid: 1);

        (await database.CreateScope().ImapMailboxes
            .ReadSummariesAsync(alice, bobsFolder, Set("1:*"), byUid: false, CancellationToken.None))
            .ShouldBeEmpty();
    }
    // ---------------------------------------------------------------------------------------
    // STORE.
    // ---------------------------------------------------------------------------------------

    private static ImapStoreRequest Store(
        ImapStoreMode mode,
        MessageFlags flags,
        bool silent = false) =>
        new(mode, silent, flags, HadUnstorableFlags: false);

    [Fact]
    public async Task Adding_a_flag_writes_it_and_reports_the_new_value()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        IReadOnlyList<ImapMessageSummary> reported = await scope.ImapWrites.StoreFlagsAsync(
            mailbox,
            folder,
            Set("1:2"),
            byUid: false,
            Store(ImapStoreMode.Add, MessageFlags.Deleted),
            CancellationToken.None);

        reported.Select(s => s.Flags).ShouldBe(
        [
            MessageFlags.Seen | MessageFlags.Deleted,
            MessageFlags.Deleted,
        ]);

        // Read back through a separate call, so the assertion is about the database rather than
        // about what the writer returned.
        IReadOnlyList<ImapMessageSummary> after = await scope.ImapMailboxes.ReadSummariesAsync(
            mailbox,
            folder,
            Set("1:*"),
            byUid: false,
            CancellationToken.None);

        after.Select(s => s.Flags).ShouldBe(
        [
            MessageFlags.Seen | MessageFlags.Deleted,
            MessageFlags.Deleted,
            MessageFlags.Flagged,
            MessageFlags.None,
        ]);
    }

    [Fact]
    public async Task Replacing_flags_takes_the_argument_wholesale()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await scope.ImapWrites.StoreFlagsAsync(
            mailbox,
            folder,
            Set("1:*"),
            byUid: false,
            Store(ImapStoreMode.Replace, MessageFlags.Draft),
            CancellationToken.None);

        IReadOnlyList<ImapMessageSummary> after = await scope.ImapMailboxes.ReadSummariesAsync(
            mailbox,
            folder,
            Set("1:*"),
            byUid: false,
            CancellationToken.None);

        after.ShouldAllBe(s => s.Flags == MessageFlags.Draft);
    }

    [Fact]
    public async Task Removing_a_flag_leaves_the_others_alone()
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

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        IReadOnlyList<ImapMessageSummary> reported = await scope.ImapWrites.StoreFlagsAsync(
            mailbox,
            folder,
            Set("1"),
            byUid: false,
            Store(ImapStoreMode.Remove, MessageFlags.Deleted),
            CancellationToken.None);

        reported[0].Flags.ShouldBe(MessageFlags.Seen | MessageFlags.Flagged);
    }

    /// <summary>
    /// Messages sharing an outcome are written in one statement, and messages with different
    /// outcomes still each get the right one — the grouping must not smear one result over the
    /// whole set.
    /// </summary>
    [Fact]
    public async Task Messages_with_different_starting_flags_get_different_results()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await scope.ImapWrites.StoreFlagsAsync(
            mailbox,
            folder,
            Set("1:*"),
            byUid: false,
            Store(ImapStoreMode.Add, MessageFlags.Answered),
            CancellationToken.None);

        IReadOnlyList<ImapMessageSummary> after = await scope.ImapMailboxes.ReadSummariesAsync(
            mailbox,
            folder,
            Set("1:*"),
            byUid: false,
            CancellationToken.None);

        after.Select(s => s.Flags).ShouldBe(
        [
            MessageFlags.Seen | MessageFlags.Answered,
            MessageFlags.Answered,
            MessageFlags.Flagged | MessageFlags.Answered,
            MessageFlags.Answered,
        ]);
    }

    /// <summary>
    /// A message already in the requested state is skipped for the write and still reported:
    /// RFC 3501 §6.4.6 returns "the new value of the flags", not "the flags that changed".
    /// </summary>
    [Fact]
    public async Task A_message_already_in_the_requested_state_is_still_reported()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        await DeliverAsync(connection, mailbox, folder, uid: 1, flags: MessageFlags.Seen);

        IReadOnlyList<ImapMessageSummary> reported = await database.CreateScope().ImapWrites
            .StoreFlagsAsync(
                mailbox,
                folder,
                Set("1"),
                byUid: false,
                Store(ImapStoreMode.Add, MessageFlags.Seen),
                CancellationToken.None);

        reported.Count.ShouldBe(1);
        reported[0].Flags.ShouldBe(MessageFlags.Seen);
    }

    [Fact]
    public async Task A_uid_store_selects_by_uid()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        IReadOnlyList<ImapMessageSummary> reported = await scope.ImapWrites.StoreFlagsAsync(
            mailbox,
            folder,
            Set("11"),
            byUid: true,
            Store(ImapStoreMode.Add, MessageFlags.Draft),
            CancellationToken.None);

        reported.Count.ShouldBe(1);
        reported[0].Uid.ShouldBe(11);
        reported[0].SequenceNumber.ShouldBe(3);
        reported[0].Flags.ShouldBe(MessageFlags.Flagged | MessageFlags.Draft);
    }

    [Fact]
    public async Task Storing_to_nothing_writes_nothing_and_reports_nothing()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (_, MailboxId mailbox, MailboxFolderId folder) =
            await SeedMessagesAsync(database, connection);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (await scope.ImapWrites.StoreFlagsAsync(
            mailbox,
            folder,
            Set("99"),
            byUid: false,
            Store(ImapStoreMode.Replace, MessageFlags.Draft),
            CancellationToken.None))
            .ShouldBeEmpty();

        IReadOnlyList<ImapMessageSummary> after = await scope.ImapMailboxes.ReadSummariesAsync(
            mailbox,
            folder,
            Set("1:*"),
            byUid: false,
            CancellationToken.None);

        after[0].Flags.ShouldBe(MessageFlags.Seen);
    }

    /// <summary>
    /// The authorisation boundary on a statement that changes data. A folder id alone must not be
    /// enough to write to somebody else's folder.
    /// </summary>
    [Fact]
    public async Task Another_mailboxs_folder_id_writes_nothing()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId alice, _) = await SeedFolderAsync(connection);

        (MailboxId bob, MailboxFolderId bobsFolder) = await SeedFolderAsync(
            connection,
            address: "bob@example.net");

        await DeliverAsync(connection, bob, bobsFolder, uid: 1, flags: MessageFlags.Seen);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (await scope.ImapWrites.StoreFlagsAsync(
            alice,
            bobsFolder,
            Set("1:*"),
            byUid: false,
            Store(ImapStoreMode.Replace, MessageFlags.Deleted),
            CancellationToken.None))
            .ShouldBeEmpty();

        IReadOnlyList<ImapMessageSummary> bobs = await scope.ImapMailboxes.ReadSummariesAsync(
            bob,
            bobsFolder,
            Set("1:*"),
            byUid: false,
            CancellationToken.None);

        bobs[0].Flags.ShouldBe(MessageFlags.Seen);
    }

    /// <summary>
    /// More UIDs than fit in one statement's parameter list, so the batching is exercised against
    /// a real driver rather than reasoned about.
    /// </summary>
    [Fact]
    public async Task A_store_over_more_messages_than_one_statement_holds_writes_them_all()
    {
        await using SqliteTestDatabase database = new();
        await using DbConnection connection = await MigratedAsync(database);

        (MailboxId mailbox, MailboxFolderId folder) = await SeedFolderAsync(connection);

        const int Count = 1_200;

        for (long uid = 1; uid <= Count; uid++)
        {
            await DeliverAsync(connection, mailbox, folder, uid);
        }

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        IReadOnlyList<ImapMessageSummary> reported = await scope.ImapWrites.StoreFlagsAsync(
            mailbox,
            folder,
            Set("1:*"),
            byUid: false,
            Store(ImapStoreMode.Add, MessageFlags.Seen),
            CancellationToken.None);

        reported.Count.ShouldBe(Count);

        IReadOnlyList<ImapMessageSummary> after = await scope.ImapMailboxes.ReadSummariesAsync(
            mailbox,
            folder,
            Set("1:*"),
            byUid: false,
            CancellationToken.None);

        after.Count.ShouldBe(Count);
        after.ShouldAllBe(s => s.Flags == MessageFlags.Seen);
    }
}
