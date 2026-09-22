using System.Data.Common;
using Dapper;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Enums;
using MailServer.Domain.Filtering;
using MailServer.Domain.ValueObjects;

namespace MailServer.Persistence.Tests;

/// <summary>
/// Migration 0015 and the repository over it, against a real database.
/// </summary>
/// <remarks>
/// <b>Milestone 12's exit criterion is a quarantine round trip</b>, and the half of it that
/// needs a database lives here: hold a message, find it in the listing, release it, and have
/// the release be the thing that decides who delivers it. The other half — that a released
/// message actually reaches a mailbox — is <c>QuarantineReleaseTests</c>, which drives the
/// real delivery service.
/// </remarks>
public sealed class QuarantineRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);

    private static readonly TimeSpan Retention = TimeSpan.FromDays(30);

    [Fact]
    public async Task The_quarantine_tables_exist()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        await using DbConnection connection = await database.ConnectionFactory
            .OpenConnectionAsync(CancellationToken.None);

        string[] tables =
        [
            .. await connection.QueryAsync<string>(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        ];

        tables.ShouldContain("QuarantinedMessages");
        tables.ShouldContain("QuarantineSignals");
    }

    /// <summary>
    /// A resolved row must say when, and a held one must not. The two columns are one fact and
    /// a schema that let them disagree would produce a quarantine nobody could reason about.
    /// </summary>
    [Fact]
    public async Task A_held_row_cannot_claim_it_was_resolved()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        await using DbConnection connection = await database.ConnectionFactory
            .OpenConnectionAsync(CancellationToken.None);

        StoredMessageId messageId = await SeedMessageAsync(connection);

        await Should.ThrowAsync<Microsoft.Data.Sqlite.SqliteException>(() => connection.ExecuteAsync(
            """
            INSERT INTO QuarantinedMessages
                (Id, MessageId, ReversePath, RemoteAddress, Score, Summary,
                 Status, QuarantinedUtc, ResolvedUtc, ResolvedBy, ExpiresUtc)
            VALUES
                (@Id, @MessageId, NULL, '198.51.100.7', 12.0, 'held',
                 0, @Now, @Now, 'someone', @Now)
            """,
            new { Id = Guid.CreateVersion7(), MessageId = messageId.Value, Now }));
    }

    /// <summary>One message is held once; a second verdict on it is a bug in the delivery path.</summary>
    [Fact]
    public async Task One_message_cannot_be_held_twice()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);

        await scope.Quarantine.AddAsync(Held(messageId), CancellationToken.None);

        await Should.ThrowAsync<Microsoft.Data.Sqlite.SqliteException>(
            () => scope.Quarantine.AddAsync(Held(messageId), CancellationToken.None));
    }

    [Fact]
    public async Task Holds_a_message_with_its_reasons()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);

        QuarantinedMessage held = Held(messageId);
        await scope.Quarantine.AddAsync(held, CancellationToken.None);

        QuarantinedMessage? read = await scope.Quarantine.GetAsync(held.Id, CancellationToken.None);

        read.ShouldNotBeNull();
        read.MessageId.ShouldBe(messageId);
        read.Status.ShouldBe(QuarantineStatus.Held);
        read.Score.ShouldBe(held.Score, 0.0001);
        read.ReversePath!.Value.ShouldBe("sender@example.net");
        read.RemoteAddress.ToString().ShouldBe("198.51.100.7");
        read.Signals.Select(s => s.Name).ShouldBe(["BLOCKED_ATTACHMENT", "DMARC_FAIL"]);
    }

    /// <summary>The order the checks produced the reasons is the order an operator reads them in.</summary>
    [Fact]
    public async Task Keeps_the_signals_in_the_order_they_were_produced()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);

        FilterSignal[] signals =
        [
            FilterSignal.Create("ZULU", 1, "last alphabetically, first produced"),
            FilterSignal.Create("ALPHA", 1, "first alphabetically, last produced"),
        ];

        QuarantinedMessage held = QuarantinedMessage.Create(
            messageId,
            null,
            IpAddressValue.Parse("198.51.100.7"),
            FilterVerdict.Create(signals, FilterPolicy.Default, FilterAction.Quarantine),
            Now,
            Retention);

        await scope.Quarantine.AddAsync(held, CancellationToken.None);

        QuarantinedMessage? read = await scope.Quarantine.GetAsync(held.Id, CancellationToken.None);

        read!.Signals.Select(s => s.Name).ShouldBe(["ZULU", "ALPHA"]);
    }

    [Fact]
    public async Task Lists_what_is_held_newest_first()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        for (int i = 0; i < 3; i++)
        {
            StoredMessageId messageId = await SeedMessageAsync(database);

            await scope.Quarantine.AddAsync(
                Held(messageId, at: Now.AddMinutes(i)), CancellationToken.None);
        }

        IReadOnlyList<QuarantinedMessage> held = await scope.Quarantine
            .ListAsync(QuarantineFilter.Held, 10, CancellationToken.None);

        held.Count.ShouldBe(3);
        held[0].QuarantinedUtc.ShouldBeGreaterThan(held[2].QuarantinedUtc);
        held.ShouldAllBe(h => h.Signals.Count == 2);
    }

    [Fact]
    public async Task Counts_what_is_held()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);
        QuarantinedMessage held = Held(messageId);

        await scope.Quarantine.AddAsync(held, CancellationToken.None);

        (await scope.Quarantine.CountHeldAsync(CancellationToken.None)).ShouldBe(1);

        held.Release("operator", Now);
        await scope.Quarantine.TryResolveAsync(held, CancellationToken.None);

        (await scope.Quarantine.CountHeldAsync(CancellationToken.None)).ShouldBe(0);
    }

    [Fact]
    public async Task Resolving_records_who_and_when()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);
        QuarantinedMessage held = Held(messageId);

        await scope.Quarantine.AddAsync(held, CancellationToken.None);

        held.Release("alice", Now.AddHours(1));

        (await scope.Quarantine.TryResolveAsync(held, CancellationToken.None)).ShouldBeTrue();

        QuarantinedMessage? read = await scope.Quarantine.GetAsync(held.Id, CancellationToken.None);

        read!.Status.ShouldBe(QuarantineStatus.Released);
        read.ResolvedBy.ShouldBe("alice");
        read.ResolvedUtc.ShouldBe(Now.AddHours(1));
        read.IsHeld.ShouldBeFalse();
    }

    /// <summary>
    /// Two administrators looking at the same quarantine is the ordinary case. Whoever clicks
    /// second must be told it was already handled, not deliver the message a second time — and
    /// that has to be a fact about the database rather than a hope about timing.
    /// </summary>
    [Fact]
    public async Task Only_one_administrator_wins_a_resolution()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);
        QuarantinedMessage held = Held(messageId);

        await scope.Quarantine.AddAsync(held, CancellationToken.None);

        // Two operators read the same row, as two IPC sessions would.
        QuarantinedMessage first = (await scope.Quarantine.GetAsync(held.Id, CancellationToken.None))!;
        QuarantinedMessage second = (await scope.Quarantine.GetAsync(held.Id, CancellationToken.None))!;

        first.Release("alice", Now);
        second.Discard("bob", Now);

        (await scope.Quarantine.TryResolveAsync(first, CancellationToken.None)).ShouldBeTrue();
        (await scope.Quarantine.TryResolveAsync(second, CancellationToken.None)).ShouldBeFalse();

        QuarantinedMessage? read = await scope.Quarantine.GetAsync(held.Id, CancellationToken.None);

        read!.Status.ShouldBe(QuarantineStatus.Released);
        read.ResolvedBy.ShouldBe("alice");
    }

    /// <summary>A held row excludes itself from the default listing once it is resolved.</summary>
    [Fact]
    public async Task A_resolved_message_leaves_the_held_listing_but_not_the_table()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);
        QuarantinedMessage held = Held(messageId);

        await scope.Quarantine.AddAsync(held, CancellationToken.None);

        held.Discard("bob", Now);
        await scope.Quarantine.TryResolveAsync(held, CancellationToken.None);

        (await scope.Quarantine.ListAsync(QuarantineFilter.Held, 10, CancellationToken.None))
            .ShouldBeEmpty();

        (await scope.Quarantine.ListAsync(QuarantineFilter.All, 10, CancellationToken.None))
            .ShouldHaveSingleItem().Status.ShouldBe(QuarantineStatus.Discarded);
    }

    [Fact]
    public async Task Purges_what_has_expired_and_says_which_messages_they_were()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        StoredMessageId expiring = await SeedMessageAsync(database);
        StoredMessageId keeping = await SeedMessageAsync(database);

        await scope.Quarantine.AddAsync(
            Held(expiring, retention: TimeSpan.FromDays(1)), CancellationToken.None);
        await scope.Quarantine.AddAsync(
            Held(keeping, retention: TimeSpan.FromDays(90)), CancellationToken.None);

        IReadOnlyList<StoredMessageId> purged = await scope.Quarantine
            .PurgeExpiredAsync(Now.AddDays(2), 100, CancellationToken.None);

        purged.ShouldHaveSingleItem().ShouldBe(expiring);

        (await scope.Quarantine.ListAsync(QuarantineFilter.All, 10, CancellationToken.None))
            .ShouldHaveSingleItem().MessageId.ShouldBe(keeping);
    }

    /// <summary>
    /// A sweep must not remove what an operator already decided about: the row is the record of
    /// the decision, and it outlives the retention on the content.
    /// </summary>
    [Fact]
    public async Task Does_not_purge_a_message_somebody_already_resolved()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);
        QuarantinedMessage held = Held(messageId, retention: TimeSpan.FromDays(1));

        await scope.Quarantine.AddAsync(held, CancellationToken.None);

        held.Release("alice", Now);
        await scope.Quarantine.TryResolveAsync(held, CancellationToken.None);

        (await scope.Quarantine.PurgeExpiredAsync(Now.AddDays(365), 100, CancellationToken.None))
            .ShouldBeEmpty();
    }

    /// <summary>
    /// Deleting the message deletes the hold. A quarantine row naming a message that no longer
    /// exists could neither be released nor read.
    /// </summary>
    [Fact]
    public async Task Deleting_the_message_removes_the_hold()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();
        StoredMessageId messageId = await SeedMessageAsync(database);
        QuarantinedMessage held = Held(messageId);

        await scope.Quarantine.AddAsync(held, CancellationToken.None);

        await using DbConnection connection = await database.ConnectionFactory
            .OpenConnectionAsync(CancellationToken.None);

        await connection.ExecuteAsync("PRAGMA foreign_keys = ON");
        await connection.ExecuteAsync(
            "DELETE FROM Messages WHERE Id = @Id", new { Id = messageId.Value });

        (await scope.Quarantine.GetAsync(held.Id, CancellationToken.None)).ShouldBeNull();
    }

    private static QuarantinedMessage Held(
        StoredMessageId messageId,
        DateTimeOffset? at = null,
        TimeSpan? retention = null) =>
        QuarantinedMessage.Create(
            messageId,
            EmailAddress.Parse("sender@example.net"),
            IpAddressValue.Parse("198.51.100.7"),
            FilterVerdict.Create(
                [
                    FilterSignal.Create("BLOCKED_ATTACHMENT", 10.0, "setup.exe: .exe can be executed"),
                    FilterSignal.Create("DMARC_FAIL", 3.0, "DMARC alignment failed."),
                ],
                FilterPolicy.Default,
                FilterAction.Quarantine),
            at ?? Now,
            retention ?? Retention);

    private static async Task<StoredMessageId> SeedMessageAsync(SqliteTestDatabase database)
    {
        await using DbConnection connection = await database.ConnectionFactory
            .OpenConnectionAsync(CancellationToken.None);

        return await SeedMessageAsync(connection);
    }

    /// <summary>
    /// Inserts a <c>Messages</c> row for the quarantine's foreign key to name.
    /// </summary>
    /// <remarks>
    /// <b>The id is bound as a <see cref="Guid"/>, not as a pre-formatted string.</b> The
    /// repository binds Guids and lets the provider decide the text form; a seed that wrote
    /// its own would agree with it only by luck, and the foreign key would fail on whichever
    /// case the two disagreed about.
    /// </remarks>
    private static async Task<StoredMessageId> SeedMessageAsync(DbConnection connection)
    {
        Guid messageId = Guid.CreateVersion7();

        await connection.ExecuteAsync(
            """
            INSERT INTO Messages
                (Id, SizeBytes, ContentSha256, ReversePath, RemoteAddress, ListenerRole, TlsActive, ReceivedUtc)
            VALUES
                (@Id, 100, @Hash, 'sender@example.net', '198.51.100.7', 0, 0, @Now)
            """,
            new { Id = messageId, Hash = new string('a', 64), Now = Now });

        return new StoredMessageId(messageId);
    }
}
