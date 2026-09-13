using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Persistence.Tests;

public sealed class TransactionTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static MailDomain NewDomain(string name) =>
        MailDomain.Create(DomainId.New(), DomainName.Parse(name), Now);

    [Fact]
    public async Task Work_inside_a_committed_transaction_is_visible_afterwards()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await scope.Transactions.ExecuteScopedAsync(async ct =>
        {
            await scope.Domains.AddAsync(NewDomain("a.example"), ct);
            await scope.Domains.AddAsync(NewDomain("b.example"), ct);
            return true;
        }, CancellationToken.None);

        (await scope.Domains.GetAllAsync(CancellationToken.None)).Count.ShouldBe(2);
    }

    [Fact]
    public async Task A_failure_rolls_the_whole_use_case_back()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await Should.ThrowAsync<InvalidOperationException>(
            () => scope.Transactions.ExecuteScopedAsync<bool>(async ct =>
            {
                await scope.Domains.AddAsync(NewDomain("a.example"), ct);
                await scope.Domains.AddAsync(NewDomain("b.example"), ct);

                // A handler failing after two successful writes. One transaction per use case
                // means neither write survives; without it, the caller would be left with a
                // half-applied operation and no way to tell.
                throw new InvalidOperationException("handler failed");
            }, CancellationToken.None));

        (await scope.Domains.GetAllAsync(CancellationToken.None)).ShouldBeEmpty();
    }

    [Fact]
    public async Task A_repository_called_outside_a_transaction_still_works()
    {
        // Repositories must be usable both inside a command's transaction and on their own,
        // so the caller does not have to know which context it is in.
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await scope.Domains.AddAsync(NewDomain("standalone.example"), CancellationToken.None);

        (await scope.Domains.GetAllAsync(CancellationToken.None)).ShouldHaveSingleItem();
    }

    [Fact]
    public async Task A_nested_transaction_joins_the_outer_one_rather_than_opening_a_second()
    {
        // Under SQLite a second write connection opened inside an open write transaction
        // deadlocks against it: the inner one waits for a writer slot the outer one holds and
        // will not release until the inner one returns.
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await scope.Transactions.ExecuteScopedAsync(async outerCt =>
        {
            await scope.Domains.AddAsync(NewDomain("outer.example"), outerCt);

            await scope.Transactions.ExecuteScopedAsync(async innerCt =>
            {
                await scope.Domains.AddAsync(NewDomain("inner.example"), innerCt);
                return true;
            }, outerCt);

            return true;
        }, CancellationToken.None);

        (await scope.Domains.GetAllAsync(CancellationToken.None)).Count.ShouldBe(2);
    }

    [Fact]
    public async Task A_failure_in_a_nested_transaction_rolls_back_the_outer_one_too()
    {
        // The corollary of joining rather than nesting: there is only one transaction, so an
        // inner failure cannot be committed around.
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await Should.ThrowAsync<InvalidOperationException>(
            () => scope.Transactions.ExecuteScopedAsync<bool>(async outerCt =>
            {
                await scope.Domains.AddAsync(NewDomain("outer.example"), outerCt);

                await scope.Transactions.ExecuteScopedAsync<bool>(
                    _ => throw new InvalidOperationException("inner failed"),
                    outerCt);

                return true;
            }, CancellationToken.None));

        (await scope.Domains.GetAllAsync(CancellationToken.None)).ShouldBeEmpty();
    }

    [Fact]
    public async Task An_aggregate_updated_inside_a_transaction_is_readable_within_it()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain domain = MailDomain.Create(
            DomainId.New(),
            DomainName.Parse("example.com"),
            Now,
            DomainName.Parse("mail.example.com"));

        await scope.Transactions.ExecuteScopedAsync(async ct =>
        {
            await scope.Domains.AddAsync(domain, ct);

            domain.Enable(Now);
            await scope.Domains.UpdateAsync(domain, ct);

            // Read-your-own-writes inside the transaction. If the repository silently escaped
            // it by opening its own connection, this would see nothing at all.
            MailDomain? reread = await scope.Domains.GetByIdAsync(domain.Id, ct);
            reread.ShouldNotBeNull();
            reread.Status.ShouldBe(DomainStatus.Active);

            return true;
        }, CancellationToken.None);
    }

    [Fact]
    public async Task Concurrent_writers_are_serialised_without_sqlite_busy_errors()
    {
        // The central SQLite concurrency claim. Several writers competing for the single
        // writer slot would normally produce SQLITE_BUSY storms; the in-process write gate
        // turns that contention into an orderly queue.
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        const int WriterCount = 8;
        const int WritesPerWriter = 5;

        Task[] writers = new Task[WriterCount];

        for (int i = 0; i < WriterCount; i++)
        {
            int writerIndex = i;

            writers[i] = Task.Run(async () =>
            {
                // Each writer gets its own scope, exactly as each IPC request would.
                SqliteTestDatabase.TestScope scope = database.CreateScope();

                for (int j = 0; j < WritesPerWriter; j++)
                {
                    await scope.Transactions.ExecuteScopedAsync(async ct =>
                    {
                        await scope.Domains.AddAsync(
                            NewDomain($"w{writerIndex}-d{j}.example"),
                            ct);

                        return true;
                    }, CancellationToken.None);
                }
            });
        }

        await Task.WhenAll(writers);

        SqliteTestDatabase.TestScope verification = database.CreateScope();

        (await verification.Domains.GetAllAsync(CancellationToken.None))
            .Count.ShouldBe(WriterCount * WritesPerWriter);
    }

    [Fact]
    public async Task Readers_are_not_blocked_by_a_writer()
    {
        // What WAL buys: an IMAP client reading while the queue writes. Under the default
        // rollback journal this would block, and on a busy server that is the difference
        // between a responsive mailbox and a stalled one.
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope seed = database.CreateScope();
        await seed.Domains.AddAsync(NewDomain("existing.example"), CancellationToken.None);

        SqliteTestDatabase.TestScope writer = database.CreateScope();
        SqliteTestDatabase.TestScope reader = database.CreateScope();

        using SemaphoreSlim writeStarted = new(0, 1);
        using SemaphoreSlim readCompleted = new(0, 1);

        Task writeTask = writer.Transactions.ExecuteScopedAsync(async ct =>
        {
            await writer.Domains.AddAsync(NewDomain("new.example"), ct);

            writeStarted.Release();

            // Hold the write transaction open while the reader runs.
            await readCompleted.WaitAsync(TimeSpan.FromSeconds(10), ct);

            return true;
        }, CancellationToken.None);

        await writeStarted.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

        IReadOnlyList<MailDomain> readWhileWriting =
            await reader.Domains.GetAllAsync(CancellationToken.None);

        readCompleted.Release();
        await writeTask;

        // The reader sees the pre-transaction snapshot: the seeded row, not the uncommitted
        // one. That is snapshot isolation working, not a stale read.
        readWhileWriting.ShouldHaveSingleItem().Name.Value.ShouldBe("existing.example");

        (await reader.Domains.GetAllAsync(CancellationToken.None)).Count.ShouldBe(2);
    }

    [Fact]
    public async Task The_write_gate_is_enabled_for_sqlite()
    {
        await using SqliteTestDatabase database = new();

        database.Dialect.RequiresSerializedWrites.ShouldBeTrue();
        database.WriteGate.IsEnabled.ShouldBeTrue();

        await Task.CompletedTask;
    }
}
