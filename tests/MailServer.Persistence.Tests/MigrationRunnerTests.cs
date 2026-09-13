using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Exceptions;

namespace MailServer.Persistence.Tests;

public sealed class MigrationRunnerTests
{
    [Fact]
    public async Task Migrating_a_fresh_database_applies_every_script()
    {
        await using SqliteTestDatabase database = new();

        MigrationRunResult result = await database.MigrateAsync(CancellationToken.None);

        result.FromVersion.ShouldBe(0);
        result.ToVersion.ShouldBeGreaterThanOrEqualTo(1);
        result.AnythingApplied.ShouldBeTrue();
        result.AppliedScripts.ShouldContain(s => s.Contains("InitialSchema", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Migrating_twice_applies_nothing_the_second_time()
    {
        await using SqliteTestDatabase database = new();

        MigrationRunResult first = await database.MigrateAsync(CancellationToken.None);
        MigrationRunResult second = await database.MigrateAsync(CancellationToken.None);

        // "Never twice" is the migration runner's first guarantee. A migration that re-ran
        // would either fail on an existing object or, far worse, re-apply a data change.
        second.AnythingApplied.ShouldBeFalse();
        second.FromVersion.ShouldBe(first.ToVersion);
        second.ToVersion.ShouldBe(first.ToVersion);
    }

    [Fact]
    public async Task Every_expected_table_exists_after_migration()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        await using System.Data.Common.DbConnection connection =
            await database.ConnectionFactory.OpenConnectionAsync(CancellationToken.None);

        string[] tables =
        [
            .. await connection.QueryAsync<string>(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        ];

        tables.ShouldContain("Domains");
        tables.ShouldContain("Mailboxes");
        tables.ShouldContain("AuditRecords");
        tables.ShouldContain("ServerSettings");
        tables.ShouldContain("SchemaVersion");
    }

    [Fact]
    public async Task The_expected_indexes_exist_after_migration()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        await using System.Data.Common.DbConnection connection =
            await database.ConnectionFactory.OpenConnectionAsync(CancellationToken.None);

        string[] indexes =
        [
            .. await connection.QueryAsync<string>(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'")
        ];

        // The unique index on Domains.Name is what actually prevents two administrators from
        // hosting the same domain twice; the handler's pre-check only improves the message.
        indexes.ShouldContain("UX_Domains_Name");
        indexes.ShouldContain("UX_Mailboxes_Address");
        indexes.ShouldContain("IX_Mailboxes_DomainId");
        indexes.ShouldContain("IX_AuditRecords_TimestampUtc");
    }

    [Fact]
    public async Task The_schema_version_row_records_the_checksum_and_timing()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        MigrationStatus status = await database.CreateMigrator().GetStatusAsync(CancellationToken.None);

        status.IsUpToDate.ShouldBeTrue();
        status.Pending.ShouldBeEmpty();
        status.Applied.ShouldNotBeEmpty();

        AppliedMigration first = status.Applied[0];
        first.Version.ShouldBe(1);
        first.Name.ShouldBe("InitialSchema");
        first.Checksum.Length.ShouldBe(64);
        first.AppliedBy.ShouldContain("TEST-MACHINE");
        first.ProductVersion.ShouldBe("0.1.0-test");
    }

    [Fact]
    public async Task An_edited_applied_migration_is_a_hard_failure()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        // Simulate somebody editing a migration that has already shipped. Continuing would
        // run every later migration against a schema whose recorded history is a fiction.
        await using (System.Data.Common.DbConnection connection =
            await database.ConnectionFactory.OpenConnectionAsync(CancellationToken.None))
        {
            await connection.ExecuteAsync(
                "UPDATE SchemaVersion SET Checksum = @Checksum WHERE Version = 1",
                new { Checksum = new string('0', 64) });
        }

        SchemaDriftException ex = await Should.ThrowAsync<SchemaDriftException>(
            () => database.MigrateAsync(CancellationToken.None));

        ex.Version.ShouldBe(1);
        ex.Code.ShouldBe("migration.checksum_mismatch");

        // The message has to tell an operator what to do at 3am, not merely that something
        // is wrong.
        ex.Message.ShouldContain("never be edited");
    }

    [Fact]
    public async Task Status_on_a_fresh_database_reports_everything_as_pending()
    {
        await using SqliteTestDatabase database = new();

        MigrationStatus status = await database.CreateMigrator().GetStatusAsync(CancellationToken.None);

        status.CurrentVersion.ShouldBe(0);
        status.IsUpToDate.ShouldBeFalse();
        status.Pending.ShouldNotBeEmpty();
        status.Applied.ShouldBeEmpty();
    }

    [Fact]
    public async Task Checksums_are_stable_across_line_ending_differences()
    {
        // Without normalisation, a Git checkout with core.autocrlf=true produces a different
        // checksum from the build server, and every developer's service would refuse to start
        // claiming schema drift that does not exist.
        await using SqliteTestDatabase database = new();

        string unix = "CREATE TABLE A (Id INTEGER);\nCREATE TABLE B (Id INTEGER);\n";
        string windows = "CREATE TABLE A (Id INTEGER);\r\nCREATE TABLE B (Id INTEGER);\r\n";

        Infrastructure.Persistence.MigrationScriptLoader.ComputeChecksum(unix)
            .ShouldBe(Infrastructure.Persistence.MigrationScriptLoader.ComputeChecksum(windows));

        await Task.CompletedTask;
    }

    [Fact]
    public async Task Wal_mode_is_actually_in_effect()
    {
        // WAL is what lets IMAP readers proceed while the queue writes. If the pragma silently
        // failed to apply, everything would still work in a single-threaded test and fall over
        // under concurrency in production.
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        await using System.Data.Common.DbConnection connection =
            await database.ConnectionFactory.OpenConnectionAsync(CancellationToken.None);

        string mode = await connection.ExecuteScalarAsync<string>("PRAGMA journal_mode") ?? string.Empty;

        mode.ShouldBe("wal", StringCompareShould.IgnoreCase);
    }

    [Fact]
    public async Task Foreign_key_enforcement_is_actually_in_effect()
    {
        // SQLite disables foreign keys by default, per connection. A server that assumes
        // referential integrity while the engine is not enforcing it accumulates orphans.
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        await using System.Data.Common.DbConnection connection =
            await database.ConnectionFactory.OpenConnectionAsync(CancellationToken.None);

        long enabled = await connection.ExecuteScalarAsync<long>("PRAGMA foreign_keys");

        enabled.ShouldBe(1);
    }
}
