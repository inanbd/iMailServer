using System.Reflection;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Infrastructure.Persistence;
using MailServer.Persistence.Sqlite;

namespace MailServer.Infrastructure.Tests;

/// <summary>
/// How the migration loader decides a script is destructive.
/// </summary>
/// <remarks>
/// <para>
/// This exists because the original rule — "the file contains the text <c>-- @Destructive</c>"
/// — made the marker depend on where a sentence happened to wrap. The natural comment at the
/// top of an additive migration is "this is not marked @Destructive", and when that wrapped so
/// the directive landed at the start of a line, the migration refused to apply and took every
/// database-backed test in the solution with it.
/// </para>
/// <para>
/// Three earlier migrations escaped only by luck of line breaking. A rule that holds by
/// accident is the kind worth pinning down.
/// </para>
/// </remarks>
public sealed class MigrationDirectiveTests
{
    /// <summary>Calls the loader's private directive check.</summary>
    /// <remarks>
    /// Reflection because the method is a private implementation detail that should stay one.
    /// The alternative — widening its visibility so a test can reach it — would make an
    /// internal parsing rule part of the type's surface purely to be observed.
    /// </remarks>
    private static bool HasDirective(string sql, string directive)
    {
        MethodInfo method = typeof(MigrationScriptLoader)
            .GetMethod("HasDirective", BindingFlags.NonPublic | BindingFlags.Static)!;

        return (bool)method.Invoke(null, [sql, directive])!;
    }

    [Theory]
    [InlineData("-- @Destructive")]
    [InlineData("--@Destructive")]
    [InlineData("   -- @Destructive   ")]
    [InlineData("-- @destructive")]
    public void A_directive_on_its_own_line_is_recognised(string line)
    {
        HasDirective($"-- header\n{line}\nCREATE TABLE X (Id TEXT);", "@Destructive")
            .ShouldBeTrue();
    }

    /// <summary>
    /// The regression. A comment that discusses the directive must not become it.
    /// </summary>
    [Theory]
    [InlineData("-- @Destructive and needs no pre-upgrade backup.")]
    [InlineData("-- so this migration is not marked @Destructive.")]
    [InlineData("-- marked @Destructive and needs no pre-upgrade backup.")]
    [InlineData("-- Purely additive, so this is not marked @Destructive.")]
    public void A_comment_that_merely_mentions_the_directive_does_not_trigger_it(string line)
    {
        HasDirective($"-- header\n{line}\nCREATE TABLE X (Id TEXT);", "@Destructive")
            .ShouldBeFalse();
    }

    [Fact]
    public void A_script_with_no_directive_is_not_destructive()
    {
        HasDirective("CREATE TABLE X (Id TEXT);", "@Destructive").ShouldBeFalse();
    }

    /// <summary>
    /// A directive inside a SQL string literal must not count either.
    /// </summary>
    /// <remarks>
    /// Not a line comment, so it cannot match. Asserted because seeding a row whose text
    /// happens to contain the marker is exactly the sort of thing that would silently make a
    /// harmless migration refuse to apply.
    /// </remarks>
    [Fact]
    public void A_directive_inside_a_string_literal_does_not_trigger_it()
    {
        HasDirective(
            "INSERT INTO Notes (Body) VALUES ('@Destructive');",
            "@Destructive").ShouldBeFalse();
    }

    [Fact]
    public void The_no_transaction_directive_follows_the_same_rule()
    {
        HasDirective("-- @NoTransaction\nCREATE INDEX X ON Y (Z);", "@NoTransaction")
            .ShouldBeTrue();

        HasDirective("-- this script is not marked @NoTransaction.\n", "@NoTransaction")
            .ShouldBeFalse();
    }

    /// <summary>
    /// Every shipped migration is additive, so none should be flagged.
    /// </summary>
    /// <remarks>
    /// The check that would actually have caught the original defect: it asserts against the
    /// real embedded scripts rather than against synthetic input, so a future migration whose
    /// header wraps unfortunately fails here rather than at a developer's first test run.
    /// </remarks>
    [Fact]
    public void No_shipped_sqlite_migration_is_marked_destructive()
    {
        IReadOnlyList<LoadedMigration> migrations =
            MigrationScriptLoader.Load(new SqliteDialect());

        migrations.ShouldNotBeEmpty();

        foreach (LoadedMigration migration in migrations)
        {
            migration.Metadata.IsDestructive.ShouldBeFalse(
                $"Migration {migration.Metadata.Version:D4}_{migration.Metadata.Name} is " +
                "flagged destructive. Every migration shipped so far is purely additive, so " +
                "this is almost certainly a comment that mentions the directive rather than a " +
                "deliberate marker — which would refuse to apply until the backup subsystem " +
                "exists in Milestone 13.");
        }
    }
}
