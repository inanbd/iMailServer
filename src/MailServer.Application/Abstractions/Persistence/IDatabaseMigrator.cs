namespace MailServer.Application.Abstractions.Persistence;

/// <summary>
/// Applies version-controlled schema migrations.
/// </summary>
/// <remarks>
/// Entity Framework is forbidden by the brief, so migrations are numbered SQL scripts
/// applied by an explicit runner. See <c>docs/Persistence.md</c> for the guarantees this
/// provides: never twice, transactional where supported, checksum drift is a hard error,
/// fail safe, back up before destructive upgrades, and an advisory lock so concurrent
/// service starts cannot race.
/// </remarks>
public interface IDatabaseMigrator
{
    /// <summary>
    /// Applies every pending migration in ascending version order.
    /// </summary>
    /// <exception cref="Exceptions.SchemaDriftException">
    /// An already-applied script's checksum no longer matches. Startup aborts: running
    /// against a schema whose history has been rewritten is how environments diverge
    /// irreparably.
    /// </exception>
    Task<MigrationRunResult> MigrateAsync(CancellationToken cancellationToken = default);

    /// <summary>Reports what would be applied, without changing anything.</summary>
    Task<MigrationStatus> GetStatusAsync(CancellationToken cancellationToken = default);
}

/// <summary>One migration script discovered on disk or in an embedded resource.</summary>
public sealed record MigrationScript(int Version, string Name, string Checksum, bool IsDestructive, bool RunsOutsideTransaction);

/// <summary>A migration that has been applied to the database.</summary>
public sealed record AppliedMigration(
    int Version,
    string Name,
    string Checksum,
    DateTimeOffset AppliedUtc,
    long DurationMs,
    string AppliedBy,
    string ProductVersion);

/// <summary>Current and pending schema state.</summary>
public sealed record MigrationStatus(
    int CurrentVersion,
    int TargetVersion,
    IReadOnlyList<AppliedMigration> Applied,
    IReadOnlyList<MigrationScript> Pending)
{
    public bool IsUpToDate => Pending.Count == 0;
}

/// <summary>Outcome of a migration run.</summary>
public sealed record MigrationRunResult(
    int FromVersion,
    int ToVersion,
    IReadOnlyList<string> AppliedScripts,
    TimeSpan Duration)
{
    public bool AnythingApplied => AppliedScripts.Count > 0;
}
