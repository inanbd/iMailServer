using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using MailServer.Application.Abstractions.Persistence;

namespace MailServer.Infrastructure.Persistence;

/// <summary>A migration script together with its text.</summary>
internal sealed record LoadedMigration(MigrationScript Metadata, string Sql);

/// <summary>
/// Discovers migration scripts embedded in a provider assembly.
/// </summary>
/// <remarks>
/// Scripts are embedded resources rather than loose files, so a deployment cannot be missing
/// them and an operator cannot edit an already-applied script on disk - which the checksum
/// check would reject at startup anyway, turning a five-minute fix into an outage.
/// </remarks>
internal static partial class MigrationScriptLoader
{
    /// <summary>Marks a migration that should trigger an automatic backup before it runs.</summary>
    private const string DestructiveDirective = "-- @Destructive";

    /// <summary>
    /// Marks a migration containing statements that cannot run inside a transaction.
    /// Deliberately explicit, so that giving up atomicity is always a visible decision.
    /// </summary>
    private const string NoTransactionDirective = "-- @NoTransaction";

    /// <summary>Loads every embedded script for the provider, ordered by version.</summary>
    /// <exception cref="InvalidOperationException">Two scripts declare the same version.</exception>
    public static IReadOnlyList<LoadedMigration> Load(ISqlDialect dialect)
    {
        ArgumentNullException.ThrowIfNull(dialect);

        Assembly assembly = dialect.MigrationsAssembly;
        string prefix = dialect.MigrationsResourcePrefix;

        List<LoadedMigration> migrations = [];

        foreach (string resourceName in assembly.GetManifestResourceNames())
        {
            if (!resourceName.StartsWith(prefix, StringComparison.Ordinal) ||
                !resourceName.EndsWith(".sql", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string fileName = resourceName[prefix.Length..];
            Match match = FileNamePattern().Match(fileName);

            if (!match.Success)
            {
                throw new InvalidOperationException(
                    $"Migration resource '{resourceName}' does not follow the required " +
                    "NNNN_Name.sql naming convention. Ordering is derived from the number, " +
                    "so an unparseable name would be applied in an undefined position.");
            }

            int version = int.Parse(match.Groups["version"].Value, CultureInfo.InvariantCulture);
            string name = match.Groups["name"].Value;

            string sql = ReadResource(assembly, resourceName);

            migrations.Add(new LoadedMigration(
                new MigrationScript(
                    version,
                    name,
                    ComputeChecksum(sql),
                    sql.Contains(DestructiveDirective, StringComparison.OrdinalIgnoreCase),
                    sql.Contains(NoTransactionDirective, StringComparison.OrdinalIgnoreCase)),
                sql));
        }

        // Duplicate versions must fail at startup rather than producing an arbitrary order.
        IGrouping<int, LoadedMigration>? duplicate = migrations
            .GroupBy(m => m.Metadata.Version)
            .FirstOrDefault(g => g.Count() > 1);

        if (duplicate is not null)
        {
            throw new InvalidOperationException(
                $"Migration version {duplicate.Key:D4} is declared by more than one script: " +
                $"{string.Join(", ", duplicate.Select(m => m.Metadata.Name))}. Versions must " +
                "be unique, because they determine the order in which schema changes apply.");
        }

        return [.. migrations.OrderBy(m => m.Metadata.Version)];
    }

    /// <summary>
    /// SHA-256 of the script with line endings normalised.
    /// </summary>
    /// <remarks>
    /// Normalising CRLF to LF is essential. Without it, a Git checkout with
    /// <c>core.autocrlf=true</c> produces a different checksum from the same file on the
    /// build server, and every developer's service would refuse to start claiming schema
    /// drift that does not exist.
    /// </remarks>
    public static string ComputeChecksum(string sql)
    {
        ArgumentNullException.ThrowIfNull(sql);

        string normalized = sql
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\r", "\n", StringComparison.Ordinal)
            .TrimEnd();

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexStringLower(hash);
    }

    private static string ReadResource(Assembly assembly, string resourceName)
    {
        using Stream stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException(
                $"Embedded migration resource '{resourceName}' could not be opened.");

        using StreamReader reader = new(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    [GeneratedRegex(@"^(?<version>\d{4})_(?<name>[A-Za-z0-9_]+)\.sql$", RegexOptions.CultureInvariant)]
    private static partial Regex FileNamePattern();
}
