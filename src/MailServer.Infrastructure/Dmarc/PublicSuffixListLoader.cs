using System.Reflection;
using System.Text;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dmarc;

/// <summary>
/// Supplies the parsed Public Suffix List that DMARC alignment computes organizational domains
/// from. A separate interface from the concrete <see cref="PublicSuffixListLoader"/> for the same
/// reason every other DNS/lookup dependency in this evaluator's neighborhood is one - so a test
/// can supply a small, deterministic list instead of the real multi-thousand-rule snapshot.
/// </summary>
public interface IPublicSuffixListProvider
{
    /// <summary>The parsed list, loaded and validated once per process.</summary>
    PublicSuffixList List { get; }
}

/// <summary>
/// Loads the Public Suffix List snapshot embedded in this assembly (<c>docs/DMARC.md</c>:
/// "the list ships with the product") into a <see cref="Domain.ValueObjects.PublicSuffixList"/>.
/// </summary>
/// <remarks>
/// The only I/O in the PSL story: parsing itself is pure and lives in the Domain value object.
/// Loaded once and cached for the process lifetime — the embedded resource cannot change without
/// a new build, so re-parsing it on every DMARC evaluation would be pure waste.
/// </remarks>
public sealed class PublicSuffixListLoader : IPublicSuffixListProvider
{
    private const string ResourceName = "MailServer.Infrastructure.Dmarc.public_suffix_list.dat";

    private readonly Lazy<PublicSuffixList> _list;

    public PublicSuffixListLoader(ILogger<PublicSuffixListLoader> logger)
    {
        _list = new Lazy<PublicSuffixList>(() =>
        {
            PublicSuffixList list = PublicSuffixList.Parse(ReadEmbeddedResource());

            if (list.SnapshotDateUtc is { } snapshot)
            {
                TimeSpan age = DateTimeOffset.UtcNow - snapshot;

                if (age > TimeSpan.FromDays(180))
                {
                    logger.LogWarning(
                        "The embedded Public Suffix List snapshot is {AgeDays} days old (published {Snapshot:yyyy-MM-dd}). " +
                        "DMARC organizational-domain alignment may be wrong for newly delegated public suffixes. " +
                        "Refresh src/MailServer.Infrastructure/Dmarc/public_suffix_list.dat from https://publicsuffix.org/list/.",
                        (int)age.TotalDays,
                        snapshot);
                }
            }
            else
            {
                logger.LogWarning("The embedded Public Suffix List snapshot carries no // VERSION: comment; its age cannot be checked.");
            }

            return list;
        });
    }

    /// <summary>The parsed list, loaded and validated once per process.</summary>
    public PublicSuffixList List => _list.Value;

    private static string ReadEmbeddedResource()
    {
        Assembly assembly = typeof(PublicSuffixListLoader).Assembly;

        using Stream stream = assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Embedded resource '{ResourceName}' could not be opened.");

        using StreamReader reader = new(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
