using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Policies;

/// <summary>
/// Orders resolved MX hosts into the sequence a delivery attempt should try them in.
/// </summary>
/// <remarks>
/// <para>
/// RFC 5321 §5.1: hosts are tried in ascending preference, and hosts that share a preference
/// are tried in an order that "SHOULD be randomized" so that load spreads across a domain's
/// equally-preferred exchangers instead of every sending server picking the first one listed.
/// </para>
/// <para>
/// Pure and DNS-free by design, for the same reason <see cref="RetryBackoffPolicy"/> is: it is
/// exhaustively testable without a resolver, a socket or the network, and the failure mode of a
/// selection bug — every sender in the world always trying the same host first — is a real
/// operational cost to whoever publishes the MX records, not just a cosmetic one.
/// </para>
/// </remarks>
public sealed class MxSelectionPolicy
{
    /// <summary>
    /// Orders <paramref name="hosts"/> for one delivery attempt: ascending preference band,
    /// shuffled within each band.
    /// </summary>
    /// <param name="hosts">Resolved candidates. Already deduplicated by the caller.</param>
    /// <param name="randomSource">
    /// Source of shuffle randomness in [0,1). Injected so the policy stays pure and its tests
    /// stay deterministic; defaults to <see cref="Random.Shared"/>.
    /// </param>
    public IReadOnlyList<MxHost> OrderForAttempt(
        IReadOnlyList<MxHost> hosts,
        Func<double>? randomSource = null)
    {
        ArgumentNullException.ThrowIfNull(hosts);

        if (hosts.Count == 0)
        {
            return [];
        }

        Func<double> random = randomSource ?? Random.Shared.NextDouble;

        return
        [
            .. hosts
                .GroupBy(static h => h.Preference)
                .OrderBy(static g => g.Key)
                .SelectMany(band => Shuffle([.. band], random)),
        ];
    }

    /// <summary>Fisher-Yates, driven by the injected random source rather than a static Random.</summary>
    private static List<MxHost> Shuffle(List<MxHost> band, Func<double> random)
    {
        for (int i = band.Count - 1; i > 0; i--)
        {
            int j = Math.Clamp((int)(random() * (i + 1)), 0, i);
            (band[i], band[j]) = (band[j], band[i]);
        }

        return band;
    }
}
