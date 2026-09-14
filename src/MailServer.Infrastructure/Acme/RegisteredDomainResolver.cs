using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Acme;

/// <summary>
/// Approximates the registered domain of a hostname, for rate-limit grouping.
/// </summary>
/// <remarks>
/// <para>
/// <b>An approximation, stated as one.</b> Let's Encrypt groups its weekly certificate limit by
/// <i>registered domain</i>, which is defined by the Public Suffix List. This server has no PSL
/// until Milestone 9 brings one for DMARC organisational-domain alignment, where getting it
/// wrong silently inverts a policy decision and correctness is not optional.
/// </para>
/// <para>
/// Here the cost of being wrong is bounded and one-directional by design. The heuristic is:
/// take the last two labels, unless the second-to-last is a known multi-part suffix component,
/// in which case take three. That over-groups in the rare cases it gets wrong — several
/// registrable domains sharing one bucket — which makes the limiter refuse <i>earlier</i> than
/// the CA would. Refusing early costs an operator a clear local message; refusing late costs a
/// real rate-limit slot.
/// </para>
/// <para>
/// The short list below is not an attempt at the PSL. It covers the suffixes that actually
/// appear on mail servers often enough to matter, and everything else falls back to two labels,
/// which is correct for the large majority of domains.
/// </para>
/// </remarks>
internal static class RegisteredDomainResolver
{
    /// <summary>
    /// Second-level components that are effectively public suffixes.
    /// </summary>
    /// <remarks>
    /// Kept deliberately short. A longer hand-maintained list drifts out of date and creates
    /// the impression of authority this heuristic does not have; the PSL in Milestone 9
    /// replaces it wholesale.
    /// </remarks>
    private static readonly HashSet<string> MultiPartSuffixComponents =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "co", "com", "net", "org", "gov", "edu", "ac", "mil", "sch", "ltd", "plc", "me",
        };

    /// <summary>Groups a hostname for rate-limit purposes.</summary>
    public static string Resolve(DomainName hostname)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        // A wildcard is validated against, and counts against, its parent.
        string value = hostname.Value.StartsWith("*.", StringComparison.Ordinal)
            ? hostname.Value[2..]
            : hostname.Value;

        string[] labels = value.Split('.');

        if (labels.Length <= 2)
        {
            return value;
        }

        string secondToLast = labels[^2];

        // 'example.co.uk' rather than 'co.uk'; 'example.com' rather than 'com'.
        int take = MultiPartSuffixComponents.Contains(secondToLast) && labels.Length >= 3 ? 3 : 2;

        return string.Join('.', labels[^take..]);
    }

    /// <summary>
    /// The single registered domain an identifier set belongs to, for one limit check.
    /// </summary>
    /// <remarks>
    /// An order can legitimately span several registered domains. Only the first is used as the
    /// grouping key, which is a simplification: the weekly per-domain limit would in principle
    /// need checking against each. It is the conservative simplification, because the limit an
    /// operator actually hits is the duplicate-certificate one, which is keyed on the whole
    /// identifier set and is checked exactly.
    /// </remarks>
    public static string ResolveForSet(IReadOnlyList<DomainName> identifiers)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        return identifiers.Count == 0 ? string.Empty : Resolve(identifiers[0]);
    }
}
