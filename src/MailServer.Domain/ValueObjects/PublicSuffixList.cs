using System.Globalization;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// Resolves a domain's organizational domain using the Public Suffix List algorithm
/// (<c>https://publicsuffix.org/list/</c>), for DMARC's relaxed alignment (RFC 7489 §3.2).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this needs a real, shipped list rather than a heuristic.</b> "The organizational
/// domain is everything from the last two labels" is wrong the moment a public suffix has more
/// than one label — <c>example.co.uk</c> and <c>other.co.uk</c> would wrongly appear to share
/// the organizational domain <c>co.uk</c>, which is a registry, not anyone's organization. Only
/// the published list of what registries actually delegate at knows the difference between
/// <c>co.uk</c> (a public suffix — anyone can register under it) and <c>github.io</c> (also a
/// public suffix, for the same reason) versus <c>example.com</c> (not — <c>example</c> is
/// somebody's registration). <c>docs/DMARC.md</c> is explicit that a stale or approximated list
/// produces subtly wrong alignment in both directions.
/// </para>
/// <para>
/// Pure: this class only interprets already-loaded list text (via <see cref="Parse"/>) and
/// already-normalised domain names. Fetching the list — from an embedded snapshot today, per
/// <c>docs/DMARC.md</c>'s "ships with the product, refreshed by housekeeping" design — is
/// necessarily I/O and lives in Infrastructure.
/// </para>
/// </remarks>
public sealed class PublicSuffixList
{
    private static readonly IdnMapping Idn = new();

    private readonly HashSet<string> _plainRules;
    private readonly HashSet<string> _wildcardConcreteSuffixes;
    private readonly HashSet<string> _exceptionRules;

    private PublicSuffixList(
        HashSet<string> plainRules,
        HashSet<string> wildcardConcreteSuffixes,
        HashSet<string> exceptionRules,
        DateTimeOffset? snapshotDateUtc)
    {
        _plainRules = plainRules;
        _wildcardConcreteSuffixes = wildcardConcreteSuffixes;
        _exceptionRules = exceptionRules;
        SnapshotDateUtc = snapshotDateUtc;
    }

    /// <summary>
    /// When this snapshot was published, parsed from the list's own <c>// VERSION:</c> comment.
    /// Null if the text supplied to <see cref="Parse"/> carried no such line (a hand-written test
    /// fixture, typically). <c>docs/DMARC.md</c>: "its age is a health check rather than an
    /// assumption" — this is the fact that check reads.
    /// </summary>
    public DateTimeOffset? SnapshotDateUtc { get; }

    /// <summary>
    /// Parses a Public Suffix List file's text (the format published at
    /// <c>https://publicsuffix.org/list/public_suffix_list.dat</c>): one rule per line, blank
    /// lines and <c>//</c>-comments ignored, a leading <c>*.</c> for a wildcard rule and a
    /// leading <c>!</c> for an exception.
    /// </summary>
    public static PublicSuffixList Parse(string listText)
    {
        ArgumentNullException.ThrowIfNull(listText);

        HashSet<string> plainRules = new(StringComparer.Ordinal);
        HashSet<string> wildcardConcreteSuffixes = new(StringComparer.Ordinal);
        HashSet<string> exceptionRules = new(StringComparer.Ordinal);
        DateTimeOffset? snapshotDateUtc = null;

        foreach (string rawLine in listText.Split('\n'))
        {
            string line = rawLine.Trim().TrimEnd('\r');

            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith("//", StringComparison.Ordinal))
            {
                snapshotDateUtc ??= TryParseVersionComment(line);
                continue;
            }

            if (line.StartsWith('!'))
            {
                exceptionRules.Add(NormalizeRule(line[1..]));
            }
            else if (line.StartsWith("*.", StringComparison.Ordinal))
            {
                wildcardConcreteSuffixes.Add(NormalizeRule(line[2..]));
            }
            else
            {
                plainRules.Add(NormalizeRule(line));
            }
        }

        return new PublicSuffixList(plainRules, wildcardConcreteSuffixes, exceptionRules, snapshotDateUtc);
    }

    /// <summary>
    /// Resolves <paramref name="domain"/>'s organizational domain: the public suffix plus one
    /// additional label. RFC 7489 §3.2's definition, via the standard PSL algorithm.
    /// </summary>
    /// <remarks>
    /// Returns <paramref name="domain"/> unchanged in the degenerate case where the domain has no
    /// more labels than its own public suffix (it names a public suffix, or a registry itself —
    /// never a real mail domain this product would ever be asked to align). There is no label
    /// left to add, and fabricating one would be worse than returning the input.
    /// </remarks>
    public DomainName GetOrganizationalDomain(DomainName domain)
    {
        ArgumentNullException.ThrowIfNull(domain);

        string[] labels = domain.Value.Split('.');
        int publicSuffixLabelCount = CountPublicSuffixLabels(labels);

        int organizationalLabelCount = publicSuffixLabelCount + 1;

        if (organizationalLabelCount >= labels.Length)
        {
            return domain;
        }

        string organizational = string.Join('.', labels[^organizationalLabelCount..]);
        return DomainName.Parse(organizational);
    }

    /// <summary>The standard PSL matching algorithm: longest matching rule wins, an exception overrides its own wildcard.</summary>
    private int CountPublicSuffixLabels(string[] labels)
    {
        int n = labels.Length;

        for (int windowLength = n; windowLength >= 1; windowLength--)
        {
            string candidate = string.Join('.', labels[(n - windowLength)..]);

            if (_exceptionRules.Contains(candidate))
            {
                // "Modify [the exception rule] by removing the leftmost label": the exception
                // declares that this specific name is NOT part of the suffix its wildcard would
                // otherwise imply, so the actual public suffix is one label shorter.
                return windowLength - 1;
            }

            if (_plainRules.Contains(candidate))
            {
                return windowLength;
            }

            if (windowLength >= 2)
            {
                string concreteTail = string.Join('.', labels[(n - windowLength + 1)..]);

                if (_wildcardConcreteSuffixes.Contains(concreteTail))
                {
                    return windowLength;
                }
            }
        }

        // No rule matched at all: the implicit "*" rule applies (RFC/PSL spec) - the single
        // rightmost label is the public suffix.
        return 1;
    }

    private static string NormalizeRule(string rule)
    {
        string trimmed = rule.Trim();

        // The list mixes ASCII/punycode and Unicode forms for internationalised TLDs; domains
        // this product compares against are always in DomainName's ASCII form, so every rule is
        // normalised to match at load time rather than at every lookup.
        string ascii = IsAscii(trimmed) ? trimmed : Idn.GetAscii(trimmed);
        return ascii.ToLowerInvariant();
    }

    private static bool IsAscii(string value)
    {
        foreach (char c in value)
        {
            if (c > 127)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Parses <c>// VERSION: 2026-09-15_10-18-26_UTC</c> into a timestamp.</summary>
    private static DateTimeOffset? TryParseVersionComment(string commentLine)
    {
        const string Marker = "// VERSION:";

        if (!commentLine.StartsWith(Marker, StringComparison.Ordinal))
        {
            return null;
        }

        string value = commentLine[Marker.Length..].Trim();

        // yyyy-MM-dd_HH-mm-ss_UTC
        string[] parts = value.Split('_');

        if (parts.Length != 3 || parts[2] != "UTC")
        {
            return null;
        }

        if (!DateOnly.TryParseExact(parts[0], "yyyy-MM-dd", out DateOnly date) ||
            !TimeOnly.TryParseExact(parts[1], "HH-mm-ss", out TimeOnly time))
        {
            return null;
        }

        return new DateTimeOffset(date, time, TimeSpan.Zero);
    }
}
