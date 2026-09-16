using MailServer.Domain.Enums;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// One directive from an SPF record's term list: a qualifier plus a mechanism and whatever the
/// mechanism needs to be evaluated. RFC 7208 §4 and §5.
/// </summary>
/// <remarks>
/// A single shape covers every mechanism rather than one type per mechanism, because the
/// evaluator dispatches on <see cref="Mechanism"/> anyway and a discriminated union would only
/// rename that dispatch, not remove it. Unused fields for a given mechanism are simply null —
/// <see cref="DomainSpec"/> is meaningless for <see cref="SpfMechanismType.Ip4"/>, for instance.
/// </remarks>
/// <param name="Qualifier">What a match means: pass, fail, softfail or neutral.</param>
/// <param name="Mechanism">Which mechanism this is.</param>
/// <param name="DomainSpec">
/// The raw domain-spec text for <c>include</c>/<c>exists</c> (required), <c>a</c>/<c>mx</c>/
/// <c>ptr</c> (optional — null means "the domain currently being evaluated"). Never present for
/// <c>all</c>/<c>ip4</c>/<c>ip6</c>.
/// </param>
/// <param name="IpNetwork">The network address, for <see cref="SpfMechanismType.Ip4"/>/<see cref="SpfMechanismType.Ip6"/> only.</param>
/// <param name="Ip4PrefixLength">
/// The CIDR prefix to apply to a resolved (or literal) IPv4 address — the <c>/24</c> in
/// <c>ip4:203.0.113.0/24</c> or in the dual-cidr-length of <c>a</c>/<c>mx</c>. Defaults to 32
/// when the mechanism carries no explicit length.
/// </param>
/// <param name="Ip6PrefixLength">The IPv6 equivalent of <see cref="Ip4PrefixLength"/>. Defaults to 128.</param>
/// <param name="UsesMacros">
/// True when <see cref="DomainSpec"/> contains a macro (a literal <c>%</c>). RFC 7208 macro
/// expansion (<c>%{s}</c>, <c>%{i}</c>, and so on) is parsed far enough to be recognised but not
/// implemented — see the addendum recording this scope decision. The evaluator treats reaching a
/// mechanism with this set as a hard <see cref="SpfResult.PermError"/> rather than silently
/// evaluating the literal, unexpanded text, which would produce a result the rest of the world's
/// SPF implementations do not agree with.
/// </param>
public sealed record SpfDirective(
    SpfQualifier Qualifier,
    SpfMechanismType Mechanism,
    string? DomainSpec,
    IpAddressValue? IpNetwork,
    int? Ip4PrefixLength,
    int? Ip6PrefixLength,
    bool UsesMacros);

/// <summary>
/// A parsed SPF record: <c>v=spf1</c> followed by an ordered list of mechanisms and, optionally,
/// a trailing <c>redirect=</c> modifier. RFC 7208 §4 and §6.
/// </summary>
/// <remarks>
/// <para>
/// <c>exp=</c> and any other <c>name=value</c> modifier are recognised as modifiers (so they do
/// not trip the "unrecognised term" syntax error a mechanism-shaped term would) but are
/// otherwise ignored — RFC 7208 §6 requires exactly this for an unrecognised modifier, and
/// <c>exp=</c>'s explanation-string mechanism is out of scope for this milestone: it only ever
/// affects the text of a bounce this server sends back to a sender who failed SPF, never the
/// pass/fail decision itself.
/// </para>
/// <para>
/// Purely a parser. Evaluating a record — walking its mechanisms against a client IP, following
/// <c>include</c>/<c>redirect</c> through DNS, enforcing the lookup and void-lookup budgets — is
/// <c>MailServer.Infrastructure.Spf.SpfEvaluator</c>'s job, because that needs DNS and this must
/// not.
/// </para>
/// </remarks>
public sealed class SpfRecord
{
    private SpfRecord(IReadOnlyList<SpfDirective> directives, string? redirectDomain, bool redirectUsesMacros)
    {
        Directives = directives;
        RedirectDomain = redirectDomain;
        RedirectUsesMacros = redirectUsesMacros;
    }

    /// <summary>The record's mechanisms, in the order they must be evaluated.</summary>
    public IReadOnlyList<SpfDirective> Directives { get; }

    /// <summary>The <c>redirect=</c> modifier's domain-spec, or null if the record has none.</summary>
    public string? RedirectDomain { get; }

    /// <summary>True when <see cref="RedirectDomain"/> contains a macro. See <see cref="SpfDirective.UsesMacros"/>.</summary>
    public bool RedirectUsesMacros { get; }

    /// <summary>Parses one candidate SPF record's text (a single TXT record's concatenated content).</summary>
    public static bool TryParse(string? recordText, out SpfRecord? record, out string? error)
    {
        record = null;
        error = null;

        if (string.IsNullOrWhiteSpace(recordText))
        {
            error = "the record is empty.";
            return false;
        }

        string[] terms = recordText.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // RFC 7208 section 4.5's ABNF (`version = "v=spf1"`) is a plain quoted string, which RFC
        // 5234 section 2.3 makes case-insensitive absent an explicit %s prefix - a domain
        // publishing "V=SPF1" is exactly as valid as one publishing "v=spf1".
        if (terms.Length == 0 || !string.Equals(terms[0], "v=spf1", StringComparison.OrdinalIgnoreCase))
        {
            error = "the record does not begin with the exact term 'v=spf1'.";
            return false;
        }

        List<SpfDirective> directives = [];
        string? redirectDomain = null;
        bool redirectUsesMacros = false;
        bool sawRedirect = false;

        for (int i = 1; i < terms.Length; i++)
        {
            string term = terms[i];
            int eqIndex = term.IndexOf('=');

            // A mechanism's value is introduced by ':' or '/', never '='; any term containing
            // '=' is therefore a modifier, per RFC 7208's ABNF.
            if (eqIndex >= 0)
            {
                string name = term[..eqIndex];
                string value = term[(eqIndex + 1)..];

                if (string.Equals(name, "redirect", StringComparison.OrdinalIgnoreCase))
                {
                    if (sawRedirect)
                    {
                        error = "the 'redirect' modifier appears more than once.";
                        return false;
                    }

                    if (value.Length == 0)
                    {
                        error = "the 'redirect' modifier requires a non-empty domain-spec.";
                        return false;
                    }

                    sawRedirect = true;
                    redirectDomain = value;
                    redirectUsesMacros = value.Contains('%', StringComparison.Ordinal);
                }

                // Every other modifier (exp=, or anything unrecognised) is ignored outright.
                continue;
            }

            if (!TryParseMechanism(term, out SpfDirective? directive, out error))
            {
                return false;
            }

            directives.Add(directive!);
        }

        record = new SpfRecord(directives, redirectDomain, redirectUsesMacros);
        return true;
    }

    private static bool TryParseMechanism(string term, out SpfDirective? directive, out string? error)
    {
        directive = null;
        error = null;

        SpfQualifier qualifier = SpfQualifier.Pass;
        string text = term;

        if (text.Length > 0 && text[0] is '+' or '-' or '~' or '?')
        {
            qualifier = text[0] switch
            {
                '-' => SpfQualifier.Fail,
                '~' => SpfQualifier.SoftFail,
                '?' => SpfQualifier.Neutral,
                _ => SpfQualifier.Pass,
            };

            text = text[1..];
        }

        int separator = text.IndexOfAny(['/', ':']);
        string name = separator < 0 ? text : text[..separator];
        string rest = separator < 0 ? string.Empty : text[separator..];

        switch (name.ToLowerInvariant())
        {
            case "all":
                if (rest.Length > 0)
                {
                    error = "'all' takes no value.";
                    return false;
                }

                directive = new SpfDirective(qualifier, SpfMechanismType.All, null, null, null, null, false);
                return true;

            case "include":
                return TryParseRequiredDomainSpec(SpfMechanismType.Include, qualifier, rest, out directive, out error);

            case "exists":
                return TryParseRequiredDomainSpec(SpfMechanismType.Exists, qualifier, rest, out directive, out error);

            case "a":
                return TryParseAOrMx(SpfMechanismType.A, qualifier, rest, out directive, out error);

            case "mx":
                return TryParseAOrMx(SpfMechanismType.Mx, qualifier, rest, out directive, out error);

            case "ptr":
                return TryParsePtr(qualifier, rest, out directive, out error);

            case "ip4":
                return TryParseIp(isIp6: false, qualifier, rest, out directive, out error);

            case "ip6":
                return TryParseIp(isIp6: true, qualifier, rest, out directive, out error);

            default:
                error = $"'{name}' is not a recognised SPF mechanism.";
                return false;
        }
    }

    private static bool TryParseRequiredDomainSpec(
        SpfMechanismType mechanism, SpfQualifier qualifier, string rest, out SpfDirective? directive, out string? error)
    {
        directive = null;
        error = null;

        if (rest.Length == 0 || rest[0] != ':' || rest.Length == 1)
        {
            error = $"'{mechanism}' requires a non-empty domain-spec, introduced by ':'.";
            return false;
        }

        string domainSpec = rest[1..];
        directive = new SpfDirective(
            qualifier, mechanism, domainSpec, null, null, null, domainSpec.Contains('%', StringComparison.Ordinal));

        return true;
    }

    private static bool TryParsePtr(SpfQualifier qualifier, string rest, out SpfDirective? directive, out string? error)
    {
        directive = null;
        error = null;

        if (rest.Length == 0)
        {
            directive = new SpfDirective(qualifier, SpfMechanismType.Ptr, null, null, null, null, false);
            return true;
        }

        if (rest[0] != ':' || rest.Length == 1)
        {
            error = "'ptr' takes only an optional domain-spec, introduced by ':'.";
            return false;
        }

        string domainSpec = rest[1..];
        directive = new SpfDirective(
            qualifier, SpfMechanismType.Ptr, domainSpec, null, null, null, domainSpec.Contains('%', StringComparison.Ordinal));

        return true;
    }

    private static bool TryParseAOrMx(
        SpfMechanismType mechanism, SpfQualifier qualifier, string rest, out SpfDirective? directive, out string? error)
    {
        directive = null;
        error = null;

        string? domainSpec = null;

        if (rest.StartsWith(':'))
        {
            int slashIndex = rest.IndexOf('/');
            domainSpec = slashIndex < 0 ? rest[1..] : rest[1..slashIndex];
            rest = slashIndex < 0 ? string.Empty : rest[slashIndex..];

            if (domainSpec.Length == 0)
            {
                error = $"'{mechanism}' domain-spec, when present, must be non-empty.";
                return false;
            }
        }
        else if (rest.Length > 0 && rest[0] != '/')
        {
            error = $"'{mechanism}' takes a domain-spec (introduced by ':') or a CIDR length (introduced by '/').";
            return false;
        }

        int? ip4Prefix = null;
        int? ip6Prefix = null;

        if (rest.Length > 0 && !TryParseDualCidr(rest, out ip4Prefix, out ip6Prefix, out error))
        {
            return false;
        }

        directive = new SpfDirective(
            qualifier, mechanism, domainSpec, null, ip4Prefix, ip6Prefix,
            domainSpec?.Contains('%', StringComparison.Ordinal) ?? false);

        return true;
    }

    private static bool TryParseIp(bool isIp6, SpfQualifier qualifier, string rest, out SpfDirective? directive, out string? error)
    {
        directive = null;
        error = null;
        string kind = isIp6 ? "ip6" : "ip4";

        if (!rest.StartsWith(':') || rest.Length == 1)
        {
            error = $"'{kind}' requires a network address, introduced by ':'.";
            return false;
        }

        string body = rest[1..];
        int slashIndex = body.IndexOf('/');
        string addressText = slashIndex < 0 ? body : body[..slashIndex];
        int defaultPrefix = isIp6 ? 128 : 32;
        int prefixLength = defaultPrefix;

        if (slashIndex >= 0 && !TryParsePrefixLength(body[(slashIndex + 1)..], defaultPrefix, out prefixLength))
        {
            error = $"'{kind}' has an invalid CIDR prefix length.";
            return false;
        }

        if (!IpAddressValue.TryParse(addressText, out IpAddressValue? address) ||
            (isIp6 ? !address.IsIpV6 : !address.IsIpV4))
        {
            error = $"'{addressText}' is not a valid {(isIp6 ? "IPv6" : "IPv4")} address.";
            return false;
        }

        directive = new SpfDirective(
            qualifier,
            isIp6 ? SpfMechanismType.Ip6 : SpfMechanismType.Ip4,
            null,
            address,
            isIp6 ? null : prefixLength,
            isIp6 ? prefixLength : null,
            false);

        return true;
    }

    /// <summary>
    /// Parses a <c>dual-cidr-length</c>: <c>/24</c> (IPv4 only), <c>/24/64</c> (both, in that
    /// order) or <c>//64</c> (IPv6 only — the empty IPv4 part before the second '/').
    /// </summary>
    private static bool TryParseDualCidr(string text, out int? ip4Prefix, out int? ip6Prefix, out string? error)
    {
        ip4Prefix = null;
        ip6Prefix = null;
        error = null;

        if (text.Length == 0 || text[0] != '/')
        {
            error = "expected a CIDR length introduced by '/'.";
            return false;
        }

        string body = text[1..];

        if (body.StartsWith('/'))
        {
            if (!TryParsePrefixLength(body[1..], 128, out int v6Only))
            {
                error = "invalid IPv6 CIDR length.";
                return false;
            }

            ip6Prefix = v6Only;
            return true;
        }

        int slashIndex = body.IndexOf('/');
        string ip4Text = slashIndex < 0 ? body : body[..slashIndex];

        if (!TryParsePrefixLength(ip4Text, 32, out int ip4))
        {
            error = "invalid IPv4 CIDR length.";
            return false;
        }

        ip4Prefix = ip4;

        if (slashIndex >= 0)
        {
            if (!TryParsePrefixLength(body[(slashIndex + 1)..], 128, out int ip6))
            {
                error = "invalid IPv6 CIDR length.";
                return false;
            }

            ip6Prefix = ip6;
        }

        return true;
    }

    private static bool TryParsePrefixLength(string text, int max, out int value) =>
        int.TryParse(text, out value) && value >= 0 && value <= max;
}
