using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Spf;

/// <summary>The outcome of evaluating an SPF record against a client IP. RFC 7208 §2.6.</summary>
public sealed record SpfEvaluationResult(SpfResult Result, string? Diagnostic);

/// <summary>
/// Evaluates a domain's SPF policy against a client IP address, per RFC 7208 §4.
/// </summary>
/// <remarks>
/// <para>
/// Recursive by construction: <c>include</c> and <c>redirect</c> both re-enter the same
/// evaluation with a different domain, sharing one <see cref="Budget"/> across every level so
/// the 10-DNS-lookup and 2-void-lookup limits (§4.6.4) are enforced across the whole tree, not
/// reset at each level — which is exactly the loophole three nested mail-provider
/// <c>include:</c>s would otherwise open. Exceeding either limit is a hard
/// <see cref="SpfResult.PermError"/>, never a partial result: <c>docs/SPF.md</c> is explicit that
/// a result the rest of the world's implementations would not agree with is worse than an
/// honest error.
/// </para>
/// <para>
/// <b>Macro expansion (<c>%{s}</c>, <c>%{i}</c>, and so on) is not implemented.</b> A record is
/// parsed regardless of whether it uses macros — see <see cref="SpfDirective.UsesMacros"/> — but
/// evaluation stops with <see cref="SpfResult.PermError"/> the moment it would need to expand
/// one, rather than evaluating the literal, unexpanded text and silently producing the wrong
/// answer.
/// </para>
/// </remarks>
public sealed class SpfEvaluator(ITxtRecordResolver txtResolver, IDnsResolver dnsResolver, ILogger<SpfEvaluator> logger)
{
    /// <summary>RFC 7208 §4.6.4: at most 10 DNS-querying mechanisms/modifiers.</summary>
    private const int MaxDnsLookups = 10;

    /// <summary>RFC 7208 §4.6.4: at most 2 of those may be void (NXDOMAIN or an empty answer).</summary>
    private const int MaxVoidLookups = 2;

    /// <summary>Shared, mutable across every level of include/redirect recursion for one evaluation.</summary>
    private sealed class Budget
    {
        public int DnsLookups;
        public int VoidLookups;
    }

    private enum MatchStatus
    {
        NotMatched,
        Matched,
        Error,
    }

    private sealed record MatchOutcome(MatchStatus Status, SpfEvaluationResult? ErrorResult)
    {
        public static readonly MatchOutcome NotMatched = new(MatchStatus.NotMatched, null);
        public static readonly MatchOutcome Matched = new(MatchStatus.Matched, null);

        public static MatchOutcome Error(SpfResult result, string? diagnostic) =>
            new(MatchStatus.Error, new SpfEvaluationResult(result, diagnostic));
    }

    /// <summary>Evaluates <paramref name="domain"/>'s SPF policy against <paramref name="clientIp"/>.</summary>
    public async Task<SpfEvaluationResult> EvaluateAsync(
        DomainName domain, IpAddressValue clientIp, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(clientIp);

        SpfEvaluationResult result = await EvaluateDomainAsync(domain.Value, clientIp, new Budget(), cancellationToken)
            .ConfigureAwait(false);

        if (result.Result is SpfResult.PermError or SpfResult.TempError)
        {
            logger.LogInformation(
                "SPF evaluation of {Domain} for {ClientIp} concluded {Result}: {Diagnostic}",
                domain.Value, clientIp.Value, result.Result, result.Diagnostic);
        }

        return result;
    }

    /// <summary>
    /// The recursive core: fetches and evaluates one domain's SPF record. Used both for the
    /// top-level check and, via <see cref="EvaluateIncludeAsync"/>/the <c>redirect=</c> handling
    /// below, for every nested domain — the same function RFC 7208 calls <c>check_host()</c>.
    /// </summary>
    /// <remarks>
    /// Deliberately does NOT charge the lookup budget for its own TXT fetch: RFC 7208 §4.6.4
    /// counts <c>include</c>, <c>a</c>, <c>mx</c>, <c>ptr</c>, <c>exists</c> and <c>redirect</c>
    /// themselves, not the entry point that starts evaluation in the first place — the caller
    /// (<see cref="EvaluateIncludeAsync"/>, or the <c>redirect=</c> handling here) already
    /// charged for the mechanism that led to this call.
    /// </remarks>
    private async Task<SpfEvaluationResult> EvaluateDomainAsync(
        string domain, IpAddressValue clientIp, Budget budget, CancellationToken cancellationToken)
    {
        TxtLookupResult txtResult = await txtResolver.GetTxtRecordsAsync(domain, cancellationToken)
            .ConfigureAwait(false);

        if (txtResult.Status == DnsLookupStatus.Temporary)
        {
            return new SpfEvaluationResult(SpfResult.TempError, txtResult.Diagnostic);
        }

        // NXDOMAIN and "no matching record" are both void lookups (RFC 7208 §4.6.4 counts a
        // void lookup for any DNS query that comes back empty, not only ones charged against the
        // 10-mechanism limit) - and both mean "this domain has no SPF policy", which check_host()
        // reports as None. Whether a None here is fatal is for the CALLER (include/redirect) to
        // decide, not this function.
        if (txtResult.Status == DnsLookupStatus.Permanent)
        {
            if (!TryChargeVoidLookup(budget, out SpfEvaluationResult? voidError))
            {
                return voidError!;
            }

            return new SpfEvaluationResult(SpfResult.None, txtResult.Diagnostic);
        }

        List<string> spfRecords = [.. txtResult.Records.Where(IsSpfRecord)];

        if (spfRecords.Count == 0)
        {
            if (!TryChargeVoidLookup(budget, out SpfEvaluationResult? voidError))
            {
                return voidError!;
            }

            return new SpfEvaluationResult(SpfResult.None, $"{domain} publishes no SPF (v=spf1) record.");
        }

        if (spfRecords.Count > 1)
        {
            return new SpfEvaluationResult(
                SpfResult.PermError,
                $"{domain} publishes {spfRecords.Count} SPF records; RFC 7208 section 4.5 " +
                "permits exactly one.");
        }

        if (!SpfRecord.TryParse(spfRecords[0], out SpfRecord? record, out string? parseError))
        {
            return new SpfEvaluationResult(SpfResult.PermError, $"{domain}'s SPF record is malformed: {parseError}");
        }

        foreach (SpfDirective directive in record!.Directives)
        {
            if (directive.UsesMacros)
            {
                return new SpfEvaluationResult(
                    SpfResult.PermError,
                    $"a '{directive.Mechanism}' mechanism uses SPF macro expansion, which this " +
                    "product does not implement.");
            }

            MatchOutcome outcome = await EvaluateMechanismAsync(directive, domain, clientIp, budget, cancellationToken)
                .ConfigureAwait(false);

            if (outcome.Status == MatchStatus.Error)
            {
                return outcome.ErrorResult!;
            }

            if (outcome.Status == MatchStatus.Matched)
            {
                return new SpfEvaluationResult(QualifierToResult(directive.Qualifier), null);
            }
        }

        if (record.RedirectDomain is not null)
        {
            return await EvaluateRedirectAsync(record, clientIp, budget, cancellationToken).ConfigureAwait(false);
        }

        // RFC 7208 §4.7: no mechanism matched and there is no redirect.
        return new SpfEvaluationResult(SpfResult.Neutral, null);
    }

    private async Task<MatchOutcome> EvaluateMechanismAsync(
        SpfDirective directive,
        string currentDomain,
        IpAddressValue clientIp,
        Budget budget,
        CancellationToken cancellationToken) => directive.Mechanism switch
    {
        SpfMechanismType.All => MatchOutcome.Matched,

        SpfMechanismType.Ip4 => MatchIp(directive, clientIp, isIp6: false),
        SpfMechanismType.Ip6 => MatchIp(directive, clientIp, isIp6: true),

        // Recognised so a record naming it does not PermError, but never queried and never
        // matched - see SpfMechanismType.Ptr's own remarks. Still charged, per RFC 7208 §4.6.4's
        // explicit list of "ptr" as a lookup-counting mechanism, so a record cannot use it to
        // evade the budget it would otherwise be subject to.
        SpfMechanismType.Ptr => TryChargeMechanismLookup(budget, out SpfEvaluationResult? ptrError)
            ? MatchOutcome.NotMatched
            : MatchOutcome.Error(ptrError!.Result, ptrError.Diagnostic),

        SpfMechanismType.A =>
            await EvaluateAAsync(directive, currentDomain, clientIp, budget, cancellationToken).ConfigureAwait(false),

        SpfMechanismType.Mx =>
            await EvaluateMxAsync(directive, currentDomain, clientIp, budget, cancellationToken).ConfigureAwait(false),

        SpfMechanismType.Exists =>
            await EvaluateExistsAsync(directive, budget, cancellationToken).ConfigureAwait(false),

        SpfMechanismType.Include =>
            await EvaluateIncludeAsync(directive, clientIp, budget, cancellationToken).ConfigureAwait(false),

        _ => MatchOutcome.Error(SpfResult.PermError, $"unhandled mechanism '{directive.Mechanism}'."),
    };

    private static MatchOutcome MatchIp(SpfDirective directive, IpAddressValue clientIp, bool isIp6)
    {
        int prefixLength = isIp6 ? directive.Ip6PrefixLength ?? 128 : directive.Ip4PrefixLength ?? 32;
        return clientIp.IsInSubnet(directive.IpNetwork!, prefixLength) ? MatchOutcome.Matched : MatchOutcome.NotMatched;
    }

    private async Task<MatchOutcome> EvaluateAAsync(
        SpfDirective directive, string currentDomain, IpAddressValue clientIp, Budget budget,
        CancellationToken cancellationToken)
    {
        if (!TryChargeMechanismLookup(budget, out SpfEvaluationResult? budgetError))
        {
            return MatchOutcome.Error(budgetError!.Result, budgetError.Diagnostic);
        }

        if (!TryResolveTargetDomain(directive.DomainSpec, currentDomain, out string? target, out string? domainError))
        {
            return MatchOutcome.Error(SpfResult.PermError, domainError);
        }

        AddressLookupResult addresses = await dnsResolver.ResolveAddressesAsync(target!, cancellationToken)
            .ConfigureAwait(false);

        if (addresses.Status == DnsLookupStatus.Temporary)
        {
            return MatchOutcome.Error(SpfResult.TempError, addresses.Diagnostic);
        }

        if (addresses.Addresses.Count == 0 && !TryChargeVoidLookup(budget, out SpfEvaluationResult? voidError))
        {
            return MatchOutcome.Error(voidError!.Result, voidError.Diagnostic);
        }

        return MatchesAny(addresses.Addresses, clientIp, directive.Ip4PrefixLength, directive.Ip6PrefixLength)
            ? MatchOutcome.Matched
            : MatchOutcome.NotMatched;
    }

    private async Task<MatchOutcome> EvaluateMxAsync(
        SpfDirective directive, string currentDomain, IpAddressValue clientIp, Budget budget,
        CancellationToken cancellationToken)
    {
        if (!TryChargeMechanismLookup(budget, out SpfEvaluationResult? budgetError))
        {
            return MatchOutcome.Error(budgetError!.Result, budgetError.Diagnostic);
        }

        if (!TryResolveTargetDomain(directive.DomainSpec, currentDomain, out string? target, out string? domainError))
        {
            return MatchOutcome.Error(SpfResult.PermError, domainError);
        }

        // ResolveMxAsync needs a validated DomainName, unlike the plain strings the rest of this
        // evaluator's DNS calls take - an underscore-prefixed "mx:" target would be highly
        // unusual (unlike an include/redirect target, where it is the norm), so requiring strict
        // hostname syntax here is an acceptable, narrow simplification rather than one worth
        // threading a second domain representation through for.
        if (!DomainName.TryParse(target, out DomainName? mxDomain))
        {
            return MatchOutcome.Error(SpfResult.PermError, $"'{target}' is not a valid domain name.");
        }

        // Reuses the outbound-delivery MX resolver, which per docs/DNS.md falls back to a
        // domain's own A/AAAA record when it publishes no MX record at all (RFC 5321's implicit
        // MX). That fallback is correct for choosing where to deliver mail; for SPF's "mx"
        // mechanism it is a known, deliberate simplification, since RFC 7208 does not specify an
        // implicit-MX fallback here - the practical effect is that this mechanism can match a
        // domain's bare A record in the specific case where the domain publishes no MX record at
        // all, which only ever makes "mx" more permissive than the strict specification, never
        // less.
        MxLookupResult mx = await dnsResolver.ResolveMxAsync(mxDomain, cancellationToken).ConfigureAwait(false);

        if (mx.Status == DnsLookupStatus.Temporary)
        {
            return MatchOutcome.Error(SpfResult.TempError, mx.Diagnostic);
        }

        if (mx.Hosts.Count == 0)
        {
            return TryChargeVoidLookup(budget, out SpfEvaluationResult? voidError)
                ? MatchOutcome.NotMatched
                : MatchOutcome.Error(voidError!.Result, voidError.Diagnostic);
        }

        // RFC 7208 §4.6.4: no more than 10 MX names need be checked, bounding how many address
        // lookups one "mx" mechanism can trigger regardless of how many MX records exist.
        foreach (MxHost host in mx.Hosts.Take(10))
        {
            AddressLookupResult addresses = await dnsResolver.ResolveAddressesAsync(host.Hostname, cancellationToken)
                .ConfigureAwait(false);

            if (addresses.Status == DnsLookupStatus.Temporary)
            {
                return MatchOutcome.Error(SpfResult.TempError, addresses.Diagnostic);
            }

            if (MatchesAny(addresses.Addresses, clientIp, directive.Ip4PrefixLength, directive.Ip6PrefixLength))
            {
                return MatchOutcome.Matched;
            }
        }

        return MatchOutcome.NotMatched;
    }

    private async Task<MatchOutcome> EvaluateExistsAsync(
        SpfDirective directive, Budget budget, CancellationToken cancellationToken)
    {
        if (!TryChargeMechanismLookup(budget, out SpfEvaluationResult? budgetError))
        {
            return MatchOutcome.Error(budgetError!.Result, budgetError.Diagnostic);
        }

        if (!IsPlausibleDomainSpec(directive.DomainSpec, out string? target, out string? domainError))
        {
            return MatchOutcome.Error(SpfResult.PermError, domainError);
        }

        // RFC 7208 §5.7 specifies an A-only lookup; this checks both A and AAAA as a deliberate
        // simplification - matching on either family is only ever more permissive than the
        // strict spec, in the direction the domain owner using "exists" already opted into.
        AddressLookupResult addresses = await dnsResolver.ResolveAddressesAsync(target, cancellationToken)
            .ConfigureAwait(false);

        if (addresses.Status == DnsLookupStatus.Temporary)
        {
            return MatchOutcome.Error(SpfResult.TempError, addresses.Diagnostic);
        }

        if (addresses.Addresses.Count == 0)
        {
            return TryChargeVoidLookup(budget, out SpfEvaluationResult? voidError)
                ? MatchOutcome.NotMatched
                : MatchOutcome.Error(voidError!.Result, voidError.Diagnostic);
        }

        return MatchOutcome.Matched;
    }

    private async Task<MatchOutcome> EvaluateIncludeAsync(
        SpfDirective directive, IpAddressValue clientIp, Budget budget, CancellationToken cancellationToken)
    {
        if (!TryChargeMechanismLookup(budget, out SpfEvaluationResult? budgetError))
        {
            return MatchOutcome.Error(budgetError!.Result, budgetError.Diagnostic);
        }

        if (!IsPlausibleDomainSpec(directive.DomainSpec, out string? target, out string? domainError))
        {
            return MatchOutcome.Error(SpfResult.PermError, domainError);
        }

        SpfEvaluationResult inner = await EvaluateDomainAsync(target, clientIp, budget, cancellationToken)
            .ConfigureAwait(false);

        // RFC 7208 §5.2: only a Pass makes the include mechanism itself match; Fail/SoftFail/
        // Neutral mean it does not match and evaluation continues with the next directive.
        // TempError propagates as-is. None or PermError from the included domain precludes
        // evaluating the parent record at all - both become PermError here.
        return inner.Result switch
        {
            SpfResult.Pass => MatchOutcome.Matched,
            SpfResult.Fail or SpfResult.SoftFail or SpfResult.Neutral => MatchOutcome.NotMatched,
            SpfResult.TempError => MatchOutcome.Error(SpfResult.TempError, inner.Diagnostic),
            _ => MatchOutcome.Error(SpfResult.PermError, $"'{target}' (included): {inner.Diagnostic}"),
        };
    }

    private async Task<SpfEvaluationResult> EvaluateRedirectAsync(
        SpfRecord record, IpAddressValue clientIp, Budget budget, CancellationToken cancellationToken)
    {
        if (record.RedirectUsesMacros)
        {
            return new SpfEvaluationResult(
                SpfResult.PermError,
                "the redirect= modifier uses SPF macro expansion, which this product does not implement.");
        }

        if (!TryChargeMechanismLookup(budget, out SpfEvaluationResult? budgetError))
        {
            return budgetError!;
        }

        if (!IsPlausibleDomainSpec(record.RedirectDomain, out string? target, out string? domainError))
        {
            return new SpfEvaluationResult(SpfResult.PermError, domainError);
        }

        SpfEvaluationResult redirected = await EvaluateDomainAsync(target, clientIp, budget, cancellationToken)
            .ConfigureAwait(false);

        // RFC 7208 §6.1: a redirect target with no SPF record is a PermError, not a None - unlike
        // the top-level domain, where None is the ordinary "not published" outcome.
        return redirected.Result == SpfResult.None
            ? new SpfEvaluationResult(SpfResult.PermError, $"the redirect target has no SPF record: {redirected.Diagnostic}")
            : redirected;
    }

    private static bool TryResolveTargetDomain(
        string? domainSpec, string currentDomain, out string? target, out string? error)
    {
        if (domainSpec is null)
        {
            target = currentDomain;
            error = null;
            return true;
        }

        return IsPlausibleDomainSpec(domainSpec, out target, out error);
    }

    /// <summary>
    /// A lightweight, lenient sanity check for a domain-spec that will be used as a raw DNS
    /// query name — never a full <see cref="DomainName"/> validation, since RFC 7208
    /// domain-specs routinely use underscore-prefixed labels (<c>_spf.</c>) that
    /// <see cref="DomainName"/>'s stricter, mail-domain-oriented rules reject outright. This only
    /// guards against the pathological (empty, absurdly long, or containing whitespace/control
    /// characters) so a malformed record fails predictably rather than producing a nonsense DNS
    /// query.
    /// </summary>
    private static bool IsPlausibleDomainSpec(string? domainSpec, out string target, out string? error)
    {
        target = domainSpec ?? string.Empty;

        if (string.IsNullOrEmpty(domainSpec) || domainSpec.Length > 253 ||
            domainSpec.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)))
        {
            error = $"'{domainSpec}' is not a usable domain-spec.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool MatchesAny(
        IReadOnlyList<IpAddressValue> addresses, IpAddressValue clientIp, int? ip4Prefix, int? ip6Prefix)
    {
        foreach (IpAddressValue candidate in addresses)
        {
            int prefixLength = candidate.IsIpV4 ? ip4Prefix ?? 32 : ip6Prefix ?? 128;

            if (clientIp.IsInSubnet(candidate, prefixLength))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryChargeMechanismLookup(Budget budget, out SpfEvaluationResult? error)
    {
        budget.DnsLookups++;

        if (budget.DnsLookups > MaxDnsLookups)
        {
            error = new SpfEvaluationResult(
                SpfResult.PermError,
                $"evaluation exceeded the {MaxDnsLookups} DNS-querying-mechanism limit (RFC 7208 section 4.6.4).");

            return false;
        }

        error = null;
        return true;
    }

    private static bool TryChargeVoidLookup(Budget budget, out SpfEvaluationResult? error)
    {
        budget.VoidLookups++;

        if (budget.VoidLookups > MaxVoidLookups)
        {
            error = new SpfEvaluationResult(
                SpfResult.PermError,
                $"evaluation exceeded the {MaxVoidLookups} void-lookup limit (RFC 7208 section 4.6.4).");

            return false;
        }

        error = null;
        return true;
    }

    // RFC 7208 section 4.5's version literal is a plain ABNF quoted string, hence
    // case-insensitive by RFC 5234 section 2.3 - see SpfRecord.TryParse's matching fix.
    private static bool IsSpfRecord(string text) =>
        text.Equals("v=spf1", StringComparison.OrdinalIgnoreCase) ||
        text.StartsWith("v=spf1 ", StringComparison.OrdinalIgnoreCase);

    private static SpfResult QualifierToResult(SpfQualifier qualifier) => qualifier switch
    {
        SpfQualifier.Pass => SpfResult.Pass,
        SpfQualifier.Fail => SpfResult.Fail,
        SpfQualifier.SoftFail => SpfResult.SoftFail,
        SpfQualifier.Neutral => SpfResult.Neutral,
        _ => SpfResult.Neutral,
    };
}
