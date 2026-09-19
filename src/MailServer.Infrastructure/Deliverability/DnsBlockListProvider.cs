using System.Collections.Concurrent;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>Which identity a list is about.</summary>
public enum ReputationListSubject
{
    /// <summary>An IP address, queried as RFC 5782 §2.1 describes.</summary>
    Address = 0,

    /// <summary>A domain name, queried as RFC 5782 §2.4 describes.</summary>
    Domain = 1,
}

/// <summary>One list this provider will query.</summary>
/// <param name="Zone">The list's DNS zone, which is also how an operator names it.</param>
/// <param name="Subject">What kind of identity it lists.</param>
public sealed record ReputationList(string Zone, ReputationListSubject Subject);

/// <summary>
/// Queries DNS-based blocklists, cached and rate-limited.
/// </summary>
/// <remarks>
/// <para>
/// <b>The caching and rate limiting are an obligation rather than an optimisation.</b> Most of
/// these lists are run by volunteers; <c>docs/Deliverability.md</c> is explicit that "Naïve
/// DNSBL querying from a busy MTA gets you blocked by the DNSBL operator and is an abuse of
/// volunteer infrastructure". Being cut off is also self-defeating in a way that is hard to
/// notice: a list that has stopped serving this server commonly answers "listed" for every
/// query, which looks exactly like a real listing.
/// </para>
/// <para>
/// Which is what the self-test is for. Every answer is accompanied by a check of RFC 5782 §5's
/// test entries, so a verdict is only ever reported alongside evidence that the list was
/// answering properly when it was given.
/// </para>
/// <para>
/// <b>No list is configured by default.</b> Querying a third party about the operator's own
/// address is a request this server makes on their behalf to an organisation they have not
/// chosen, so it happens only once they name the lists.
/// </para>
/// </remarks>
/// <param name="dns">The uncached diagnostic resolver, so a delisting shows up when it happens.</param>
/// <param name="lists">The lists to query. Empty by default — see the remarks.</param>
/// <param name="clock">The clock the cache and the throttle are measured against.</param>
/// <param name="delay">
/// How the throttle waits, defaulting to <see cref="Task.Delay(TimeSpan, CancellationToken)"/>.
/// A seam rather than a real dependency: the alternative is a test that genuinely sleeps two
/// seconds per list, which is how throttle tests end up deleted.
/// </param>
public sealed class DnsBlockListProvider(
    IDnsDiagnosticsService dns,
    IReadOnlyList<ReputationList> lists,
    IClock clock,
    Func<TimeSpan, CancellationToken, Task>? delay = null) : IReputationProvider
{
    /// <summary>
    /// RFC 5782 §5's entry that must be listed: 127.0.0.2, reversed.
    /// </summary>
    public const string MustBeListed = "2.0.0.127";

    /// <summary>RFC 5782 §5's entry that must not be listed: 127.0.0.1, reversed.</summary>
    public const string MustNotBeListed = "1.0.0.127";

    /// <summary>
    /// RFC 2606's reserved name a domain list must carry, per §5.
    /// </summary>
    /// <remarks>
    /// §5: "Domain-name-based DNSxLs MUST contain an entry for the [RFC2606] reserved domain name
    /// 'TEST' and MUST NOT contain an entry for the reserved domain name 'INVALID'."
    /// </remarks>
    public const string DomainMustBeListed = "TEST";

    /// <summary>The reserved name a domain list must not carry.</summary>
    public const string DomainMustNotBeListed = "INVALID";

    /// <summary>
    /// How long an answer is reused.
    /// </summary>
    /// <remarks>
    /// Long by the standards of a cache and short by the standards of a listing: a delisting
    /// takes hours to days to take effect anyway, so an operator who has just requested one
    /// gains nothing from a fresher answer and the list gains a great deal from being asked
    /// less.
    /// </remarks>
    public static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(15);

    /// <summary>The least time between two queries to the same list.</summary>
    public static readonly TimeSpan MinimumInterval = TimeSpan.FromSeconds(2);

    private readonly ConcurrentDictionary<string, CachedAnswer> _cache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastQueried = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CachedHealth> _health = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public IReadOnlyList<string> Lists { get; } = [.. lists.Select(l => l.Zone)];

    /// <inheritdoc />
    public Task<IReadOnlyList<ReputationListing>> CheckAddressAsync(
        IpAddressValue address,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        return CheckAsync(ReputationListSubject.Address, ReversedOctets(address), cancellationToken);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<ReputationListing>> CheckDomainAsync(
        DomainName domain,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        return CheckAsync(ReputationListSubject.Domain, domain.Value, cancellationToken);
    }

    /// <summary>
    /// The octets of an address in the order a DNSxL query wants them.
    /// </summary>
    /// <remarks>
    /// RFC 5782 §2.1 builds the name by "reversing the order of the components of the dotted
    /// text representation of the IP address, and appending the domain name of the DNSxL" — the
    /// same reversal as a PTR query but without the <c>in-addr.arpa</c> suffix, which belongs to
    /// reverse DNS and not to a list's own zone.
    /// </remarks>
    public static string ReversedOctets(IpAddressValue address)
    {
        ArgumentNullException.ThrowIfNull(address);

        string reverse = address.ToReverseDnsName();

        foreach (string suffix in (string[])[".in-addr.arpa", ".ip6.arpa"])
        {
            if (reverse.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return reverse[..^suffix.Length];
            }
        }

        return reverse;
    }

    private async Task<IReadOnlyList<ReputationListing>> CheckAsync(
        ReputationListSubject subject,
        string queryPrefix,
        CancellationToken cancellationToken)
    {
        List<ReputationListing> results = [];

        foreach (ReputationList list in lists.Where(l => l.Subject == subject))
        {
            ReputationListHealth health = await HealthAsync(list, cancellationToken)
                .ConfigureAwait(false);

            // A list that cannot be believed is not asked about the real identity at all: the
            // answer could not be used, and asking anyway would spend a query on a list that is
            // very likely already refusing this server's.
            if (health is not ReputationListHealth.Healthy)
            {
                results.Add(new ReputationListing(list.Zone, false, [], null, health));
                continue;
            }

            (bool listed, IReadOnlyList<string> codes) =
                await LookupAsync(list.Zone, queryPrefix, cancellationToken).ConfigureAwait(false);

            string? reason = listed
                ? await ReasonAsync(list.Zone, queryPrefix, cancellationToken).ConfigureAwait(false)
                : null;

            results.Add(new ReputationListing(list.Zone, listed, codes, reason, health));
        }

        return results;
    }

    /// <summary>
    /// Whether a list is answering this server's queries the way RFC 5782 §5 requires.
    /// </summary>
    /// <remarks>
    /// Cached for the same lifetime as an answer, because it is asked before every one of them
    /// and two more queries per list per check would treble this provider's load on exactly the
    /// infrastructure it is trying not to abuse.
    /// </remarks>
    private async Task<ReputationListHealth> HealthAsync(
        ReputationList list,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;

        if (_health.TryGetValue(list.Zone, out CachedHealth cached) && cached.Expires > now)
        {
            return cached.Health;
        }

        (string listedName, string unlistedName) = list.Subject switch
        {
            ReputationListSubject.Domain => (DomainMustBeListed, DomainMustNotBeListed),
            _ => (MustBeListed, MustNotBeListed),
        };

        (bool positive, _) = await LookupAsync(list.Zone, listedName, cancellationToken)
            .ConfigureAwait(false);

        (bool negative, _) = await LookupAsync(list.Zone, unlistedName, cancellationToken)
            .ConfigureAwait(false);

        ReputationListHealth health = (positive, negative) switch
        {
            // The entry that must be there is, and the one that must not be is not.
            (true, false) => ReputationListHealth.Healthy,

            // Nothing is listed, including the test entry - the zone is not serving this server.
            (false, false) => ReputationListHealth.NotAnswering,

            // Everything is listed, or the wrong thing is. Either way its verdicts are noise.
            _ => ReputationListHealth.Unreliable,
        };

        _health[list.Zone] = new CachedHealth(health, now + CacheLifetime);

        return health;
    }

    private async Task<(bool Listed, IReadOnlyList<string> Codes)> LookupAsync(
        string zone,
        string prefix,
        CancellationToken cancellationToken)
    {
        string name = $"{prefix}.{zone}";
        DateTimeOffset now = clock.UtcNow;

        if (_cache.TryGetValue(name, out CachedAnswer cached) && cached.Expires > now)
        {
            return (cached.Listed, cached.Codes);
        }

        await ThrottleAsync(zone, cancellationToken).ConfigureAwait(false);

        DnsDiagnosticAnswer answer = await dns
            .LookupAsync(name, DnsDiagnosticRecordType.A, cancellationToken)
            .ConfigureAwait(false);

        // RFC 5782 §2.1: "Each entry in the DNSxL MUST have an A record", and an entry that is
        // not there is what "not listed" means. A lookup that did not answer is neither, and is
        // not cached - the health test is what turns a silent list into a reported one.
        if (!answer.Answered)
        {
            return (false, []);
        }

        CachedAnswer fresh = new(answer.Values.Count > 0, answer.Values, clock.UtcNow + CacheLifetime);

        _cache[name] = fresh;

        return (fresh.Listed, fresh.Codes);
    }

    /// <summary>The TXT record explaining a listing, if the list publishes one.</summary>
    private async Task<string?> ReasonAsync(
        string zone,
        string prefix,
        CancellationToken cancellationToken)
    {
        await ThrottleAsync(zone, cancellationToken).ConfigureAwait(false);

        DnsDiagnosticAnswer answer = await dns
            .LookupAsync($"{prefix}.{zone}", DnsDiagnosticRecordType.Txt, cancellationToken)
            .ConfigureAwait(false);

        return answer.HasValues ? string.Join(" ", answer.Values) : null;
    }

    /// <summary>
    /// Keeps two queries to the same list at least <see cref="MinimumInterval"/> apart.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per zone rather than globally, since the load that matters is the load on one operator's
    /// nameservers — and a report that checked six lists would otherwise take six times as long
    /// for no benefit to any of them.
    /// </para>
    /// <para>
    /// <b>The zone is passed in rather than derived from the query name.</b> A DNSBL name is the
    /// zone with a prefix of four labels for an IPv4 address and thirty-two for an IPv6 one, so
    /// anything that tried to recover the zone by trimming labels would group almost every query
    /// under a key of its own — a throttle that compiles, reads correctly, and does nothing.
    /// </para>
    /// </remarks>
    private async Task ThrottleAsync(string zone, CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;

        if (_lastQueried.TryGetValue(zone, out DateTimeOffset last))
        {
            TimeSpan since = now - last;

            if (since < MinimumInterval)
            {
                await (delay ?? DefaultDelay)(MinimumInterval - since, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        _lastQueried[zone] = clock.UtcNow;
    }

    private static Task DefaultDelay(TimeSpan span, CancellationToken cancellationToken) =>
        Task.Delay(span, cancellationToken);

    private readonly record struct CachedAnswer(
        bool Listed,
        IReadOnlyList<string> Codes,
        DateTimeOffset Expires);

    private readonly record struct CachedHealth(ReputationListHealth Health, DateTimeOffset Expires);
}
