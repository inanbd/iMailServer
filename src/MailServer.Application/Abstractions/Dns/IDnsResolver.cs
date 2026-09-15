using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Dns;

/// <summary>How a DNS lookup concluded, for the purpose of deciding what to do next.</summary>
/// <remarks>
/// Not a raw DNS response code. <c>docs/DNS.md</c>'s single most consequential rule is that
/// every possible outcome collapses to exactly one of these three, because the caller's next
/// action - retry later, bounce now, or proceed - depends on nothing else.
/// </remarks>
public enum DnsLookupStatus
{
    /// <summary>The lookup answered. At least one usable result is present.</summary>
    Success = 0,

    /// <summary>
    /// A timeout or <c>SERVFAIL</c>. Worth retrying: the answer may simply not be available yet.
    /// </summary>
    Temporary = 1,

    /// <summary>
    /// <c>NXDOMAIN</c>, a published null MX (RFC 7505), or a name with neither MX nor A/AAAA
    /// records. Never worth retrying.
    /// </summary>
    Permanent = 2,
}

/// <summary>The result of resolving a domain's mail exchangers.</summary>
/// <param name="Status">See <see cref="DnsLookupStatus"/>.</param>
/// <param name="Hosts">
/// Candidate hosts to attempt delivery to, when <paramref name="Status"/> is
/// <see cref="DnsLookupStatus.Success"/>. Not yet ordered for an attempt - see
/// <see cref="Policies.MxSelectionPolicy"/> for that, which is a separate, pure step so it can
/// be tested without a resolver.
/// </param>
/// <param name="Diagnostic">Human-readable detail, for the delivery attempt record and logs.</param>
public sealed record MxLookupResult(DnsLookupStatus Status, IReadOnlyList<MxHost> Hosts, string? Diagnostic)
{
    public static MxLookupResult Success(IReadOnlyList<MxHost> hosts) =>
        new(DnsLookupStatus.Success, hosts, null);

    public static MxLookupResult Temporary(string diagnostic) =>
        new(DnsLookupStatus.Temporary, [], diagnostic);

    public static MxLookupResult Permanent(string diagnostic) =>
        new(DnsLookupStatus.Permanent, [], diagnostic);
}

/// <summary>The result of resolving a hostname's addresses.</summary>
public sealed record AddressLookupResult(
    DnsLookupStatus Status,
    IReadOnlyList<IpAddressValue> Addresses,
    string? Diagnostic)
{
    public static AddressLookupResult Success(IReadOnlyList<IpAddressValue> addresses) =>
        new(DnsLookupStatus.Success, addresses, null);

    public static AddressLookupResult Temporary(string diagnostic) =>
        new(DnsLookupStatus.Temporary, [], diagnostic);

    public static AddressLookupResult Permanent(string diagnostic) =>
        new(DnsLookupStatus.Permanent, [], diagnostic);
}

/// <summary>
/// The hot-path DNS resolver: MX resolution for outbound delivery. Cached, bounded, fast.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="System.Net.Dns"/> cannot do MX at all, which is the entire reason this interface
/// exists. See <c>docs/DNS.md</c> for the full design; the short version is repeated here
/// because it is binding on every implementation:
/// </para>
/// <list type="bullet">
///   <item><description><b>Implicit MX:</b> a domain with no MX record but an A/AAAA record
///   falls back to that host. Implementations apply this internally, so a caller never needs
///   to know the fallback happened - it just receives a usable host list.</description></item>
///   <item><description><b>Null MX</b> (RFC 7505, a single <c>0 .</c> record) is reported as
///   <see cref="DnsLookupStatus.Permanent"/>: the domain has declared it accepts no
///   mail.</description></item>
///   <item><description><b>Caching</b> respects TTLs with a 30-second floor and a one-hour
///   ceiling; negative results are cached for a shorter period.</description></item>
/// </list>
/// <para>
/// This is deliberately a different, narrower interface than a future diagnostic resolver
/// (<c>docs/DNS.md</c>'s <c>IDnsDiagnosticsService</c>, Milestone 11): that one bypasses the
/// cache and queries authoritative nameservers directly to answer "what is actually published",
/// which is the opposite of what the delivery hot path wants.
/// </para>
/// </remarks>
public interface IDnsResolver
{
    /// <summary>
    /// Resolves the hosts a message to <paramref name="domain"/> should be attempted against.
    /// </summary>
    Task<MxLookupResult> ResolveMxAsync(DomainName domain, CancellationToken cancellationToken);

    /// <summary>Resolves a specific hostname's addresses, for connecting to a chosen MX host.</summary>
    Task<AddressLookupResult> ResolveAddressesAsync(string hostname, CancellationToken cancellationToken);
}
