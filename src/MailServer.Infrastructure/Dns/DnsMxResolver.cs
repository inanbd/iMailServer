using DnsClient;
using DnsClient.Protocol;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dns;

/// <summary>
/// The one operation this resolver actually needs from <c>DnsClient.NET</c>.
/// </summary>
/// <remarks>
/// <see cref="global::DnsClient.IDnsQuery"/> declares upward of thirty members covering reverse
/// lookups, raw server queries and service discovery that this resolver never calls. Depending
/// on it directly would mean a test double either implements all thirty or throws from most of
/// them; this interface is the one method actually used, so a fake needs to implement exactly
/// that one.
/// </remarks>
internal interface IMxDnsClient
{
    Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken);
}

/// <summary>Adapts a real <see cref="LookupClient"/> to <see cref="IMxDnsClient"/>.</summary>
internal sealed class LookupClientMxAdapter(ILookupClient client) : IMxDnsClient
{
    public Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken) =>
        ((IDnsQuery)client).QueryAsync(query, queryType, cancellationToken: cancellationToken);
}

/// <summary>
/// Resolves MX records for outbound delivery, via <c>DnsClient.NET</c>.
/// </summary>
/// <remarks>
/// See <c>docs/DNS.md</c> for the design this implements exactly: TTLs respected with a
/// 30-second floor and a one-hour ceiling (<see cref="LookupClientOptions.MinimumCacheTimeout"/>
/// / <see cref="LookupClientOptions.MaximumCacheTimeout"/> - the library's own cache, not a
/// second one layered on top of it), implicit MX fallback to A/AAAA when a domain publishes
/// none, null MX (RFC 7505) treated as an immediate permanent failure, and
/// <c>NXDOMAIN</c>/<c>SERVFAIL</c>/timeout classified as permanent/temporary/temporary
/// respectively.
/// </remarks>
internal sealed class DnsMxResolver(IMxDnsClient client, ILogger<DnsMxResolver> logger) : IDnsResolver
{
    public async Task<MxLookupResult> ResolveMxAsync(DomainName domain, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        QueryOutcome outcome = await RunQueryAsync(domain.Value, QueryType.MX, cancellationToken)
            .ConfigureAwait(false);

        if (outcome.Status == DnsLookupStatus.Permanent)
        {
            return MxLookupResult.Permanent(
                outcome.Diagnostic ?? $"{domain.Value} does not exist (NXDOMAIN).");
        }

        if (outcome.Status == DnsLookupStatus.Temporary)
        {
            return MxLookupResult.Temporary(
                outcome.Diagnostic ?? $"MX lookup for {domain.Value} failed temporarily.");
        }

        IReadOnlyList<MxRecord> records = [.. outcome.Response!.Answers.MxRecords()];

        if (records.Count == 1 && IsNullMxTarget(records[0].Exchange.Value))
        {
            // RFC 7505: a single "0 ." record is the domain declaring it accepts no mail at all.
            // An immediate permanent failure, never a retry loop.
            return MxLookupResult.Permanent(
                $"{domain.Value} publishes a null MX record (RFC 7505): it does not accept mail.");
        }

        if (records.Count > 0)
        {
            return MxLookupResult.Success(
                [.. records.Select(r => new MxHost(TrimTrailingDot(r.Exchange.Value), r.Preference))]);
        }

        // No MX record at all, but the query itself succeeded (NOERROR, empty answer). RFC 5321
        // §5.1's implicit MX: fall back to the domain name's own A/AAAA records.
        AddressLookupResult fallback = await ResolveAddressesAsync(domain.Value, cancellationToken)
            .ConfigureAwait(false);

        return fallback.Status switch
        {
            DnsLookupStatus.Success => MxLookupResult.Success([new MxHost(domain.Value, 0)]),

            DnsLookupStatus.Temporary => MxLookupResult.Temporary(
                fallback.Diagnostic ?? $"{domain.Value} has no MX record, and its A/AAAA lookup failed temporarily."),

            _ => MxLookupResult.Permanent(
                $"{domain.Value} has neither an MX record nor an A/AAAA record; mail cannot be delivered."),
        };
    }

    public async Task<AddressLookupResult> ResolveAddressesAsync(string hostname, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostname);

        Task<QueryOutcome> aTask = RunQueryAsync(hostname, QueryType.A, cancellationToken);
        Task<QueryOutcome> aaaaTask = RunQueryAsync(hostname, QueryType.AAAA, cancellationToken);

        await Task.WhenAll(aTask, aaaaTask).ConfigureAwait(false);

        QueryOutcome a = await aTask.ConfigureAwait(false);
        QueryOutcome aaaa = await aaaaTask.ConfigureAwait(false);

        List<IpAddressValue> addresses = [];

        if (a.Response is not null)
        {
            addresses.AddRange(a.Response.Answers.ARecords().Select(r => IpAddressValue.From(r.Address)));
        }

        if (aaaa.Response is not null)
        {
            addresses.AddRange(aaaa.Response.Answers.AaaaRecords().Select(r => IpAddressValue.From(r.Address)));
        }

        if (addresses.Count > 0)
        {
            return AddressLookupResult.Success(addresses);
        }

        // Both came back with nothing usable. If either failed for a reason worth retrying, the
        // whole lookup is temporary - a resolver hiccup on the AAAA query must not be reported as
        // "this host has no addresses" when the A query might succeed with real data next time.
        if (a.Status == DnsLookupStatus.Temporary || aaaa.Status == DnsLookupStatus.Temporary)
        {
            return AddressLookupResult.Temporary(
                $"Address lookup for {hostname} failed temporarily: A={a.Diagnostic ?? "no records"}, " +
                $"AAAA={aaaa.Diagnostic ?? "no records"}.");
        }

        return AddressLookupResult.Permanent($"{hostname} has no A or AAAA record.");
    }

    /// <summary>Runs one query and classifies the result, folding a thrown exception into the
    /// same shape as an ordinary error response so callers have exactly one path to handle.</summary>
    private async Task<QueryOutcome> RunQueryAsync(string name, QueryType queryType, CancellationToken cancellationToken)
    {
        try
        {
            IDnsQueryResponse response = await client
                .QueryAsync(name, queryType, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            if (!response.HasError)
            {
                return new QueryOutcome(DnsLookupStatus.Success, response, null);
            }

            DnsLookupStatus status = response.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain
                ? DnsLookupStatus.Permanent
                : DnsLookupStatus.Temporary;

            return new QueryOutcome(
                status,
                response,
                $"{queryType} lookup for {name} returned {response.Header.ResponseCode}: {response.ErrorMessage}");
        }
        catch (DnsResponseException ex)
        {
            DnsLookupStatus status = ex.Code == DnsResponseCode.NotExistentDomain
                ? DnsLookupStatus.Permanent
                : DnsLookupStatus.Temporary;

            return new QueryOutcome(status, null, $"{queryType} lookup for {name} failed: {ex.Message}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "{QueryType} lookup for {Name} failed at the transport level.", queryType, name);

            return new QueryOutcome(
                DnsLookupStatus.Temporary, null, $"{queryType} lookup for {name} failed: {ex.Message}");
        }
    }

    /// <summary>True for the RFC 7505 null MX target: the root label, on its own.</summary>
    private static bool IsNullMxTarget(string exchange) =>
        string.IsNullOrEmpty(exchange) || exchange == ".";

    private static string TrimTrailingDot(string hostname) =>
        hostname.Length > 0 && hostname[^1] == '.' ? hostname[..^1] : hostname;

    private readonly record struct QueryOutcome(
        DnsLookupStatus Status,
        IDnsQueryResponse? Response,
        string? Diagnostic);
}
