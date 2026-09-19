using System.Globalization;
using DnsClient;
using DnsClient.Protocol;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dns;

/// <summary>
/// The one operation the diagnostic resolver needs from <c>DnsClient.NET</c>.
/// </summary>
/// <remarks>
/// The same argument <see cref="IMxDnsClient"/> makes: a test double should implement the one
/// method actually called rather than thirty it never will. A separate interface from that one
/// because the two are backed by differently configured clients — this one does not cache.
/// </remarks>
internal interface IDiagnosticDnsClient
{
    Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken);
}

/// <summary>Adapts an uncached <see cref="LookupClient"/> to <see cref="IDiagnosticDnsClient"/>.</summary>
internal sealed class LookupClientDiagnosticAdapter(ILookupClient client) : IDiagnosticDnsClient
{
    public Task<IDnsQueryResponse> QueryAsync(
        string query,
        QueryType queryType,
        CancellationToken cancellationToken) =>
        ((IDnsQuery)client).QueryAsync(query, queryType, cancellationToken: cancellationToken);
}

/// <summary>
/// The admin tools' resolver: uncached, and it reports who answered.
/// </summary>
/// <remarks>
/// <para>
/// <c>docs/DNS.md</c>: it "<b>bypasses the cache</b> and may query authoritative nameservers
/// directly, because 'it works on my resolver' is exactly the problem a diagnostic tool exists
/// to solve. It reports the TTL, the answering server, and the actual versus expected value."
/// </para>
/// <para>
/// <b>An empty answer is a success, not a failure.</b> A name that exists and has no TXT record
/// is a fact about the configuration and the caller — the SPF check, the DMARC check — is the
/// only thing that knows whether the absence matters. Reporting it as a lookup failure would
/// make every "you have not published this yet" finding indistinguishable from a resolver
/// outage, which is the one distinction the whole score depends on.
/// </para>
/// </remarks>
internal sealed class DnsDiagnosticsService(
    IDiagnosticDnsClient client,
    ILogger<DnsDiagnosticsService> logger) : IDnsDiagnosticsService
{
    public Task<DnsDiagnosticAnswer> LookupAsync(
        string name,
        DnsDiagnosticRecordType type,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        return QueryAsync(name, type, cancellationToken);
    }

    public Task<DnsDiagnosticAnswer> LookupPointerAsync(
        IpAddressValue address,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        // The caller should not have to know the difference between in-addr.arpa and the
        // nibble-reversed ip6.arpa form; the value object already does.
        return QueryAsync(
            address.ToReverseDnsName(),
            DnsDiagnosticRecordType.Ptr,
            cancellationToken);
    }

    private async Task<DnsDiagnosticAnswer> QueryAsync(
        string name,
        DnsDiagnosticRecordType type,
        CancellationToken cancellationToken)
    {
        QueryType queryType = QueryTypeOf(type);

        try
        {
            IDnsQueryResponse response = await client
                .QueryAsync(name, queryType, cancellationToken)
                .ConfigureAwait(false);

            string? server = response.NameServer?.ToString();

            if (response.HasError)
            {
                string diagnostic =
                    $"{queryType} lookup for {name} returned {response.Header.ResponseCode}: " +
                    response.ErrorMessage;

                // The same classification the delivery path uses, for the same reason: a
                // timeout and an NXDOMAIN lead to different advice.
                return response.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain
                    ? DnsDiagnosticAnswer.Permanent(diagnostic, server)
                    : DnsDiagnosticAnswer.Temporary(diagnostic, server);
            }

            IReadOnlyList<DnsResourceRecord> answers = [.. response.Answers];

            return DnsDiagnosticAnswer.Success(
                [.. answers.Select(r => Render(r, type)).Where(v => v is not null).Select(v => v!)],
                SmallestTtl(answers),
                server);
        }
        catch (DnsResponseException ex)
        {
            string diagnostic = $"{queryType} lookup for {name} failed: {ex.Message}";

            return ex.Code == DnsResponseCode.NotExistentDomain
                ? DnsDiagnosticAnswer.Permanent(diagnostic)
                : DnsDiagnosticAnswer.Temporary(diagnostic);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(
                ex,
                "{QueryType} lookup for {Name} failed at the transport level.",
                queryType,
                name);

            return DnsDiagnosticAnswer.Temporary($"{queryType} lookup for {name} failed: {ex.Message}");
        }
    }

    /// <summary>
    /// The smallest TTL in the answer.
    /// </summary>
    /// <remarks>
    /// The smallest rather than the first, because it is the one that decides how long a
    /// correction takes to become visible — which is the question an operator is asking when
    /// they look at a TTL in a diagnostic report.
    /// </remarks>
    private static TimeSpan? SmallestTtl(IReadOnlyList<DnsResourceRecord> answers)
    {
        int? smallest = null;

        foreach (DnsResourceRecord record in answers)
        {
            if (smallest is null || record.InitialTimeToLive < smallest)
            {
                smallest = record.InitialTimeToLive;
            }
        }

        return smallest is null ? null : TimeSpan.FromSeconds(smallest.Value);
    }

    /// <summary>
    /// Renders one record in the form it would be published in.
    /// </summary>
    /// <remarks>
    /// Published form rather than the library's <c>ToString</c>, which prefixes the owner name,
    /// class and TTL. An operator comparing a diagnostic report against their DNS panel should
    /// be looking at the same text in both places.
    /// </remarks>
    private static string? Render(DnsResourceRecord record, DnsDiagnosticRecordType type) =>
        (record, type) switch
        {
            (ARecord a, DnsDiagnosticRecordType.A) => a.Address.ToString(),
            (AaaaRecord a, DnsDiagnosticRecordType.Aaaa) => a.Address.ToString(),
            (MxRecord mx, DnsDiagnosticRecordType.Mx) => string.Create(
                CultureInfo.InvariantCulture,
                $"{mx.Preference} {TrimRoot(mx.Exchange.Value)}"),
            (TxtRecord txt, DnsDiagnosticRecordType.Txt) => string.Concat(txt.Text),
            (PtrRecord ptr, DnsDiagnosticRecordType.Ptr) => TrimRoot(ptr.PtrDomainName.Value),
            (CaaRecord caa, DnsDiagnosticRecordType.Caa) => string.Create(
                CultureInfo.InvariantCulture,
                $"{caa.Flags} {caa.Tag} \"{caa.Value}\""),
            (NsRecord ns, DnsDiagnosticRecordType.Ns) => TrimRoot(ns.NSDName.Value),
            (CNameRecord cname, _) => TrimRoot(cname.CanonicalName.Value),

            // A record of a type that was not asked for. DNS answers may legitimately carry
            // them, and a diagnostic report that listed them would show an operator records
            // they did not ask about next to the ones they did.
            _ => null,
        };

    /// <summary>Strips the root label DNS names carry on the wire.</summary>
    private static string TrimRoot(string name) =>
        name.Length > 1 && name[^1] == '.' ? name[..^1] : name;

    private static QueryType QueryTypeOf(DnsDiagnosticRecordType type) => type switch
    {
        DnsDiagnosticRecordType.A => QueryType.A,
        DnsDiagnosticRecordType.Aaaa => QueryType.AAAA,
        DnsDiagnosticRecordType.Mx => QueryType.MX,
        DnsDiagnosticRecordType.Txt => QueryType.TXT,
        DnsDiagnosticRecordType.Ptr => QueryType.PTR,
        DnsDiagnosticRecordType.Caa => QueryType.CAA,
        DnsDiagnosticRecordType.Ns => QueryType.NS,
        DnsDiagnosticRecordType.Cname => QueryType.CNAME,
        _ => throw new ArgumentOutOfRangeException(
            nameof(type),
            type,
            "Not a diagnostic record type."),
    };
}
