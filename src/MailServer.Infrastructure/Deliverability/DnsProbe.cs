using System.Globalization;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Gathers the observations the DNS checks judge.
/// </summary>
/// <remarks>
/// The third of the probes, and the same division as the other two: all I/O, no rules, and the
/// distinction between "did not answer" and "answered with nothing" carried through intact.
/// </remarks>
public sealed class DnsProbe(IDnsDiagnosticsService dns)
{
    /// <summary>
    /// How far up the tree the CAA walk goes.
    /// </summary>
    /// <remarks>
    /// RFC 8659 §3 walks from the FQDN to the root, and a public suffix list would be needed to
    /// stop anywhere sensible short of it. Sixteen is past the length of any name a mail server
    /// is configured with and bounds the work whatever is handed in.
    /// </remarks>
    public const int MaxCaaAncestors = 16;

    /// <summary>Looks up everything the DNS checks need.</summary>
    /// <param name="domain">The domain being judged.</param>
    /// <param name="hostname">The name this server calls itself.</param>
    /// <param name="acmeIssuerDomain">
    /// The CA this server renews from, or null when it does not use ACME.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<DnsFacts> GatherAsync(
        DomainName domain,
        DomainName hostname,
        string? acmeIssuerDomain,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(hostname);

        DnsDiagnosticAnswer mx = await dns
            .LookupAsync(domain.Value, DnsDiagnosticRecordType.Mx, cancellationToken)
            .ConfigureAwait(false);

        List<MxTarget>? targets = mx.Answered ? [] : null;

        if (targets is not null)
        {
            foreach (string value in mx.Values)
            {
                if (ReadMx(value) is not { } record)
                {
                    continue;
                }

                targets.Add(record.Host is "." or ""
                    // RFC 7505's null MX names no host, so there is nothing to look up and
                    // nothing an empty result would mean. Asking anyway would put a query for
                    // the root in the report and invite an operator to fix it.
                    ? new MxTarget(record.Preference, record.Host, [], false)
                    : await DescribeAsync(record.Preference, record.Host, cancellationToken)
                        .ConfigureAwait(false));
            }
        }

        IReadOnlyList<string>? caa = await CaaAsync(domain.Value, cancellationToken)
            .ConfigureAwait(false);

        return new DnsFacts(domain, hostname, targets, mx.Ttl, caa, acmeIssuerDomain);
    }

    /// <summary>Resolves one MX target and notices whether it is an alias.</summary>
    private async Task<MxTarget> DescribeAsync(
        int preference,
        string host,
        CancellationToken cancellationToken)
    {
        DnsDiagnosticAnswer v4 = await dns
            .LookupAsync(host, DnsDiagnosticRecordType.A, cancellationToken)
            .ConfigureAwait(false);

        DnsDiagnosticAnswer v6 = await dns
            .LookupAsync(host, DnsDiagnosticRecordType.Aaaa, cancellationToken)
            .ConfigureAwait(false);

        DnsDiagnosticAnswer cname = await dns
            .LookupAsync(host, DnsDiagnosticRecordType.Cname, cancellationToken)
            .ConfigureAwait(false);

        // As in IdentityProbe: one family answering is an answer. A great many networks have no
        // IPv6 resolver path, and treating a timed-out AAAA as "did not answer" would leave the
        // MX checks inconclusive on most of the internet.
        if (!v4.Answered && !v6.Answered)
        {
            return new MxTarget(preference, host, null, cname.HasValues);
        }

        List<IpAddressValue> addresses = [];

        foreach (string value in v4.Values.Concat(v6.Values))
        {
            if (IpAddressValue.TryParse(value, out IpAddressValue? address))
            {
                addresses.Add(address);
            }
        }

        return new MxTarget(preference, host, addresses, cname.HasValues);
    }

    /// <summary>
    /// The relevant CAA RRset, walking up the tree.
    /// </summary>
    /// <remarks>
    /// RFC 8659 §3 defines the set as the first one found walking from the FQDN towards the
    /// root, and gives the worked example: "CAA('X.Y.Z.') = Empty; domain = Parent('X.Y.Z.') =
    /// 'Y.Z.'" and so on. A probe that asked only at the domain itself would report "no CAA
    /// restriction" for a domain whose parent forbids the issuer outright — the exact case where
    /// an operator has published a restriction once, at the registered domain, and forgotten it.
    /// </remarks>
    private async Task<IReadOnlyList<string>?> CaaAsync(string name, CancellationToken cancellationToken)
    {
        string current = name;
        bool anyAnswered = false;

        for (int depth = 0; depth < MaxCaaAncestors && current.Contains('.', StringComparison.Ordinal); depth++)
        {
            DnsDiagnosticAnswer answer = await dns
                .LookupAsync(current, DnsDiagnosticRecordType.Caa, cancellationToken)
                .ConfigureAwait(false);

            if (answer.Answered)
            {
                anyAnswered = true;

                if (answer.Values.Count > 0)
                {
                    return answer.Values;
                }
            }

            current = current[(current.IndexOf('.', StringComparison.Ordinal) + 1)..];
        }

        // An empty list only when the walk actually completed. If every lookup in it failed, the
        // checks must not read "nobody restricts issuance" out of a resolver that said nothing.
        return anyAnswered ? [] : null;
    }

    /// <summary>
    /// Splits an MX value, which arrives rendered as <c>preference host</c>.
    /// </summary>
    /// <remarks>
    /// Null for anything that does not split that way: a malformed answer is not a route, and
    /// inventing a preference for it would put a record in the report that DNS never returned.
    /// </remarks>
    private static (int Preference, string Host)? ReadMx(string value)
    {
        int space = value.IndexOf(' ', StringComparison.Ordinal);

        if (space <= 0 ||
            !int.TryParse(value[..space], NumberStyles.None, CultureInfo.InvariantCulture, out int preference))
        {
            return null;
        }

        return (preference, value[(space + 1)..].Trim());
    }
}
