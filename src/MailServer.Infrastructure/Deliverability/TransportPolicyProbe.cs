using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Gathers the observations the MTA-STS and TLS-RPT checks judge.
/// </summary>
/// <remarks>
/// <b>The only probe that does not fetch everything it could.</b> The policy resource is read
/// only when a <c>_mta-sts</c> record says there is one, because RFC 8461 §3.1 has senders "skip
/// the remaining steps of policy discovery" without a usable record — so a fetch this server
/// made anyway would be an outbound request to a host named by the domain under test, on the
/// strength of nothing the domain published.
/// </remarks>
public sealed class TransportPolicyProbe(IDnsDiagnosticsService dns, IMtaStsPolicyFetcher fetcher)
{
    /// <summary>The label an MTA-STS record is published under. RFC 8461 §3.1.</summary>
    public const string StsLabel = "_mta-sts";

    /// <summary>The label a TLS-RPT record is published under. RFC 8460 §3.</summary>
    public const string TlsRptLabel = "_smtp._tls";

    /// <summary>Looks up everything the transport-policy checks need.</summary>
    /// <param name="domain">The domain being judged.</param>
    /// <param name="mxHosts">
    /// The MX hosts the policy must cover, or null when they are not known. Passed through
    /// rather than resolved here: <see cref="DnsProbe"/> has already asked, and asking twice
    /// would let the two halves of one report disagree about what the domain publishes.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<TransportPolicyFacts> GatherAsync(
        DomainName domain,
        IReadOnlyList<string>? mxHosts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        IReadOnlyList<string>? sts = await TextAsync(
                $"{StsLabel}.{domain.Value}",
                cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyList<string>? tlsRpt = await TextAsync(
                $"{TlsRptLabel}.{domain.Value}",
                cancellationToken)
            .ConfigureAwait(false);

        MtaStsFetchOutcome outcome = MtaStsFetchOutcome.NotAttempted;
        string? text = null;

        if (sts is { Count: > 0 })
        {
            MtaStsPolicyFetch fetch = await fetcher
                .FetchAsync(domain, cancellationToken)
                .ConfigureAwait(false);

            outcome = fetch.Outcome;
            text = fetch.Text;
        }

        return new TransportPolicyFacts(domain, mxHosts, sts, outcome, text, tlsRpt);
    }

    /// <summary>The TXT records at a name, or null when the lookup did not answer.</summary>
    private async Task<IReadOnlyList<string>?> TextAsync(string name, CancellationToken cancellationToken)
    {
        DnsDiagnosticAnswer answer = await dns
            .LookupAsync(name, DnsDiagnosticRecordType.Txt, cancellationToken)
            .ConfigureAwait(false);

        return answer.Answered ? answer.Values : null;
    }
}
