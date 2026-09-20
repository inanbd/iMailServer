using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>What a report run is allowed to do.</summary>
/// <param name="RunRelayTest">
/// Whether to open an SMTP connection to this server's own listener. Off for a run that must
/// make no connections at all; the check then reports "not tested" rather than a verdict.
/// </param>
/// <param name="QueryReputationLists">
/// Whether to ask the configured blocklists. Separate from the rest because those queries go to
/// third parties, and an operator may want the other ninety points without them.
/// </param>
/// <param name="FetchMtaStsPolicy">
/// Whether to fetch the MTA-STS policy resource over HTTPS. The policy host is named by the
/// domain under test, so this is the one outbound request the report makes to a host the
/// operator has not necessarily configured.
/// </param>
public sealed record DeliverabilityRunOptions(
    bool RunRelayTest = true,
    bool QueryReputationLists = true,
    bool FetchMtaStsPolicy = true)
{
    /// <summary>Everything on.</summary>
    public static DeliverabilityRunOptions Full { get; } = new();

    /// <summary>Only what can be learned from DNS and this server's own state.</summary>
    /// <remarks>
    /// The mode for a run that must not touch anything outside DNS: no connection to the SMTP
    /// listener, no HTTPS request to a policy host, no queries to third-party lists. The checks
    /// those would have fed report as not tested, which the score already knows how to carry.
    /// </remarks>
    public static DeliverabilityRunOptions DnsOnly { get; } =
        new(RunRelayTest: false, QueryReputationLists: false, FetchMtaStsPolicy: false);
}

/// <summary>Produces the whole readiness report for a domain.</summary>
/// <remarks>
/// <b>One run produces one report.</b> The categories share a resolver, an MX answer and an SMTP
/// conversation between them; running them separately would ask DNS the same questions several
/// times and could produce a report whose halves disagree about what the domain publishes.
/// </remarks>
public interface IDeliverabilityReportService
{
    /// <summary>Runs every check that the options allow.</summary>
    Task<DeliverabilityReport> RunAsync(
        DomainName domain,
        DeliverabilityRunOptions options,
        CancellationToken cancellationToken);
}
