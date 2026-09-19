using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>The result of trying to read a domain's MTA-STS policy resource.</summary>
/// <param name="Outcome">How the fetch went.</param>
/// <param name="Text">The resource's content when it was retrieved, and null otherwise.</param>
/// <param name="Diagnostic">
/// What happened, for the operator: the status code, the media type served, the TLS error. Never
/// the finding itself — the checks write those.
/// </param>
public sealed record MtaStsPolicyFetch(MtaStsFetchOutcome Outcome, string? Text, string? Diagnostic);

/// <summary>
/// Reads a domain's MTA-STS policy over HTTPS. RFC 8461 §3.2.
/// </summary>
/// <remarks>
/// <para>
/// An abstraction rather than a call, because the whole point of this fetch is how it
/// <i>fails</i>. A bad certificate on the policy host, a 404, a policy served as HTML — each is
/// a distinct finding with a distinct remedy, and each is invisible from a browser that clicks
/// through the warning or follows the redirect.
/// </para>
/// <para>
/// <b>This is the one part of the deliverability report that makes an outbound request to a host
/// named by the domain under test.</b> Implementations follow no redirects, cap the response,
/// and never disable certificate validation — a policy host that fails validation is the
/// finding, not an obstacle to route around.
/// </para>
/// </remarks>
public interface IMtaStsPolicyFetcher
{
    /// <summary>Fetches the policy for a domain. Never throws for a fetch that simply failed.</summary>
    Task<MtaStsPolicyFetch> FetchAsync(DomainName domain, CancellationToken cancellationToken);
}
