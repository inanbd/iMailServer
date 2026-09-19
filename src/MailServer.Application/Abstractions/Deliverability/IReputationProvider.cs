using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>
/// Asks the public lists what they think of an address or a domain.
/// </summary>
/// <remarks>
/// <para>
/// <b>Implementations cache and rate-limit, and that is not a performance concern.</b>
/// <c>docs/Deliverability.md</c>: "Naïve DNSBL querying from a busy MTA gets you blocked by the
/// DNSBL operator and is an abuse of volunteer infrastructure." Most of these lists are run by
/// volunteers and funded by nobody; a diagnostic tool that hammered them would be taking from
/// the commons it depends on, and would be cut off for it — which shows up as every address
/// appearing listed, the very failure
/// <see cref="ReputationListHealth"/> exists to catch.
/// </para>
/// <para>
/// Each answer carries the list's health alongside its verdict, because a verdict without it
/// cannot be acted on.
/// </para>
/// </remarks>
public interface IReputationProvider
{
    /// <summary>The lists this provider will query, as an operator would recognise them.</summary>
    IReadOnlyList<string> Lists { get; }

    /// <summary>What the lists say about a sending address.</summary>
    Task<IReadOnlyList<ReputationListing>> CheckAddressAsync(
        IpAddressValue address,
        CancellationToken cancellationToken);

    /// <summary>What the lists say about a domain.</summary>
    Task<IReadOnlyList<ReputationListing>> CheckDomainAsync(
        DomainName domain,
        CancellationToken cancellationToken);
}
