using MailServer.Application.Abstractions.Deliverability;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Gathers the observations the reputation checks judge.
/// </summary>
/// <remarks>
/// Thinner than the other probes, because <see cref="IReputationProvider"/> already owns the
/// caching, the rate limiting and RFC 5782 §5's self-test. What is left is the one decision this
/// layer has to make: with no list configured the checks are handed null rather than an empty
/// list, so they report "not tested" instead of "nobody has anything against you".
/// </remarks>
public sealed class ReputationProbe(IReputationProvider provider)
{
    /// <summary>Asks the configured lists about a domain and the address it sends from.</summary>
    public async Task<ReputationFacts> GatherAsync(
        DomainName domain,
        IpAddressValue? address,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        if (provider.Lists.Count == 0)
        {
            return new ReputationFacts(domain, address, null, null);
        }

        IReadOnlyList<ReputationListing>? ip = address is null
            ? null
            : await provider.CheckAddressAsync(address, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<ReputationListing> domainListings = await provider
            .CheckDomainAsync(domain, cancellationToken)
            .ConfigureAwait(false);

        return new ReputationFacts(domain, address, ip, domainListings);
    }
}
