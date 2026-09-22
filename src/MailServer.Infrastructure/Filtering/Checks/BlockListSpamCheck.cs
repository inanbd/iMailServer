using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Filtering;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Filtering;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Filtering.Checks;

/// <summary>
/// Asks the public block lists about the host that delivered the message.
/// </summary>
/// <remarks>
/// <para>
/// <b>The same <see cref="IReputationProvider"/> the readiness report uses, and that matters.</b>
/// Its implementation caches and rate-limits, because most of these lists are run by volunteers
/// and a busy MTA querying one naïvely gets cut off — which presents as every address appearing
/// listed, and would turn this check into one that junks all mail. A second, simpler querying
/// path for the delivery hot path is exactly how that happens.
/// </para>
/// <para>
/// <b>A list that is unhealthy is not consulted.</b> <c>ReputationListing.Health</c> exists
/// because a cut-off or misconfigured list answers "listed" to everything, and a filter that
/// believed it would reject the Internet. An unhealthy list contributes nothing and is logged.
/// </para>
/// <para>
/// <b>Weighed, never decisive.</b> A listing is somebody else's opinion, arrived at by criteria
/// this server cannot see and cannot appeal. It is good evidence and it is wrong often enough
/// — a shared NAT, a recycled address, a stale entry nobody removed — that mail should not be
/// destroyed on it alone.
/// </para>
/// </remarks>
public sealed class BlockListSpamCheck(
    IReputationProvider reputation,
    ILogger<BlockListSpamCheck> logger) : ISpamCheck
{
    /// <summary>What one healthy list's listing contributes.</summary>
    /// <remarks>
    /// Below the junk threshold on purpose: one list is one opinion. Two independent lists
    /// agreeing is a different matter, and two of these add up to it.
    /// </remarks>
    public const double ListedScore = 3.0;

    /// <inheritdoc />
    public string Name => "BlockLists";

    /// <inheritdoc />
    public bool NeedsContent => false;

    /// <inheritdoc />
    public async Task<SpamCheckResult> InspectAsync(
        MessageFilterContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (reputation.Lists.Count == 0)
        {
            return SpamCheckResult.Nothing;
        }

        IReadOnlyList<ReputationListing> listings = await reputation
            .CheckAddressAsync(context.Request.RemoteAddress, cancellationToken)
            .ConfigureAwait(false);

        List<FilterSignal> signals = [];

        foreach (ReputationListing listing in listings)
        {
            if (listing.Health != ReputationListHealth.Healthy)
            {
                logger.LogDebug(
                    "Block list {Provider} reported {Health}; it was not counted against message {MessageId}.",
                    listing.Provider,
                    listing.Health,
                    context.Request.Message.Id.Value);

                continue;
            }

            if (!listing.Listed)
            {
                continue;
            }

            signals.Add(FilterSignal.Create(
                "BLOCKLISTED",
                ListedScore,
                $"The sending host is listed on {listing.Provider}."));
        }

        return SpamCheckResult.Weigh(signals);
    }
}
