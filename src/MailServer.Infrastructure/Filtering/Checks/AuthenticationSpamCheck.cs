using MailServer.Application.Abstractions.Filtering;
using MailServer.Domain.Filtering;

namespace MailServer.Infrastructure.Filtering.Checks;

/// <summary>Weighs what SPF, DKIM and DMARC already concluded.</summary>
/// <remarks>
/// <b>Nothing is re-verified here.</b> <c>LocalDeliveryService</c> verified the signatures and
/// evaluated alignment before the filter ran, and recorded the results. Verifying again would
/// cost a second pass over the body and a second set of DNS lookups to reach an answer this
/// server already has — and would disagree with the recorded one the moment a key rotated
/// between the two reads.
/// </remarks>
public sealed class AuthenticationSpamCheck : ISpamCheck
{
    /// <inheritdoc />
    public string Name => "Authentication";

    /// <inheritdoc />
    public bool NeedsContent => false;

    /// <inheritdoc />
    public Task<SpamCheckResult> InspectAsync(
        MessageFilterContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        return Task.FromResult(
            SpamCheckResult.Weigh(AuthenticationWeighting.Evaluate(context.Request.Authentication)));
    }
}

/// <summary>Runs the structural header checks.</summary>
public sealed class HeaderHeuristicSpamCheck : ISpamCheck
{
    /// <inheritdoc />
    public string Name => "Headers";

    /// <inheritdoc />
    public bool NeedsContent => false;

    /// <summary>A message whose header block could not be located at all.</summary>
    /// <remarks>
    /// Heavier than any single structural fault, because it is not one: a message this server
    /// cannot find a header/body boundary in is malformed at the level RFC 5322 §2.1 describes,
    /// which no ordinary sender produces. It is still only weighed — a parser bug of this
    /// server's own would otherwise quarantine everybody's mail.
    /// </remarks>
    public const double UnparseableHeadersScore = 3.0;

    /// <inheritdoc />
    public Task<SpamCheckResult> InspectAsync(
        MessageFilterContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Headers is null)
        {
            return Task.FromResult(SpamCheckResult.Weigh([
                FilterSignal.Create(
                    "UNPARSEABLE_HEADERS",
                    UnparseableHeadersScore,
                    "The message has no locatable header/body boundary."),
            ]));
        }

        return Task.FromResult(
            SpamCheckResult.Weigh(HeaderHeuristics.Evaluate(context.Headers, context.Envelope)));
    }
}
