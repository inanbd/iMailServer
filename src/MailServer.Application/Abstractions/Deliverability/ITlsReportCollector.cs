namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>What one collection pass did.</summary>
/// <param name="Examined">Messages opened.</param>
/// <param name="Collected">Reports newly stored.</param>
/// <param name="Duplicates">Reports already held — a sender retrying a delivery.</param>
/// <param name="NotReports">Messages that held no readable report.</param>
/// <remarks>
/// <see cref="Duplicates"/> is reported separately rather than folded into <see cref="Examined"/>
/// because the two say different things about a run: duplicates are normal and expected — RFC
/// 8460 §4.1's <c>report-id</c> is how a retried delivery is recognised — while a pass that is
/// all duplicates and no new reports means senders are retrying and something is not being
/// acknowledged.
/// </remarks>
public sealed record TlsReportCollectionResult(
    int Examined,
    int Collected,
    int Duplicates,
    int NotReports)
{
    /// <summary>A pass that did nothing, because collection is off or the mailbox is unknown.</summary>
    public static TlsReportCollectionResult None { get; } = new(0, 0, 0, 0);
}

/// <summary>
/// Reads RFC 8460 reports out of the mailbox the <c>rua</c> address delivers to.
/// </summary>
/// <remarks>
/// A port, so the hosted service that runs this on a timer depends on "collect once" rather than
/// on the mailbox mechanics.
/// </remarks>
public interface ITlsReportCollector
{
    /// <summary>
    /// Makes one bounded pass over the report mailbox.
    /// </summary>
    /// <remarks>
    /// A no-op when collection is disabled, the configured address is not an address, or no
    /// mailbox exists for it. None of those is an error worth failing a host over: collection is
    /// a diagnostic, and the server is otherwise serving mail perfectly well.
    /// </remarks>
    Task<TlsReportCollectionResult> CollectAsync(CancellationToken cancellationToken);
}
