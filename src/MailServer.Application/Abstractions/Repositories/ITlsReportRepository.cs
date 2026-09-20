using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>One collected report, as the listing shows it.</summary>
/// <param name="Id">This server's identifier for the collected row.</param>
/// <param name="PolicyDomain">The domain the report is about.</param>
/// <param name="OrganizationName">Who said they sent it. A claim.</param>
/// <param name="ContactInfo">Their contact address. A claim.</param>
/// <param name="ReportId">Their identifier for it.</param>
/// <param name="StartUtc">Start of the period it covers, as they stated it.</param>
/// <param name="EndUtc">End of that period.</param>
/// <param name="SuccessfulSessionCount">Sessions that negotiated TLS as required.</param>
/// <param name="FailedSessionCount">Sessions that did not.</param>
/// <param name="Summary">The one-sentence verdict, composed at collection.</param>
/// <param name="CollectedUtc">When this server collected it.</param>
/// <param name="Failures">The failures, grouped by result type and ordered by impact.</param>
public sealed record CollectedTlsReport(
    Guid Id,
    string PolicyDomain,
    string? OrganizationName,
    string? ContactInfo,
    string? ReportId,
    DateTimeOffset? StartUtc,
    DateTimeOffset? EndUtc,
    long SuccessfulSessionCount,
    long FailedSessionCount,
    string Summary,
    DateTimeOffset CollectedUtc,
    IReadOnlyList<TlsFailureSummary> Failures);

/// <summary>
/// Stores the RFC 8460 reports other senders delivered, and remembers which messages have
/// already been looked at.
/// </summary>
/// <remarks>
/// <b>The examined-messages half is what makes collection re-runnable.</b> A pass over a mailbox
/// must not re-read what it read last time, and must not re-examine a message that turned out
/// not to be a report — a bounce or a covering note would otherwise be opened and rejected on
/// every pass forever. Both outcomes are recorded, the failure with its reason, so an operator
/// asking why something was not collected gets an answer rather than silence.
/// </remarks>
public interface ITlsReportRepository
{
    /// <summary>
    /// Message ids in this mailbox's folder that have not been examined yet, oldest first.
    /// </summary>
    /// <param name="mailboxId">The mailbox holding the <c>rua</c> address's mail.</param>
    /// <param name="limit">The most to return, so one pass is bounded.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task<IReadOnlyList<StoredMessageId>> ListUnexaminedAsync(
        MailboxId mailboxId,
        int limit,
        CancellationToken cancellationToken);

    /// <summary>
    /// Records a report and the message it came from, in one transaction.
    /// </summary>
    /// <remarks>
    /// Returns false when the report was already held — RFC 8460 §4.1's <c>report-id</c> is
    /// unique per sender, and a sender that retries a delivery sends the same one again. The
    /// message is still marked examined, because it has been.
    /// </remarks>
    Task<bool> RecordAsync(
        StoredMessageId messageId,
        string policyDomain,
        TlsReport report,
        DateTimeOffset collectedUtc,
        CancellationToken cancellationToken);

    /// <summary>Records that a message held no readable report, and why.</summary>
    Task RecordFailureAsync(
        StoredMessageId messageId,
        string error,
        DateTimeOffset examinedUtc,
        CancellationToken cancellationToken);

    /// <summary>The most recently collected reports for a domain, newest first.</summary>
    Task<IReadOnlyList<CollectedTlsReport>> ListRecentAsync(
        string policyDomain,
        int limit,
        CancellationToken cancellationToken);
}
