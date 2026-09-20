using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Reads RFC 8460 reports out of the mailbox the <c>rua</c> address delivers to.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a mailbox rather than an endpoint.</b> §3 allows <c>mailto:</c> and <c>https:</c>, and
/// the senders that matter — Google, Microsoft — use <c>mailto:</c>. An HTTPS endpoint would be
/// less code and would collect almost nothing.
/// </para>
/// <para>
/// <b>It reads the mailbox and does not change it.</b> No message is marked seen, moved or
/// deleted: a human may be reading the same mailbox, and a collector that marked its own reading
/// would fight them for the unread count. What has been looked at is recorded separately, in
/// <c>TlsReportSources</c>.
/// </para>
/// <para>
/// <b>Failures are recorded, not just successes.</b> A bounce, a covering note or somebody's
/// reply will sit in that mailbox forever, and a collector that only remembered successes would
/// open and reject each of them on every pass for the life of the installation.
/// </para>
/// <para>
/// <b>One pass is bounded.</b> A mailbox with a year of unread reports must not be worked
/// through in a single pass that holds a connection and a transaction open for minutes; oldest
/// first means a bounded pass still makes progress rather than re-reading the newest few.
/// </para>
/// </remarks>
public sealed class TlsReportCollector(
    ITlsReportRepository reports,
    ITlsReportExtractor extractor,
    IMailboxRepository mailboxes,
    IMessageStore messageStore,
    IClock clock,
    IOptions<MailServerOptions> options,
    ILogger<TlsReportCollector> logger) : ITlsReportCollector
{
    /// <summary>
    /// The most messages one pass will open.
    /// </summary>
    /// <remarks>
    /// Each one is a stored message read from disk, a MIME parse and a decompression. Fifty is
    /// a backlog cleared in a few passes without any single pass being long.
    /// </remarks>
    public const int MaxMessagesPerPass = 50;

    private TlsRptOptions Options => options.Value.Deliverability.TlsRpt;

    public async Task<TlsReportCollectionResult> CollectAsync(CancellationToken cancellationToken)
    {
        if (!Options.Enabled)
        {
            return TlsReportCollectionResult.None;
        }

        if (!EmailAddress.TryParse(Options.ReportMailbox, out EmailAddress? address))
        {
            // Said once per pass rather than thrown: collection is a diagnostic, and a
            // misconfigured address should not take down a host that is otherwise serving mail.
            logger.LogWarning(
                "TLS report collection is enabled but {Address} is not an email address, so " +
                "nothing will be collected.",
                Options.ReportMailbox);

            return TlsReportCollectionResult.None;
        }

        Mailbox? mailbox = await mailboxes
            .GetByAddressAsync(address, cancellationToken)
            .ConfigureAwait(false);

        if (mailbox is null)
        {
            logger.LogWarning(
                "TLS report collection is enabled but no mailbox exists for {Address}. Senders " +
                "deliver reports to the rua address, so that address needs a mailbox here.",
                address.Value);

            return TlsReportCollectionResult.None;
        }

        IReadOnlyList<StoredMessageId> pending = await reports
            .ListUnexaminedAsync(mailbox.Id, MaxMessagesPerPass, cancellationToken)
            .ConfigureAwait(false);

        if (pending.Count == 0)
        {
            return TlsReportCollectionResult.None;
        }

        int collected = 0;
        int duplicates = 0;
        int notReports = 0;

        foreach (StoredMessageId id in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();

            (bool isReport, bool isNew) = await ExamineAsync(id, address, cancellationToken)
                .ConfigureAwait(false);

            if (!isReport)
            {
                notReports++;
            }
            else if (isNew)
            {
                collected++;
            }
            else
            {
                duplicates++;
            }
        }

        logger.LogInformation(
            "TLS report collection examined {Examined} message(s) in {Mailbox}: {Collected} new, " +
            "{Duplicates} already held, {NotReports} not reports.",
            pending.Count,
            address.Value,
            collected,
            duplicates,
            notReports);

        return new TlsReportCollectionResult(pending.Count, collected, duplicates, notReports);
    }

    /// <summary>
    /// Opens one message and records what came of it.
    /// </summary>
    /// <remarks>
    /// <b>Every outcome ends in a recorded decision, including the failures.</b> A message that
    /// cannot be read at all is marked examined with the reason rather than left pending: the
    /// alternative is a message that fails the same way on every pass forever, and a log that
    /// fills with it.
    /// </remarks>
    private async Task<(bool IsReport, bool IsNew)> ExamineAsync(
        StoredMessageId id,
        EmailAddress address,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;

        byte[] octets;

        try
        {
            await using Stream content = await messageStore
                .OpenReadAsync(id, cancellationToken)
                .ConfigureAwait(false);

            using MemoryStream buffer = new();

            await content.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);

            octets = buffer.ToArray();
        }
        catch (Exception ex) when (ex is IOException or FileNotFoundException)
        {
            await reports
                .RecordFailureAsync(id, $"the message could not be read: {ex.Message}", now, cancellationToken)
                .ConfigureAwait(false);

            return (false, false);
        }

        if (!extractor.TryExtract(octets, out TlsReport? report, out string? error))
        {
            await reports.RecordFailureAsync(id, error!, now, cancellationToken).ConfigureAwait(false);

            return (false, false);
        }

        // The report is filed under the domain of the mailbox that received it, not under the
        // policy-domain the sender wrote. A report is about the domain whose rua address it was
        // delivered to; taking the sender's word for that would let anyone who can reach the
        // address file a report against any domain this server hosts.
        bool isNew = await reports
            .RecordAsync(id, address.Domain.Value, report!, now, cancellationToken)
            .ConfigureAwait(false);

        return (true, isNew);
    }
}
