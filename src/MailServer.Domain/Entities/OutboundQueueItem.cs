using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// One recipient of one message, waiting to be relayed onward.
/// </summary>
/// <remarks>
/// <para>
/// <b>One row per recipient, not per message.</b> A message to fifty recipients across a dozen
/// domains must be able to succeed for forty-nine of them and defer the fiftieth; a queue item
/// per message cannot represent partial success, so this aggregate is deliberately the smaller
/// unit even though it means the same message body is referenced by several queue items.
/// </para>
/// <para>
/// <b>Leasing, not locking.</b> A worker claims items by writing <see cref="LeaseOwner"/> and
/// <see cref="LeaseExpiresUtc"/> in the same atomic statement that moves the status to
/// <see cref="QueueStatus.Processing"/> (<c>IOutboundQueueRepository.ClaimDueAsync</c>, not a
/// method here — see its remarks for why the claim itself is not aggregate-mediated). A worker
/// that crashes mid-delivery leaves a lease that simply expires; nothing here requires manual
/// intervention, and nothing here assumes there is only ever one worker.
/// </para>
/// <para>
/// The envelope fields (<see cref="ReversePath"/>, <see cref="DestinationAddress"/>) are copied
/// from the originating <see cref="MessageRecipient"/> rather than joined at read time, because
/// every attempt reads them and a worker processing thousands of due items should not join three
/// tables to find out who a message is for.
/// </para>
/// </remarks>
public sealed class OutboundQueueItem
{
    private OutboundQueueItem(
        QueueId id,
        StoredMessageId messageId,
        Guid recipientId,
        EmailAddress destinationAddress,
        EmailAddress? reversePath,
        bool requireTls,
        bool isDsn,
        int priority,
        QueueStatus status,
        int attemptCount,
        DateTimeOffset firstQueuedUtc,
        DateTimeOffset nextAttemptUtc,
        string? leaseOwner,
        DateTimeOffset? leaseExpiresUtc,
        DateTimeOffset? delayWarningSentUtc,
        string? lastFailureReason,
        DateTimeOffset modifiedUtc)
    {
        Id = id;
        MessageId = messageId;
        RecipientId = recipientId;
        DestinationAddress = destinationAddress;
        ReversePath = reversePath;
        RequireTls = requireTls;
        IsDsn = isDsn;
        Priority = priority;
        Status = status;
        AttemptCount = attemptCount;
        FirstQueuedUtc = firstQueuedUtc;
        NextAttemptUtc = nextAttemptUtc;
        LeaseOwner = leaseOwner;
        LeaseExpiresUtc = leaseExpiresUtc;
        DelayWarningSentUtc = delayWarningSentUtc;
        LastFailureReason = lastFailureReason;
        ModifiedUtc = modifiedUtc;
    }

    /// <summary>Identity of this queue item.</summary>
    public QueueId Id { get; }

    /// <summary>The message body this item relays. Shared with every other recipient of it.</summary>
    public StoredMessageId MessageId { get; }

    /// <summary>The <see cref="MessageRecipient"/> this item originated from.</summary>
    public Guid RecipientId { get; }

    /// <summary>The address to deliver to.</summary>
    public EmailAddress DestinationAddress { get; }

    /// <summary>The destination's domain, for MX resolution and per-domain throttling.</summary>
    public DomainName DestinationDomain => DestinationAddress.Domain;

    /// <summary>
    /// The envelope sender, or null for the null reverse path.
    /// </summary>
    /// <remarks>
    /// The single field the bounce-loop rule reads: a queue item with a null reverse path must
    /// never itself generate a DSN on failure. See <see cref="ShouldGenerateDsnOnFailure"/>.
    /// </remarks>
    public EmailAddress? ReversePath { get; }

    /// <summary>
    /// Whether this item's origin domain requires TLS for outbound delivery.
    /// </summary>
    /// <remarks>
    /// A snapshot of <c>MailDomain.RequireTlsForOutbound</c> taken when the item was enqueued.
    /// Re-reading the domain on every attempt would let an administrator's change mid-retry
    /// silently alter a policy that is meant to apply to a specific message; a snapshot means
    /// what happens to this item is what the policy said when the sender sent it.
    /// </remarks>
    public bool RequireTls { get; }

    /// <summary>True when this item carries a DSN this server generated, not a relayed message.</summary>
    public bool IsDsn { get; }

    /// <summary>
    /// Scheduling priority. Lower values are claimed first.
    /// </summary>
    /// <remarks>
    /// DSNs are prioritised ahead of ordinary mail: a bounce is time-sensitive information the
    /// original sender needs promptly, and it should not sit behind a large backlog of ordinary
    /// relay traffic.
    /// </remarks>
    public int Priority { get; }

    /// <summary>Where this item is in its lifecycle.</summary>
    public QueueStatus Status { get; private set; }

    /// <summary>How many delivery attempts have been made, including the one in progress.</summary>
    public int AttemptCount { get; private set; }

    /// <summary>When this item was first queued. Fixed for its whole lifetime.</summary>
    public DateTimeOffset FirstQueuedUtc { get; }

    /// <summary>When this item next becomes eligible to be claimed.</summary>
    public DateTimeOffset NextAttemptUtc { get; private set; }

    /// <summary>The worker instance currently holding this item, or null.</summary>
    public string? LeaseOwner { get; private set; }

    /// <summary>When the current lease expires and the item becomes reclaimable.</summary>
    public DateTimeOffset? LeaseExpiresUtc { get; private set; }

    /// <summary>When a "delivery is delayed" warning DSN was sent, or null if none has been.</summary>
    public DateTimeOffset? DelayWarningSentUtc { get; private set; }

    /// <summary>Human-readable reason for the most recent failure, or null before any failure.</summary>
    public string? LastFailureReason { get; private set; }

    /// <summary>When this row last changed.</summary>
    public DateTimeOffset ModifiedUtc { get; private set; }

    /// <summary>
    /// Whether a failure of this item should generate a DSN.
    /// </summary>
    /// <remarks>
    /// False for a null reverse path, which is the entire bounce-loop-prevention rule: a message
    /// that cannot itself be bounced (because it has no sender to bounce to, which is exactly
    /// what a null reverse path means) must not have its failure turn into another message that
    /// could, in turn, fail and be bounced again.
    /// </remarks>
    public bool ShouldGenerateDsnOnFailure => ReversePath is not null;

    /// <summary>Enqueues a new item.</summary>
    public static OutboundQueueItem Create(
        StoredMessageId messageId,
        Guid recipientId,
        EmailAddress destinationAddress,
        EmailAddress? reversePath,
        bool requireTls,
        bool isDsn,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(destinationAddress);

        return new OutboundQueueItem(
            QueueId.New(),
            messageId,
            recipientId,
            destinationAddress,
            reversePath,
            requireTls,
            isDsn,
            priority: isDsn ? -1 : 0,
            QueueStatus.Pending,
            attemptCount: 0,
            firstQueuedUtc: nowUtc,
            nextAttemptUtc: nowUtc,
            leaseOwner: null,
            leaseExpiresUtc: null,
            delayWarningSentUtc: null,
            lastFailureReason: null,
            modifiedUtc: nowUtc);
    }

    /// <summary>Rehydrates from storage, including from an atomic claim statement's own result.</summary>
    public static OutboundQueueItem Rehydrate(
        QueueId id,
        StoredMessageId messageId,
        Guid recipientId,
        EmailAddress destinationAddress,
        EmailAddress? reversePath,
        bool requireTls,
        bool isDsn,
        int priority,
        QueueStatus status,
        int attemptCount,
        DateTimeOffset firstQueuedUtc,
        DateTimeOffset nextAttemptUtc,
        string? leaseOwner,
        DateTimeOffset? leaseExpiresUtc,
        DateTimeOffset? delayWarningSentUtc,
        string? lastFailureReason,
        DateTimeOffset modifiedUtc) =>
        new(
            id, messageId, recipientId, destinationAddress, reversePath, requireTls, isDsn,
            priority, status, attemptCount, firstQueuedUtc, nextAttemptUtc, leaseOwner,
            leaseExpiresUtc, delayWarningSentUtc, lastFailureReason, modifiedUtc);

    /// <summary>Records that the remote MX accepted the message. Terminal.</summary>
    public void MarkDelivered(DateTimeOffset nowUtc)
    {
        RequireProcessing();

        Status = QueueStatus.Delivered;
        LeaseOwner = null;
        LeaseExpiresUtc = null;
        ModifiedUtc = nowUtc;
    }

    /// <summary>Records a transient failure and schedules the next attempt.</summary>
    public void MarkDeferred(DateTimeOffset nextAttemptUtc, string reason, DateTimeOffset nowUtc)
    {
        RequireProcessing();
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        Status = QueueStatus.Deferred;
        NextAttemptUtc = nextAttemptUtc;
        LeaseOwner = null;
        LeaseExpiresUtc = null;
        LastFailureReason = reason;
        ModifiedUtc = nowUtc;
    }

    /// <summary>Records a permanent failure. Terminal; retried never.</summary>
    public void MarkBounced(string reason, DateTimeOffset nowUtc)
    {
        RequireProcessing();
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        Status = QueueStatus.Bounced;
        LeaseOwner = null;
        LeaseExpiresUtc = null;
        LastFailureReason = reason;
        ModifiedUtc = nowUtc;
    }

    /// <summary>Withdraws the item before delivery. Terminal.</summary>
    public void MarkCancelled(DateTimeOffset nowUtc)
    {
        if (Status is QueueStatus.Delivered or QueueStatus.Bounced or QueueStatus.Cancelled)
        {
            throw new DomainRuleViolationException(
                "queue.cancel.terminal",
                $"Queue item {Id.Value} is already {Status} and cannot be cancelled.");
        }

        Status = QueueStatus.Cancelled;
        LeaseOwner = null;
        LeaseExpiresUtc = null;
        ModifiedUtc = nowUtc;
    }

    /// <summary>Records that a delay-warning DSN has been sent for this item.</summary>
    public void MarkDelayWarningSent(DateTimeOffset nowUtc)
    {
        DelayWarningSentUtc = nowUtc;
        ModifiedUtc = nowUtc;
    }

    private void RequireProcessing()
    {
        if (Status != QueueStatus.Processing)
        {
            throw new DomainRuleViolationException(
                "queue.transition.not_processing",
                $"Queue item {Id.Value} is {Status}, not Processing; only a claimed item can " +
                "record an attempt outcome.");
        }
    }
}
