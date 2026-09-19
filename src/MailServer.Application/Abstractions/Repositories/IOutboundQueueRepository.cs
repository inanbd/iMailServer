using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>Depth of the outbound queue, for health reporting.</summary>
/// <param name="Pending">Items waiting for their first or next attempt (Pending or Deferred).</param>
/// <param name="Processing">Items currently leased by a worker.</param>
/// <param name="OldestPendingUtc">
/// When the oldest still-waiting item was first queued, or null if the queue is empty. The gap
/// between this and now is the single number that answers "is the queue keeping up".
/// </param>
public sealed record QueueDepth(int Pending, int Processing, DateTimeOffset? OldestPendingUtc);

/// <summary>How recent delivery attempts turned out.</summary>
/// <param name="Delivered">Attempts that ended in delivery.</param>
/// <param name="Bounced">Attempts that ended in a permanent failure.</param>
/// <remarks>
/// <b>Deferred attempts are counted in neither.</b> A deferral is the queue working: the message
/// has not failed and has not arrived, and including it in either number would make a busy day
/// against a slow destination look like a delivery problem. The deliverability report's bounce
/// rate is <c>Bounced / (Delivered + Bounced)</c>, which is the ratio a receiver's own reputation
/// system computes from the same two events.
/// </remarks>
public sealed record DeliveryOutcomeCounts(int Delivered, int Bounced);

/// <summary>Persists the outbound queue and its delivery attempt history.</summary>
/// <remarks>
/// <para>
/// <b>Claiming is not aggregate-mediated.</b> <see cref="ClaimDueAsync"/> is a single atomic
/// statement across potentially many rows - <c>UPDATE ... WHERE ... RETURNING</c> on SQLite,
/// <c>UPDATE TOP (@n) ... WITH (READPAST, UPDLOCK, ROWLOCK) ... OUTPUT</c> on SQL Server - and
/// there is no way to express "claim whichever due rows nobody else has" by loading aggregates
/// one at a time without a race between two workers claiming the same row. Every other method
/// here does operate on one already-claimed aggregate, exactly like every other repository in
/// this product.
/// </para>
/// <para>
/// <b>No transaction here ever spans a network call.</b> A caller claims, then leaves the
/// transaction, then talks to a remote MX, then opens a second short transaction to record the
/// outcome. See <c>docs/Architecture.md</c> §9: "the pattern open transaction → SMTP delivery →
/// commit is forbidden."
/// </para>
/// </remarks>
public interface IOutboundQueueRepository
{
    /// <summary>Enqueues a new item.</summary>
    Task AddAsync(OutboundQueueItem item, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically claims up to <paramref name="maxItems"/> due items for <paramref name="leaseOwner"/>.
    /// </summary>
    /// <remarks>
    /// A due item is one that is <see cref="QueueStatus.Pending"/> or
    /// <see cref="QueueStatus.Deferred"/> with <c>NextAttemptUtc &lt;= nowUtc</c>, OR one that is
    /// <see cref="QueueStatus.Processing"/> with an expired lease - a worker that crashed mid
    /// delivery leaves exactly this behind, and reclaiming it is what makes leasing self-healing
    /// without an operator's intervention. Ordered by priority, then by age, so a DSN jumps an
    /// ordinary backlog and an old item is not starved behind a stream of newer ones.
    /// </remarks>
    Task<IReadOnlyList<OutboundQueueItem>> ClaimDueAsync(
        string leaseOwner,
        int maxItems,
        TimeSpan leaseDuration,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken);

    /// <summary>
    /// Persists the outcome recorded on an already-claimed item (delivered, deferred, bounced or
    /// cancelled - see <see cref="OutboundQueueItem"/>'s transition methods).
    /// </summary>
    Task UpdateAsync(OutboundQueueItem item, CancellationToken cancellationToken);

    /// <summary>Records one delivery attempt.</summary>
    Task AddAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken);

    /// <summary>
    /// Returns every item still leased by <paramref name="leaseOwner"/> to <see cref="QueueStatus.Pending"/>
    /// immediately, without waiting for the lease to expire.
    /// </summary>
    /// <remarks>
    /// Called on graceful shutdown. Without it, an item a worker was midway through when the
    /// service stopped cleanly would sit unclaimable until its lease timed out - correct
    /// eventually, but a needless delay for the ordinary case of a planned restart.
    /// </remarks>
    Task ReleaseLeaseAsync(string leaseOwner, DateTimeOffset nowUtc, CancellationToken cancellationToken);

    /// <summary>Current queue depth, for the health registry.</summary>
    Task<QueueDepth> GetDepthAsync(CancellationToken cancellationToken);

    /// <summary>
    /// How attempts completed since an instant, for the deliverability report's bounce rate.
    /// </summary>
    /// <remarks>
    /// Counted in the database rather than by loading the attempts: a busy server records one
    /// row per destination per retry, and a report that pulled a fortnight of them into memory to
    /// divide two numbers would be the heaviest thing the admin surface does.
    /// </remarks>
    Task<DeliveryOutcomeCounts> GetOutcomeCountsAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken);
}
