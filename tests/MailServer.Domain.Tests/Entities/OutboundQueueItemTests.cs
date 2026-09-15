using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.Entities;

/// <summary>
/// Status transition legality and the bounce-loop-prevention rule.
/// </summary>
public sealed class OutboundQueueItemTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static OutboundQueueItem CreatePending(bool requireTls = false, bool isDsn = false) =>
        OutboundQueueItem.Create(
            StoredMessageId.New(),
            Guid.NewGuid(),
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls,
            isDsn,
            Now);

    [Fact]
    public void A_new_item_is_pending_and_due_immediately()
    {
        OutboundQueueItem item = CreatePending();

        item.Status.ShouldBe(QueueStatus.Pending);
        item.AttemptCount.ShouldBe(0);
        item.NextAttemptUtc.ShouldBe(Now);
        item.FirstQueuedUtc.ShouldBe(Now);
        item.LeaseOwner.ShouldBeNull();
    }

    [Fact]
    public void A_dsn_is_prioritised_ahead_of_ordinary_mail()
    {
        OutboundQueueItem ordinary = CreatePending();
        OutboundQueueItem dsn = CreatePending(isDsn: true);

        dsn.Priority.ShouldBeLessThan(ordinary.Priority);
    }

    [Fact]
    public void The_destination_domain_is_read_from_the_destination_address()
    {
        OutboundQueueItem item = CreatePending();

        item.DestinationDomain.Value.ShouldBe("destination.example");
    }

    // ---- Bounce-loop prevention ------------------------------------------------------------

    [Fact]
    public void An_item_with_a_reverse_path_should_generate_a_dsn_on_failure()
    {
        CreatePending().ShouldGenerateDsnOnFailure.ShouldBeTrue();
    }

    [Fact]
    public void An_item_with_the_null_reverse_path_never_generates_a_dsn()
    {
        OutboundQueueItem item = OutboundQueueItem.Create(
            StoredMessageId.New(),
            Guid.NewGuid(),
            EmailAddress.Parse("recipient@destination.example"),
            reversePath: null,
            requireTls: false,
            isDsn: true,
            Now);

        item.ShouldGenerateDsnOnFailure.ShouldBeFalse();
    }

    // ---- Transitions ------------------------------------------------------------------------

    [Fact]
    public void Marking_delivered_requires_the_item_to_be_processing()
    {
        OutboundQueueItem item = CreatePending();

        Should.Throw<DomainRuleViolationException>(() => item.MarkDelivered(Now))
            .Code.ShouldBe("queue.transition.not_processing");
    }

    [Fact]
    public void A_processing_item_can_be_marked_delivered()
    {
        OutboundQueueItem item = ClaimForTest(CreatePending());

        item.MarkDelivered(Now.AddSeconds(1));

        item.Status.ShouldBe(QueueStatus.Delivered);
        item.LeaseOwner.ShouldBeNull();
        item.LeaseExpiresUtc.ShouldBeNull();
    }

    [Fact]
    public void A_processing_item_can_be_deferred_with_a_reason_and_next_attempt()
    {
        OutboundQueueItem item = ClaimForTest(CreatePending());
        DateTimeOffset next = Now.AddMinutes(5);

        item.MarkDeferred(next, "421 4.3.0 try again later", Now);

        item.Status.ShouldBe(QueueStatus.Deferred);
        item.NextAttemptUtc.ShouldBe(next);
        item.LastFailureReason.ShouldBe("421 4.3.0 try again later");
        item.LeaseOwner.ShouldBeNull();
    }

    [Fact]
    public void A_processing_item_can_be_bounced_and_is_then_terminal()
    {
        OutboundQueueItem item = ClaimForTest(CreatePending());

        item.MarkBounced("550 5.1.1 no such user", Now);

        item.Status.ShouldBe(QueueStatus.Bounced);
        item.LastFailureReason.ShouldBe("550 5.1.1 no such user");

        Should.Throw<DomainRuleViolationException>(() => item.MarkCancelled(Now));
    }

    [Fact]
    public void A_pending_item_can_be_cancelled()
    {
        OutboundQueueItem item = CreatePending();

        item.MarkCancelled(Now);

        item.Status.ShouldBe(QueueStatus.Cancelled);
    }

    [Fact]
    public void A_delivered_item_cannot_be_cancelled()
    {
        OutboundQueueItem item = ClaimForTest(CreatePending());
        item.MarkDelivered(Now);

        Should.Throw<DomainRuleViolationException>(() => item.MarkCancelled(Now));
    }

    /// <summary>
    /// Simulates the atomic claim a repository performs directly in SQL: rehydrates the same
    /// item as Processing with its attempt count advanced, since the aggregate itself does not
    /// expose a claim method (see <see cref="OutboundQueueItem"/>'s remarks on why).
    /// </summary>
    private static OutboundQueueItem ClaimForTest(OutboundQueueItem pending) =>
        OutboundQueueItem.Rehydrate(
            pending.Id,
            pending.MessageId,
            pending.RecipientId,
            pending.DestinationAddress,
            pending.ReversePath,
            pending.RequireTls,
            pending.IsDsn,
            pending.Priority,
            QueueStatus.Processing,
            attemptCount: pending.AttemptCount + 1,
            pending.FirstQueuedUtc,
            pending.NextAttemptUtc,
            leaseOwner: "worker-1",
            leaseExpiresUtc: Now.AddMinutes(5),
            pending.DelayWarningSentUtc,
            pending.LastFailureReason,
            pending.ModifiedUtc);
}
