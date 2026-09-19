using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>A queue that answers the two questions the probe asks and nothing else.</summary>
internal sealed class ScriptedQueue(QueueDepth depth, DeliveryOutcomeCounts counts)
    : IOutboundQueueRepository
{
    /// <summary>The instant the outcome window was asked about.</summary>
    public DateTimeOffset? AskedSince { get; private set; }

    public Task<QueueDepth> GetDepthAsync(CancellationToken cancellationToken) =>
        Task.FromResult(depth);

    public Task<DeliveryOutcomeCounts> GetOutcomeCountsAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken)
    {
        AskedSince = sinceUtc;

        return Task.FromResult(counts);
    }

    public Task AddAsync(OutboundQueueItem item, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<OutboundQueueItem?> GetAsync(QueueId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<IReadOnlyList<OutboundQueueItem>> ClaimDueAsync(
        string workerId,
        int maxItems,
        TimeSpan leaseDuration,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task UpdateAsync(OutboundQueueItem item, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task AddAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<int> ReleaseExpiredLeasesAsync(DateTimeOffset nowUtc, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task ReleaseLeaseAsync(string workerId, DateTimeOffset nowUtc, CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

internal sealed class FixedVolume((long Free, long Total)? measurement) : IVolumeMeasure
{
    public (long Free, long Total)? Measure(string path) => measurement;
}

internal sealed class FixedStore(string path) : IMessageStoreLocation
{
    public string Path => path;
}

internal sealed class FixedTimeReference(TimeSpan? skew) : ITimeReference
{
    public Task<TimeSpan?> GetSkewAsync(CancellationToken cancellationToken) => Task.FromResult(skew);
}

internal sealed class ProbeClock(DateTimeOffset now) : IClock
{
    public DateTimeOffset UtcNow => now;

    public long GetTimestamp() => now.UtcTicks;

    public TimeSpan GetElapsedTime(long startingTimestamp) =>
        TimeSpan.FromTicks(now.UtcTicks - startingTimestamp);
}

public sealed class OperationsProbeTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);

    private const long OneHundredGb = 100L * 1024 * 1024 * 1024;

    private static OperationsProbe Probe(
        QueueDepth? depth = null,
        DeliveryOutcomeCounts? counts = null,
        (long Free, long Total)? disk = null,
        TimeSpan? skew = null,
        bool withTimeReference = true,
        ScriptedQueue? queue = null) =>
        new(
            queue ?? new ScriptedQueue(
                depth ?? new QueueDepth(0, 0, null),
                counts ?? new DeliveryOutcomeCounts(100, 2)),
            new ProbeClock(Now),
            new FixedVolume(disk ?? (OneHundredGb / 2, OneHundredGb)),
            new FixedStore("/var/mail"),
            withTimeReference ? new FixedTimeReference(skew) : null);

    // ---------------------------------------------------------------------------------------
    // The relay self-test.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A test that did not run is null, never false.
    /// </summary>
    /// <remarks>
    /// The most dangerous false pass available in this report. "The listener refused the
    /// connection" says nothing about what it does with one it accepts, and reporting that as
    /// "not an open relay" would hand an operator a clean bill of health on the one finding that
    /// is an emergency.
    /// </remarks>
    [Fact]
    public async Task A_relay_test_that_did_not_run_leaves_the_check_unjudged()
    {
        OperationsFacts facts = await Probe().GatherAsync(
            new OpenRelayResult(Ran: false, Relayed: false, "127.0.0.1", []),
            CancellationToken.None);

        facts.RelaysForStrangers.ShouldBeNull();

        OperationsChecks.Evaluate(facts)
            .Single(c => c.Id == OperationsChecks.NotAnOpenRelayId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>No test at all is likewise unjudged.</summary>
    [Fact]
    public async Task No_relay_test_leaves_the_check_unjudged()
    {
        OperationsFacts facts = await Probe().GatherAsync(null, CancellationToken.None);

        facts.RelaysForStrangers.ShouldBeNull();
    }

    /// <summary>A completed test is carried through, with the address it ran from.</summary>
    [Theory]
    [InlineData(true, DeliverabilityOutcome.Fail)]
    [InlineData(false, DeliverabilityOutcome.Pass)]
    public async Task A_completed_relay_test_is_carried_through(bool relayed, DeliverabilityOutcome expected)
    {
        OperationsFacts facts = await Probe().GatherAsync(
            new OpenRelayResult(Ran: true, relayed, "203.0.113.10", []),
            CancellationToken.None);

        facts.RelaysForStrangers.ShouldBe(relayed);
        facts.RelayTestSource.ShouldBe("203.0.113.10");

        OperationsChecks.Evaluate(facts)
            .Single(c => c.Id == OperationsChecks.NotAnOpenRelayId)
            .Outcome.ShouldBe(expected);
    }

    // ---------------------------------------------------------------------------------------
    // The queue.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The oldest message's age is computed against the clock, not stored.
    /// </summary>
    /// <remarks>
    /// The repository reports an instant; the check judges a duration. Doing the subtraction
    /// here is what keeps the pure check free of a clock, and getting the direction wrong would
    /// report every queue as fresh.
    /// </remarks>
    [Fact]
    public async Task The_oldest_messages_age_is_computed_from_the_clock()
    {
        OperationsFacts facts = await Probe(
                depth: new QueueDepth(3, 1, Now.AddHours(-6)))
            .GatherAsync(null, CancellationToken.None);

        facts.QueuePending.ShouldBe(3);
        facts.OldestPendingAge.ShouldBe(TimeSpan.FromHours(6));

        OperationsChecks.Evaluate(facts)
            .Single(c => c.Id == OperationsChecks.QueueHealthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>An empty queue has no oldest message, and the age is null rather than zero.</summary>
    [Fact]
    public async Task An_empty_queue_has_no_age()
    {
        OperationsFacts facts = await Probe(depth: new QueueDepth(0, 0, null))
            .GatherAsync(null, CancellationToken.None);

        facts.QueuePending.ShouldBe(0);
        facts.OldestPendingAge.ShouldBeNull();
    }

    // ---------------------------------------------------------------------------------------
    // The bounce rate.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The denominator is deliveries plus bounces, and deferrals are in neither.
    /// </summary>
    /// <remarks>
    /// A deferral is the queue working. Counting one as a delivery would flatter the rate and
    /// counting it as a bounce would make a slow destination look like a delivery problem; the
    /// repository returns only the two terminal outcomes for exactly that reason.
    /// </remarks>
    [Fact]
    public async Task The_bounce_rate_denominator_is_deliveries_plus_bounces()
    {
        OperationsFacts facts = await Probe(counts: new DeliveryOutcomeCounts(90, 10))
            .GatherAsync(null, CancellationToken.None);

        facts.RecentDeliveries.ShouldBe(100);
        facts.RecentBounces.ShouldBe(10);

        OperationsChecks.Evaluate(facts)
            .Single(c => c.Id == OperationsChecks.BounceRateId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>The window asked about is the one the probe documents.</summary>
    [Fact]
    public async Task The_bounce_window_is_a_week_back_from_now()
    {
        ScriptedQueue queue = new(new QueueDepth(0, 0, null), new DeliveryOutcomeCounts(0, 0));

        await Probe(queue: queue).GatherAsync(null, CancellationToken.None);

        queue.AskedSince.ShouldBe(Now - OperationsProbe.BounceWindow);
    }

    // ---------------------------------------------------------------------------------------
    // Disk and clock.
    // ---------------------------------------------------------------------------------------

    /// <summary>The volume holding the message store is the one measured.</summary>
    [Fact]
    public async Task The_message_stores_volume_is_measured()
    {
        OperationsFacts facts = await Probe(disk: (OneHundredGb / 100, OneHundredGb))
            .GatherAsync(null, CancellationToken.None);

        facts.FreeDiskBytes.ShouldBe(OneHundredGb / 100);
        facts.TotalDiskBytes.ShouldBe(OneHundredGb);

        OperationsChecks.Evaluate(facts)
            .Single(c => c.Id == OperationsChecks.DiskSpaceId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>A volume that cannot be read leaves the check unjudged rather than failing it.</summary>
    [Fact]
    public async Task An_unreadable_volume_leaves_the_disk_check_unjudged()
    {
        OperationsProbe probe = new(
            new ScriptedQueue(new QueueDepth(0, 0, null), new DeliveryOutcomeCounts(100, 1)),
            new ProbeClock(Now),
            new FixedVolume(null),
            new FixedStore("/var/mail"));

        OperationsFacts facts = await probe.GatherAsync(null, CancellationToken.None);

        facts.FreeDiskBytes.ShouldBeNull();
        facts.TotalDiskBytes.ShouldBeNull();

        OperationsChecks.Evaluate(facts)
            .Single(c => c.Id == OperationsChecks.DiskSpaceId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>The skew is carried through as the reference reported it.</summary>
    [Fact]
    public async Task The_clock_skew_is_carried_through()
    {
        OperationsFacts facts = await Probe(skew: TimeSpan.FromMinutes(10))
            .GatherAsync(null, CancellationToken.None);

        facts.ClockSkew.ShouldBe(TimeSpan.FromMinutes(10));

        OperationsChecks.Evaluate(facts)
            .Single(c => c.Id == OperationsChecks.ClockSkewId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// With no time reference configured, the clock goes unjudged rather than assumed correct.
    /// </summary>
    /// <remarks>
    /// Zero would be a measurement nobody made. A server with no NTP and no reference is exactly
    /// the one whose clock is most likely wrong.
    /// </remarks>
    [Fact]
    public async Task With_no_time_reference_the_clock_is_unjudged()
    {
        OperationsFacts facts = await Probe(withTimeReference: false)
            .GatherAsync(null, CancellationToken.None);

        facts.ClockSkew.ShouldBeNull();

        OperationsChecks.Evaluate(facts)
            .Single(c => c.Id == OperationsChecks.ClockSkewId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>A reference that could not be reached is likewise null, not zero.</summary>
    [Fact]
    public async Task An_unreachable_time_reference_is_null_rather_than_zero()
    {
        OperationsFacts facts = await Probe(skew: null).GatherAsync(null, CancellationToken.None);

        facts.ClockSkew.ShouldBeNull();
    }
}
