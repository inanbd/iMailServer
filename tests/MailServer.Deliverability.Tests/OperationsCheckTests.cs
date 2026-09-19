using MailServer.Domain.Deliverability;

namespace MailServer.Deliverability.Tests;

public sealed class OperationsCheckTests
{
    private const long OneHundredGb = 100L * 1024 * 1024 * 1024;

    /// <summary>
    /// A healthy server, with one aspect replaced.
    /// </summary>
    /// <remarks>
    /// As everywhere else in this project, a null argument means "leave this correct" — so
    /// <paramref name="skew"/> defaults to zero rather than to null, and a test that needs "no
    /// reference was consulted" builds <see cref="OperationsFacts"/> directly. The two meanings
    /// cannot share one parameter without one of them being silently unreachable, which is how a
    /// test passes for the wrong reason.
    /// </remarks>
    private static OperationsFacts Facts(
        bool? relays = false,
        int? pending = 0,
        TimeSpan? oldest = null,
        int? deliveries = 1000,
        int? bounces = 5,
        long? free = OneHundredGb / 2,
        long? total = OneHundredGb,
        TimeSpan? skew = null,
        string? relaySource = "127.0.0.1") =>
        new(relays, relaySource, pending, oldest, deliveries, bounces, free, total, skew ?? TimeSpan.Zero);

    private static DeliverabilityCheck Check(OperationsFacts facts, string id) =>
        OperationsChecks.Evaluate(facts).Single(c => c.Id == id);

    // ---------------------------------------------------------------------------------------
    // Shape.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Every_operations_check_is_in_the_operations_category()
    {
        foreach (DeliverabilityCheck check in OperationsChecks.Evaluate(Facts()))
        {
            check.Category.ShouldBe(DeliverabilityCategory.Operations);
        }
    }

    /// <summary>
    /// The weights are relative, and normalise to the category's five points.
    /// </summary>
    /// <remarks>
    /// <see cref="DeliverabilityReport.From"/> scales a category's checks against its weight, so
    /// what matters is not the sum but that it normalises — which this asserts directly rather
    /// than by arithmetic on the constants.
    /// </remarks>
    [Fact]
    public void The_operations_weights_normalise_to_the_categorys_five_points()
    {
        DeliverabilityReport report = DeliverabilityReport.From(
            OperationsChecks.Evaluate(Facts()),
            DateTimeOffset.UnixEpoch);

        report.Categories
            .Single(c => c.Category == DeliverabilityCategory.Operations)
            .Earned.ShouldBe(
                DeliverabilityCategories.WeightOf(DeliverabilityCategory.Operations),
                0.0001);
    }

    [Fact]
    public void Operations_check_ids_are_unique()
    {
        IReadOnlyList<DeliverabilityCheck> checks = OperationsChecks.Evaluate(Facts());

        checks.Select(c => c.Id).Distinct().Count().ShouldBe(checks.Count);
    }

    [Fact]
    public void A_healthy_server_passes_every_operations_check()
    {
        foreach (DeliverabilityCheck check in OperationsChecks.Evaluate(Facts()))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Pass, check.Id);
        }
    }

    /// <summary>Anything that is not a pass says what to do about it.</summary>
    [Fact]
    public void Every_operations_finding_carries_a_remedy()
    {
        OperationsFacts[] broken =
        [
            Facts(relays: true),
            Facts(pending: 5, oldest: TimeSpan.FromHours(6)),
            Facts(pending: 5, oldest: TimeSpan.FromHours(30)),
            Facts(bounces: 30),
            Facts(bounces: 100),
            Facts(free: OneHundredGb / 10),
            Facts(free: OneHundredGb / 50),
            Facts(skew: TimeSpan.FromSeconds(45)),
            Facts(skew: TimeSpan.FromMinutes(10)),
            Facts(skew: TimeSpan.FromMinutes(-10)),
        ];

        foreach (OperationsFacts facts in broken)
        {
            foreach (DeliverabilityCheck check in OperationsChecks.Evaluate(facts))
            {
                if (check.Outcome is DeliverabilityOutcome.Warn or DeliverabilityOutcome.Fail)
                {
                    check.Remedy.ShouldNotBeNullOrWhiteSpace(check.Id);
                }
            }
        }
    }

    /// <summary>Nothing measured leaves everything unjudged, and nothing passing.</summary>
    [Fact]
    public void An_unmeasured_server_is_entirely_unjudged()
    {
        OperationsFacts facts = new(null, null, null, null, null, null, null, null, null);

        foreach (DeliverabilityCheck check in OperationsChecks.Evaluate(facts))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, check.Id);
        }
    }

    // ---------------------------------------------------------------------------------------
    // The open relay.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An open relay fails, and the remedy says to unplug it rather than to configure it.
    /// </summary>
    /// <remarks>
    /// The one finding in this report that is an emergency. While the listener is reachable it
    /// is being used, so advice that begins with a settings change is advice that leaves it
    /// running for however long the change takes.
    /// </remarks>
    [Fact]
    public void An_open_relay_fails_and_the_remedy_says_to_unplug_it()
    {
        DeliverabilityCheck check = Check(Facts(relays: true), OperationsChecks.NotAnOpenRelayId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Remedy.ShouldNotBeNull().ShouldContain("off the public network now");

        // The address is named, because this server's only address-based relay path is a list an
        // operator typed - so an operator who put 127.0.0.1 on it recognises their own doing,
        // and one who did not knows where to look.
        check.Detail.ShouldContain("tested from 127.0.0.1");
    }

    /// <summary>
    /// An open relay makes the whole report Not ready, whatever it scores.
    /// </summary>
    /// <remarks>
    /// The category is weighted lightest of the six and this is why that is safe: readiness is
    /// the worst outcome present, never the arithmetic. A server scoring 96 with an open relay
    /// is Not ready, and the UI leads with the verdict.
    /// </remarks>
    [Fact]
    public void An_open_relay_makes_the_whole_report_not_ready()
    {
        DeliverabilityReport report = DeliverabilityReport.From(
            OperationsChecks.Evaluate(Facts(relays: true)),
            DateTimeOffset.UnixEpoch);

        report.Readiness.ShouldBe(DeliverabilityReadiness.NotReady);
        report.Score.ShouldNotBeNull().ShouldBeGreaterThan(50d);
    }

    /// <summary>No self-test leaves it unjudged rather than assuming the best.</summary>
    [Fact]
    public void No_relay_self_test_leaves_it_unjudged()
    {
        Check(Facts(relays: null), OperationsChecks.NotAnOpenRelayId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    // ---------------------------------------------------------------------------------------
    // The queue.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The queue is judged on age, not depth.
    /// </summary>
    /// <remarks>
    /// A queue of ten thousand that clears in a minute is a busy server; a queue of one that has
    /// been there since yesterday is a broken one. Only the age distinguishes them, and a check
    /// on depth would report the busy server and miss the broken one.
    /// </remarks>
    [Fact]
    public void A_large_but_fresh_queue_passes_and_a_small_stale_one_does_not()
    {
        Check(Facts(pending: 10_000, oldest: TimeSpan.FromMinutes(2)), OperationsChecks.QueueHealthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);

        Check(Facts(pending: 1, oldest: TimeSpan.FromHours(30)), OperationsChecks.QueueHealthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    [Theory]
    [InlineData(1, DeliverabilityOutcome.Pass)]
    [InlineData(4, DeliverabilityOutcome.Warn)]
    [InlineData(23, DeliverabilityOutcome.Warn)]
    [InlineData(24, DeliverabilityOutcome.Fail)]
    public void The_queue_is_judged_by_the_oldest_messages_age(int hours, DeliverabilityOutcome expected)
    {
        Check(Facts(pending: 3, oldest: TimeSpan.FromHours(hours)), OperationsChecks.QueueHealthId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>An empty queue passes without needing an age.</summary>
    [Fact]
    public void An_empty_queue_passes()
    {
        Check(Facts(pending: 0, oldest: null), OperationsChecks.QueueHealthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// A non-empty queue with no age is unjudged, because depth alone says nothing.
    /// </summary>
    /// <remarks>
    /// Reporting a pass here would be the busy-server mistake in reverse: a queue that has been
    /// stuck for a week would read as healthy on the strength of a number that never describes
    /// health.
    /// </remarks>
    [Fact]
    public void A_queue_with_no_known_age_is_unjudged()
    {
        DeliverabilityCheck check = Check(
            Facts(pending: 5, oldest: null),
            OperationsChecks.QueueHealthId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
        check.Detail.ShouldContain("depth alone says nothing");
    }

    // ---------------------------------------------------------------------------------------
    // The bounce rate.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(1000, 5, DeliverabilityOutcome.Pass)]
    [InlineData(1000, 20, DeliverabilityOutcome.Warn)]
    [InlineData(1000, 49, DeliverabilityOutcome.Warn)]
    [InlineData(1000, 50, DeliverabilityOutcome.Fail)]
    [InlineData(1000, 200, DeliverabilityOutcome.Fail)]
    public void The_bounce_rate_is_judged_against_its_thresholds(
        int deliveries,
        int bounces,
        DeliverabilityOutcome expected)
    {
        Check(Facts(deliveries: deliveries, bounces: bounces), OperationsChecks.BounceRateId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>
    /// Too few deliveries means no rate at all.
    /// </summary>
    /// <remarks>
    /// Two bounces out of three is 67% and means nothing. An operator on their first day would
    /// otherwise be shown a catastrophic number generated entirely by their own test messages —
    /// and would go looking for a problem that does not exist.
    /// </remarks>
    [Fact]
    public void Too_few_deliveries_means_no_rate()
    {
        DeliverabilityCheck check = Check(
            Facts(deliveries: 3, bounces: 2),
            OperationsChecks.BounceRateId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
        check.Detail.ShouldContain("too few");
    }

    /// <summary>The threshold itself is enough to compute a rate from.</summary>
    [Fact]
    public void Exactly_the_minimum_number_of_deliveries_is_enough()
    {
        Check(
                Facts(deliveries: OperationsChecks.MinimumDeliveriesForRate, bounces: 0),
                OperationsChecks.BounceRateId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>The remedy says removing bounced addresses is the fix, not retrying them.</summary>
    [Fact]
    public void The_bounce_remedy_says_to_stop_retrying_dead_addresses()
    {
        Check(Facts(bounces: 30), OperationsChecks.BounceRateId)
            .Remedy.ShouldNotBeNull().ShouldContain("retrying them");
    }

    // ---------------------------------------------------------------------------------------
    // Disk.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(50, DeliverabilityOutcome.Pass)]
    [InlineData(15, DeliverabilityOutcome.Pass)]
    [InlineData(14, DeliverabilityOutcome.Warn)]
    [InlineData(5, DeliverabilityOutcome.Warn)]
    [InlineData(4, DeliverabilityOutcome.Fail)]
    public void The_disk_check_is_judged_on_the_share_free(int percentFree, DeliverabilityOutcome expected)
    {
        Check(
                Facts(free: OneHundredGb * percentFree / 100, total: OneHundredGb),
                OperationsChecks.DiskSpaceId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>A volume of no size is not a full volume.</summary>
    [Fact]
    public void A_volume_of_unknown_size_is_unjudged()
    {
        Check(Facts(free: 0, total: 0), OperationsChecks.DiskSpaceId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>The finding says what a full volume does to mail, not just that it is full.</summary>
    [Fact]
    public void The_disk_finding_says_what_a_full_volume_does_to_mail()
    {
        Check(Facts(free: OneHundredGb / 100), OperationsChecks.DiskSpaceId)
            .Detail.ShouldContain("senders retry for days");
    }

    // ---------------------------------------------------------------------------------------
    // The clock.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(0, DeliverabilityOutcome.Pass)]
    [InlineData(29, DeliverabilityOutcome.Pass)]
    [InlineData(30, DeliverabilityOutcome.Warn)]
    [InlineData(299, DeliverabilityOutcome.Warn)]
    [InlineData(300, DeliverabilityOutcome.Fail)]
    public void The_clock_check_is_judged_on_the_size_of_the_skew(int seconds, DeliverabilityOutcome expected)
    {
        Check(Facts(skew: TimeSpan.FromSeconds(seconds)), OperationsChecks.ClockSkewId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>
    /// A clock behind is judged the same as a clock ahead, and the finding says which.
    /// </summary>
    /// <remarks>
    /// Both break the same things; the direction is what tells an operator whether they are
    /// looking at a stopped clock or one that ran away. A check on the signed value rather than
    /// the magnitude would pass every slow clock in the world.
    /// </remarks>
    [Fact]
    public void A_clock_behind_is_judged_the_same_as_one_ahead()
    {
        DeliverabilityCheck behind = Check(
            Facts(skew: TimeSpan.FromMinutes(-10)),
            OperationsChecks.ClockSkewId);

        behind.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        behind.Detail.ShouldContain("behind");

        Check(Facts(skew: TimeSpan.FromMinutes(10)), OperationsChecks.ClockSkewId)
            .Detail.ShouldContain("ahead of");
    }

    /// <summary>
    /// The finding names the consequences, because none of them looks like a clock problem.
    /// </summary>
    /// <remarks>
    /// DKIM signatures with an expiry, a certificate that looks not-yet-valid, Received headers
    /// dated wrongly. An operator shown only "your clock is wrong" has no reason to connect it
    /// to the delivery failures they are actually chasing.
    /// </remarks>
    [Fact]
    public void The_clock_finding_names_what_the_skew_breaks()
    {
        string detail = Check(Facts(skew: TimeSpan.FromMinutes(10)), OperationsChecks.ClockSkewId).Detail;

        detail.ShouldContain("DKIM");
        detail.ShouldContain("certificate");
        detail.ShouldContain("Received");
    }

    /// <summary>No reference consulted leaves it unjudged rather than assuming zero skew.</summary>
    [Fact]
    public void No_time_reference_leaves_the_clock_unjudged()
    {
        OperationsFacts facts = new(false, "127.0.0.1", 0, null, 1000, 5, OneHundredGb / 2, OneHundredGb, null);

        Check(facts, OperationsChecks.ClockSkewId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }
}
