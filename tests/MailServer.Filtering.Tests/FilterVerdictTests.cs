using MailServer.Domain.Filtering;

namespace MailServer.Filtering.Tests;

public sealed class FilterPolicyTests
{
    [Theory]
    [InlineData(0.0, FilterAction.Accept)]
    [InlineData(4.9, FilterAction.Accept)]
    [InlineData(5.0, FilterAction.Junk)]
    [InlineData(9.9, FilterAction.Junk)]
    [InlineData(10.0, FilterAction.Quarantine)]
    [InlineData(1000.0, FilterAction.Quarantine)]
    public void Maps_a_score_to_an_action(double score, FilterAction expected) =>
        FilterPolicy.Default.Decide(score).ShouldBe(expected);

    /// <summary>
    /// The default must never discard mail, however high a score the checks produce. A tuning
    /// change that made rejection reachable by accident is the one mistake in this subsystem
    /// that cannot be noticed after the fact, because a rejected message leaves nothing behind.
    /// </summary>
    [Fact]
    public void Never_rejects_by_default() =>
        FilterPolicy.Default.Decide(double.MaxValue).ShouldBe(FilterAction.Quarantine);

    [Fact]
    public void Rejects_only_when_an_operator_sets_a_finite_threshold()
    {
        FilterPolicy policy = new() { RejectThreshold = 15.0 };

        policy.Decide(14.9).ShouldBe(FilterAction.Quarantine);
        policy.Decide(15.0).ShouldBe(FilterAction.Reject);
    }

    /// <summary>
    /// A negative score is what a well-authenticated message earns, and it must land on Accept
    /// rather than wrapping into some other branch.
    /// </summary>
    [Fact]
    public void Treats_a_negative_score_as_clean() =>
        FilterPolicy.Default.Decide(-4.0).ShouldBe(FilterAction.Accept);

    [Fact]
    public void Knows_when_its_thresholds_are_in_order()
    {
        FilterPolicy.Default.IsOrdered.ShouldBeTrue();

        new FilterPolicy { JunkThreshold = 10, QuarantineThreshold = 5 }.IsOrdered.ShouldBeFalse();
    }

    /// <summary>
    /// An out-of-order policy is still misconfigured, but it must not do something arbitrary:
    /// a score over both thresholds takes the stricter one.
    /// </summary>
    [Fact]
    public void Degrades_to_the_strictest_threshold_a_score_passes()
    {
        FilterPolicy inverted = new() { JunkThreshold = 10, QuarantineThreshold = 5 };

        inverted.Decide(12).ShouldBe(FilterAction.Quarantine);
    }
}

public sealed class FilterSignalTests
{
    [Fact]
    public void Truncates_a_detail_a_stranger_made_too_long()
    {
        FilterSignal signal = FilterSignal.Create("X", 1, new string('a', 5_000));

        signal.Detail.Length.ShouldBe(FilterSignal.MaxDetailLength);
    }

    [Fact]
    public void Keeps_a_detail_that_fits()
    {
        FilterSignal signal = FilterSignal.Create("X", 1, "short");

        signal.Detail.ShouldBe("short");
    }

    [Fact]
    public void Refuses_a_signal_with_no_name() =>
        Should.Throw<ArgumentException>(() => FilterSignal.Create(" ", 1, "detail"));
}

public sealed class FilterVerdictTests
{
    private static FilterSignal Signal(double score, string name = "S") =>
        FilterSignal.Create(name, score, "detail");

    [Fact]
    public void Sums_the_signals()
    {
        FilterVerdict verdict = FilterVerdict.Create(
            [Signal(2.0), Signal(1.5), Signal(-0.5)], FilterPolicy.Default);

        verdict.Score.ShouldBe(3.0, 0.0001);
        verdict.Action.ShouldBe(FilterAction.Accept);
    }

    [Fact]
    public void Applies_the_policy_to_the_total()
    {
        FilterVerdict verdict = FilterVerdict.Create(
            [Signal(3.0), Signal(3.0)], FilterPolicy.Default);

        verdict.Action.ShouldBe(FilterAction.Junk);
    }

    /// <summary>
    /// The floor is how malware and a blocked attachment state a conclusion the score cannot
    /// overturn. A clean-scoring message carrying an executable must still be held.
    /// </summary>
    [Fact]
    public void Honours_a_floor_the_score_would_not_reach()
    {
        FilterVerdict verdict = FilterVerdict.Create(
            [Signal(-5.0)], FilterPolicy.Default, FilterAction.Quarantine);

        verdict.Score.ShouldBe(-5.0, 0.0001);
        verdict.Action.ShouldBe(FilterAction.Quarantine);
    }

    /// <summary>And a floor never softens a verdict the score reached on its own.</summary>
    [Fact]
    public void Never_lowers_an_action_the_score_earned()
    {
        FilterVerdict verdict = FilterVerdict.Create(
            [Signal(12.0)], FilterPolicy.Default, FilterAction.Junk);

        verdict.Action.ShouldBe(FilterAction.Quarantine);
    }

    [Fact]
    public void Orders_the_aggravating_signals_heaviest_first()
    {
        FilterVerdict verdict = FilterVerdict.Create(
            [Signal(1.0, "LIGHT"), Signal(-2.0, "GOOD"), Signal(4.0, "HEAVY")],
            FilterPolicy.Default);

        verdict.Aggravating().Select(s => s.Name).ShouldBe(["HEAVY", "LIGHT"]);
    }

    [Fact]
    public void Summarises_a_message_nothing_fired_on() =>
        FilterVerdict.Clean.Summarise().ShouldBe("Nothing was found.");

    [Fact]
    public void Summarises_a_message_only_good_signals_fired_on()
    {
        FilterVerdict verdict = FilterVerdict.Create([Signal(-2.5, "DMARC_PASS")], FilterPolicy.Default);

        verdict.Summarise().ShouldBe("Scored -2.5; nothing counted against it.");
    }

    [Fact]
    public void Names_the_heaviest_reasons_and_counts_the_rest()
    {
        FilterVerdict verdict = FilterVerdict.Create(
            [Signal(5.0, "A"), Signal(4.0, "B"), Signal(3.0, "C"), Signal(2.0, "D")],
            FilterPolicy.Default);

        verdict.Summarise().ShouldBe("Scored 14.0 — A, B, C, and 1 more.");
    }

    [Fact]
    public void The_clean_verdict_accepts() =>
        FilterVerdict.Clean.Action.ShouldBe(FilterAction.Accept);
}
