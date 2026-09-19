using MailServer.Domain.Deliverability;

namespace MailServer.Deliverability.Tests;

public sealed class DeliverabilityScoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private static DeliverabilityCheck Check(
        DeliverabilityCategory category,
        DeliverabilityOutcome outcome,
        int weight = 1,
        string id = "test.check") =>
        new(
            id,
            category,
            "A check",
            weight,
            outcome,
            "because",
            new DeliverabilityEvidence("expected", "found"));

    private static DeliverabilityReport Report(params DeliverabilityCheck[] checks) =>
        DeliverabilityReport.From(checks, Now);

    // ---------------------------------------------------------------------------------------
    // The published weights.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>docs/Deliverability.md</c>'s table gives Identity 20, Authentication 30, TLS 20, DNS
    /// 15, Reputation 10 and Operations 5. A table in a document and a switch in a file are two
    /// places for one number to live, so the sum is asserted here rather than trusted.
    /// </summary>
    [Fact]
    public void The_published_weights_sum_to_one_hundred()
    {
        int total = 0;

        foreach (DeliverabilityCategory category in DeliverabilityCategories.All)
        {
            total += DeliverabilityCategories.WeightOf(category);
        }

        total.ShouldBe(DeliverabilityCategories.TotalWeight);
    }

    /// <summary>The weights are the ones the document publishes, individually.</summary>
    [Theory]
    [InlineData(DeliverabilityCategory.Identity, 20)]
    [InlineData(DeliverabilityCategory.Authentication, 30)]
    [InlineData(DeliverabilityCategory.Tls, 20)]
    [InlineData(DeliverabilityCategory.Dns, 15)]
    [InlineData(DeliverabilityCategory.Reputation, 10)]
    [InlineData(DeliverabilityCategory.Operations, 5)]
    public void Each_category_carries_the_weight_the_document_publishes(
        DeliverabilityCategory category,
        int expected) =>
        DeliverabilityCategories.WeightOf(category).ShouldBe(expected);

    /// <summary>
    /// Authentication outweighs every other category, which is the document's own argument:
    /// it is "the part that is entirely within your control and entirely verifiable before you
    /// send anything".
    /// </summary>
    [Fact]
    public void Authentication_outweighs_every_other_category()
    {
        int authentication = DeliverabilityCategories.WeightOf(DeliverabilityCategory.Authentication);

        foreach (DeliverabilityCategory category in DeliverabilityCategories.All)
        {
            if (category != DeliverabilityCategory.Authentication)
            {
                DeliverabilityCategories.WeightOf(category).ShouldBeLessThan(authentication);
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // The arithmetic.
    // ---------------------------------------------------------------------------------------

    /// <summary>Everything passing is a hundred, with nothing left unjudged.</summary>
    [Fact]
    public void A_report_in_which_everything_passes_scores_one_hundred()
    {
        DeliverabilityReport report = Report(
            [.. DeliverabilityCategories.All.Select(c => Check(c, DeliverabilityOutcome.Pass))]);

        report.Score!.Value.ShouldBe(100, 0.0001);
        report.Unjudged.ShouldBe(0, 0.0001);
        report.Readiness.ShouldBe(DeliverabilityReadiness.Ready);
    }

    /// <summary>Everything failing is nought, and still fully judged.</summary>
    [Fact]
    public void A_report_in_which_everything_fails_scores_nothing()
    {
        DeliverabilityReport report = Report(
            [.. DeliverabilityCategories.All.Select(c => Check(c, DeliverabilityOutcome.Fail))]);

        report.Score!.Value.ShouldBe(0, 0.0001);
        report.Unjudged.ShouldBe(0, 0.0001);
        report.Readiness.ShouldBe(DeliverabilityReadiness.NotReady);
    }

    /// <summary>
    /// A warning is worth half its weight. Full credit would make the score say nothing about a
    /// configuration one bad day from failing; no credit would make a warning indistinguishable
    /// from a failure, so an operator would not know which to fix first.
    /// </summary>
    [Fact]
    public void A_warning_is_worth_half_its_weight()
    {
        DeliverabilityReport report = Report(
            [.. DeliverabilityCategories.All.Select(c => Check(c, DeliverabilityOutcome.Warn))]);

        report.Score!.Value.ShouldBe(50, 0.0001);
        report.Readiness.ShouldBe(DeliverabilityReadiness.Ready);
    }

    [Theory]
    [InlineData(DeliverabilityOutcome.Pass, 1.0)]
    [InlineData(DeliverabilityOutcome.Warn, 0.5)]
    [InlineData(DeliverabilityOutcome.Fail, 0.0)]
    public void Each_outcome_is_worth_what_it_is_worth(DeliverabilityOutcome outcome, double credit) =>
        DeliverabilityCheck.CreditFor(outcome).ShouldBe(credit);

    /// <summary>
    /// An inconclusive check is excluded from the score rather than given a credit, so asking
    /// for one is a caller's mistake. A silent zero would make a resolver timeout look like a
    /// misconfiguration.
    /// </summary>
    [Fact]
    public void An_inconclusive_outcome_has_no_credit() =>
        Should.Throw<ArgumentOutOfRangeException>(() =>
            DeliverabilityCheck.CreditFor(DeliverabilityOutcome.Inconclusive));

    /// <summary>
    /// Within a category the checks' weights are relative to each other and the category's
    /// published share is divided in that proportion. Two checks weighted 1 and 3 in a category
    /// worth 20 are worth 5 and 15, so failing the heavier one costs fifteen points.
    /// </summary>
    [Fact]
    public void A_categorys_share_is_divided_between_its_checks_in_proportion()
    {
        DeliverabilityReport report = Report(
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Pass, weight: 1, id: "a"),
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Fail, weight: 3, id: "b"));

        DeliverabilityCategoryScore identity =
            report.Categories.Single(c => c.Category == DeliverabilityCategory.Identity);

        identity.Judged.ShouldBe(20, 0.0001);
        identity.Earned.ShouldBe(5, 0.0001);
        identity.Percentage!.Value.ShouldBe(25, 0.0001);
    }

    /// <summary>
    /// The per-category numbers add up to the report's own, because the UI shows how the total
    /// was computed and a total that did not match its parts would be worse than no explanation.
    /// </summary>
    [Fact]
    public void The_categories_add_up_to_the_report()
    {
        DeliverabilityReport report = Report(
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Pass, id: "a"),
            Check(DeliverabilityCategory.Authentication, DeliverabilityOutcome.Warn, id: "b"),
            Check(DeliverabilityCategory.Tls, DeliverabilityOutcome.Fail, id: "c"),
            Check(DeliverabilityCategory.Dns, DeliverabilityOutcome.Inconclusive, id: "d"));

        report.Earned.ShouldBe(report.Categories.Sum(c => c.Earned), 0.0001);
        report.Judged.ShouldBe(report.Categories.Sum(c => c.Judged), 0.0001);
        report.Unjudged.ShouldBe(report.Categories.Sum(c => c.Unjudged), 0.0001);
    }

    // ---------------------------------------------------------------------------------------
    // What cannot be judged.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An inconclusive check lowers the ceiling rather than the score. Reporting a hundred out
    /// of a hundred while fifteen of those points were never tested would be a lie in the one
    /// direction that matters, because an operator acts on it by sending mail.
    /// </summary>
    [Fact]
    public void An_inconclusive_check_leaves_its_points_unjudged()
    {
        DeliverabilityReport report = Report(
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Pass, id: "a"),
            Check(DeliverabilityCategory.Dns, DeliverabilityOutcome.Inconclusive, id: "b"));

        report.Categories.Single(c => c.Category == DeliverabilityCategory.Dns)
            .Judged.ShouldBe(0, 0.0001);

        // The fifteen DNS points and the sixty-five belonging to categories with no checks.
        report.Unjudged.ShouldBe(80, 0.0001);
        report.Judged.ShouldBe(20, 0.0001);
        report.Score!.Value.ShouldBe(100, 0.0001);
        report.Readiness.ShouldBe(DeliverabilityReadiness.Unknown);
    }

    /// <summary>
    /// A category with no checks at all is entirely unjudged — not perfect and not zero.
    /// Leaving the reputation providers unconfigured must not silently award ten points, and
    /// must not silently deduct them either.
    /// </summary>
    [Fact]
    public void A_category_with_no_checks_is_entirely_unjudged()
    {
        DeliverabilityCategoryScore reputation =
            Report(Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Pass))
                .Categories
                .Single(c => c.Category == DeliverabilityCategory.Reputation);

        reputation.Judged.ShouldBe(0, 0.0001);
        reputation.Earned.ShouldBe(0, 0.0001);
        reputation.Unjudged.ShouldBe(10, 0.0001);
        reputation.Percentage.ShouldBeNull();
    }

    /// <summary>
    /// A report that learned nothing has no score. Null rather than zero and rather than a
    /// hundred: both of those numbers would be read as a finding.
    /// </summary>
    [Fact]
    public void A_report_that_learned_nothing_has_no_score()
    {
        DeliverabilityReport report = Report(
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Inconclusive));

        report.Score.ShouldBeNull();
        report.Readiness.ShouldBe(DeliverabilityReadiness.Unknown);
        report.Summarise().ShouldBe("No check could be completed, so there is no score.");
    }

    /// <summary>An empty report knows nothing, which is Unknown rather than Ready.</summary>
    [Fact]
    public void An_empty_report_is_not_ready_and_not_failing()
    {
        DeliverabilityReport report = Report();

        report.Score.ShouldBeNull();
        report.Readiness.ShouldBe(DeliverabilityReadiness.Unknown);
        report.Categories.Count.ShouldBe(DeliverabilityCategories.All.Count);
    }

    // ---------------------------------------------------------------------------------------
    // Readiness is not the score.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A comfortable-looking number can hide a configuration receivers will reject on the first
    /// message, so the verdict is decided by the worst outcome present and never by arithmetic.
    /// </summary>
    [Fact]
    public void A_high_score_with_one_failure_is_still_not_ready()
    {
        DeliverabilityReport report = Report(
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Pass, id: "a"),
            Check(DeliverabilityCategory.Authentication, DeliverabilityOutcome.Pass, id: "b"),
            Check(DeliverabilityCategory.Tls, DeliverabilityOutcome.Pass, id: "c"),
            Check(DeliverabilityCategory.Dns, DeliverabilityOutcome.Pass, id: "d"),
            Check(DeliverabilityCategory.Reputation, DeliverabilityOutcome.Pass, id: "e"),
            Check(DeliverabilityCategory.Operations, DeliverabilityOutcome.Fail, id: "f"));

        report.Score!.Value.ShouldBe(95, 0.0001);
        report.Readiness.ShouldBe(DeliverabilityReadiness.NotReady);
    }

    /// <summary>A failure outranks an inconclusive: there is something known to be broken.</summary>
    [Fact]
    public void A_failure_outranks_something_unmeasured() =>
        Report(
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Inconclusive, id: "a"),
            Check(DeliverabilityCategory.Tls, DeliverabilityOutcome.Fail, id: "b"))
            .Readiness.ShouldBe(DeliverabilityReadiness.NotReady);

    /// <summary>Warnings alone are still ready: mail flows today.</summary>
    [Fact]
    public void Warnings_alone_are_ready() =>
        Report(Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Warn))
            .Readiness.ShouldBe(DeliverabilityReadiness.Ready);

    // ---------------------------------------------------------------------------------------
    // Presentation.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A partially judged report never leads with a number out of a hundred. One passing check
    /// and eighty untested points rescales to a hundred per cent, and a sentence beginning
    /// "100 out of 100" is read as perfect however carefully it is qualified afterwards — by an
    /// operator skimming, by a UI that truncates, by a screenshot.
    /// </summary>
    [Fact]
    public void A_partially_judged_summary_never_leads_with_a_number_out_of_a_hundred()
    {
        DeliverabilityReport report = Report(
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Pass, id: "a"),
            Check(DeliverabilityCategory.Dns, DeliverabilityOutcome.Inconclusive, id: "b"));

        report.Summarise().ShouldBe(
            "20 out of the 20 points that could be judged; 80 of 100 were not tested");

        // The rescaled score is still a hundred per cent - which is exactly why the sentence
        // above must not be built from it.
        report.Score!.Value.ShouldBe(100, 0.0001);
        report.Summarise().ShouldNotStartWith("100 out of 100");
    }

    /// <summary>A fully judged report says nothing about points that do not exist.</summary>
    [Fact]
    public void A_fully_judged_summary_is_just_the_score() =>
        Report([.. DeliverabilityCategories.All.Select(c => Check(c, DeliverabilityOutcome.Pass))])
            .Summarise()
            .ShouldBe("100 out of 100");

    /// <summary>The report separates what an operator must act on from what it merely noted.</summary>
    [Fact]
    public void The_report_separates_failures_warnings_and_what_it_could_not_measure()
    {
        DeliverabilityReport report = Report(
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Fail, id: "a"),
            Check(DeliverabilityCategory.Tls, DeliverabilityOutcome.Warn, id: "b"),
            Check(DeliverabilityCategory.Dns, DeliverabilityOutcome.Inconclusive, id: "c"),
            Check(DeliverabilityCategory.Operations, DeliverabilityOutcome.Pass, id: "d"));

        report.Failures.Select(c => c.Id).ShouldBe(["a"]);
        report.Warnings.Select(c => c.Id).ShouldBe(["b"]);
        report.Unmade.Select(c => c.Id).ShouldBe(["c"]);
    }

    /// <summary>A check with no weight would divide by nothing; it is a caller's mistake.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_check_must_carry_a_weight(int weight) =>
        Should.Throw<ArgumentOutOfRangeException>(() =>
            Report(Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Pass, weight)));

    /// <summary>The report keeps the checks it was given, in the order it was given them.</summary>
    [Fact]
    public void The_report_keeps_every_check_in_order()
    {
        DeliverabilityReport report = Report(
            Check(DeliverabilityCategory.Tls, DeliverabilityOutcome.Pass, id: "first"),
            Check(DeliverabilityCategory.Identity, DeliverabilityOutcome.Pass, id: "second"));

        report.Checks.Select(c => c.Id).ShouldBe(["first", "second"]);
        report.ProducedAt.ShouldBe(Now);
    }
}
