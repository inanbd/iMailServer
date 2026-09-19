using System.Globalization;

namespace MailServer.Domain.Deliverability;

/// <summary>
/// Whether the server is ready to send, which is a separate question from the score.
/// </summary>
/// <remarks>
/// <b>A number is not a verdict.</b> A report can score 94 with a failing SPF record if
/// everything else is perfect, and 94 is a comfortable-looking number that hides a configuration
/// receivers will reject on the first message. The readiness is therefore decided by the worst
/// outcome present, never by arithmetic, and the UI leads with it.
/// </remarks>
public enum DeliverabilityReadiness
{
    /// <summary>Every check that ran passed or warned. Nothing is known to be broken.</summary>
    Ready = 0,

    /// <summary>At least one check could not be made, so readiness is genuinely unknown.</summary>
    Unknown = 1,

    /// <summary>At least one check failed. Mail will be refused or filtered.</summary>
    NotReady = 2,
}

/// <summary>One category's contribution to the score, with the arithmetic shown.</summary>
/// <param name="Category">Which group.</param>
/// <param name="Weight">Its share of the hundred, from <see cref="DeliverabilityCategories"/>.</param>
/// <param name="Earned">Points earned, out of <paramref name="Judged"/>.</param>
/// <param name="Judged">
/// Points that could be judged. Less than <paramref name="Weight"/> when some of the category's
/// checks were inconclusive, and zero when none of them ran at all.
/// </param>
/// <param name="Checks">The checks themselves, in the order they were supplied.</param>
public sealed record DeliverabilityCategoryScore(
    DeliverabilityCategory Category,
    int Weight,
    double Earned,
    double Judged,
    IReadOnlyList<DeliverabilityCheck> Checks)
{
    /// <summary>Points that could not be judged, because the checks for them did not conclude.</summary>
    public double Unjudged => Weight - Judged;

    /// <summary>The category's own percentage, or null when nothing in it could be judged.</summary>
    public double? Percentage => Judged <= 0 ? null : Earned / Judged * 100.0;
}

/// <summary>
/// A readiness report: every check, the score, and how the score was arrived at.
/// </summary>
/// <remarks>
/// <para>
/// <c>docs/Deliverability.md</c>: "The UI shows exactly how the total was computed. A bare
/// '94/100' that cannot be explained is useless to an operator trying to fix the missing six."
/// Everything in this type exists to make that sentence true — the per-category arithmetic is
/// part of the report rather than something the UI recomputes.
/// </para>
/// <para>
/// <b>An inconclusive check lowers the ceiling rather than the score.</b> If the resolver cannot
/// be reached, the DNS category's fifteen points are not lost and not given away: they are
/// reported as unjudged, the score is stated out of what remained, and
/// <see cref="Readiness"/> becomes <see cref="DeliverabilityReadiness.Unknown"/>. A server that
/// answered "100 out of 100" while fifteen of those points were never tested would be lying in
/// the one direction that matters, because an operator acts on it by sending mail.
/// </para>
/// <para>
/// <b>A category with no checks at all is entirely unjudged.</b> Not perfect, not zero. Leaving
/// the reputation providers unconfigured must not silently award ten points, and must not
/// silently deduct them either.
/// </para>
/// </remarks>
public sealed record DeliverabilityReport
{
    private DeliverabilityReport(
        IReadOnlyList<DeliverabilityCheck> checks,
        IReadOnlyList<DeliverabilityCategoryScore> categories,
        DateTimeOffset producedAt)
    {
        Checks = checks;
        Categories = categories;
        ProducedAt = producedAt;
    }

    /// <summary>Every check, in the order it was supplied.</summary>
    public IReadOnlyList<DeliverabilityCheck> Checks { get; }

    /// <summary>The per-category arithmetic, one entry per category, always all six.</summary>
    public IReadOnlyList<DeliverabilityCategoryScore> Categories { get; }

    /// <summary>When the report was produced. A readiness report is a snapshot, not a fact.</summary>
    public DateTimeOffset ProducedAt { get; }

    /// <summary>Points earned.</summary>
    public double Earned
    {
        get
        {
            double total = 0;

            foreach (DeliverabilityCategoryScore category in Categories)
            {
                total += category.Earned;
            }

            return total;
        }
    }

    /// <summary>Points that could be judged. The score's denominator.</summary>
    public double Judged
    {
        get
        {
            double total = 0;

            foreach (DeliverabilityCategoryScore category in Categories)
            {
                total += category.Judged;
            }

            return total;
        }
    }

    /// <summary>Points no check could speak to.</summary>
    public double Unjudged => DeliverabilityCategories.TotalWeight - Judged;

    /// <summary>
    /// The score out of a hundred, or null when nothing could be judged.
    /// </summary>
    /// <remarks>
    /// Null rather than zero, and null rather than a hundred. A report in which every check was
    /// inconclusive has learned nothing, and both of the numbers one might reach for would be
    /// read as a finding.
    /// </remarks>
    public double? Score => Judged <= 0 ? null : Earned / Judged * DeliverabilityCategories.TotalWeight;

    /// <summary>
    /// The verdict, decided by the worst outcome present rather than by the score.
    /// </summary>
    public DeliverabilityReadiness Readiness
    {
        get
        {
            bool unknown = false;

            foreach (DeliverabilityCheck check in Checks)
            {
                switch (check.Outcome)
                {
                    case DeliverabilityOutcome.Fail:
                        return DeliverabilityReadiness.NotReady;

                    case DeliverabilityOutcome.Inconclusive:
                        unknown = true;
                        break;
                }
            }

            // A report with no checks at all knows nothing, which is Unknown rather than Ready.
            return unknown || Checks.Count == 0
                ? DeliverabilityReadiness.Unknown
                : DeliverabilityReadiness.Ready;
        }
    }

    /// <summary>The failing checks, worst first, for the UI to lead with.</summary>
    public IReadOnlyList<DeliverabilityCheck> Failures => Where(DeliverabilityOutcome.Fail);

    /// <summary>The warnings.</summary>
    public IReadOnlyList<DeliverabilityCheck> Warnings => Where(DeliverabilityOutcome.Warn);

    /// <summary>The checks that could not be made.</summary>
    public IReadOnlyList<DeliverabilityCheck> Unmade => Where(DeliverabilityOutcome.Inconclusive);

    /// <summary>
    /// Builds a report from a set of checks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Within a category the checks' own weights are relative to each other, and the category's
    /// published share is divided between them in that proportion. Two checks weighted 1 and 3
    /// in a category worth 20 are worth 5 and 15. That keeps a check's weight a local decision —
    /// adding a seventh identity check does not require re-deciding the other six — while the
    /// category totals stay exactly the numbers <c>docs/Deliverability.md</c> publishes.
    /// </para>
    /// <para>
    /// An inconclusive check keeps its share of the category out of both the numerator and the
    /// denominator, which is what makes its points show up as unjudged rather than as a loss.
    /// </para>
    /// </remarks>
    /// <param name="checks">The checks. May be empty, which produces an entirely unjudged report.</param>
    /// <param name="producedAt">When the report was produced.</param>
    public static DeliverabilityReport From(
        IEnumerable<DeliverabilityCheck> checks,
        DateTimeOffset producedAt)
    {
        ArgumentNullException.ThrowIfNull(checks);

        List<DeliverabilityCheck> all = [.. checks];

        foreach (DeliverabilityCheck check in all)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(check.Weight, nameof(checks));
        }

        List<DeliverabilityCategoryScore> categories = [];

        foreach (DeliverabilityCategory category in DeliverabilityCategories.All)
        {
            List<DeliverabilityCheck> inCategory = [.. all.Where(c => c.Category == category)];

            int weight = DeliverabilityCategories.WeightOf(category);
            int total = 0;
            int judgedWeight = 0;
            double earnedWeight = 0;

            foreach (DeliverabilityCheck check in inCategory)
            {
                total += check.Weight;

                if (!check.IsJudged)
                {
                    continue;
                }

                judgedWeight += check.Weight;
                earnedWeight += check.Weight * DeliverabilityCheck.CreditFor(check.Outcome);
            }

            // A category with no checks has nothing to divide its share between, so all of it is
            // unjudged - which is what an unconfigured reputation provider should look like.
            double judged = total == 0 ? 0 : weight * ((double)judgedWeight / total);
            double earned = total == 0 ? 0 : weight * (earnedWeight / total);

            categories.Add(new DeliverabilityCategoryScore(
                category,
                weight,
                earned,
                judged,
                inCategory));
        }

        return new DeliverabilityReport(all, categories, producedAt);
    }

    /// <summary>The score as the UI prints it, or the reason there is not one.</summary>
    /// <remarks>
    /// <para>
    /// <b>The first number is never "out of 100" unless it really is.</b> A report with one
    /// passing check and eighty untested points rescales to a hundred per cent, and a sentence
    /// beginning "100 out of 100" is read as perfect however carefully it is qualified
    /// afterwards — by an operator skimming, by a UI that truncates, by a screenshot. So when
    /// anything went unjudged the summary states the points earned out of the points that could
    /// be judged, and names the remainder as untested.
    /// </para>
    /// <para>
    /// The rescaled <see cref="Score"/> is still available for a progress bar, where the
    /// denominator is drawn rather than written. It is not what this sentence says.
    /// </para>
    /// </remarks>
    public string Summarise()
    {
        if (Score is not { } score)
        {
            return "No check could be completed, so there is no score.";
        }

        if (Unjudged <= 0)
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"{Math.Round(score):0} out of {DeliverabilityCategories.TotalWeight}");
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{Math.Round(Earned):0} out of the {Math.Round(Judged):0} points that could be " +
            $"judged; {Math.Round(Unjudged):0} of {DeliverabilityCategories.TotalWeight} were " +
            $"not tested");
    }

    private IReadOnlyList<DeliverabilityCheck> Where(DeliverabilityOutcome outcome) =>
        [.. Checks.Where(c => c.Outcome == outcome)];
}
