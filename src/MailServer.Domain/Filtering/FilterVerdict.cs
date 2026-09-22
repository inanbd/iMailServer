namespace MailServer.Domain.Filtering;

/// <summary>What the filter decided to do with a message.</summary>
/// <remarks>
/// Ordered by severity, so <c>Math.Max</c> over several opinions is the strictest of them and
/// a comparison reads the way an operator would say it.
/// </remarks>
public enum FilterAction
{
    /// <summary>Deliver to the INBOX, unchanged.</summary>
    Accept = 0,

    /// <summary>
    /// Deliver, but to the recipient's <c>\Junk</c> folder.
    /// </summary>
    /// <remarks>
    /// The right action for "probably spam". The recipient still has it, can still find it, and
    /// can still tell the operator it was wrong — none of which is true of anything stronger.
    /// </remarks>
    Junk = 1,

    /// <summary>
    /// Hold the message where only an operator can see it, and deliver it to nobody.
    /// </summary>
    /// <remarks>
    /// For what should not reach a recipient even in a junk folder — malware, a blocked
    /// attachment — but which a human should be able to look at and release. The recipient is
    /// never told, because telling them is how a quarantine becomes a delivery channel for the
    /// notification's own contents.
    /// </remarks>
    Quarantine = 2,

    /// <summary>
    /// Refuse the message at SMTP time, so the sender is told.
    /// </summary>
    /// <remarks>
    /// <b>The only action that produces no copy of anything.</b> Refusing during the SMTP
    /// conversation makes it the sending server's problem to report — a legitimate sender whose
    /// mail this server got wrong finds out immediately, which is the one thing junking and
    /// quarantining cannot offer. It is also irreversible, which is why nothing scored reaches
    /// it by default: see <see cref="FilterPolicy.RejectThreshold"/>.
    /// </remarks>
    Reject = 3,
}

/// <summary>
/// One reason the filter reached its verdict.
/// </summary>
/// <remarks>
/// <para>
/// <b>A signal describes, and never quotes.</b> A verdict is readable under
/// <c>ViewServerState</c>; the message it is about needs <c>ReadMessageContent</c>. A signal
/// carrying a subject line, an address from the body or a snippet of text would be a way to
/// read mail with the weaker of the two permissions, so <see cref="Detail"/> says what was
/// observed — "the Date header is missing", "listed on zen.spamhaus.org" — and never what the
/// message said. <c>FilterSignalTests</c> pins this.
/// </para>
/// <para>
/// <b>Scores are additive and signed.</b> A check that finds evidence of legitimacy contributes
/// a negative score, because the alternative — a separate "good" list that the policy has to
/// weigh against the bad one — makes every threshold two numbers instead of one.
/// </para>
/// </remarks>
/// <param name="Name">
/// A stable identifier for the check, in <c>UPPER_SNAKE_CASE</c>. An operator tuning weights
/// needs to name a signal in configuration, so this is part of the product's surface and does
/// not change because the wording of the detail did.
/// </param>
/// <param name="Score">
/// What this signal contributed. Positive means "more like spam", negative means "less".
/// </param>
/// <param name="Detail">What was observed. Never message content.</param>
public sealed record FilterSignal(string Name, double Score, string Detail)
{
    /// <summary>The longest detail a signal may carry.</summary>
    /// <remarks>
    /// A bound rather than a style rule: several signals come from strangers' DNS answers and
    /// header values, and a verdict is rendered in a grid and written to a row. Truncating at
    /// the source keeps one hostile answer from deciding how wide a column is.
    /// </remarks>
    public const int MaxDetailLength = 200;

    /// <summary>Builds a signal, trimming a detail that is too long to be worth keeping whole.</summary>
    public static FilterSignal Create(string name, double score, string detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(detail);

        return new FilterSignal(
            name,
            score,
            detail.Length <= MaxDetailLength ? detail : detail[..MaxDetailLength]);
    }
}

/// <summary>
/// What the filter concluded about one message, and why.
/// </summary>
/// <remarks>
/// <b>The signals are the product, not the score.</b> A number on its own cannot be argued
/// with, and the question an operator actually has — "why did this land in junk?" — is only
/// answerable from the list. The score exists so that a policy can have one threshold instead
/// of a rule per check.
/// </remarks>
public sealed record FilterVerdict
{
    private FilterVerdict(double score, FilterAction action, IReadOnlyList<FilterSignal> signals)
    {
        Score = score;
        Action = action;
        Signals = signals;
    }

    /// <summary>The sum of every signal's contribution.</summary>
    public double Score { get; }

    /// <summary>What to do with the message.</summary>
    public FilterAction Action { get; }

    /// <summary>Every signal that fired, in the order the checks produced them.</summary>
    public IReadOnlyList<FilterSignal> Signals { get; }

    /// <summary>A verdict that found nothing. What a message with no signals gets.</summary>
    public static FilterVerdict Clean { get; } = new(0, FilterAction.Accept, []);

    /// <summary>Sums the signals and applies the policy.</summary>
    public static FilterVerdict Create(
        IReadOnlyList<FilterSignal> signals,
        FilterPolicy policy,
        FilterAction floor = FilterAction.Accept)
    {
        ArgumentNullException.ThrowIfNull(signals);
        ArgumentNullException.ThrowIfNull(policy);

        double score = signals.Sum(s => s.Score);
        FilterAction scored = policy.Decide(score);

        // The floor is how a check states a conclusion the score cannot overturn: malware found,
        // an attachment the operator blocked outright. Expressing those as a very large score
        // would work until somebody tuned a weight, and then it would silently stop working.
        return new FilterVerdict(score, scored > floor ? scored : floor, signals);
    }

    /// <summary>The signals that pushed the score up, heaviest first.</summary>
    /// <remarks>
    /// What belongs at the top of an explanation: an operator asking why a message was junked
    /// wants the reason that decided it, not the alphabetical list.
    /// </remarks>
    public IReadOnlyList<FilterSignal> Aggravating() =>
        [.. Signals.Where(s => s.Score > 0).OrderByDescending(s => s.Score)];

    /// <summary>One line an operator can read, naming the heaviest reasons.</summary>
    public string Summarise()
    {
        if (Signals.Count == 0)
        {
            return "Nothing was found.";
        }

        IReadOnlyList<FilterSignal> worst = Aggravating();

        if (worst.Count == 0)
        {
            return $"Scored {Score:0.0}; nothing counted against it.";
        }

        string reasons = string.Join(", ", worst.Take(3).Select(s => s.Name));
        string more = worst.Count > 3 ? $", and {worst.Count - 3} more" : string.Empty;

        return $"Scored {Score:0.0} — {reasons}{more}.";
    }
}
