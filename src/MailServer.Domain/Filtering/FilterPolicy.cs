namespace MailServer.Domain.Filtering;

/// <summary>
/// Turns a score into an action.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three thresholds rather than one, because the three actions are not equally reversible.</b>
/// A message in the junk folder is a minor annoyance its owner can undo. A quarantined message
/// needs an operator. A rejected message is gone, and the only party who can do anything about
/// it is the sender — who, if this server was wrong, is a customer who now believes the
/// organisation's mail server does not work.
/// </para>
/// <para>
/// <b>Rejection is off by default and has to be turned on deliberately.</b>
/// <see cref="RejectThreshold"/> defaults to <see cref="double.PositiveInfinity"/>, so no score
/// reaches it however the weights are tuned. The reason is that heuristic scoring is wrong
/// often enough that a server which discards mail on it will, eventually, discard something
/// that mattered — and nobody will know, because a rejection leaves nothing to find. An
/// operator who wants that trade can have it; they should have to say so.
/// </para>
/// <para>
/// <b>What is hard-decided is not scored.</b> Malware and a blocked attachment do not push a
/// number up: they set a floor on the action (see
/// <see cref="FilterVerdict.Create(IReadOnlyList{FilterSignal}, FilterPolicy, FilterAction)"/>),
/// so no combination of weights can tune them away.
/// </para>
/// </remarks>
public sealed class FilterPolicy
{
    /// <summary>The default thresholds. Junk at 5, quarantine at 10, never reject.</summary>
    /// <remarks>
    /// Five is deliberately not a strong claim: it is roughly "two independent checks both
    /// think so". The numbers are conventional rather than derived, and are worth saying so —
    /// this product has no corpus to have tuned them against, which
    /// <c>docs/Filtering.md</c> records.
    /// </remarks>
    public static FilterPolicy Default { get; } = new();

    /// <summary>At or above this, the message goes to <c>\Junk</c>.</summary>
    public double JunkThreshold { get; init; } = 5.0;

    /// <summary>At or above this, the message is held for an operator.</summary>
    public double QuarantineThreshold { get; init; } = 10.0;

    /// <summary>At or above this, the message is refused at SMTP time. Infinite by default.</summary>
    public double RejectThreshold { get; init; } = double.PositiveInfinity;

    /// <summary>Whether the thresholds are in a usable order.</summary>
    /// <remarks>
    /// An out-of-order set is a configuration mistake with a silent failure mode: a quarantine
    /// threshold below the junk one means nothing is ever junked, and an operator reading a
    /// dashboard of quarantined mail would conclude the filter was working rather than that it
    /// was misconfigured.
    /// </remarks>
    public bool IsOrdered =>
        JunkThreshold <= QuarantineThreshold && QuarantineThreshold <= RejectThreshold;

    /// <summary>What to do with a message that scored this much.</summary>
    public FilterAction Decide(double score)
    {
        // Checked strongest-first so an out-of-order configuration degrades to "the strictest
        // threshold the score passes" instead of to "whichever branch happened to be written
        // first". It is still misconfigured, and IsOrdered is how an operator is told.
        if (score >= RejectThreshold)
        {
            return FilterAction.Reject;
        }

        if (score >= QuarantineThreshold)
        {
            return FilterAction.Quarantine;
        }

        return score >= JunkThreshold ? FilterAction.Junk : FilterAction.Accept;
    }
}
