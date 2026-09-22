using MailServer.Domain.Enums;

namespace MailServer.Domain.Filtering;

/// <summary>
/// What the authentication mechanisms concluded about one message.
/// </summary>
/// <remarks>
/// Named for the message to keep it apart from <c>Deliverability.AuthenticationFacts</c>, which
/// is about a domain's published records rather than a message's results — the readiness report
/// asks "is this domain set up correctly", and this asks "did this message check out".
/// </remarks>
/// <param name="Spf">The SPF result, or null when SPF was not evaluated.</param>
/// <param name="Dkim">The best result among the message's signatures, or null when it had none.</param>
/// <param name="Dmarc">The DMARC result, or null when no policy applied.</param>
/// <param name="DmarcDisposition">
/// The policy the publishing domain asked for, which is not the same thing as what this server
/// did about it. A <c>p=quarantine</c> domain whose mail fails is the publisher telling us what
/// they want; it is weighted because they are the authority on their own mail.
/// </param>
public sealed record MessageAuthenticationFacts(
    SpfResult? Spf,
    DkimVerificationResult? Dkim,
    DmarcResult? Dmarc,
    DmarcPolicy? DmarcDisposition);

/// <summary>
/// Turns the authentication results into filter signals.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are the only signals in this product with real evidence behind them.</b> Everything
/// else the filter does is a heuristic about how mail usually looks; a DKIM signature that
/// verifies is arithmetic. That is why they carry the heaviest weights in both directions, and
/// why the negative ones matter as much as the positive: a DMARC pass is the strongest
/// available statement that a message is what it says it is, and a filter that could not lower
/// a score would junk legitimate mail every time a heuristic misfired.
/// </para>
/// <para>
/// <b>A failure is weighted, not decisive.</b> Enforcement of <c>p=reject</c> already happened
/// before the filter runs — <c>LocalDeliveryService</c> refuses those outright. What reaches
/// here is mail the publishing domain did not ask to have rejected, so the filter's job is to
/// weigh it rather than to re-litigate a decision DMARC already made.
/// </para>
/// <para>
/// <b>Temporary errors score nothing at all.</b> A DNS timeout is a fact about this server's
/// resolver, not about the sender, and scoring it would make a local outage look like a spam
/// wave — while quietly junking the mail of whoever was unlucky enough to send during it.
/// </para>
/// </remarks>
public static class AuthenticationWeighting
{
    /// <summary>A DMARC pass. The strongest evidence of legitimacy available.</summary>
    public const double DmarcPassScore = -2.5;

    /// <summary>A DMARC fail, where the domain published no enforcement request.</summary>
    public const double DmarcFailScore = 3.0;

    /// <summary>A DMARC fail where the domain asked for quarantine or reject.</summary>
    /// <remarks>
    /// <para>
    /// <b>Set to exactly <see cref="FilterPolicy.JunkThreshold"/>'s default, and that equality is
    /// deliberate.</b> This signal fires only when the publishing domain published
    /// <c>p=quarantine</c>, the message failed its alignment, and <c>pct=</c> sampling selected
    /// it — <c>DmarcEvaluationOutcome.Disposition</c> is <c>None</c> in every other case. RFC
    /// 7489 §6.3 is that the domain owner wants such mail treated as suspicious, and the junk
    /// folder is what that means. So one such signal, alone, junks the message: the publisher
    /// asked, and they are the authority on their own mail.
    /// </para>
    /// <para>
    /// It does not reach <see cref="FilterPolicy.QuarantineThreshold"/>, and must not. Holding
    /// mail where only an operator can see it is this server's own decision about a message
    /// nobody can read, and no single signal earns that. <c>p=reject</c> never arrives here at
    /// all — <c>LocalDeliveryService</c> refuses it before the filter runs.
    /// </para>
    /// </remarks>
    public const double DmarcFailEnforcingScore = 5.0;

    /// <summary>A verified DKIM signature.</summary>
    public const double DkimPassScore = -1.0;

    /// <summary>A signature that was present and did not verify.</summary>
    /// <remarks>
    /// Worth more than no signature at all: an unsigned message says nothing, whereas a broken
    /// signature means either the message was modified in transit or somebody attached a
    /// signature they could not produce. Both are worth knowing, and neither is common in
    /// ordinary mail.
    /// </remarks>
    public const double DkimFailScore = 1.5;

    /// <summary>An SPF pass.</summary>
    /// <remarks>
    /// Small, because SPF passes for anybody who controls the envelope sender's domain —
    /// including every spammer who registered one this morning. It is evidence that the message
    /// came from where it claims, not that where it claims is trustworthy.
    /// </remarks>
    public const double SpfPassScore = -0.5;

    /// <summary>An SPF fail: the domain's own record says this host is not authorized.</summary>
    public const double SpfFailScore = 2.0;

    /// <summary>An SPF softfail.</summary>
    public const double SpfSoftFailScore = 0.5;

    /// <summary>Weighs the results.</summary>
    public static IReadOnlyList<FilterSignal> Evaluate(MessageAuthenticationFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        List<FilterSignal> signals = [];

        switch (facts.Dmarc)
        {
            case DmarcResult.Pass:
                signals.Add(FilterSignal.Create(
                    "DMARC_PASS", DmarcPassScore, "DMARC alignment passed."));
                break;

            case DmarcResult.Fail when facts.DmarcDisposition is DmarcPolicy.Quarantine or DmarcPolicy.Reject:
                signals.Add(FilterSignal.Create(
                    "DMARC_FAIL_ENFORCING",
                    DmarcFailEnforcingScore,
                    $"DMARC alignment failed, and the domain publishes p={facts.DmarcDisposition.ToString()!.ToLowerInvariant()}."));
                break;

            case DmarcResult.Fail:
                signals.Add(FilterSignal.Create(
                    "DMARC_FAIL", DmarcFailScore, "DMARC alignment failed."));
                break;

            default:
                break;
        }

        switch (facts.Dkim)
        {
            case DkimVerificationResult.Pass:
                signals.Add(FilterSignal.Create(
                    "DKIM_PASS", DkimPassScore, "A DKIM signature verified."));
                break;

            case DkimVerificationResult.Fail:
                signals.Add(FilterSignal.Create(
                    "DKIM_FAIL", DkimFailScore, "A DKIM signature was present and did not verify."));
                break;

            default:
                break;
        }

        switch (facts.Spf)
        {
            case SpfResult.Pass:
                signals.Add(FilterSignal.Create("SPF_PASS", SpfPassScore, "SPF passed."));
                break;

            case SpfResult.Fail:
                signals.Add(FilterSignal.Create(
                    "SPF_FAIL", SpfFailScore, "SPF failed: the domain does not authorize this host."));
                break;

            case SpfResult.SoftFail:
                signals.Add(FilterSignal.Create("SPF_SOFTFAIL", SpfSoftFailScore, "SPF soft-failed."));
                break;

            default:
                break;
        }

        return signals;
    }
}
