namespace MailServer.Domain.Deliverability;

/// <summary>
/// How one readiness check concluded.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="Inconclusive"/> is a first-class outcome and not a failure.</b> A DNS timeout,
/// a resolver that will not answer, a provider API that is rate-limiting — none of those are
/// facts about the operator's configuration, and scoring them as failures would tell an
/// operator to fix something that is not broken. Scoring them as passes would be worse: it
/// would report readiness the server has no evidence for. They are therefore excluded from the
/// score's denominator and reported separately; see <see cref="DeliverabilityReport"/>.
/// </para>
/// <para>
/// <b><see cref="Warn"/> means "works, but will bite you".</b> An SPF record ending in
/// <c>~all</c> rather than <c>-all</c>, a TTL so long that a mistake takes a day to correct, a
/// certificate three weeks from expiry. Mail flows today. The distinction from
/// <see cref="Fail"/> is whether a receiver would reject the message now.
/// </para>
/// </remarks>
public enum DeliverabilityOutcome
{
    /// <summary>The check was made and the configuration is correct.</summary>
    Pass = 0,

    /// <summary>The check was made and found something that works but should be improved.</summary>
    Warn = 1,

    /// <summary>The check was made and found something that will cost delivery.</summary>
    Fail = 2,

    /// <summary>The check could not be made. Not a fact about the configuration.</summary>
    Inconclusive = 3,
}

/// <summary>
/// The six groups <c>docs/Deliverability.md</c> weights the score by.
/// </summary>
/// <remarks>
/// <b>Authentication carries the most weight, and the document says why:</b> "SPF, DKIM and
/// DMARC are the checks a receiver can evaluate on the very first message from an unknown
/// sender. Everything else — volume patterns, complaint rates, engagement — takes time to
/// accumulate. Getting authentication right is the part that is entirely within your control
/// and entirely verifiable before you send anything."
/// </remarks>
public enum DeliverabilityCategory
{
    /// <summary>A/AAAA, PTR, FCrDNS, and the EHLO name agreeing with all of them.</summary>
    Identity = 0,

    /// <summary>SPF, DKIM and DMARC published, sane, and verified against a real message.</summary>
    Authentication = 1,

    /// <summary>Certificate trust, hostname, expiry, renewal health, STARTTLS, MTA-STS, TLS-RPT.</summary>
    Tls = 2,

    /// <summary>MX correctness, lookup limits, TTL sanity, CAA sanity.</summary>
    Dns = 3,

    /// <summary>Whatever the configured reputation providers report.</summary>
    Reputation = 4,

    /// <summary>Relay posture, queue health, disk, clock skew, bounce rate.</summary>
    Operations = 5,
}

/// <summary>The weights <c>docs/Deliverability.md</c> publishes, and the arithmetic over them.</summary>
public static class DeliverabilityCategories
{
    /// <summary>Every category, in the order the report presents them.</summary>
    public static IReadOnlyList<DeliverabilityCategory> All { get; } =
        Enum.GetValues<DeliverabilityCategory>();

    /// <summary>What a perfect report scores.</summary>
    public const int TotalWeight = 100;

    /// <summary>
    /// One category's share of the hundred.
    /// </summary>
    /// <remarks>
    /// These are the numbers in <c>docs/Deliverability.md</c>'s table and they sum to
    /// <see cref="TotalWeight"/> — which
    /// <c>DeliverabilityScoreTests.The_published_weights_sum_to_one_hundred</c> asserts, because
    /// a table in a document and a switch in a file are two places for one number to live.
    /// </remarks>
    public static int WeightOf(DeliverabilityCategory category) => category switch
    {
        DeliverabilityCategory.Identity => 20,
        DeliverabilityCategory.Authentication => 30,
        DeliverabilityCategory.Tls => 20,
        DeliverabilityCategory.Dns => 15,
        DeliverabilityCategory.Reputation => 10,
        DeliverabilityCategory.Operations => 5,
        _ => throw new ArgumentOutOfRangeException(
            nameof(category),
            category,
            "Not a deliverability category."),
    };

    /// <summary>The human-readable name, for the report.</summary>
    public static string NameOf(DeliverabilityCategory category) => category switch
    {
        DeliverabilityCategory.Identity => "Identity",
        DeliverabilityCategory.Authentication => "Authentication",
        DeliverabilityCategory.Tls => "TLS",
        DeliverabilityCategory.Dns => "DNS",
        DeliverabilityCategory.Reputation => "Reputation",
        DeliverabilityCategory.Operations => "Operations",
        _ => throw new ArgumentOutOfRangeException(
            nameof(category),
            category,
            "Not a deliverability category."),
    };
}

/// <summary>
/// What a check actually observed, so an operator can act on it without re-running the tool.
/// </summary>
/// <remarks>
/// <para>
/// <c>docs/Deliverability.md</c>: "Every check returns Pass / Warn / Fail / Inconclusive
/// <b>with evidence</b>: the record actually found, the value expected, the resolver used, the
/// TTL observed." All four fields exist for that sentence.
/// </para>
/// <para>
/// <b>A check with no evidence is a check an operator cannot act on.</b> "SPF is wrong" sends
/// somebody to their DNS panel to guess; "expected <c>v=spf1 mx -all</c>, found
/// <c>v=spf1 mx ~all</c>, from 198.51.100.53, TTL 3600" is a fix. The type is therefore
/// required on every outcome but <see cref="DeliverabilityOutcome.Inconclusive"/>, where by
/// definition there was nothing to observe.
/// </para>
/// </remarks>
/// <param name="Expected">What the check wanted to find, in the form it would be published in.</param>
/// <param name="Found">What was actually there, or null when nothing was.</param>
/// <param name="Source">
/// Where the answer came from — a resolver address, a certificate store, a queue. "It works on
/// my resolver" is the problem a diagnostic tool exists to solve, so the tool says whose answer
/// it is reporting.
/// </param>
/// <param name="Ttl">The TTL observed, when the answer came from DNS.</param>
public sealed record DeliverabilityEvidence(
    string Expected,
    string? Found,
    string? Source = null,
    TimeSpan? Ttl = null)
{
    /// <summary>Evidence for a value that is simply absent.</summary>
    public static DeliverabilityEvidence Missing(string expected, string? source = null) =>
        new(expected, null, source);
}

/// <summary>
/// One readiness check, its verdict, and everything needed to act on it.
/// </summary>
/// <param name="Id">
/// A stable machine-readable name, such as <c>identity.ptr</c>. The UI, the documentation and
/// an operator's notes all need to refer to one check across releases, and a title is prose
/// that will be rewritten.
/// </param>
/// <param name="Category">Which group's weight this check draws on.</param>
/// <param name="Title">One line, for the report's row.</param>
/// <param name="Weight">
/// This check's share of its category, relative to the other checks in it. Not a share of a
/// hundred — see <see cref="DeliverabilityReport"/> for how the two combine.
/// </param>
/// <param name="Outcome">The verdict.</param>
/// <param name="Detail">Why the verdict is what it is, in a sentence an operator can read.</param>
/// <param name="Evidence">What was observed. Null only when nothing could be.</param>
/// <param name="Remedy">
/// What to do about it, when there is something to do. Null for a passing check.
/// </param>
public sealed record DeliverabilityCheck(
    string Id,
    DeliverabilityCategory Category,
    string Title,
    int Weight,
    DeliverabilityOutcome Outcome,
    string Detail,
    DeliverabilityEvidence? Evidence = null,
    string? Remedy = null)
{
    /// <summary>
    /// What a check's outcome is worth, as a fraction of its weight.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A warning is worth half.</b> The alternatives are both wrong: full credit makes the
    /// score say nothing about a configuration that is one bad day from failing, and no credit
    /// makes a warning indistinguishable from a failure — so an operator with a working setup
    /// and one soft-fail SPF record would see the same number as one whose SPF is missing
    /// entirely, and would not know which to fix first.
    /// </para>
    /// <para>
    /// <see cref="DeliverabilityOutcome.Inconclusive"/> has no value here because it is not
    /// scored at all; asking for it is a caller's mistake rather than a zero.
    /// </para>
    /// </remarks>
    public static double CreditFor(DeliverabilityOutcome outcome) => outcome switch
    {
        DeliverabilityOutcome.Pass => 1.0,
        DeliverabilityOutcome.Warn => 0.5,
        DeliverabilityOutcome.Fail => 0.0,
        _ => throw new ArgumentOutOfRangeException(
            nameof(outcome),
            outcome,
            "An inconclusive check is excluded from the score rather than given a credit."),
    };

    /// <summary>Whether this check produced a fact about the configuration.</summary>
    public bool IsJudged => Outcome != DeliverabilityOutcome.Inconclusive;
}
