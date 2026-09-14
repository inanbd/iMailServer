namespace MailServer.Domain.Policies;

/// <summary>Why a proposed order was refused before it reached the CA.</summary>
/// <param name="IsAllowed">False when submitting would breach a documented limit.</param>
/// <param name="Reason">
/// What was breached and what to do about it, written for an operator rather than a log parser.
/// </param>
/// <param name="RetryAfterUtc">When the limit is expected to clear, if it is time-based.</param>
public sealed record RateLimitDecision(
    bool IsAllowed,
    string? Reason = null,
    DateTimeOffset? RetryAfterUtc = null)
{
    public static RateLimitDecision Allowed { get; } = new(true);
}

/// <summary>
/// Let's Encrypt's documented rate limits, enforced locally before an order is submitted.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why enforce someone else's limits ourselves.</b> A rejected order is not free: a failed
/// validation consumes a slot in a limit that is five per hour, so a retry loop that looks
/// harmless locally can lock an operator out of issuance for the rest of the day — and
/// sustained hammering gets an installation blocked outright. Refusing locally costs one
/// database read and produces an explanation, rather than an opaque CA error after the damage.
/// </para>
/// <para>
/// <b>These are production limits.</b> Staging's are far looser, which is exactly why a new
/// installation defaults to staging: an operator fixing DNS can iterate there without spending
/// anything that matters.
/// </para>
/// <para>
/// The numbers are Let's Encrypt's published figures and are deliberately treated as a
/// <i>floor</i> rather than as truth. They change; the CA is authoritative; and this check
/// exists to stop obvious self-harm, not to predict the CA's answer exactly.
/// </para>
/// </remarks>
public sealed class AcmeRateLimitPolicy
{
    /// <summary>Certificates per registered domain, per week.</summary>
    public int CertificatesPerRegisteredDomainPerWeek { get; init; } = 50;

    /// <summary>
    /// Certificates with an identical identifier set, per week.
    /// </summary>
    /// <remarks>
    /// The limit operators actually hit. Retrying the same hostname list after a
    /// misconfiguration burns this five times over before anyone notices, and then there is
    /// nothing to do but wait a week.
    /// </remarks>
    public int DuplicateCertificatesPerWeek { get; init; } = 5;

    /// <summary>Failed validations per account, per hostname, per hour.</summary>
    public int FailedValidationsPerHostnamePerHour { get; init; } = 5;

    /// <summary>The window the weekly limits are measured over.</summary>
    public TimeSpan WeeklyWindow { get; init; } = TimeSpan.FromDays(7);

    /// <summary>The window the failed-validation limit is measured over.</summary>
    public TimeSpan FailureWindow { get; init; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Headroom left below each weekly limit.
    /// </summary>
    /// <remarks>
    /// The local count can disagree with the CA's: a certificate issued by another tool for the
    /// same domain, or an order this server never recorded, both count against the CA's tally
    /// and not ours. Stopping one short of the published figure means a disagreement produces a
    /// local refusal the operator can read rather than a CA rejection that costs a slot.
    /// </remarks>
    public int SafetyMargin { get; init; } = 1;

    /// <summary>
    /// Decides whether an order may be submitted.
    /// </summary>
    /// <param name="certificatesForRegisteredDomain">Issued for the registered domain inside the weekly window.</param>
    /// <param name="duplicateCertificates">Issued for this exact identifier set inside the weekly window.</param>
    /// <param name="recentFailedValidations">Failed validations for these identifiers inside the failure window.</param>
    /// <param name="oldestRelevantAttemptUtc">
    /// The oldest attempt still inside the binding window, used to say when the limit clears.
    /// Null when nothing is recorded.
    /// </param>
    /// <param name="now">The current instant.</param>
    /// <remarks>
    /// Checked most-specific first. An operator who has hit both the duplicate limit and the
    /// failed-validation limit needs to hear about the failures, because that is the one they
    /// caused and the one they can fix.
    /// </remarks>
    public RateLimitDecision Evaluate(
        int certificatesForRegisteredDomain,
        int duplicateCertificates,
        int recentFailedValidations,
        DateTimeOffset? oldestRelevantAttemptUtc,
        DateTimeOffset now)
    {
        if (recentFailedValidations >= FailedValidationsPerHostnamePerHour)
        {
            return new RateLimitDecision(
                false,
                $"{recentFailedValidations} validation(s) have failed for these hostnames in " +
                $"the last hour, and the limit is {FailedValidationsPerHostnamePerHour} per " +
                "hour. Retrying will not succeed and each attempt extends the block. Fix the " +
                "underlying problem first — usually DNS not pointing here, or inbound port 80 " +
                "blocked upstream — and verify it from outside your own network.",
                oldestRelevantAttemptUtc?.Add(FailureWindow) ?? now.Add(FailureWindow));
        }

        if (duplicateCertificates >= DuplicateCertificatesPerWeek - SafetyMargin)
        {
            return new RateLimitDecision(
                false,
                $"{duplicateCertificates} certificate(s) have already been issued this week for " +
                "this exact set of hostnames, and the limit is " +
                $"{DuplicateCertificatesPerWeek} per week. Use the staging directory to test " +
                "changes; staging certificates are not publicly trusted but cost no production " +
                "quota.",
                oldestRelevantAttemptUtc?.Add(WeeklyWindow) ?? now.Add(WeeklyWindow));
        }

        if (certificatesForRegisteredDomain >= CertificatesPerRegisteredDomainPerWeek - SafetyMargin)
        {
            return new RateLimitDecision(
                false,
                $"{certificatesForRegisteredDomain} certificate(s) have been issued for this " +
                $"registered domain this week, and the limit is " +
                $"{CertificatesPerRegisteredDomainPerWeek} per week across every subdomain.",
                oldestRelevantAttemptUtc?.Add(WeeklyWindow) ?? now.Add(WeeklyWindow));
        }

        return RateLimitDecision.Allowed;
    }
}
