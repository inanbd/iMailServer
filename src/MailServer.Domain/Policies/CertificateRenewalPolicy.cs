using MailServer.Domain.Enums;

namespace MailServer.Domain.Policies;

/// <summary>What the lifecycle service should do about a certificate right now.</summary>
public enum RenewalAction
{
    /// <summary>Nothing. Well clear of expiry.</summary>
    None = 0,

    /// <summary>Inside the renewal window: attempt renewal, but nothing is broken yet.</summary>
    Renew = 1,

    /// <summary>
    /// Expired, or so close to it that an outage is imminent. Renewal is attempted and the
    /// operator is alerted regardless of whether it succeeds.
    /// </summary>
    RenewUrgently = 2,
}

/// <summary>
/// When to renew a certificate, how loudly to complain as expiry approaches, and — most
/// importantly — what must never happen when renewal fails.
/// </summary>
/// <remarks>
/// <para>
/// A policy object rather than constants scattered through a background service, for the same
/// reason as <see cref="LockoutPolicy"/>: the thresholds are a decision worth testing on their
/// own, and a decision worth being able to read in one place.
/// </para>
/// <para>
/// The windows are chosen against Let's Encrypt's 90-day lifetime. Renewing at 30 days leaves
/// three full weeks of retries before anything breaks, which is what makes a transient DNS or
/// rate-limit failure a non-event rather than an incident.
/// </para>
/// </remarks>
public sealed class CertificateRenewalPolicy
{
    /// <summary>Days before expiry at which renewal is first attempted.</summary>
    public int RenewalWindowDays { get; init; } = 30;

    /// <summary>
    /// Days remaining at which health severity escalates.
    /// </summary>
    /// <remarks>
    /// Four steps rather than one, because a single alert at 30 days is read once and
    /// forgotten, and a single alert at 1 day arrives too late to act on. Escalation is what
    /// makes an ignored warning become impossible to ignore while there is still time.
    /// </remarks>
    public IReadOnlyList<int> EscalationThresholdDays { get; init; } = [30, 21, 14, 7];

    /// <summary>Days remaining below which the situation is treated as urgent.</summary>
    public int UrgentThresholdDays { get; init; } = 7;

    /// <summary>
    /// Never true, and it is a property rather than an absence so that the rule is visible in
    /// the model and assertable in a test.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The non-negotiable rule.</b> When renewal fails while the current certificate is
    /// still valid, the current certificate is kept. A self-signed certificate is never
    /// substituted for one from any other source.
    /// </para>
    /// <para>
    /// The reasoning is about blast radius. A failed renewal on a certificate with three weeks
    /// left is a warning affecting nobody. Replacing it with a self-signed certificate is an
    /// immediate, simultaneous TLS failure against every remote MTA that verifies peers and
    /// every mail client in the organisation — converting a problem the operator has time to
    /// fix into an outage they must fix now, caused by the software's own attempt to be
    /// helpful.
    /// </para>
    /// </remarks>
    public static bool MayDowngradeToSelfSignedOnRenewalFailure => false;

    /// <summary>
    /// The warning shown verbatim on every surface that displays a self-signed certificate.
    /// </summary>
    /// <remarks>
    /// Held here, as one constant, because "verbatim" is only meaningful if there is exactly
    /// one copy. Three hand-typed variants in three views is how a warning quietly softens
    /// into a hint.
    /// </remarks>
    public const string SelfSignedWarning =
        "SELF-SIGNED CERTIFICATES ARE NOT PUBLICLY TRUSTED.\n" +
        "MAIL CLIENTS AND REMOTE SYSTEMS MAY DISPLAY CERTIFICATE WARNINGS.\n" +
        "USE LET'S ENCRYPT OR ANOTHER PUBLIC CA FOR INTERNET-FACING PRODUCTION SERVERS.";

    /// <summary>Decides what to do about a certificate with this much life left.</summary>
    public RenewalAction GetAction(int daysRemaining) => daysRemaining switch
    {
        _ when daysRemaining <= UrgentThresholdDays => RenewalAction.RenewUrgently,
        _ when daysRemaining <= RenewalWindowDays => RenewalAction.Renew,
        _ => RenewalAction.None,
    };

    /// <summary>
    /// Maps days remaining to a health state.
    /// </summary>
    /// <remarks>
    /// Expired is <see cref="HealthState.Critical"/> rather than Warning: at that point
    /// every verifying peer is refusing the connection, which is not a degradation.
    /// </remarks>
    public HealthState GetHealthState(int daysRemaining)
    {
        if (daysRemaining <= 0)
        {
            return HealthState.Critical;
        }

        if (daysRemaining <= UrgentThresholdDays)
        {
            return HealthState.Critical;
        }

        return daysRemaining <= RenewalWindowDays
            ? HealthState.Warning
            : HealthState.Healthy;
    }

    /// <summary>
    /// The escalation step this many days out, or null when none has been crossed.
    /// </summary>
    /// <remarks>
    /// Returns the <i>lowest</i> threshold crossed, so an alert at 20 days reports the
    /// 21-day step and an alert at 6 reports the 7-day step. Reporting the highest would
    /// mean every alert from 30 days onward said "30 days", and the escalation would be
    /// invisible to the person reading it.
    /// </remarks>
    public int? GetEscalationThreshold(int daysRemaining)
    {
        int? crossed = null;

        foreach (int threshold in EscalationThresholdDays)
        {
            if (daysRemaining <= threshold && (crossed is null || threshold < crossed))
            {
                crossed = threshold;
            }
        }

        return crossed;
    }
}
