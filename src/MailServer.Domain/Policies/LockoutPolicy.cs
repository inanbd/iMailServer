using MailServer.Domain.Exceptions;

namespace MailServer.Domain.Policies;

/// <summary>
/// Decides when repeated authentication failures should lock an account, and for how long.
/// </summary>
/// <remarks>
/// <para>
/// A pure policy: no clock, no storage, no configuration object. Every decision is a function
/// of the failure count and the two timestamps passed in, which makes the whole thing
/// exhaustively testable without sleeping.
/// </para>
/// <para>
/// <b>Escalating rather than fixed.</b> A fixed 15-minute lockout after five failures gives an
/// attacker a steady, predictable budget: five guesses every fifteen minutes, forever. Doubling
/// the window on each subsequent lockout turns a sustained campaign into hours of waiting for a
/// handful of attempts, while a legitimate administrator who mistyped twice is barely
/// inconvenienced.
/// </para>
/// <para>
/// <b>Why lock at all, given the pipe is already ACL'd.</b> The named pipe admits only local
/// administrators, so an attacker at this point already has significant access. Lockout still
/// matters: it turns a silent, automated offline-speed guessing run into something slow and
/// loudly audited, and it protects against a compromised-but-unprivileged foothold escalating
/// through a weak master password.
/// </para>
/// </remarks>
public sealed class LockoutPolicy
{
    /// <summary>Failures before the first lockout.</summary>
    public const int DefaultThreshold = 5;

    /// <summary>Duration of the first lockout.</summary>
    public static readonly TimeSpan DefaultInitialDuration = TimeSpan.FromMinutes(15);

    /// <summary>Ceiling on the escalated duration.</summary>
    public static readonly TimeSpan DefaultMaximumDuration = TimeSpan.FromHours(8);

    /// <summary>
    /// Idle period after which the failure counter resets.
    /// </summary>
    /// <remarks>
    /// Without this, three mistypes spread across a year would eventually lock an account that
    /// is under no attack at all.
    /// </remarks>
    public static readonly TimeSpan DefaultCounterResetWindow = TimeSpan.FromHours(1);

    private readonly int _threshold;
    private readonly TimeSpan _initialDuration;
    private readonly TimeSpan _maximumDuration;
    private readonly TimeSpan _counterResetWindow;

    public LockoutPolicy(
        int threshold = DefaultThreshold,
        TimeSpan? initialDuration = null,
        TimeSpan? maximumDuration = null,
        TimeSpan? counterResetWindow = null)
    {
        if (threshold < 1)
        {
            throw new DomainRuleViolationException(
                "lockout.threshold.invalid",
                "The lockout threshold must be at least 1.");
        }

        TimeSpan initial = initialDuration ?? DefaultInitialDuration;
        TimeSpan maximum = maximumDuration ?? DefaultMaximumDuration;

        if (initial <= TimeSpan.Zero)
        {
            throw new DomainRuleViolationException(
                "lockout.duration.invalid",
                "The initial lockout duration must be positive.");
        }

        if (maximum < initial)
        {
            throw new DomainRuleViolationException(
                "lockout.duration.inverted",
                "The maximum lockout duration cannot be shorter than the initial duration.");
        }

        _threshold = threshold;
        _initialDuration = initial;
        _maximumDuration = maximum;
        _counterResetWindow = counterResetWindow ?? DefaultCounterResetWindow;
    }

    /// <summary>Failures tolerated before a lockout begins.</summary>
    public int Threshold => _threshold;

    /// <summary>How long the counter may sit idle before it resets.</summary>
    public TimeSpan CounterResetWindow => _counterResetWindow;

    /// <summary>
    /// True when the failure counter should be treated as zero because the last failure is old
    /// enough to be unrelated.
    /// </summary>
    public bool ShouldResetCounter(DateTimeOffset? lastFailureUtc, DateTimeOffset nowUtc) =>
        lastFailureUtc is null || nowUtc - lastFailureUtc.Value >= _counterResetWindow;

    /// <summary>True when this many consecutive failures warrants a lockout.</summary>
    public bool ShouldLock(int consecutiveFailures) => consecutiveFailures >= _threshold;

    /// <summary>
    /// The lockout duration for a given number of consecutive failures.
    /// </summary>
    /// <remarks>
    /// Doubles for each full multiple of the threshold beyond the first, capped. With the
    /// defaults: 5 failures gives 15 minutes, 10 gives 30, 15 gives 1 hour, and so on to the
    /// 8-hour ceiling.
    /// </remarks>
    public TimeSpan GetLockoutDuration(int consecutiveFailures)
    {
        if (consecutiveFailures < _threshold)
        {
            return TimeSpan.Zero;
        }

        int escalations = (consecutiveFailures / _threshold) - 1;

        // Bound the exponent before computing, so a large counter cannot overflow the double.
        escalations = Math.Min(escalations, 32);

        double ticks = _initialDuration.Ticks * Math.Pow(2, escalations);

        return ticks >= _maximumDuration.Ticks
            ? _maximumDuration
            : TimeSpan.FromTicks((long)ticks);
    }

    /// <summary>
    /// When a lockout that began now would end.
    /// </summary>
    public DateTimeOffset GetLockoutExpiry(int consecutiveFailures, DateTimeOffset nowUtc) =>
        nowUtc + GetLockoutDuration(consecutiveFailures);

    /// <summary>True when a lockout expiring at the given instant is still in force.</summary>
    public static bool IsLockedOut(DateTimeOffset? lockedOutUntilUtc, DateTimeOffset nowUtc) =>
        lockedOutUntilUtc is not null && lockedOutUntilUtc.Value > nowUtc;

    /// <summary>Time left on a lockout, or zero if it has expired.</summary>
    public static TimeSpan GetRemainingLockout(DateTimeOffset? lockedOutUntilUtc, DateTimeOffset nowUtc) =>
        IsLockedOut(lockedOutUntilUtc, nowUtc)
            ? lockedOutUntilUtc!.Value - nowUtc
            : TimeSpan.Zero;
}
