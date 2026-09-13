using MailServer.Domain.Exceptions;

namespace MailServer.Domain.Policies;

/// <summary>
/// Computes when a deferred delivery should next be attempted.
/// </summary>
/// <remarks>
/// <para>
/// A pure policy with no dependencies, living in the Domain layer, because retry timing is
/// a business rule with real consequences: too aggressive and the destination throttles or
/// blocklists the sending IP; too lax and legitimate mail sits in the queue for hours after
/// a transient failure has cleared.
/// </para>
/// <para>
/// Being pure makes it exhaustively unit-testable without a clock, a database or a socket,
/// which matters because the failure mode of a retry bug - a retry storm aimed at Gmail -
/// is expensive and hard to reverse.
/// </para>
/// </remarks>
public sealed class RetryBackoffPolicy
{
    /// <summary>
    /// The default schedule, in minutes: 1m, 5m, 15m, 30m, 1h, 2h, 4h, 8h. Attempts beyond
    /// the last entry repeat at that final interval until the message expires.
    /// </summary>
    public static readonly IReadOnlyList<int> DefaultScheduleMinutes =
        [1, 5, 15, 30, 60, 120, 240, 480];

    /// <summary>Default time after which an undeliverable message is bounced: 5 days.</summary>
    public static readonly TimeSpan DefaultMaximumLifetime = TimeSpan.FromDays(5);

    /// <summary>Default delay before a "delivery is delayed" warning DSN is sent: 4 hours.</summary>
    public static readonly TimeSpan DefaultDelayWarningThreshold = TimeSpan.FromHours(4);

    private readonly IReadOnlyList<int> _scheduleMinutes;
    private readonly double _jitterFraction;

    /// <param name="scheduleMinutes">Backoff intervals in minutes, ascending.</param>
    /// <param name="maximumLifetime">How long to keep retrying before bouncing.</param>
    /// <param name="delayWarningThreshold">When to send a delay-warning DSN.</param>
    /// <param name="jitterFraction">
    /// Fraction of the interval used as random jitter, 0.0 to 0.5. Jitter matters: without
    /// it, a destination outage synchronises every deferred message onto the same retry
    /// instant, and the recovery produces a thundering herd aimed at a server that has only
    /// just come back.
    /// </param>
    public RetryBackoffPolicy(
        IReadOnlyList<int>? scheduleMinutes = null,
        TimeSpan? maximumLifetime = null,
        TimeSpan? delayWarningThreshold = null,
        double jitterFraction = 0.15)
    {
        IReadOnlyList<int> schedule = scheduleMinutes ?? DefaultScheduleMinutes;

        if (schedule.Count == 0)
        {
            throw new DomainRuleViolationException(
                "retry.schedule.empty",
                "The retry schedule must contain at least one interval.");
        }

        for (int i = 0; i < schedule.Count; i++)
        {
            if (schedule[i] <= 0)
            {
                throw new DomainRuleViolationException(
                    "retry.schedule.non_positive",
                    $"Retry interval at position {i} is {schedule[i]} minutes; intervals must be positive.");
            }

            if (i > 0 && schedule[i] < schedule[i - 1])
            {
                throw new DomainRuleViolationException(
                    "retry.schedule.not_ascending",
                    "Retry intervals must not decrease: a backoff that shortens over time " +
                    "attacks the destination rather than backing off from it.");
            }
        }

        if (jitterFraction is < 0 or > 0.5)
        {
            throw new DomainRuleViolationException(
                "retry.jitter.out_of_range",
                "The jitter fraction must be between 0.0 and 0.5.");
        }

        _scheduleMinutes = schedule;
        _jitterFraction = jitterFraction;
        MaximumLifetime = maximumLifetime ?? DefaultMaximumLifetime;
        DelayWarningThreshold = delayWarningThreshold ?? DefaultDelayWarningThreshold;
    }

    /// <summary>How long to keep retrying before generating a permanent failure DSN.</summary>
    public TimeSpan MaximumLifetime { get; }

    /// <summary>Age at which a "delivery delayed" warning DSN is generated.</summary>
    public TimeSpan DelayWarningThreshold { get; }

    /// <summary>Number of configured intervals before the schedule plateaus.</summary>
    public int ScheduleLength => _scheduleMinutes.Count;

    /// <summary>
    /// The base interval before attempt number <paramref name="attemptNumber"/>, excluding
    /// jitter. Attempt 1 is the first retry, i.e. the one after the initial delivery failed.
    /// </summary>
    public TimeSpan GetInterval(int attemptNumber)
    {
        if (attemptNumber < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(attemptNumber),
                attemptNumber,
                "Attempt numbers start at 1.");
        }

        int index = Math.Min(attemptNumber - 1, _scheduleMinutes.Count - 1);
        return TimeSpan.FromMinutes(_scheduleMinutes[index]);
    }

    /// <summary>
    /// Computes the next attempt time, applying jitter.
    /// </summary>
    /// <param name="attemptNumber">The attempt that has just failed, 1-based.</param>
    /// <param name="nowUtc">Current time.</param>
    /// <param name="randomSource">
    /// Source of jitter in [0,1). Injected rather than taken from a static Random so the
    /// policy stays pure and its tests stay deterministic.
    /// </param>
    public DateTimeOffset GetNextAttemptUtc(
        int attemptNumber,
        DateTimeOffset nowUtc,
        Func<double>? randomSource = null)
    {
        TimeSpan interval = GetInterval(attemptNumber);

        if (_jitterFraction > 0)
        {
            double sample = randomSource?.Invoke() ?? Random.Shared.NextDouble();
            sample = Math.Clamp(sample, 0d, 1d);

            // Map [0,1) onto [-jitter, +jitter] so the mean interval is unchanged.
            double offset = (sample * 2d - 1d) * _jitterFraction;
            interval = TimeSpan.FromTicks((long)(interval.Ticks * (1d + offset)));
        }

        return nowUtc + interval;
    }

    /// <summary>
    /// True when a message first queued at <paramref name="firstQueuedUtc"/> has exhausted
    /// its lifetime and must now be bounced.
    /// </summary>
    public bool HasExpired(DateTimeOffset firstQueuedUtc, DateTimeOffset nowUtc) =>
        nowUtc - firstQueuedUtc >= MaximumLifetime;

    /// <summary>
    /// True when a delay-warning DSN is now due and has not already been sent.
    /// </summary>
    public bool ShouldSendDelayWarning(
        DateTimeOffset firstQueuedUtc,
        DateTimeOffset nowUtc,
        bool warningAlreadySent) =>
        !warningAlreadySent && nowUtc - firstQueuedUtc >= DelayWarningThreshold;
}
