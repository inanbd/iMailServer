namespace MailServer.Application.Abstractions.Time;

/// <summary>
/// The current time, injected rather than taken from <see cref="DateTimeOffset.UtcNow"/>.
/// </summary>
/// <remarks>
/// <para>
/// Mail is full of time-dependent logic: retry backoff, certificate expiry thresholds, DKIM
/// key rotation windows, queue lifetime, lockout windows, DNS TTLs. None of that can be
/// tested honestly against the wall clock, and tests that sleep to advance time are slow and
/// flaky.
/// </para>
/// <para>
/// Always UTC. A mail server that stores local times breaks twice a year, and breaks
/// differently depending on where it is installed.
/// </para>
/// </remarks>
public interface IClock
{
    /// <summary>The current instant, in UTC.</summary>
    DateTimeOffset UtcNow { get; }

    /// <summary>
    /// A monotonic timestamp for measuring elapsed time. Unlike <see cref="UtcNow"/>, this
    /// is unaffected by NTP corrections, so a clock step during a long delivery cannot make
    /// a duration come out negative.
    /// </summary>
    long GetTimestamp();

    /// <summary>Elapsed time since a timestamp from <see cref="GetTimestamp"/>.</summary>
    TimeSpan GetElapsedTime(long startingTimestamp);
}
