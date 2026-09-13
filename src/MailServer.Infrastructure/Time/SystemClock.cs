using System.Diagnostics;
using MailServer.Application.Abstractions.Time;

namespace MailServer.Infrastructure.Time;

/// <summary>
/// The real clock.
/// </summary>
/// <remarks>
/// Elapsed time comes from <see cref="Stopwatch"/>'s monotonic counter, not from subtracting
/// two wall-clock readings. A mail server runs for months, NTP corrects the wall clock while
/// it does so, and a delivery that appears to have taken minus four seconds produces
/// nonsense in the metrics and, worse, in retry scheduling.
/// </remarks>
public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public long GetTimestamp() => Stopwatch.GetTimestamp();

    public TimeSpan GetElapsedTime(long startingTimestamp) =>
        Stopwatch.GetElapsedTime(startingTimestamp);
}
