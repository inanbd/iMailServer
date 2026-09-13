using System.Windows.Threading;

namespace MailServer.Admin.Services;

/// <summary>Watches for administrator inactivity so the console can lock itself.</summary>
public interface IIdleMonitor : IDisposable
{
    /// <summary>Raised on the UI thread once the idle period elapses.</summary>
    event EventHandler? IdleTimeoutElapsed;

    /// <summary>Starts watching, with the timeout the service reported for this session.</summary>
    void Start(TimeSpan timeout);

    /// <summary>Stops watching.</summary>
    void Stop();

    /// <summary>Resets the timer. Called on any administrator interaction.</summary>
    void RecordActivity();
}

/// <summary>
/// Dispatcher-timer idle monitor.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the convenience half of auto-lock, not the control.</b> The service enforces the
/// same idle timeout on the session itself, so a modified client that declined to lock would
/// still find its next request refused with <c>Unauthenticated</c>. What this provides is a
/// screen that clears promptly when somebody walks away, rather than one that stays showing
/// mailbox data until the next request happens to be made.
/// </para>
/// <para>
/// It ticks at a fraction of the timeout rather than once at the deadline, so that activity
/// recorded midway does not require tearing down and recreating a timer on every keystroke.
/// </para>
/// </remarks>
public sealed class IdleMonitor : IIdleMonitor
{
    /// <summary>Number of ticks per timeout period. Four gives adequate resolution cheaply.</summary>
    private const int TicksPerPeriod = 4;

    private readonly DispatcherTimer _timer = new(DispatcherPriority.Background);

    private TimeSpan _timeout = TimeSpan.FromMinutes(10);
    private DateTimeOffset _lastActivityUtc = DateTimeOffset.UtcNow;
    private bool _disposed;

    public IdleMonitor() => _timer.Tick += OnTick;

    public event EventHandler? IdleTimeoutElapsed;

    public void Start(TimeSpan timeout)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Clamped: a service reporting a nonsensical timeout must not produce a timer that
        // either never fires or fires continuously.
        _timeout = TimeSpan.FromSeconds(Math.Clamp(timeout.TotalSeconds, 60, 24 * 60 * 60));

        _lastActivityUtc = DateTimeOffset.UtcNow;
        _timer.Interval = TimeSpan.FromSeconds(
            Math.Max(5, _timeout.TotalSeconds / TicksPerPeriod));

        _timer.Start();
    }

    public void Stop() => _timer.Stop();

    public void RecordActivity() => _lastActivityUtc = DateTimeOffset.UtcNow;

    private void OnTick(object? sender, EventArgs e)
    {
        if (DateTimeOffset.UtcNow - _lastActivityUtc < _timeout)
        {
            return;
        }

        // Stop before raising: locking is not instantaneous, and a second tick arriving during
        // the sign-out round trip would raise the event again.
        _timer.Stop();
        IdleTimeoutElapsed?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        _timer.Stop();
        _timer.Tick -= OnTick;
    }
}
