using System.Collections.Concurrent;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Enums;

namespace MailServer.Infrastructure.Monitoring;

/// <summary>
/// In-memory registry of the latest health reading per subsystem.
/// </summary>
/// <remarks>
/// <para>
/// Push-based and lock-free on the publish path. Workers publish as their state changes, and
/// <see cref="Publish(HealthReading)"/> is a single dictionary write that cannot block. A
/// health system able to stall the SMTP accept loop would be a liability rather than an
/// asset, so the publish path is designed to be uninterruptible.
/// </para>
/// <para>
/// Singleton, and deliberately not persisted: health is a statement about the process
/// running right now. Reading a stale "Healthy" from before a restart would be actively
/// misleading.
/// </para>
/// </remarks>
public sealed class HealthRegistry(IClock clock) : IHealthRegistry
{
    private readonly ConcurrentDictionary<string, HealthReading> _readings =
        new(StringComparer.OrdinalIgnoreCase);

    public void Publish(HealthReading reading)
    {
        ArgumentNullException.ThrowIfNull(reading);
        _readings[reading.Component] = reading;
    }

    public void Publish(string component, HealthState state, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(component);
        Publish(new HealthReading(component, state, message, clock.UtcNow));
    }

    public IReadOnlyList<HealthReading> GetAll() => [.. _readings.Values];

    public HealthReading? Get(string component) =>
        _readings.TryGetValue(component, out HealthReading? reading) ? reading : null;

    public HealthState GetOverallState()
    {
        HealthState worst = HealthState.Healthy;
        bool any = false;

        foreach (HealthReading reading in _readings.Values)
        {
            any = true;

            // Critical dominates; Unknown is treated as worse than Healthy but better than
            // Warning, because "we could not determine this" should draw attention without
            // outranking a confirmed degradation.
            if (reading.State == HealthState.Critical)
            {
                return HealthState.Critical;
            }

            if (reading.State == HealthState.Warning && worst != HealthState.Warning)
            {
                worst = HealthState.Warning;
            }
            else if (reading.State == HealthState.Unknown && worst == HealthState.Healthy)
            {
                worst = HealthState.Unknown;
            }
        }

        return any ? worst : HealthState.Unknown;
    }
}
