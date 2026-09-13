using MailServer.Domain.Enums;

namespace MailServer.Application.Abstractions.Monitoring;

/// <summary>The health of one subsystem at a point in time.</summary>
/// <param name="Component">Subsystem name, e.g. <c>SmtpInbound</c>.</param>
/// <param name="State">Current state.</param>
/// <param name="Message">Human-readable summary. Must never contain a secret.</param>
/// <param name="ObservedUtc">When this reading was taken.</param>
/// <param name="Data">Optional structured detail for the UI.</param>
public sealed record HealthReading(
    string Component,
    HealthState State,
    string Message,
    DateTimeOffset ObservedUtc,
    IReadOnlyDictionary<string, string>? Data = null);

/// <summary>
/// Collects health readings from every subsystem.
/// </summary>
/// <remarks>
/// <para>
/// Push-based rather than pull-based. A background worker knows its own state continuously;
/// asking it on demand would require it to expose internals or to re-run work it has
/// already done. Workers publish as their state changes, and the registry holds the latest
/// reading per component.
/// </para>
/// <para>
/// The registry never blocks a publisher. A health system that can stall the SMTP path is
/// a liability, not an asset.
/// </para>
/// </remarks>
public interface IHealthRegistry
{
    /// <summary>Records the current state of a component, replacing its previous reading.</summary>
    void Publish(HealthReading reading);

    /// <summary>Convenience overload.</summary>
    void Publish(string component, HealthState state, string message);

    /// <summary>The latest reading for every component that has reported.</summary>
    IReadOnlyList<HealthReading> GetAll();

    /// <summary>The latest reading for one component, or null if it has never reported.</summary>
    HealthReading? Get(string component);

    /// <summary>
    /// The worst state across all components - the single value shown in the admin
    /// application's status strip.
    /// </summary>
    HealthState GetOverallState();
}
