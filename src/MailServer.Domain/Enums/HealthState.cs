namespace MailServer.Domain.Enums;

/// <summary>
/// The four-state health vocabulary used consistently everywhere in the product: health
/// checks, certificate status, deliverability checks and the service dashboard.
/// </summary>
/// <remarks>
/// One vocabulary, reused everywhere, is a deliberate UX decision. An administrator learns
/// four words once rather than a different colour scheme per screen.
/// </remarks>
public enum HealthState
{
    /// <summary>The check has not run, or could not reach what it needed to evaluate.</summary>
    Unknown = 0,

    /// <summary>Operating correctly.</summary>
    Healthy = 1,

    /// <summary>Degraded, or heading toward a failure that has not happened yet.</summary>
    Warning = 2,

    /// <summary>Failing now, or certain to fail imminently. Requires attention.</summary>
    Critical = 3,
}
