namespace MailServer.Domain.Primitives;

/// <summary>
/// A fact that has already happened inside the domain.
/// </summary>
/// <remarks>
/// Domain events are raised by aggregates and drained by the Application layer after the
/// owning transaction commits. They are deliberately free of any dispatch mechanism: the
/// Domain layer neither knows nor cares that MediatR exists.
/// </remarks>
public interface IDomainEvent
{
    /// <summary>Instant, in UTC, at which the fact became true.</summary>
    DateTimeOffset OccurredUtc { get; }
}
