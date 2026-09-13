namespace MailServer.Domain.Primitives;

/// <summary>
/// An entity that is the consistency boundary for a cluster of objects.
/// </summary>
/// <remarks>
/// <para>
/// Only aggregate roots get repositories. Everything inside an aggregate is loaded and
/// saved through its root, which is what makes the root's invariants enforceable: there
/// is no way to reach the inner objects and mutate them behind its back.
/// </para>
/// <para>
/// Aggregate roots collect domain events. The Application layer drains them after the
/// transaction commits, so a handler can never observe an event describing a change that
/// was subsequently rolled back.
/// </para>
/// </remarks>
public abstract class AggregateRoot<TId> : Entity<TId>
    where TId : struct, IEquatable<TId>
{
    private readonly List<IDomainEvent> _domainEvents = [];

    protected AggregateRoot(TId id) : base(id)
    {
    }

    /// <summary>Events raised since this aggregate was loaded, in the order they occurred.</summary>
    public IReadOnlyList<IDomainEvent> DomainEvents => _domainEvents;

    protected void Raise(IDomainEvent domainEvent)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        _domainEvents.Add(domainEvent);
    }

    /// <summary>
    /// Removes and returns every pending event. Called by the Application layer after
    /// commit; draining rather than clearing prevents an event from being published twice.
    /// </summary>
    public IReadOnlyList<IDomainEvent> DrainDomainEvents()
    {
        if (_domainEvents.Count == 0)
        {
            return [];
        }

        IDomainEvent[] drained = [.. _domainEvents];
        _domainEvents.Clear();
        return drained;
    }
}
