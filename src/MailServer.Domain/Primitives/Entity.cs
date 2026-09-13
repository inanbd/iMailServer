namespace MailServer.Domain.Primitives;

/// <summary>
/// Base class for entities: objects with a stable identity whose attributes may change.
/// </summary>
/// <typeparam name="TId">
/// The strongly-typed identifier. Strong typing is deliberate: a method that accepts a
/// <c>MailboxId</c> cannot silently be handed a <c>DomainId</c>, which turns a whole class
/// of data-loss bug into a compile error.
/// </typeparam>
public abstract class Entity<TId> : IEquatable<Entity<TId>>
    where TId : struct, IEquatable<TId>
{
    protected Entity(TId id) => Id = id;

    public TId Id { get; }

    /// <summary>
    /// Entity equality is identity equality. Two <see cref="Entity{TId}"/> instances with
    /// the same identifier are the same entity even if their attributes differ, because
    /// one of them is simply staler than the other.
    /// </summary>
    public bool Equals(Entity<TId>? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        // Subclass check prevents a Mailbox and an Alias sharing a GUID from comparing equal.
        return GetType() == other.GetType() && Id.Equals(other.Id);
    }

    public override bool Equals(object? obj) => Equals(obj as Entity<TId>);

    public override int GetHashCode() => HashCode.Combine(GetType(), Id);

    public static bool operator ==(Entity<TId>? left, Entity<TId>? right) =>
        left?.Equals(right) ?? right is null;

    public static bool operator !=(Entity<TId>? left, Entity<TId>? right) => !(left == right);
}
