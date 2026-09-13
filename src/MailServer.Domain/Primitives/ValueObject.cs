namespace MailServer.Domain.Primitives;

/// <summary>
/// Base class for multi-component value objects: objects with no identity, compared by
/// the whole of their state, and immutable once constructed.
/// </summary>
/// <remarks>
/// Single-component value objects (<c>DomainName</c>, <c>EmailAddress</c>, the strongly-typed
/// ids) do not use this base - they implement <see cref="IEquatable{T}"/> directly or are
/// record structs, which is cheaper and clearer.
/// </remarks>
public abstract class ValueObject : IEquatable<ValueObject>
{
    /// <summary>Yields each component that participates in equality, in a stable order.</summary>
    protected abstract IEnumerable<object?> GetEqualityComponents();

    public bool Equals(ValueObject? other)
    {
        if (other is null || other.GetType() != GetType())
        {
            return false;
        }

        return GetEqualityComponents().SequenceEqual(other.GetEqualityComponents());
    }

    public override bool Equals(object? obj) => Equals(obj as ValueObject);

    public override int GetHashCode()
    {
        HashCode hash = new();
        foreach (object? component in GetEqualityComponents())
        {
            hash.Add(component);
        }

        return hash.ToHashCode();
    }

    public static bool operator ==(ValueObject? left, ValueObject? right) =>
        left?.Equals(right) ?? right is null;

    public static bool operator !=(ValueObject? left, ValueObject? right) => !(left == right);
}
