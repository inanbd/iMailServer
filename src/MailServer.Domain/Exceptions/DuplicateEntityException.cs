namespace MailServer.Domain.Exceptions;

/// <summary>
/// An aggregate with the same natural key already exists.
/// </summary>
/// <remarks>
/// This is raised by the Application layer after a pre-check, and also mapped from the
/// database's unique-constraint violation. Both paths exist on purpose: the pre-check gives
/// a good error message, and the constraint is what actually guarantees correctness under
/// concurrency.
/// </remarks>
public sealed class DuplicateEntityException : DomainException
{
    public DuplicateEntityException(string entityType, string identifier)
        : base($"{entityType.ToLowerInvariant()}.duplicate",
               $"{entityType} '{identifier}' already exists.")
    {
        EntityType = entityType;
        Identifier = identifier;
    }

    public string EntityType { get; }

    public string Identifier { get; }
}
