namespace MailServer.Domain.Exceptions;

/// <summary>
/// A referenced aggregate does not exist.
/// </summary>
/// <remarks>
/// The message deliberately includes the entity type and identifier because this exception
/// is only ever surfaced to an authenticated administrator. It is never returned to an
/// unauthenticated SMTP or IMAP peer, where confirming or denying the existence of a
/// mailbox is an enumeration oracle.
/// </remarks>
public sealed class EntityNotFoundException : DomainException
{
    public EntityNotFoundException(string entityType, string identifier)
        : base($"{entityType.ToLowerInvariant()}.not_found",
               $"{entityType} '{identifier}' was not found.")
    {
        EntityType = entityType;
        Identifier = identifier;
    }

    public string EntityType { get; }

    public string Identifier { get; }
}
