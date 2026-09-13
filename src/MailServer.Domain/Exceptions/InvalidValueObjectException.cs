namespace MailServer.Domain.Exceptions;

/// <summary>
/// A value object was handed input it cannot represent.
/// </summary>
/// <remarks>
/// Value objects validate in their constructor, so an instance that exists is always valid.
/// Callers that expect invalid input as a normal occurrence (anything parsing data from a
/// network peer or an administrator's form) should use the <c>TryParse</c> overload instead
/// of catching this, because exceptions on a hot path such as SMTP address parsing are far
/// too expensive.
/// </remarks>
public sealed class InvalidValueObjectException : DomainException
{
    public InvalidValueObjectException(string valueObjectName, string reason)
        : base($"value.{valueObjectName.ToLowerInvariant()}.invalid",
               $"{valueObjectName} is invalid: {reason}")
    {
        ValueObjectName = valueObjectName;
        Reason = reason;
    }

    public string ValueObjectName { get; }

    public string Reason { get; }
}
