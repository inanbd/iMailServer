namespace MailServer.Domain.Exceptions;

/// <summary>
/// An operation was rejected because it would have broken an aggregate's invariant.
/// </summary>
public sealed class DomainRuleViolationException : DomainException
{
    public DomainRuleViolationException(string code, string message) : base(code, message)
    {
    }
}
