namespace MailServer.Domain.Exceptions;

/// <summary>
/// Base type for every violation of a domain rule.
/// </summary>
/// <remarks>
/// Domain exceptions carry a stable machine-readable <see cref="Code"/> in addition to the
/// human-readable message. The code is what the IPC layer and the UI switch on; the message
/// is what an administrator reads. Localising or rewording a message must never break a
/// caller, which is why callers are given a code to work with.
/// </remarks>
public abstract class DomainException : Exception
{
    protected DomainException(string code, string message) : base(message) => Code = code;

    protected DomainException(string code, string message, Exception innerException)
        : base(message, innerException) => Code = code;

    /// <summary>Stable, machine-readable identifier, e.g. <c>domain.name.invalid</c>.</summary>
    public string Code { get; }
}
