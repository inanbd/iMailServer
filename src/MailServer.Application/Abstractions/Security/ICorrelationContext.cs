using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Security;

/// <summary>
/// Carries the correlation identifier for the operation in flight.
/// </summary>
/// <remarks>
/// Scoped, not static: brief rule 111 forbids static mutable state, and an ambient static
/// correlation id leaks across concurrent SMTP sessions in ways that are effectively
/// impossible to debug because the log lines then lie about which session did what.
/// </remarks>
public interface ICorrelationContext
{
    /// <summary>The correlation identifier for this operation.</summary>
    CorrelationId CorrelationId { get; }

    /// <summary>
    /// Sets the correlation identifier. Called once, at the outermost pipeline behavior or
    /// at the session boundary. Later calls are ignored so that a handler cannot re-label an
    /// operation halfway through and break the trace.
    /// </summary>
    void Initialize(CorrelationId correlationId);
}
