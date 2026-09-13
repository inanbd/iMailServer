using MailServer.Application.Abstractions.Security;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// Scoped holder for the correlation identifier of the operation in flight.
/// </summary>
/// <remarks>
/// Registered <b>scoped</b>, never static and never <c>AsyncLocal</c>. Brief rule 111 forbids
/// static mutable state, and an ambient static correlation id leaks between concurrent SMTP
/// sessions, producing log lines that confidently attribute one session's actions to another.
/// A DI scope per request or per session makes the lifetime explicit and inspectable.
/// </remarks>
public sealed class CorrelationContext : ICorrelationContext
{
    private CorrelationId? _correlationId;

    public CorrelationId CorrelationId => _correlationId ??= CorrelationId.New();

    /// <summary>
    /// Sets the identifier if none has been set yet. Idempotent by design: an id adopted at
    /// the IPC boundary must win over the one the pipeline would otherwise mint, and a
    /// handler must not be able to re-label an operation halfway through and break the trace.
    /// </summary>
    public void Initialize(CorrelationId correlationId) => _correlationId ??= correlationId;
}
