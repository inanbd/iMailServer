using MailServer.Domain.Enums;

namespace MailServer.Application.Abstractions.Security;

/// <summary>
/// Records security events.
/// </summary>
/// <remarks>
/// <para>
/// <b>Buffered during the request, flushed on its own connection afterwards.</b> This is the
/// same pattern the audit trail uses for failures, and it exists for two reasons that pull in
/// the same direction:
/// </para>
/// <list type="number">
///   <item><description><b>Survival.</b> The events worth recording — a refused sign-in, a
///   rejected recovery key — occur inside a transaction that is about to roll back. Writing
///   them in that transaction would mean an attacker who can make an operation fail thereby
///   erases the record of their attempt.</description></item>
///   <item><description><b>Deadlock avoidance.</b> Opening a second connection while a write
///   transaction is open blocks under SQLite's single-writer model: the second write waits for
///   a lock the first will not release until it returns. The wait ends in a busy-timeout error,
///   so the event is lost <i>and</i> the request stalls for the length of the timeout.</description></item>
/// </list>
/// <para>
/// So nothing is written during the request. <c>UnhandledExceptionBehavior</c> flushes the
/// buffer from its <c>finally</c>, which runs after the transaction behavior has committed or
/// rolled back; callers outside the pipeline flush explicitly.
/// </para>
/// <para>
/// <b>Flushing never throws.</b> Letting an event-write failure abort an authentication check
/// would turn a logging problem into a denial of service, and letting it abort a
/// <i>rejection</i> would turn it into an authentication bypass.
/// </para>
/// </remarks>
public interface ISecurityEventRecorder
{
    /// <summary>
    /// Buffers an event. Performs no database work.
    /// </summary>
    /// <param name="description">
    /// Human-readable summary. Must never contain a credential — not the attempted password,
    /// not the presented token, not the recovery key.
    /// </param>
    Task RecordAsync(
        SecurityEventType eventType,
        string? subject,
        string? origin,
        string description,
        CancellationToken cancellationToken);

    /// <summary>True when at least one event is buffered.</summary>
    bool HasPendingEvents { get; }

    /// <summary>
    /// Writes every buffered event on a fresh connection and clears the buffer.
    /// </summary>
    /// <remarks>
    /// Must only be called once no write transaction is open. Never throws.
    /// </remarks>
    Task FlushAsync(CancellationToken cancellationToken);
}
