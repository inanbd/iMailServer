using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Security;

/// <summary>
/// Writes the audit trail.
/// </summary>
/// <remarks>
/// <para>
/// Two write paths exist, and the distinction matters.
/// </para>
/// <para>
/// <b>Immediate</b> writes join the ambient transaction, so a successful change and the
/// audit record describing it commit together. An audit trail that can disagree with the
/// data it audits is worse than no audit trail.
/// </para>
/// <para>
/// <b>Deferred</b> writes are for failures and denials, which must survive the rollback of
/// the very transaction that failed. They are queued during the request and flushed from a
/// separate connection once the failed transaction has been rolled back. Flushing them
/// while the write transaction is still open would open a second write connection, which
/// under SQLite's single-writer model deadlocks against the transaction we are trying to
/// roll back.
/// </para>
/// </remarks>
public interface IAuditTrail
{
    /// <summary>
    /// Writes an audit record now, joining the ambient transaction if one is in progress.
    /// </summary>
    Task RecordAsync(
        AuditDescriptor descriptor,
        AuditResult result,
        string? detail,
        CancellationToken cancellationToken);

    /// <summary>
    /// Queues an audit record to be written after any failed transaction has rolled back.
    /// Does not touch the database.
    /// </summary>
    void QueueDeferred(AuditDescriptor descriptor, AuditResult result, string? detail);

    /// <summary>
    /// Writes every queued record using a fresh connection, then clears the queue. Called
    /// from the outermost exception behavior, after rollback. Never throws: losing the
    /// request's real exception behind an audit-write failure would be a poor trade, so a
    /// failure here is logged and swallowed.
    /// </summary>
    Task FlushDeferredAsync(CancellationToken cancellationToken);

    /// <summary>True when at least one record is queued.</summary>
    bool HasDeferredRecords { get; }
}
