using MailServer.Domain.Entities;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>
/// Appends to the audit trail.
/// </summary>
/// <remarks>
/// Append-only by design: there is no update and no delete. Retention trimming is a
/// separate, itself-audited maintenance operation, not an ordinary repository method.
/// </remarks>
public interface IAuditRepository
{
    Task AppendAsync(AuditRecord record, CancellationToken cancellationToken);
}
