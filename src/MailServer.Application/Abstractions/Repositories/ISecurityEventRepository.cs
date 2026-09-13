using MailServer.Domain.Entities;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>
/// Appends to the security event log.
/// </summary>
/// <remarks>
/// Append-only: no update, no delete. Retention trimming is a separate, itself-audited
/// maintenance operation.
/// </remarks>
public interface ISecurityEventRepository
{
    Task AppendAsync(SecurityEvent securityEvent, CancellationToken cancellationToken);
}
