using MailServer.Application.Common;
using MailServer.Application.Security.Dtos;

namespace MailServer.Application.Abstractions.Queries;

/// <summary>Read model for the audit trail.</summary>
public interface IAuditQueries
{
    Task<PagedResult<AuditRecordDto>> SearchAsync(
        AuditSearchRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Read model for the security event log.</summary>
public interface ISecurityEventQueries
{
    Task<PagedResult<SecurityEventDto>> SearchAsync(
        SecurityEventSearchRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Failed sign-in attempts since the given instant.
    /// </summary>
    /// <remarks>
    /// Drives the security overview. A steady trickle of failures is the visible signature of
    /// an ongoing guessing campaign, which is otherwise easy to miss among successful sign-ins.
    /// </remarks>
    Task<int> CountFailedSignInsSinceAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken);
}
