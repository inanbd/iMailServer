using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Security;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 8 of 8, innermost. Writes the audit record for requests marked
/// <see cref="IAuditableRequest"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Placed inside the transaction stage on purpose.</b> The audit record for a successful
/// change is written in the same transaction as the change, so the two commit or roll back
/// together. An audit trail that can disagree with the data it describes is worse than none,
/// because it is trusted.
/// </para>
/// <para>
/// Failures take the deferred path instead: the transaction is about to roll back, so an
/// immediate write would be undone with it. The record is queued and flushed by the
/// outermost exception behavior once rollback has completed - see <see cref="IAuditTrail"/>
/// for why it cannot simply open a second connection here.
/// </para>
/// <para>
/// <b>Only the request's own descriptor is recorded.</b> Nothing is reflected out of the
/// request object, which is what keeps secrets out of the audit table by construction.
/// </para>
/// </remarks>
public sealed class AuditBehavior<TRequest, TResponse>(
    IAuditTrail auditTrail,
    ILogger<AuditBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        if (request is not IAuditableRequest auditable)
        {
            return await next(cancellationToken).ConfigureAwait(false);
        }

        AuditDescriptor descriptor = auditable.DescribeForAudit();

        TResponse response;
        try
        {
            response = await next(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Deferred, not immediate: this transaction is about to roll back.
            auditTrail.QueueDeferred(descriptor, AuditResult.Failure, Summarize(ex));
            throw;
        }

        await auditTrail
            .RecordAsync(descriptor, AuditResult.Success, descriptor.Detail, cancellationToken)
            .ConfigureAwait(false);

        logger.LogDebug(
            "Audited {AuditAction} on {AuditTarget}.",
            descriptor.Action,
            descriptor.TargetIdentifier ?? descriptor.TargetType);

        return response;
    }

    /// <summary>
    /// Produces a short, bounded failure summary.
    /// </summary>
    /// <remarks>
    /// Truncated because an exception message can be arbitrarily long - a SQL error can
    /// carry a whole statement - and the audit table is not a log sink. The full detail is
    /// in the structured log under the same correlation id.
    /// </remarks>
    private static string Summarize(Exception ex)
    {
        const int MaxLength = 512;
        string text = $"{ex.GetType().Name}: {ex.Message}";
        return text.Length <= MaxLength ? text : string.Concat(text.AsSpan(0, MaxLength - 1), "…");
    }
}
