using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Exceptions;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 5 of 8. Enforces the permission each request declares, and the current
/// maintenance mode.
/// </summary>
/// <remarks>
/// <para>
/// <b>Placed before validation, deliberately.</b> If validation ran first, an unauthorized
/// caller could read the validation errors as an oracle: "domain 'secret-client.com' already
/// exists" tells them something they are not entitled to know. Denying first means an
/// unauthorized caller learns exactly one thing - that they are unauthorized.
/// </para>
/// <para>
/// Denials are audited here rather than by the audit stage, because a denial never reaches
/// the audit stage: it throws first. The record is queued as deferred so it is written from
/// a clean connection once the request has unwound.
/// </para>
/// </remarks>
public sealed class AuthorizationBehavior<TRequest, TResponse>(
    IAdminContext adminContext,
    IMaintenanceModeAccessor maintenanceMode,
    IAuditTrail auditTrail,
    ILogger<AuthorizationBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        if (request is IAuthorizedRequest authorized)
        {
            AdminPermission required = authorized.RequiredPermission;

            if (!adminContext.IsAuthenticated || !adminContext.HasPermission(required))
            {
                logger.LogWarning(
                    "Denied {RequestName} for {Administrator}: {RequiredPermission} is required.",
                    typeof(TRequest).Name,
                    adminContext.Administrator,
                    required);

                QueueDenial(request, $"Missing permission {required}.");
                throw new AuthorizationFailedException(required);
            }
        }

        // A command that mutates state is refused while the server is read-only or in full
        // maintenance. Queries are unaffected, so an operator can still see what is going on
        // while a restore or a provider migration runs.
        if (request is ITransactionalRequest && !maintenanceMode.AreAdministrativeWritesEnabled)
        {
            MaintenanceMode mode = maintenanceMode.Current;

            logger.LogWarning(
                "Refused {RequestName}: the server is in {MaintenanceMode} mode.",
                typeof(TRequest).Name,
                mode);

            QueueDenial(request, $"Server is in {mode} mode.");
            throw new MaintenanceModeException(mode);
        }

        return await next(cancellationToken).ConfigureAwait(false);
    }

    private void QueueDenial(TRequest request, string reason)
    {
        AuditDescriptor descriptor = request is IAuditableRequest auditable
            ? auditable.DescribeForAudit()
            : new AuditDescriptor(typeof(TRequest).Name, "Request", null);

        auditTrail.QueueDeferred(descriptor, AuditResult.Denied, reason);
    }
}
