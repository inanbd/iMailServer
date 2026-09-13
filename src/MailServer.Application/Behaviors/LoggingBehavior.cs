using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Security;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 4 of 8. Records the start and completion of every request.
/// </summary>
/// <remarks>
/// <para>
/// <b>The request object is never serialised.</b> This is the single most important property
/// of this class. A behavior that logged <c>JsonSerializer.Serialize(request)</c> would
/// faithfully write new mailbox passwords, imported PFX passphrases, smarthost credentials
/// and recovery keys into the log file - and log files are copied into support tickets.
/// </para>
/// <para>
/// Instead it logs the request <i>type name</i>, and, when the request implements
/// <see cref="IAuditableRequest"/>, the descriptor that request hand-wrote as safe to
/// record. Adding a secret-bearing property to a command therefore cannot start leaking it
/// here; the property is simply invisible to logging until somebody deliberately adds it to
/// the descriptor.
/// </para>
/// </remarks>
public sealed class LoggingBehavior<TRequest, TResponse>(
    IAdminContext adminContext,
    ILogger<LoggingBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        string requestName = typeof(TRequest).Name;

        // Only ever the hand-written descriptor - never reflection over the request.
        string? target = request is IAuditableRequest auditable
            ? auditable.DescribeForAudit().TargetIdentifier
            : null;

        logger.LogInformation(
            "Handling {RequestName} for target {Target} as {Administrator}.",
            requestName,
            target ?? "(none)",
            adminContext.Administrator);

        TResponse response = await next(cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Handled {RequestName}.", requestName);

        return response;
    }
}
