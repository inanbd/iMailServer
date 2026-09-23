using MailServer.Application.Abstractions.Security;
using MailServer.Application.Exceptions;
using MailServer.Domain.Exceptions;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 2 of 8. Logs failures with full context and flushes deferred audit records.
/// </summary>
/// <remarks>
/// <para>
/// Sits outside validation, authorization and the transaction so that it also catches
/// failures thrown <b>by</b> those stages, not only by the handler. An exception filter that
/// wraps the handler alone misses precisely the infrastructure failures that are hardest to
/// diagnose.
/// </para>
/// <para>
/// It does not swallow anything. Brief rule 105 forbids silent exception swallowing, so the
/// exception is always rethrown; this stage only decides how loudly it is recorded.
/// Expected, well-modelled failures (validation, authorization, a domain rule) are logged at
/// Warning because they are part of normal operation. Everything else is Error, because an
/// unmodelled exception in a mail server is a defect.
/// </para>
/// <para>
/// The <c>finally</c> flushes deferred audit records and buffered security events. By the time
/// it runs, the transaction behavior has committed or rolled back, so both writes get a clean
/// connection - see <see cref="IAuditTrail"/> and <see cref="ISecurityEventRecorder"/> for why
/// neither may be written while a transaction is open.
/// </para>
/// </remarks>
public sealed class UnhandledExceptionBehavior<TRequest, TResponse>(
    IAuditTrail auditTrail,
    ISecurityEventRecorder securityEvents,
    ILogger<UnhandledExceptionBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        string requestName = typeof(TRequest).Name;

        try
        {
            return await next(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Cooperative shutdown or a client that went away. Not a fault; logging it as an
            // error would fill the log with alarming noise every time the service stops.
            logger.LogDebug("{RequestName} was cancelled.", requestName);
            throw;
        }
        catch (ValidationFailedException ex)
        {
            logger.LogWarning(
                "{RequestName} rejected by validation: {ErrorCount} error(s).",
                requestName,
                ex.Errors.Values.Sum(v => v.Length));
            throw;
        }
        catch (AuthorizationFailedException ex)
        {
            logger.LogWarning(
                "{RequestName} denied: the session lacks {RequiredPermission}.",
                requestName,
                ex.RequiredPermission);
            throw;
        }
        catch (DomainException ex)
        {
            logger.LogWarning(
                ex,
                "{RequestName} rejected by domain rule {DomainRuleCode}.",
                requestName,
                ex.Code);
            throw;
        }
        catch (ApplicationLayerException ex) when (ex.IsRefusal)
        {
            // Answered as designed - a wrong password, a lockout, a maintenance window. Logged
            // without the exception, because a stack trace says "look here" about code that
            // did exactly what it should. The security event log keeps the detail that matters.
            logger.LogWarning(
                "{RequestName} refused: {ErrorCode}.",
                requestName,
                ex.Code);
            throw;
        }
        catch (ApplicationLayerException ex)
        {
            logger.LogError(
                ex,
                "{RequestName} failed with application error {ErrorCode}.",
                requestName,
                ex.Code);
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "{RequestName} failed with an unhandled exception.", requestName);
            throw;
        }
        finally
        {
            // Both flushes happen HERE, outside the transaction behavior, because this
            // behavior's finally runs after that one has committed or rolled back. Writing
            // either of these while a write transaction is still open would block under
            // SQLite's single-writer model until the busy timeout expired, losing the record
            // and stalling the request for the length of the timeout.
            //
            // CancellationToken.None throughout: a record describing a failure must still be
            // written when the failure was a cancellation.
            if (auditTrail.HasDeferredRecords)
            {
                await auditTrail.FlushDeferredAsync(CancellationToken.None).ConfigureAwait(false);
            }

            if (securityEvents.HasPendingEvents)
            {
                await securityEvents.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
    }
}
