using MailServer.Application.Abstractions.Security;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 1 of 8. Establishes the correlation identifier and opens the logging
/// scope that every later stage, handler and log line inherits.
/// </summary>
/// <remarks>
/// <para>
/// Runs <b>first</b> so that every subsequent behavior - including the exception logger -
/// already has an identifier to attach. Assigning it later would leave the earliest and most
/// interesting failures uncorrelated, which is exactly when correlation is most needed.
/// </para>
/// <para>
/// When a request arrives over IPC carrying a correlation id from the admin application,
/// that id is adopted (after sanitising) so one operation is traceable across both
/// processes. Otherwise a fresh id is minted.
/// </para>
/// </remarks>
public sealed class CorrelationBehavior<TRequest, TResponse>(
    ICorrelationContext correlationContext,
    ILogger<CorrelationBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        // Initialize is idempotent: a correlation id adopted at the IPC boundary wins, and
        // this call is then a no-op rather than overwriting it mid-operation.
        correlationContext.Initialize(CorrelationId.New());

        using IDisposable? scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["CorrelationId"] = correlationContext.CorrelationId.Value,
            ["RequestType"] = typeof(TRequest).Name,
        });

        return await next(cancellationToken).ConfigureAwait(false);
    }
}
