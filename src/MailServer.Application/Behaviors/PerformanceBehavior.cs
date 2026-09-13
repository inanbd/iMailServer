using MailServer.Application.Abstractions.Time;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 3 of 8. Measures handler duration and warns when a request is slow.
/// </summary>
/// <remarks>
/// <para>
/// Uses the injected clock's monotonic timestamp rather than <c>DateTime</c> arithmetic, so
/// an NTP correction during a long-running operation cannot produce a negative or absurd
/// duration.
/// </para>
/// <para>
/// Slow administrative requests matter on a mail server for a specific reason: under SQLite
/// a long write transaction blocks every other writer, including the queue processor. A
/// slow "list domains" is cosmetic; a slow "create mailbox" is a mail-flow stall.
/// </para>
/// </remarks>
public sealed class PerformanceBehavior<TRequest, TResponse>(
    IClock clock,
    ILogger<PerformanceBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    /// <summary>Requests slower than this are logged at Warning.</summary>
    public static readonly TimeSpan WarningThreshold = TimeSpan.FromMilliseconds(1500);

    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        long start = clock.GetTimestamp();

        try
        {
            return await next(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            TimeSpan elapsed = clock.GetElapsedTime(start);

            if (elapsed >= WarningThreshold)
            {
                logger.LogWarning(
                    "{RequestName} took {ElapsedMs} ms, exceeding the {ThresholdMs} ms threshold.",
                    typeof(TRequest).Name,
                    (long)elapsed.TotalMilliseconds,
                    (long)WarningThreshold.TotalMilliseconds);
            }
            else
            {
                logger.LogDebug(
                    "{RequestName} completed in {ElapsedMs} ms.",
                    typeof(TRequest).Name,
                    (long)elapsed.TotalMilliseconds);
            }
        }
    }
}
