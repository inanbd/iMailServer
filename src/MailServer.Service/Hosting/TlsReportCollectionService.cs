using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Domain.Enums;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Service.Hosting;

/// <summary>
/// Looks in the TLS report mailbox on a timer.
/// </summary>
/// <remarks>
/// <para>
/// <b>Six hours by default, because reports are daily.</b> RFC 8460 §3 has a sender send at most
/// one aggregate report per day per domain, so polling often buys nothing and costs a mailbox
/// scan each time. Six hours picks a report up the same day it arrives.
/// </para>
/// <para>
/// <b>A failed pass is never fatal.</b> Collection is a diagnostic: a database hiccup or an
/// unreadable message must not take down a host that is otherwise receiving and delivering mail
/// perfectly well. The exception is logged, health says so, and the next tick tries again.
/// </para>
/// </remarks>
public sealed class TlsReportCollectionService(
    IServiceScopeFactory scopeFactory,
    IHealthRegistry health,
    IOptions<MailServerOptions> options,
    ILogger<TlsReportCollectionService> logger)
    : ResilientBackgroundService(health, logger)
{
    public override string ComponentName => "TlsReportCollection";

    private TlsRptOptions Options => options.Value.Deliverability.TlsRpt;

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        if (!Options.Enabled)
        {
            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Healthy,
                "TLS report collection is disabled. Reports can still be analysed one at a time " +
                "from the deliverability page.",
                DateTimeOffset.UtcNow));

            return;
        }

        using PeriodicTimer timer = new(TimeSpan.FromMinutes(Options.PollMinutes));

        // Once immediately, so a restart picks up whatever arrived while the service was down
        // rather than waiting out a six-hour interval first.
        await CollectAsync(stoppingToken).ConfigureAwait(false);

        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await CollectAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task CollectAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

            ITlsReportCollector collector =
                scope.ServiceProvider.GetRequiredService<ITlsReportCollector>();

            TlsReportCollectionResult result = await collector
                .CollectAsync(cancellationToken)
                .ConfigureAwait(false);

            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Healthy,
                result.Examined == 0
                    ? "Nothing new in the report mailbox."
                    : $"Examined {result.Examined}: {result.Collected} new, " +
                      $"{result.Duplicates} already held, {result.NotReports} not reports.",
                DateTimeOffset.UtcNow));
        }
        catch (OperationCanceledException)
        {
            // Ordinary shutdown.
            throw;
        }
        catch (Exception ex)
        {
            Logger.LogError(
                ex,
                "A TLS report collection pass failed. Mail flow is unaffected; the next pass " +
                "will try again.");

            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Warning,
                "The last collection pass failed. Reports are not being collected until it " +
                "succeeds; mail flow is unaffected.",
                DateTimeOffset.UtcNow));
        }
    }
}
