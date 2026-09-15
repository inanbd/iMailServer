using System.Collections.Concurrent;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Service.Hosting;

/// <summary>
/// Claims due outbound queue items and delivers them.
/// </summary>
/// <remarks>
/// <para>
/// <b>One worker, not the scheduler/deliverer split the architecture doc's diagram shows.</b>
/// <c>docs/Architecture.md</c> §8 separates <c>QueueSchedulerHostedService</c> (leases work) from
/// <c>OutboundDeliveryHostedService</c> (N workers delivering it), coordinated through some
/// in-process handoff. This class does both: it claims a batch, then delivers the whole batch
/// concurrently (bounded by the same per-domain and total concurrency limits the split design
/// would need anyway), then claims again. The leasing contract - claim, work outside a
/// transaction, record the outcome in a second short transaction - is identical either way, and
/// splitting the claim and the delivery into two hosted services buys nothing this milestone
/// needs that a documented simplification does not also provide. Recorded here rather than left
/// to be discovered by a reader expecting two classes.
/// </para>
/// <para>
/// <b>Never a transaction across a network call.</b> Claiming happens in one repository call,
/// delivery happens over a real TCP connection with no transaction open, and the outcome is
/// written in a second repository call. See <c>docs/Architecture.md</c> §9.
/// </para>
/// </remarks>
public sealed class OutboundDeliveryHostedService(
    IServiceScopeFactory scopeFactory,
    IClock clock,
    IOptions<MailServerOptions> options,
    IHealthRegistry health,
    ILogger<OutboundDeliveryHostedService> logger) : ResilientBackgroundService(health, logger)
{
    private static readonly MxSelectionPolicy MxSelection = new();
    private static readonly IpAddressValue LoopbackAddress = IpAddressValue.Parse("127.0.0.1");

    private readonly string _instanceId = $"{Environment.MachineName}:{Environment.ProcessId}:{Guid.NewGuid():N}";
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _domainGates = new(StringComparer.OrdinalIgnoreCase);

    private RetryBackoffPolicy _retryPolicy = new();
    private SemaphoreSlim _globalGate = new(1);

    public override string ComponentName => "OutboundDelivery";

    private OutboundOptions Options => options.Value.Outbound;

    protected override Task InitializeAsync(CancellationToken cancellationToken)
    {
        _retryPolicy = new RetryBackoffPolicy(
            Options.RetryScheduleMinutes as IReadOnlyList<int>,
            TimeSpan.FromDays(Options.MaximumLifetimeDays),
            TimeSpan.FromHours(Options.DelayWarningThresholdHours));

        _globalGate = new SemaphoreSlim(Options.MaxConcurrentDeliveriesTotal);

        return Task.CompletedTask;
    }

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(TimeSpan.FromSeconds(Options.PollIntervalSeconds));

        await ProcessDueItemsAsync(stoppingToken).ConfigureAwait(false);

        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await ProcessDueItemsAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

            IOutboundQueueRepository queue =
                scope.ServiceProvider.GetRequiredService<IOutboundQueueRepository>();

            // Items this instance was mid-delivery on become claimable again immediately,
            // rather than sitting unclaimed until the lease naturally expires. Not required for
            // correctness - the expiry already reclaims them - but a planned restart should not
            // impose an avoidable delay on mail that did nothing wrong.
            await queue.ReleaseLeaseAsync(_instanceId, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Logger.LogWarning(
                ex,
                "Could not release outbound queue leases held by {Instance} during shutdown; " +
                "they will be reclaimed once their lease expires.",
                _instanceId);
        }

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task ProcessDueItemsAsync(CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        IOutboundQueueRepository queue =
            scope.ServiceProvider.GetRequiredService<IOutboundQueueRepository>();

        QueueDepth depth = await queue.GetDepthAsync(cancellationToken).ConfigureAwait(false);

        Health.Publish(new HealthReading(
            ComponentName,
            HealthState.Healthy,
            $"{depth.Pending} pending, {depth.Processing} in progress.",
            clock.UtcNow,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Pending"] = depth.Pending.ToString(),
                ["Processing"] = depth.Processing.ToString(),
                ["OldestPendingUtc"] = depth.OldestPendingUtc?.ToString("O") ?? "n/a",
            }));

        IReadOnlyList<OutboundQueueItem> claimed = await queue.ClaimDueAsync(
            _instanceId,
            Options.ClaimBatchSize,
            TimeSpan.FromSeconds(Options.LeaseDurationSeconds),
            clock.UtcNow,
            cancellationToken).ConfigureAwait(false);

        if (claimed.Count == 0)
        {
            return;
        }

        await Task.WhenAll(claimed.Select(item => ProcessOneWithThrottleAsync(item, cancellationToken)))
            .ConfigureAwait(false);
    }

    private async Task ProcessOneWithThrottleAsync(OutboundQueueItem item, CancellationToken cancellationToken)
    {
        SemaphoreSlim domainGate = _domainGates.GetOrAdd(
            item.DestinationDomain.Value,
            _ => new SemaphoreSlim(Options.MaxConcurrentDeliveriesPerDomain));

        await _globalGate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            await domainGate.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                await DeliverOneAsync(item, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                domainGate.Release();
            }
        }
        finally
        {
            _globalGate.Release();
        }
    }

    private async Task DeliverOneAsync(OutboundQueueItem item, CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

        IOutboundQueueRepository queue =
            scope.ServiceProvider.GetRequiredService<IOutboundQueueRepository>();

        DateTimeOffset now = clock.UtcNow;

        try
        {
            if (_retryPolicy.HasExpired(item.FirstQueuedUtc, now))
            {
                await BounceAsync(
                    scope,
                    queue,
                    item,
                    "The message could not be delivered within its maximum retry window.",
                    remoteMta: null,
                    now,
                    cancellationToken).ConfigureAwait(false);

                return;
            }

            IDnsResolver dns = scope.ServiceProvider.GetRequiredService<IDnsResolver>();
            MxLookupResult mx = await dns.ResolveMxAsync(item.DestinationDomain, cancellationToken)
                .ConfigureAwait(false);

            if (mx.Status == DnsLookupStatus.Permanent)
            {
                await BounceAsync(
                    scope, queue, item, mx.Diagnostic ?? "MX lookup failed permanently.", null, now, cancellationToken)
                    .ConfigureAwait(false);

                return;
            }

            if (mx.Status == DnsLookupStatus.Temporary)
            {
                await DeferAsync(queue, item, mx.Diagnostic ?? "MX lookup failed temporarily.", now, cancellationToken)
                    .ConfigureAwait(false);

                return;
            }

            await AttemptDeliveryAsync(scope, queue, item, mx.Hosts, now, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Logger.LogError(
                ex,
                "Unhandled failure processing outbound queue item {QueueItemId} for {Recipient}.",
                item.Id.Value,
                item.DestinationAddress.Value);

            await DeferAsync(queue, item, $"Internal error: {ex.Message}", now, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task AttemptDeliveryAsync(
        AsyncServiceScope scope,
        IOutboundQueueRepository queue,
        OutboundQueueItem item,
        IReadOnlyList<MxHost> hosts,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        IOutboundDeliveryClient client = scope.ServiceProvider.GetRequiredService<IOutboundDeliveryClient>();

        IReadOnlyList<MxHost> ordered = MxSelection.OrderForAttempt(hosts);
        OutboundDeliveryResult? lastResult = null;
        string? lastHost = null;

        foreach (MxHost host in ordered)
        {
            OutboundDeliveryRequest request = new(
                host.Hostname,
                Options.DeliveryPort,
                item.ReversePath,
                item.DestinationAddress,
                item.MessageId,
                item.RequireTls);

            DateTimeOffset attemptStart = clock.UtcNow;
            OutboundDeliveryResult result;

            try
            {
                result = await client.DeliverAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Logger.LogWarning(
                    ex,
                    "Delivery of {QueueItemId} to {Recipient} via {Host} raised an unexpected exception.",
                    item.Id.Value,
                    item.DestinationAddress.Value,
                    host.Hostname);

                result = new OutboundDeliveryResult(
                    DeliveryOutcome.Deferred,
                    FailureClassification.Temporary,
                    RemoteAddress: null,
                    TlsActive: false,
                    TlsProtocol: null,
                    TlsCipher: null,
                    PeerCertificateSubject: null,
                    PeerCertificateIssuer: null,
                    ReplyCode: null,
                    EnhancedStatus: null,
                    ReplyText: null,
                    ErrorDetail: ex.Message);
            }

            DateTimeOffset attemptEnd = clock.UtcNow;

            DeliveryAttempt attemptRecord = DeliveryAttempt.Create(
                item.Id,
                item.AttemptCount,
                attemptStart,
                attemptEnd,
                host.Hostname,
                result.RemoteAddress,
                result.TlsActive,
                result.TlsProtocol,
                result.TlsCipher,
                result.PeerCertificateSubject,
                result.PeerCertificateIssuer,
                result.ReplyCode,
                result.EnhancedStatus,
                result.ReplyText,
                result.Outcome,
                result.Classification,
                result.ErrorDetail);

            await queue.AddAttemptAsync(attemptRecord, cancellationToken).ConfigureAwait(false);

            lastResult = result;
            lastHost = host.Hostname;

            if (result.Outcome == DeliveryOutcome.Delivered)
            {
                item.MarkDelivered(clock.UtcNow);
                await queue.UpdateAsync(item, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (result.Outcome == DeliveryOutcome.Bounced)
            {
                // A permanent refusal of this recipient is final regardless of which MX host in
                // the rotation said so - trying the next host would not change the answer.
                await BounceAsync(
                    scope, queue, item, DescribeFailure(result), lastHost, now, cancellationToken)
                    .ConfigureAwait(false);

                return;
            }

            // Deferred or TlsRequiredFailure: fall through and try the next host, if any.
        }

        await DeferAsync(queue, item, DescribeFailure(lastResult!), now, cancellationToken).ConfigureAwait(false);
    }

    private async Task DeferAsync(
        IOutboundQueueRepository queue,
        OutboundQueueItem item,
        string reason,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        DateTimeOffset nextAttempt = _retryPolicy.GetNextAttemptUtc(item.AttemptCount, now);
        item.MarkDeferred(nextAttempt, reason, now);
        await queue.UpdateAsync(item, cancellationToken).ConfigureAwait(false);

        if (item.ShouldGenerateDsnOnFailure &&
            _retryPolicy.ShouldSendDelayWarning(item.FirstQueuedUtc, now, item.DelayWarningSentUtc.HasValue))
        {
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();

            await GenerateDsnAsync(scope, queue, item, reason, remoteMta: null, isDelayWarning: true, now, cancellationToken)
                .ConfigureAwait(false);

            item.MarkDelayWarningSent(now);
            await queue.UpdateAsync(item, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task BounceAsync(
        AsyncServiceScope scope,
        IOutboundQueueRepository queue,
        OutboundQueueItem item,
        string reason,
        string? remoteMta,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        item.MarkBounced(reason, now);
        await queue.UpdateAsync(item, cancellationToken).ConfigureAwait(false);

        if (item.ShouldGenerateDsnOnFailure)
        {
            await GenerateDsnAsync(scope, queue, item, reason, remoteMta, isDelayWarning: false, now, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            // The bounce-loop-prevention rule: a message that itself had a null reverse path is
            // recorded and dropped here rather than turned into a DSN nobody could receive.
            Logger.LogWarning(
                "Message {MessageId} to {Recipient} failed permanently and has a null reverse " +
                "path, so no DSN can be sent. Reason: {Reason}",
                item.MessageId.Value,
                item.DestinationAddress.Value,
                reason);
        }
    }

    private async Task GenerateDsnAsync(
        AsyncServiceScope scope,
        IOutboundQueueRepository queue,
        OutboundQueueItem item,
        string reason,
        string? remoteMta,
        bool isDelayWarning,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (item.ReversePath is null)
        {
            // Guarded by every caller already; defensive, since generating a DSN addressed to
            // nobody is not a smaller mistake than generating one at all.
            return;
        }

        IDsnComposer composer = scope.ServiceProvider.GetRequiredService<IDsnComposer>();
        IMessageStore store = scope.ServiceProvider.GetRequiredService<IMessageStore>();
        IDeliveryRepository deliveries = scope.ServiceProvider.GetRequiredService<IDeliveryRepository>();

        DsnMessage dsn = composer.Compose(new DsnRequest(
            item.ReversePath,
            item.DestinationAddress,
            item.MessageId,
            isDelayWarning,
            ReplyCode: null,
            EnhancedStatus: null,
            Diagnostic: reason,
            remoteMta,
            item.FirstQueuedUtc,
            now));

        await using IMessageWriter writer = await store
            .BeginWriteAsync(dsn.Content.LongLength, cancellationToken)
            .ConfigureAwait(false);

        await writer.WriteAsync(dsn.Content, cancellationToken).ConfigureAwait(false);
        StoredMessage stored = await writer.CommitAsync(cancellationToken).ConfigureAwait(false);

        // A DSN is a message this server wrote, not one it received - SmtpListenerRole.Generated
        // and the loopback address say so honestly rather than fabricating a peer.
        MessageRecord record = MessageRecord.Create(
            stored.Id,
            stored.SizeBytes,
            stored.ContentHash,
            reversePath: null,
            LoopbackAddress,
            greetedName: null,
            SmtpListenerRole.Generated,
            tlsActive: false,
            authenticatedAs: null,
            now);

        await deliveries.AddMessageAsync(record, cancellationToken).ConfigureAwait(false);

        MessageRecipient recipient = MessageRecipient.Create(
            stored.Id, item.ReversePath, RelayDecision.AcceptRelay);

        await deliveries.AddRecipientAsync(recipient, cancellationToken).ConfigureAwait(false);

        OutboundQueueItem dsnItem = OutboundQueueItem.Create(
            stored.Id,
            recipient.Id,
            item.ReversePath,
            reversePath: null,
            requireTls: false,
            isDsn: true,
            now);

        await queue.AddAsync(dsnItem, cancellationToken).ConfigureAwait(false);

        Logger.LogInformation(
            "Generated a {Kind} DSN for {Recipient} regarding message {MessageId}.",
            isDelayWarning ? "delay-warning" : "failure",
            item.ReversePath.Value,
            item.MessageId.Value);
    }

    private static string DescribeFailure(OutboundDeliveryResult result)
    {
        if (!string.IsNullOrEmpty(result.ErrorDetail))
        {
            return result.ErrorDetail;
        }

        if (result.ReplyCode is { } code)
        {
            return $"{code} {result.EnhancedStatus} {result.ReplyText}".Trim();
        }

        return "Delivery failed for an unspecified reason.";
    }
}
