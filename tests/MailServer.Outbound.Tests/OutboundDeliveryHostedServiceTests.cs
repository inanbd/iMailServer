using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Service.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Outbound.Tests;

/// <summary>
/// <see cref="OutboundDeliveryHostedService"/>'s decisions - retry scheduling, bounce, DSN
/// generation and bounce-loop prevention - against in-memory fakes of every dependency.
/// Persistence correctness itself belongs to <c>MailServer.Persistence.Tests</c>; what matters
/// here is that the worker reacts correctly to a given queue and delivery outcome, which a real
/// database would only make slower to prove.
/// </summary>
public sealed class OutboundDeliveryHostedServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private sealed class Harness : IAsyncDisposable
    {
        public FakeOutboundQueueRepository Queue { get; } = new();

        public FakeDnsResolver Dns { get; } = new();

        public FakeOutboundDeliveryClient DeliveryClient { get; } = new();

        public FakeDsnComposer DsnComposer { get; } = new();

        public FakeMessageStore MessageStore { get; } = new();

        public FakeDeliveryRepository Deliveries { get; } = new();

        public FakeClock Clock { get; } = new(Now);

        public FakeHostedDomains HostedDomains { get; } = new();

        public RecordingLocalDelivery LocalDelivery { get; } = new();

        private readonly ServiceProvider _provider;
        private readonly OutboundDeliveryHostedService _service;

        public Harness(Action<OutboundOptions>? configureOptions = null)
        {
            OutboundOptions outboundOptions = new()
            {
                PollIntervalSeconds = 1,
                ClaimBatchSize = 50,
                LeaseDurationSeconds = 60,
                MaxConcurrentDeliveriesPerDomain = 4,
                MaxConcurrentDeliveriesTotal = 10,
                MaximumLifetimeDays = 5,
                DelayWarningThresholdHours = 4,
            };

            configureOptions?.Invoke(outboundOptions);

            ServiceCollection services = new();
            services.AddSingleton<IOutboundQueueRepository>(Queue);
            services.AddSingleton<IDnsResolver>(Dns);
            services.AddSingleton<IOutboundDeliveryClient>(DeliveryClient);
            services.AddSingleton<IDsnComposer>(DsnComposer);
            services.AddSingleton<IMessageStore>(MessageStore);
            services.AddSingleton<IDeliveryRepository>(Deliveries);
            services.AddSingleton<ISmtpDirectory>(HostedDomains);
            services.AddSingleton<ILocalDeliveryService>(LocalDelivery);

            _provider = services.BuildServiceProvider();

            _service = new OutboundDeliveryHostedService(
                _provider.GetRequiredService<IServiceScopeFactory>(),
                Clock,
                Options.Create(new MailServerOptions { Outbound = outboundOptions }),
                new FakeHealthRegistry(),
                NullLogger<OutboundDeliveryHostedService>.Instance);
        }

        /// <summary>Runs the worker until <paramref name="until"/> is true, or a timeout elapses.</summary>
        public async Task RunUntilAsync(Func<bool> until, TimeSpan? timeout = null)
        {
            await _service.StartAsync(CancellationToken.None);

            DateTime deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));

            try
            {
                while (!until() && DateTime.UtcNow < deadline)
                {
                    await Task.Delay(20).ConfigureAwait(false);
                }
            }
            finally
            {
                await _service.StopAsync(CancellationToken.None);
            }

            until().ShouldBeTrue("the expected condition was never reached within the timeout.");
        }

        public async ValueTask DisposeAsync() => await _provider.DisposeAsync();
    }

    private static async Task<(StoredMessageId MessageId, Guid RecipientId)> SeedMessageAsync(
        FakeDeliveryRepository deliveries, FakeMessageStore store, EmailAddress? reversePath)
    {
        await using IMessageWriter writer = await store.BeginWriteAsync(1024, CancellationToken.None);
        await writer.WriteAsync("body"u8.ToArray(), CancellationToken.None);
        StoredMessage stored = await writer.CommitAsync(CancellationToken.None);

        MessageRecord message = MessageRecord.Create(
            stored.Id, stored.SizeBytes, stored.ContentHash, reversePath,
            IpAddressValue.Parse("203.0.113.10"), null, SmtpListenerRole.Submission, true, null, Now);
        await deliveries.AddMessageAsync(message, CancellationToken.None);

        MessageRecipient recipient = MessageRecipient.Create(
            stored.Id, EmailAddress.Parse("recipient@destination.example"), RelayDecision.AcceptRelay);
        await deliveries.AddRecipientAsync(recipient, CancellationToken.None);

        return (stored.Id, recipient.Id);
    }

    private static OutboundDeliveryResult Delivered() => new(
        DeliveryOutcome.Delivered, FailureClassification.None, null, false, null, null, null, null,
        250, "2.0.0", "OK", null);

    private static OutboundDeliveryResult Bounced(string text = "no such user") => new(
        DeliveryOutcome.Bounced, FailureClassification.Permanent, null, false, null, null, null, null,
        550, "5.1.1", text, null);

    private static OutboundDeliveryResult Deferred(string text = "try again") => new(
        DeliveryOutcome.Deferred, FailureClassification.Temporary, null, false, null, null, null, null,
        421, "4.3.0", text, null);

    [Fact]
    public async Task A_successful_delivery_marks_the_item_delivered()
    {
        await using Harness harness = new();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("sender@origin.example"));

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"), requireTls: false, isDsn: false, Now);
        await harness.Queue.AddAsync(item, CancellationToken.None);

        harness.DeliveryClient.Enqueue(Delivered());

        await harness.RunUntilAsync(() =>
            harness.Queue.AllItems.Single(i => i.Id == item.Id).Status == QueueStatus.Delivered);
    }

    [Fact]
    public async Task A_temporary_failure_is_rescheduled_per_the_retry_backoff_policy()
    {
        await using Harness harness = new();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("sender@origin.example"));

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"), requireTls: false, isDsn: false, Now);
        await harness.Queue.AddAsync(item, CancellationToken.None);

        harness.DeliveryClient.Enqueue(Deferred());

        await harness.RunUntilAsync(() =>
            harness.Queue.AllItems.Single(i => i.Id == item.Id).Status == QueueStatus.Deferred);

        OutboundQueueItem deferred = harness.Queue.AllItems.Single(i => i.Id == item.Id);

        // Attempt 1's interval is 1 minute per RetryBackoffPolicy.DefaultScheduleMinutes.
        deferred.NextAttemptUtc.ShouldBeInRange(
            Now.AddMinutes(1).AddSeconds(-30), Now.AddMinutes(1).AddSeconds(30));
        deferred.AttemptCount.ShouldBe(1);
        deferred.LastFailureReason.ShouldNotBeNull().ShouldContain("try again");
    }

    [Fact]
    public async Task A_permanent_failure_bounces_and_generates_a_dsn_to_the_reverse_path()
    {
        await using Harness harness = new();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("sender@origin.example"));

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("nobody@destination.example"),
            EmailAddress.Parse("sender@origin.example"), requireTls: false, isDsn: false, Now);
        await harness.Queue.AddAsync(item, CancellationToken.None);

        harness.DeliveryClient.Enqueue(Bounced());

        await harness.RunUntilAsync(() =>
            harness.Queue.AllItems.Single(i => i.Id == item.Id).Status == QueueStatus.Bounced);

        harness.DsnComposer.Requests.ShouldHaveSingleItem();
        harness.DsnComposer.Requests[0].OriginalReversePath.Value.ShouldBe("sender@origin.example");
        harness.DsnComposer.Requests[0].IsDelayWarning.ShouldBeFalse();

        // The DSN itself became a new queue item, addressed back to the original sender.
        OutboundQueueItem dsnItem = harness.Queue.AllItems.Single(i => i.IsDsn);
        dsnItem.DestinationAddress.Value.ShouldBe("sender@origin.example");
        dsnItem.ReversePath.ShouldBeNull();
    }

    /// <summary>
    /// A bounce for a sender this server hosts is delivered here, not relayed back out.
    /// </summary>
    /// <remarks>
    /// Found by running the server: the bounce was queued for outbound delivery to the hosted
    /// domain, the worker looked up that domain's MX in public DNS, found none, failed the DSN
    /// permanently — and, a DSN having a null reverse path, dropped it without trace. Since
    /// submission only accepts hosted senders, that was every bounce any user ever received.
    /// </remarks>
    [Fact]
    public async Task A_bounce_for_a_hosted_sender_is_delivered_locally()
    {
        await using Harness harness = new();
        harness.HostedDomains.Hosted.Add("hosted.example");

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("alice@hosted.example"));

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("nobody@destination.example"),
            EmailAddress.Parse("alice@hosted.example"), requireTls: false, isDsn: false, Now);
        await harness.Queue.AddAsync(item, CancellationToken.None);

        harness.DeliveryClient.Enqueue(Bounced());

        await harness.RunUntilAsync(() => harness.LocalDelivery.Requests.Count == 1);

        DeliveryRequest bounce = harness.LocalDelivery.Requests.ShouldHaveSingleItem();

        // Addressed to the original sender, from the null reverse path RFC 3464 requires, and
        // marked as this server's own composition so it is neither re-verified nor filtered.
        bounce.Recipients.ShouldHaveSingleItem().ShouldBe(
            new AcceptedRecipient(EmailAddress.Parse("alice@hosted.example"), RelayDecision.AcceptLocal));
        bounce.ReversePath.ShouldBeNull();
        bounce.ListenerRole.ShouldBe(SmtpListenerRole.Generated);

        // And it was not also queued for relay.
        harness.Queue.AllItems.ShouldNotContain(i => i.IsDsn);
    }

    /// <summary>A delay warning for a hosted sender takes the same route as a failure notice.</summary>
    [Fact]
    public async Task A_delay_warning_for_a_hosted_sender_is_delivered_locally()
    {
        await using Harness harness = new(o => o.DelayWarningThresholdHours = 4);
        harness.HostedDomains.Hosted.Add("hosted.example");

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("alice@hosted.example"));

        OutboundQueueItem fresh = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("nobody@destination.example"),
            EmailAddress.Parse("alice@hosted.example"), requireTls: false, isDsn: false, Now);

        // Old enough that the next temporary failure crosses the delay-warning threshold.
        OutboundQueueItem aged = OutboundQueueItem.Rehydrate(
            fresh.Id, fresh.MessageId, fresh.RecipientId, fresh.DestinationAddress, fresh.ReversePath,
            fresh.RequireTls, fresh.IsDsn, fresh.Priority, QueueStatus.Pending, 3,
            Now.AddHours(-5), Now.AddHours(-5), null, null, delayWarningSentUtc: null, "previously deferred",
            Now.AddHours(-5));
        await harness.Queue.AddAsync(aged, CancellationToken.None);

        harness.DeliveryClient.Enqueue(Deferred());

        await harness.RunUntilAsync(() => harness.LocalDelivery.Requests.Count == 1);

        harness.DsnComposer.Requests.ShouldHaveSingleItem().IsDelayWarning.ShouldBeTrue();
        harness.Queue.AllItems.ShouldNotContain(i => i.IsDsn);
    }

    /// <summary>
    /// A remote sender's bounce is still relayed. The routing change is about hosted senders only.
    /// </summary>
    [Fact]
    public async Task A_bounce_for_a_remote_sender_is_still_queued_for_relay()
    {
        await using Harness harness = new();
        harness.HostedDomains.Hosted.Add("hosted.example");

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("sender@origin.example"));

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("nobody@destination.example"),
            EmailAddress.Parse("sender@origin.example"), requireTls: false, isDsn: false, Now);
        await harness.Queue.AddAsync(item, CancellationToken.None);

        harness.DeliveryClient.Enqueue(Bounced());

        await harness.RunUntilAsync(() => harness.Queue.AllItems.Any(i => i.IsDsn));

        harness.LocalDelivery.Requests.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_null_reverse_path_message_that_bounces_never_generates_a_dsn()
    {
        await using Harness harness = new();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, reversePath: null);

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("nobody@destination.example"),
            reversePath: null, requireTls: false, isDsn: false, Now);
        await harness.Queue.AddAsync(item, CancellationToken.None);

        harness.DeliveryClient.Enqueue(Bounced());

        await harness.RunUntilAsync(() =>
            harness.Queue.AllItems.Single(i => i.Id == item.Id).Status == QueueStatus.Bounced);

        // Bounce-loop prevention: no DSN was composed, and no new item was queued.
        harness.DsnComposer.Requests.ShouldBeEmpty();
        harness.Queue.AllItems.Count(i => i.Id != item.Id).ShouldBe(0);
    }

    [Fact]
    public async Task A_permanent_mx_failure_bounces_without_ever_calling_the_delivery_client()
    {
        await using Harness harness = new();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("sender@origin.example"));

        harness.Dns.SetMx("destination.example", MxLookupResult.Permanent("NXDOMAIN"));

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"), requireTls: false, isDsn: false, Now);
        await harness.Queue.AddAsync(item, CancellationToken.None);

        await harness.RunUntilAsync(() =>
            harness.Queue.AllItems.Single(i => i.Id == item.Id).Status == QueueStatus.Bounced);

        harness.DeliveryClient.Requests.ShouldBeEmpty();
        harness.DsnComposer.Requests.ShouldHaveSingleItem();
    }

    [Fact]
    public async Task A_temporary_mx_failure_defers_without_ever_calling_the_delivery_client()
    {
        await using Harness harness = new();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("sender@origin.example"));

        harness.Dns.SetMx("destination.example", MxLookupResult.Temporary("SERVFAIL"));

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"), requireTls: false, isDsn: false, Now);
        await harness.Queue.AddAsync(item, CancellationToken.None);

        await harness.RunUntilAsync(() =>
            harness.Queue.AllItems.Single(i => i.Id == item.Id).Status == QueueStatus.Deferred);

        harness.DeliveryClient.Requests.ShouldBeEmpty();
    }

    [Fact]
    public async Task An_item_past_its_maximum_lifetime_bounces_without_attempting_delivery()
    {
        await using Harness harness = new(o => o.MaximumLifetimeDays = 5);

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("sender@origin.example"));

        OutboundQueueItem fresh = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"), requireTls: false, isDsn: false, Now);

        // OutboundQueueItem.Create always stamps "now" as FirstQueuedUtc; rehydrate with an old
        // one instead, exactly as a repository read of a long-queued row would.
        OutboundQueueItem item = OutboundQueueItem.Rehydrate(
            fresh.Id, fresh.MessageId, fresh.RecipientId, fresh.DestinationAddress, fresh.ReversePath,
            fresh.RequireTls, fresh.IsDsn, fresh.Priority, QueueStatus.Pending, 0,
            Now.AddDays(-6), Now.AddDays(-6), null, null, null, null, Now.AddDays(-6));

        await harness.Queue.AddAsync(item, CancellationToken.None);

        await harness.RunUntilAsync(() =>
            harness.Queue.AllItems.Single(i => i.Id == item.Id).Status == QueueStatus.Bounced);

        harness.DeliveryClient.Requests.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_delay_warning_dsn_is_sent_once_the_age_threshold_passes_and_never_sent_twice()
    {
        await using Harness harness = new(o => o.DelayWarningThresholdHours = 4);

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(
            harness.Deliveries, harness.MessageStore, EmailAddress.Parse("sender@origin.example"));

        OutboundQueueItem fresh = OutboundQueueItem.Create(
            messageId, recipientId, EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"), requireTls: false, isDsn: false, Now);

        OutboundQueueItem item = OutboundQueueItem.Rehydrate(
            fresh.Id, fresh.MessageId, fresh.RecipientId, fresh.DestinationAddress, fresh.ReversePath,
            fresh.RequireTls, fresh.IsDsn, fresh.Priority, QueueStatus.Pending, 3,
            Now.AddHours(-5), Now.AddHours(-5), null, null, delayWarningSentUtc: null, "previously deferred",
            Now.AddHours(-5));

        await harness.Queue.AddAsync(item, CancellationToken.None);
        harness.DeliveryClient.Enqueue(Deferred());

        await harness.RunUntilAsync(() => harness.DsnComposer.Requests.Count == 1);

        harness.DsnComposer.Requests[0].IsDelayWarning.ShouldBeTrue();

        OutboundQueueItem afterFirstWarning = harness.Queue.AllItems.Single(i => i.Id == item.Id);
        afterFirstWarning.DelayWarningSentUtc.ShouldNotBeNull();

        // Advance the clock and fail again: no second delay-warning DSN.
        harness.Clock.UtcNow = Now.AddHours(-5) + TimeSpan.FromMinutes(90);
        harness.DeliveryClient.Enqueue(Deferred());

        await harness.RunUntilAsync(
            () => harness.Queue.AllItems.Single(i => i.Id == item.Id).AttemptCount == 4,
            TimeSpan.FromSeconds(3));

        harness.DsnComposer.Requests.Count.ShouldBe(1);
    }
}
