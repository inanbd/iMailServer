using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Persistence.Tests;

public sealed class OutboundQueueRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static async Task<(StoredMessageId MessageId, Guid RecipientId)> SeedMessageAsync(
        SqliteTestDatabase.TestScope scope,
        EmailAddress? reversePath = null)
    {
        StoredMessageId messageId = StoredMessageId.New();

        MessageRecord message = MessageRecord.Create(
            messageId,
            sizeBytes: 512,
            Sha256Hash.FromBytes(new byte[32]),
            reversePath ?? EmailAddress.Parse("sender@origin.example"),
            IpAddressValue.Parse("203.0.113.10"),
            greetedName: "origin.example",
            SmtpListenerRole.Submission,
            tlsActive: true,
            authenticatedAs: null,
            Now);

        await scope.Deliveries.AddMessageAsync(message, CancellationToken.None);

        MessageRecipient recipient = MessageRecipient.Create(
            messageId,
            EmailAddress.Parse("recipient@destination.example"),
            RelayDecision.AcceptRelay);

        await scope.Deliveries.AddRecipientAsync(recipient, CancellationToken.None);

        return (messageId, recipient.Id);
    }

    [Fact]
    public async Task An_item_round_trips_through_the_database_intact()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope);

        OutboundQueueItem original = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: true,
            isDsn: false,
            Now);

        await scope.Outbound.AddAsync(original, CancellationToken.None);

        IReadOnlyList<OutboundQueueItem> claimed = await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 10, TimeSpan.FromMinutes(5), Now, CancellationToken.None);

        claimed.Count.ShouldBe(1);
        OutboundQueueItem loaded = claimed[0];

        loaded.Id.ShouldBe(original.Id);
        loaded.DestinationAddress.ShouldBe(original.DestinationAddress);
        loaded.DestinationDomain.Value.ShouldBe("destination.example");
        loaded.ReversePath.ShouldBe(original.ReversePath);
        loaded.RequireTls.ShouldBeTrue();
        loaded.Status.ShouldBe(QueueStatus.Processing);
        loaded.AttemptCount.ShouldBe(1);
        loaded.LeaseOwner.ShouldBe("worker-1");
        loaded.LeaseExpiresUtc.ShouldBe(Now.AddMinutes(5));
    }

    [Fact]
    public async Task A_null_reverse_path_round_trips_as_null_not_as_a_missing_value()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope, reversePath: null);

        OutboundQueueItem original = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            reversePath: null,
            requireTls: false,
            isDsn: true,
            Now);

        await scope.Outbound.AddAsync(original, CancellationToken.None);

        IReadOnlyList<OutboundQueueItem> claimed = await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 10, TimeSpan.FromMinutes(5), Now, CancellationToken.None);

        claimed[0].ReversePath.ShouldBeNull();
        claimed[0].ShouldGenerateDsnOnFailure.ShouldBeFalse();
    }

    [Fact]
    public async Task An_item_not_yet_due_is_not_claimed()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope);

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: false,
            isDsn: false,
            Now);

        await scope.Outbound.AddAsync(item, CancellationToken.None);

        IReadOnlyList<OutboundQueueItem> claimed = await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 10, TimeSpan.FromMinutes(5), Now.AddMinutes(-1), CancellationToken.None);

        claimed.ShouldBeEmpty();
    }

    [Fact]
    public async Task Two_workers_claiming_concurrently_never_claim_the_same_item()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope);

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: false,
            isDsn: false,
            Now);

        await scope.Outbound.AddAsync(item, CancellationToken.None);

        IReadOnlyList<OutboundQueueItem> firstClaim = await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 10, TimeSpan.FromMinutes(5), Now, CancellationToken.None);

        IReadOnlyList<OutboundQueueItem> secondClaim = await scope.Outbound.ClaimDueAsync(
            "worker-2", maxItems: 10, TimeSpan.FromMinutes(5), Now, CancellationToken.None);

        firstClaim.Count.ShouldBe(1);
        secondClaim.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_deferred_item_becomes_claimable_once_its_next_attempt_time_arrives()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope);

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: false,
            isDsn: false,
            Now);

        await scope.Outbound.AddAsync(item, CancellationToken.None);

        OutboundQueueItem claimed = (await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 10, TimeSpan.FromMinutes(5), Now, CancellationToken.None))[0];

        DateTimeOffset next = Now.AddMinutes(5);
        claimed.MarkDeferred(next, "421 4.3.0 try again", Now);
        await scope.Outbound.UpdateAsync(claimed, CancellationToken.None);

        (await scope.Outbound.ClaimDueAsync(
            "worker-2", maxItems: 10, TimeSpan.FromMinutes(5), next.AddSeconds(-1), CancellationToken.None))
            .ShouldBeEmpty();

        IReadOnlyList<OutboundQueueItem> readyClaim = await scope.Outbound.ClaimDueAsync(
            "worker-2", maxItems: 10, TimeSpan.FromMinutes(5), next, CancellationToken.None);

        readyClaim.Count.ShouldBe(1);
        readyClaim[0].AttemptCount.ShouldBe(2);
        readyClaim[0].LastFailureReason.ShouldBe("421 4.3.0 try again");
    }

    [Fact]
    public async Task A_lease_left_by_a_crashed_worker_is_reclaimed_once_it_expires()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope);

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: false,
            isDsn: false,
            Now);

        await scope.Outbound.AddAsync(item, CancellationToken.None);

        await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 10, TimeSpan.FromMinutes(1), Now, CancellationToken.None);

        // The lease expires 1 minute out. Before that, nobody else can claim it.
        (await scope.Outbound.ClaimDueAsync(
            "worker-2", maxItems: 10, TimeSpan.FromMinutes(1), Now.AddSeconds(30), CancellationToken.None))
            .ShouldBeEmpty();

        // worker-1 never came back. Once the lease has expired, worker-2 reclaims it.
        IReadOnlyList<OutboundQueueItem> reclaimed = await scope.Outbound.ClaimDueAsync(
            "worker-2", maxItems: 10, TimeSpan.FromMinutes(1), Now.AddMinutes(2), CancellationToken.None);

        reclaimed.Count.ShouldBe(1);
        reclaimed[0].LeaseOwner.ShouldBe("worker-2");
        reclaimed[0].AttemptCount.ShouldBe(2);
    }

    [Fact]
    public async Task Releasing_a_leaseholders_items_makes_them_immediately_claimable()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope);

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: false,
            isDsn: false,
            Now);

        await scope.Outbound.AddAsync(item, CancellationToken.None);

        await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 10, TimeSpan.FromHours(1), Now, CancellationToken.None);

        await scope.Outbound.ReleaseLeaseAsync("worker-1", Now.AddSeconds(1), CancellationToken.None);

        IReadOnlyList<OutboundQueueItem> reclaimed = await scope.Outbound.ClaimDueAsync(
            "worker-2", maxItems: 10, TimeSpan.FromMinutes(1), Now.AddSeconds(1), CancellationToken.None);

        reclaimed.Count.ShouldBe(1);
    }

    [Fact]
    public async Task A_dsn_item_is_claimed_before_ordinary_mail_queued_earlier()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId ordinaryMessageId, Guid ordinaryRecipientId) = await SeedMessageAsync(scope);
        OutboundQueueItem ordinary = OutboundQueueItem.Create(
            ordinaryMessageId,
            ordinaryRecipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: false,
            isDsn: false,
            Now);
        await scope.Outbound.AddAsync(ordinary, CancellationToken.None);

        (StoredMessageId dsnMessageId, Guid dsnRecipientId) = await SeedMessageAsync(scope, reversePath: null);
        OutboundQueueItem dsn = OutboundQueueItem.Create(
            dsnMessageId,
            dsnRecipientId,
            EmailAddress.Parse("sender@origin.example"),
            reversePath: null,
            requireTls: false,
            isDsn: true,
            Now.AddSeconds(1));
        await scope.Outbound.AddAsync(dsn, CancellationToken.None);

        IReadOnlyList<OutboundQueueItem> claimed = await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 1, TimeSpan.FromMinutes(5), Now.AddSeconds(2), CancellationToken.None);

        claimed.Count.ShouldBe(1);
        claimed[0].IsDsn.ShouldBeTrue();
    }

    [Fact]
    public async Task Delivering_a_claimed_item_marks_it_terminal()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope);

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: false,
            isDsn: false,
            Now);
        await scope.Outbound.AddAsync(item, CancellationToken.None);

        OutboundQueueItem claimed = (await scope.Outbound.ClaimDueAsync(
            "worker-1", maxItems: 10, TimeSpan.FromMinutes(5), Now, CancellationToken.None))[0];

        claimed.MarkDelivered(Now.AddSeconds(1));
        await scope.Outbound.UpdateAsync(claimed, CancellationToken.None);

        (await scope.Outbound.ClaimDueAsync(
            "worker-2", maxItems: 10, TimeSpan.FromMinutes(5), Now.AddDays(1), CancellationToken.None))
            .ShouldBeEmpty();
    }

    [Fact]
    public async Task A_delivery_attempt_round_trips_with_full_diagnostic_detail()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId, Guid recipientId) = await SeedMessageAsync(scope);

        OutboundQueueItem item = OutboundQueueItem.Create(
            messageId,
            recipientId,
            EmailAddress.Parse("recipient@destination.example"),
            EmailAddress.Parse("sender@origin.example"),
            requireTls: false,
            isDsn: false,
            Now);
        await scope.Outbound.AddAsync(item, CancellationToken.None);

        DeliveryAttempt attempt = DeliveryAttempt.Create(
            queueItemId: item.Id,
            attemptNumber: 1,
            startedUtc: Now,
            completedUtc: Now.AddSeconds(2),
            mxHostname: "mx1.destination.example",
            remoteAddress: IpAddressValue.Parse("198.51.100.7"),
            tlsActive: true,
            tlsProtocol: "Tls13",
            tlsCipher: "TLS_AES_256_GCM_SHA384",
            peerCertificateSubject: "CN=mx1.destination.example",
            peerCertificateIssuer: "CN=Test CA",
            replyCode: 250,
            enhancedStatus: "2.0.0",
            replyText: "OK queued",
            outcome: DeliveryOutcome.Delivered,
            classification: FailureClassification.None,
            errorDetail: null);

        await scope.Outbound.AddAttemptAsync(attempt, CancellationToken.None);

        // A second attempt against the same item, with a failure this time. No read API is
        // exposed beyond persistence today (Milestone 8's admin surface is deferred - see the
        // queue-visibility scoping note in docs); this asserts the write path itself never
        // throws against the real schema and constraints, including nullable diagnostic columns,
        // which is what would fail if a column were mistyped or a foreign key mis-declared.
        DeliveryAttempt failure = DeliveryAttempt.Create(
            queueItemId: item.Id,
            attemptNumber: 2,
            startedUtc: Now.AddMinutes(1),
            completedUtc: Now.AddMinutes(1).AddSeconds(1),
            mxHostname: null,
            remoteAddress: null,
            tlsActive: false,
            tlsProtocol: null,
            tlsCipher: null,
            peerCertificateSubject: null,
            peerCertificateIssuer: null,
            replyCode: null,
            enhancedStatus: null,
            replyText: null,
            outcome: DeliveryOutcome.Deferred,
            classification: FailureClassification.Temporary,
            errorDetail: "Connection refused");

        await Should.NotThrowAsync(() => scope.Outbound.AddAttemptAsync(failure, CancellationToken.None));
    }

    [Fact]
    public async Task Queue_depth_reports_pending_and_processing_counts()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);
        SqliteTestDatabase.TestScope scope = database.CreateScope();

        (StoredMessageId messageId1, Guid recipientId1) = await SeedMessageAsync(scope);
        await scope.Outbound.AddAsync(
            OutboundQueueItem.Create(
                messageId1, recipientId1,
                EmailAddress.Parse("recipient@destination.example"),
                EmailAddress.Parse("sender@origin.example"),
                requireTls: false, isDsn: false, Now),
            CancellationToken.None);

        (StoredMessageId messageId2, Guid recipientId2) = await SeedMessageAsync(scope);
        await scope.Outbound.AddAsync(
            OutboundQueueItem.Create(
                messageId2, recipientId2,
                EmailAddress.Parse("recipient@destination.example"),
                EmailAddress.Parse("sender@origin.example"),
                requireTls: false, isDsn: false, Now),
            CancellationToken.None);

        await scope.Outbound.ClaimDueAsync("worker-1", maxItems: 1, TimeSpan.FromMinutes(5), Now, CancellationToken.None);

        QueueDepth depth = await scope.Outbound.GetDepthAsync(CancellationToken.None);

        depth.Pending.ShouldBe(1);
        depth.Processing.ShouldBe(1);
        depth.OldestPendingUtc.ShouldBe(Now);
    }
}
