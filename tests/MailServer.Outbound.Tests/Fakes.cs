using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Outbound.Tests;

internal sealed class FakeServerIdentity : IServerIdentityProvider
{
    public string Hostname => "test-client.example";

    public string? PublicIpAddress => null;

    public string ProductName => "Test";
}

/// <summary>
/// An in-memory queue repository, for testing <c>OutboundDeliveryHostedService</c>'s decisions
/// (retry scheduling, bounce, DSN generation) without a real database - persistence correctness
/// itself is <c>MailServer.Persistence.Tests</c>'s job; what is tested here is that the worker
/// makes the right call given a queue state, which does not need SQLite to prove.
/// </summary>
internal sealed class FakeOutboundQueueRepository : IOutboundQueueRepository
{
    private readonly Lock _gate = new();
    private readonly Dictionary<Guid, OutboundQueueItem> _items = [];

    public List<DeliveryAttempt> Attempts { get; } = [];

    public IReadOnlyList<OutboundQueueItem> AllItems
    {
        get { lock (_gate) { return [.. _items.Values]; } }
    }

    public Task AddAsync(OutboundQueueItem item, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _items[item.Id.Value] = item;
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<OutboundQueueItem>> ClaimDueAsync(
        string leaseOwner, int maxItems, TimeSpan leaseDuration, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            List<OutboundQueueItem> claimed = [];

            foreach (OutboundQueueItem item in _items.Values.OrderBy(i => i.Priority).ThenBy(i => i.FirstQueuedUtc))
            {
                bool due =
                    (item.Status is QueueStatus.Pending or QueueStatus.Deferred && item.NextAttemptUtc <= nowUtc) ||
                    (item.Status == QueueStatus.Processing && item.LeaseExpiresUtc <= nowUtc);

                if (!due)
                {
                    continue;
                }

                OutboundQueueItem rehydrated = OutboundQueueItem.Rehydrate(
                    item.Id,
                    item.MessageId,
                    item.RecipientId,
                    item.DestinationAddress,
                    item.ReversePath,
                    item.RequireTls,
                    item.IsDsn,
                    item.Priority,
                    QueueStatus.Processing,
                    item.AttemptCount + 1,
                    item.FirstQueuedUtc,
                    item.NextAttemptUtc,
                    leaseOwner,
                    nowUtc + leaseDuration,
                    item.DelayWarningSentUtc,
                    item.LastFailureReason,
                    nowUtc);

                _items[item.Id.Value] = rehydrated;
                claimed.Add(rehydrated);

                if (claimed.Count >= maxItems)
                {
                    break;
                }
            }

            return Task.FromResult<IReadOnlyList<OutboundQueueItem>>(claimed);
        }
    }

    public Task UpdateAsync(OutboundQueueItem item, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _items[item.Id.Value] = item;
        }

        return Task.CompletedTask;
    }

    public Task AddAttemptAsync(DeliveryAttempt attempt, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            Attempts.Add(attempt);
        }

        return Task.CompletedTask;
    }

    public Task ReleaseLeaseAsync(string leaseOwner, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            foreach (Guid key in _items.Keys.ToList())
            {
                OutboundQueueItem item = _items[key];

                if (item.Status != QueueStatus.Processing)
                {
                    continue;
                }

                _items[key] = OutboundQueueItem.Rehydrate(
                    item.Id, item.MessageId, item.RecipientId, item.DestinationAddress, item.ReversePath,
                    item.RequireTls, item.IsDsn, item.Priority, QueueStatus.Pending, item.AttemptCount,
                    item.FirstQueuedUtc, nowUtc, null, null, item.DelayWarningSentUtc, item.LastFailureReason, nowUtc);
            }
        }

        return Task.CompletedTask;
    }

    public Task<QueueDepth> GetDepthAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            int pending = _items.Values.Count(i => i.Status is QueueStatus.Pending or QueueStatus.Deferred);
            int processing = _items.Values.Count(i => i.Status == QueueStatus.Processing);
            DateTimeOffset? oldest = _items.Values
                .Where(i => i.Status is QueueStatus.Pending or QueueStatus.Deferred)
                .Select(i => (DateTimeOffset?)i.FirstQueuedUtc)
                .OrderBy(d => d)
                .FirstOrDefault();

            return Task.FromResult(new QueueDepth(pending, processing, oldest));
        }
    }

    public Task<DeliveryOutcomeCounts> GetOutcomeCountsAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            List<DeliveryAttempt> recent = [.. Attempts.Where(a => a.CompletedUtc >= sinceUtc)];

            return Task.FromResult(new DeliveryOutcomeCounts(
                recent.Count(a => a.Outcome == DeliveryOutcome.Delivered),
                recent.Count(a => a.Outcome == DeliveryOutcome.Bounced)));
        }
    }
}

/// <summary>A scriptable fake MX resolver: one result per domain, set up by the test.</summary>
internal sealed class FakeDnsResolver : IDnsResolver
{
    private readonly Dictionary<string, MxLookupResult> _mx = new(StringComparer.OrdinalIgnoreCase);

    public void SetMx(string domain, MxLookupResult result) => _mx[domain] = result;

    public Task<MxLookupResult> ResolveMxAsync(DomainName domain, CancellationToken cancellationToken) =>
        Task.FromResult(_mx.TryGetValue(domain.Value, out MxLookupResult? result)
            ? result
            : MxLookupResult.Success([new MxHost(domain.Value, 0)]));

    public Task<AddressLookupResult> ResolveAddressesAsync(string hostname, CancellationToken cancellationToken) =>
        Task.FromResult(AddressLookupResult.Success([IpAddressValue.Parse("203.0.113.10")]));
}

/// <summary>A scriptable fake delivery client: returns queued results in order, per target host.</summary>
internal sealed class FakeOutboundDeliveryClient : IOutboundDeliveryClient
{
    private readonly Queue<OutboundDeliveryResult> _results = new();

    public List<OutboundDeliveryRequest> Requests { get; } = [];

    public void Enqueue(OutboundDeliveryResult result) => _results.Enqueue(result);

    public Task<OutboundDeliveryResult> DeliverAsync(OutboundDeliveryRequest request, CancellationToken cancellationToken)
    {
        Requests.Add(request);

        OutboundDeliveryResult result = _results.Count > 0
            ? _results.Dequeue()
            : new OutboundDeliveryResult(
                DeliveryOutcome.Delivered, FailureClassification.None, null, false, null, null, null, null,
                250, "2.0.0", "OK", null);

        return Task.FromResult(result);
    }
}

/// <summary>A DSN composer producing deterministic, inspectable content.</summary>
internal sealed class FakeDsnComposer : IDsnComposer
{
    public List<DsnRequest> Requests { get; } = [];

    public DsnMessage Compose(DsnRequest request)
    {
        Requests.Add(request);

        string subject = request.IsDelayWarning ? "Delayed" : "Failed";
        byte[] content = System.Text.Encoding.UTF8.GetBytes(
            $"To: {request.OriginalReversePath.Value}\r\nSubject: {subject}\r\n\r\n{request.Diagnostic}\r\n");

        return new DsnMessage(content, request.OriginalReversePath, subject);
    }
}

/// <summary>An in-memory message store.</summary>
internal sealed class FakeMessageStore : IMessageStore
{
    private readonly Dictionary<Guid, byte[]> _content = [];

    public ValueTask<IMessageWriter> BeginWriteAsync(long maxSizeBytes, CancellationToken cancellationToken) =>
        ValueTask.FromResult<IMessageWriter>(new Writer(this));

    public ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult<Stream>(new MemoryStream(_content[id.Value]));

    public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_content.ContainsKey(id.Value));

    public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_content.Remove(id.Value));

    private sealed class Writer(FakeMessageStore store) : IMessageWriter
    {
        private readonly MemoryStream _buffer = new();

        public StoredMessageId Id { get; } = StoredMessageId.New();

        public long BytesWritten => _buffer.Length;

        public ValueTask WriteAsync(ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken)
        {
            _buffer.Write(chunk.Span);
            return ValueTask.CompletedTask;
        }

        public ValueTask<StoredMessage> CommitAsync(CancellationToken cancellationToken)
        {
            byte[] bytes = _buffer.ToArray();
            store._content[Id.Value] = bytes;

            return ValueTask.FromResult(new StoredMessage(
                Id, bytes.LongLength, Sha256Hash.FromBytes(System.Security.Cryptography.SHA256.HashData(bytes)),
                DateTimeOffset.UtcNow));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

/// <summary>Records what a DSN's envelope was written as, without touching a real database.</summary>
internal sealed class FakeDeliveryRepository : IDeliveryRepository
{
    public List<MessageRecord> Messages { get; } = [];

    public List<MessageRecipient> Recipients { get; } = [];

    public Task AddMessageAsync(MessageRecord message, CancellationToken cancellationToken)
    {
        Messages.Add(message);
        return Task.CompletedTask;
    }

    public Task AddRecipientAsync(MessageRecipient recipient, CancellationToken cancellationToken)
    {
        Recipients.Add(recipient);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<MessageRecipient>> ListRecipientsAsync(
        StoredMessageId messageId,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<MessageRecipient>>(
            [.. Recipients.Where(r => r.MessageId == messageId)]);

    public Task<long> AllocateUidAsync(MailboxFolderId folderId, CancellationToken cancellationToken) =>
        Task.FromResult(1L);

    public Task AddDeliveryAsync(Delivery delivery, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task AddStorageUsedAsync(MailboxId mailboxId, long bytes, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task<MailboxFolder?> GetFolderAsync(
        MailboxId mailboxId, FolderSpecialUse specialUse, CancellationToken cancellationToken) =>
        Task.FromResult<MailboxFolder?>(null);

    public Task AddDkimVerificationAsync(DkimVerificationRecord record, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task AddDmarcVerificationAsync(DmarcVerificationRecord record, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task MarkContentRemovedAsync(StoredMessageId messageId, DateTimeOffset removedUtc, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}

/// <summary>
/// Reports every domain as unknown, so <c>OutboundSmtpClient</c>'s DKIM signing lookup always
/// finds nothing and sends unsigned - exactly this test suite's existing behaviour, since none
/// of its scenarios are about DKIM.
/// </summary>
internal sealed class FakeDomainRepository : IDomainRepository
{
    public Task<MailDomain?> GetByIdAsync(DomainId id, CancellationToken cancellationToken) =>
        Task.FromResult<MailDomain?>(null);

    public Task<MailDomain?> GetByNameAsync(DomainName name, CancellationToken cancellationToken) =>
        Task.FromResult<MailDomain?>(null);

    public Task<bool> ExistsAsync(DomainName name, CancellationToken cancellationToken) =>
        Task.FromResult(false);

    public Task<IReadOnlyList<MailDomain>> GetAllAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<MailDomain>>([]);

    public Task<IReadOnlyList<MailDomain>> GetOperationalAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<MailDomain>>([]);

    public Task AddAsync(MailDomain domain, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task UpdateAsync(MailDomain domain, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task RemoveAsync(DomainId id, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<int> CountMailboxesAsync(DomainId id, CancellationToken cancellationToken) => Task.FromResult(0);
}

/// <summary>Reports no active key for any domain, for the same reason as <see cref="FakeDomainRepository"/>.</summary>
internal sealed class FakeDkimKeyRepository : IDkimKeyRepository
{
    public Task<DkimKey?> GetAsync(DkimKeyId id, CancellationToken cancellationToken) =>
        Task.FromResult<DkimKey?>(null);

    public Task<IReadOnlyList<DkimKey>> GetForDomainAsync(DomainId domainId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<DkimKey>>([]);

    public Task<DkimKey?> GetActiveForDomainAsync(DomainId domainId, CancellationToken cancellationToken) =>
        Task.FromResult<DkimKey?>(null);

    public Task<IReadOnlyList<DkimKey>> GetAllAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<DkimKey>>([]);

    public Task AddAsync(DkimKey key, byte[] pkcs8PrivateKey, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task UpdateAsync(DkimKey key, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task RemoveAsync(DkimKeyId id, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<byte[]?> GetPrivateKeyAsync(DkimKeyId id, CancellationToken cancellationToken) =>
        Task.FromResult<byte[]?>(null);
}

internal sealed class FakeClock(DateTimeOffset now) : IClock
{
    public DateTimeOffset UtcNow { get; set; } = now;

    public long GetTimestamp() => UtcNow.Ticks;

    public TimeSpan GetElapsedTime(long startingTimestamp) => UtcNow - new DateTimeOffset(startingTimestamp, TimeSpan.Zero);
}

internal sealed class FakeHealthRegistry : IHealthRegistry
{
    private readonly Dictionary<string, HealthReading> _readings = new(StringComparer.Ordinal);

    public void Publish(HealthReading reading) => _readings[reading.Component] = reading;

    public void Publish(string component, HealthState state, string message) =>
        Publish(new HealthReading(component, state, message, DateTimeOffset.UtcNow));

    public IReadOnlyList<HealthReading> GetAll() => [.. _readings.Values];

    public HealthReading? Get(string component) => _readings.GetValueOrDefault(component);

    public HealthState GetOverallState() =>
        _readings.Values.Select(r => r.State).DefaultIfEmpty(HealthState.Unknown).Max();
}

/// <summary>A directory that knows which domains are hosted here, and nothing else.</summary>
/// <remarks>
/// The worker asks it one question — is a bounce's recipient one of ours — so the others refuse
/// loudly rather than answering something a test did not arrange.
/// </remarks>
internal sealed class FakeHostedDomains : ISmtpDirectory
{
    public HashSet<string> Hosted { get; } = new(StringComparer.OrdinalIgnoreCase);

    public ValueTask<bool> IsLocalDomainAsync(DomainName domain, CancellationToken cancellationToken) =>
        ValueTask.FromResult(Hosted.Contains(domain.Value));

    public ValueTask<DomainStatus?> GetConfiguredDomainStatusAsync(
        DomainName domain, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public ValueTask<LocalRecipientStatus> InspectLocalRecipientAsync(
        EmailAddress recipient, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public ValueTask<bool> IsAuthorizedRelayAddressAsync(
        IpAddressValue address, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public ValueTask<bool> MayActAsAsync(
        EmailAddress authenticatedMailbox, EmailAddress claimedSender, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public ValueTask<bool> MayRelayAsAsync(
        EmailAddress authenticatedMailbox, EmailAddress recipient, CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

/// <summary>Local delivery that records what it was handed, and places it in one mailbox per recipient.</summary>
internal sealed class RecordingLocalDelivery : ILocalDeliveryService
{
    public List<DeliveryRequest> Requests { get; } = [];

    /// <summary>Set to zero to act out a recipient whose mailbox no longer exists.</summary>
    public int MailboxesPerRecipient { get; set; } = 1;

    public Task<DeliveryResult> DeliverAsync(DeliveryRequest request, CancellationToken cancellationToken)
    {
        Requests.Add(request);

        return Task.FromResult(new DeliveryResult(
            request.Message.Id,
            [.. request.Recipients.Select(r => new RecipientOutcome(r.Address, MailboxesPerRecipient, false))]));
    }

    public Task<DeliveryResult> DeliverReleasedAsync(ReleaseRequest request, CancellationToken cancellationToken) =>
        throw new NotSupportedException("The outbound worker never releases quarantined mail.");
}
