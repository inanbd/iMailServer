using System.IO.Compression;
using System.Text;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Deliverability;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// Reading reports out of the mailbox the rua address delivers to.
/// </summary>
/// <remarks>
/// The interesting behaviour is all about not doing something twice: not re-reading a report
/// already held, and not re-opening a message that turned out not to be one.
/// </remarks>
public sealed class TlsReportCollectorTests
{
    private static readonly EmailAddress ReportAddress = EmailAddress.Parse("tlsrpt@example.com");

    private static byte[] ReportMessage(string reportId, string organization = "Google Inc.")
    {
        string json = $$"""
            {
              "organization-name": "{{organization}}",
              "report-id": "{{reportId}}",
              "policies": [{
                "summary": { "total-successful-session-count": 10, "total-failure-session-count": 1 },
                "failure-details": [
                  { "result-type": "certificate-expired", "receiving-mx-hostname": "mx.example.com", "failed-session-count": 1 }
                ]
              }]
            }
            """;

        using MemoryStream gz = new();

        using (GZipStream zip = new(gz, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            zip.Write(bytes, 0, bytes.Length);
        }

        return Encoding.ASCII.GetBytes(
            "From: noreply@google.com\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: application/tlsrpt+gzip\r\n" +
            "Content-Transfer-Encoding: base64\r\n" +
            "\r\n" +
            Convert.ToBase64String(gz.ToArray(), Base64FormattingOptions.InsertLineBreaks) + "\r\n");
    }

    private static (TlsReportCollector Collector, FakeReports Reports, FakeStore Store) Build(
        bool enabled = true,
        string mailbox = "tlsrpt@example.com",
        bool mailboxExists = true)
    {
        MailServerOptions options = new();

        options.Deliverability.TlsRpt.Enabled = enabled;
        options.Deliverability.TlsRpt.ReportMailbox = mailbox;

        FakeReports reports = new();
        FakeStore store = new();

        TlsReportCollector collector = new(
            reports,
            new TlsReportExtractor(new TlsReportReader()),
            new FakeMailboxes(mailboxExists),
            store,
            new FixedClock(),
            Options.Create(options),
            NullLogger<TlsReportCollector>.Instance);

        return (collector, reports, store);
    }

    [Fact]
    public async Task A_report_message_is_collected()
    {
        (TlsReportCollector collector, FakeReports reports, FakeStore store) = Build();

        StoredMessageId id = store.Add(ReportMessage("r1"));
        reports.Pending.Add(id);

        TlsReportCollectionResult result = await collector.CollectAsync(CancellationToken.None);

        result.Examined.ShouldBe(1);
        result.Collected.ShouldBe(1);
        result.NotReports.ShouldBe(0);

        reports.Recorded.ShouldHaveSingleItem().Report.OrganizationName.ShouldBe("Google Inc.");
    }

    /// <summary>
    /// The report is filed under the domain whose rua address received it, never the
    /// policy-domain the sender wrote — otherwise anyone who can reach the address could file a
    /// report against any domain this server hosts.
    /// </summary>
    [Fact]
    public async Task A_report_is_filed_under_the_receiving_domain()
    {
        (TlsReportCollector collector, FakeReports reports, FakeStore store) = Build();

        reports.Pending.Add(store.Add(ReportMessage("r1")));

        await collector.CollectAsync(CancellationToken.None);

        reports.Recorded.ShouldHaveSingleItem().PolicyDomain.ShouldBe(ReportAddress.Domain.Value);
    }

    /// <summary>
    /// §4.1's report-id is how a retried delivery is recognised. Counted separately, because a
    /// pass that is all duplicates says something different from a pass that found nothing.
    /// </summary>
    [Fact]
    public async Task A_report_already_held_counts_as_a_duplicate_and_is_still_marked_examined()
    {
        (TlsReportCollector collector, FakeReports reports, FakeStore store) = Build();

        StoredMessageId id = store.Add(ReportMessage("r1"));

        reports.Pending.Add(id);
        reports.AlreadyHeld.Add("r1");

        TlsReportCollectionResult result = await collector.CollectAsync(CancellationToken.None);

        result.Duplicates.ShouldBe(1);
        result.Collected.ShouldBe(0);

        // The message must not come back next pass, or a sender retrying would have its
        // delivery re-opened forever.
        reports.Examined.ShouldContain(id);
    }

    /// <summary>
    /// A bounce or a covering note will sit in that mailbox forever. Recording the failure is
    /// what stops it being opened and rejected on every pass for the life of the installation.
    /// </summary>
    [Fact]
    public async Task A_message_that_is_not_a_report_is_marked_examined_with_its_reason()
    {
        (TlsReportCollector collector, FakeReports reports, FakeStore store) = Build();

        StoredMessageId id = store.Add(Encoding.ASCII.GetBytes(
            "From: someone@example.net\r\nContent-Type: text/plain\r\n\r\nNot a report.\r\n"));

        reports.Pending.Add(id);

        TlsReportCollectionResult result = await collector.CollectAsync(CancellationToken.None);

        result.NotReports.ShouldBe(1);
        result.Collected.ShouldBe(0);

        reports.Examined.ShouldContain(id);
        reports.Failures[id].ShouldContain("no attachment");
    }

    /// <summary>
    /// A message whose content is gone must not be retried forever either — the reason is
    /// recorded so an operator asking why gets an answer.
    /// </summary>
    [Fact]
    public async Task A_message_that_cannot_be_read_is_recorded_rather_than_retried_forever()
    {
        (TlsReportCollector collector, FakeReports reports, FakeStore store) = Build();

        StoredMessageId missing = new(Guid.NewGuid());

        reports.Pending.Add(missing);
        store.Unreadable.Add(missing);

        TlsReportCollectionResult result = await collector.CollectAsync(CancellationToken.None);

        result.NotReports.ShouldBe(1);
        reports.Failures[missing].ShouldContain("could not be read");
    }

    [Fact]
    public async Task Collection_is_a_no_op_when_disabled()
    {
        (TlsReportCollector collector, FakeReports reports, FakeStore store) = Build(enabled: false);

        reports.Pending.Add(store.Add(ReportMessage("r1")));

        (await collector.CollectAsync(CancellationToken.None)).ShouldBe(TlsReportCollectionResult.None);
        reports.Recorded.ShouldBeEmpty();
    }

    /// <summary>
    /// Neither a misconfigured address nor a missing mailbox is an error worth failing a host
    /// over: collection is a diagnostic and the server is otherwise serving mail.
    /// </summary>
    [Theory]
    [InlineData("not an address", true)]
    [InlineData("tlsrpt@example.com", false)]
    public async Task A_misconfiguration_collects_nothing_rather_than_throwing(
        string mailbox,
        bool mailboxExists)
    {
        (TlsReportCollector collector, FakeReports reports, FakeStore store) =
            Build(mailbox: mailbox, mailboxExists: mailboxExists);

        reports.Pending.Add(store.Add(ReportMessage("r1")));

        (await collector.CollectAsync(CancellationToken.None)).ShouldBe(TlsReportCollectionResult.None);
        reports.Recorded.ShouldBeEmpty();
    }

    /// <summary>A pass is bounded so a year of backlog is not worked through in one go.</summary>
    [Fact]
    public async Task One_pass_asks_for_no_more_than_its_limit()
    {
        (TlsReportCollector collector, FakeReports reports, FakeStore store) = Build();

        reports.Pending.Add(store.Add(ReportMessage("r1")));

        await collector.CollectAsync(CancellationToken.None);

        reports.RequestedLimit.ShouldBe(TlsReportCollector.MaxMessagesPerPass);
    }

    // ---- Fakes --------------------------------------------------------------------------------

    private sealed class FakeReports : ITlsReportRepository
    {
        public List<StoredMessageId> Pending { get; } = [];

        public HashSet<string> AlreadyHeld { get; } = [];

        public List<(StoredMessageId MessageId, string PolicyDomain, TlsReport Report)> Recorded { get; } = [];

        public List<StoredMessageId> Examined { get; } = [];

        public Dictionary<StoredMessageId, string> Failures { get; } = [];

        public int RequestedLimit { get; private set; }

        public Task<IReadOnlyList<StoredMessageId>> ListUnexaminedAsync(
            MailboxId mailboxId,
            int limit,
            CancellationToken cancellationToken)
        {
            RequestedLimit = limit;
            return Task.FromResult<IReadOnlyList<StoredMessageId>>([.. Pending.Take(limit)]);
        }

        public Task<bool> RecordAsync(
            StoredMessageId messageId,
            string policyDomain,
            TlsReport report,
            DateTimeOffset collectedUtc,
            CancellationToken cancellationToken)
        {
            Examined.Add(messageId);

            bool held = report.ReportId is { Length: > 0 } && AlreadyHeld.Contains(report.ReportId);

            if (!held)
            {
                Recorded.Add((messageId, policyDomain, report));
            }

            return Task.FromResult(!held);
        }

        public Task RecordFailureAsync(
            StoredMessageId messageId,
            string error,
            DateTimeOffset examinedUtc,
            CancellationToken cancellationToken)
        {
            Examined.Add(messageId);
            Failures[messageId] = error;

            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<CollectedTlsReport>> ListRecentAsync(
            string policyDomain,
            int limit,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FakeStore : IMessageStore
    {
        private readonly Dictionary<StoredMessageId, byte[]> _messages = [];

        public HashSet<StoredMessageId> Unreadable { get; } = [];

        public StoredMessageId Add(byte[] octets)
        {
            StoredMessageId id = new(Guid.NewGuid());
            _messages[id] = octets;
            return id;
        }

        public ValueTask<IMessageWriter> BeginWriteAsync(long maxSizeBytes, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken) =>
            Unreadable.Contains(id) || !_messages.TryGetValue(id, out byte[]? octets)
                ? throw new FileNotFoundException("The message content is gone.")
                : ValueTask.FromResult<Stream>(new MemoryStream(octets));

        public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_messages.ContainsKey(id));

        public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_messages.Remove(id));
    }

    /// <summary>
    /// Only <see cref="GetByAddressAsync"/> is reachable from the collector; the rest of the
    /// repository's surface throws, so a change that made the collector reach for something else
    /// fails loudly here rather than quietly doing it.
    /// </summary>
    private sealed class FakeMailboxes(bool exists) : IMailboxRepository
    {
        public Task<Mailbox?> GetByAddressAsync(EmailAddress address, CancellationToken cancellationToken) =>
            Task.FromResult(exists ? Existing(address) : null);

        private static Mailbox Existing(EmailAddress address)
        {
            DateTimeOffset now = new(2026, 9, 20, 12, 0, 0, TimeSpan.Zero);

            MailDomain domain = MailDomain.Create(new DomainId(Guid.NewGuid()), address.Domain, now);

            return Mailbox.Create(
                domain.Id,
                address,
                domain,
                "Reports",
                QuotaBytes.Unlimited,
                MailboxAccess.Imap,
                now);
        }

        public Task<Mailbox?> GetAsync(MailboxId id, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<bool> AddressExistsAsync(EmailAddress address, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<Mailbox>> GetByDomainAsync(DomainId domainId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<int> CountByDomainAsync(DomainId domainId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task AddAsync(Mailbox mailbox, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task UpdateAsync(Mailbox mailbox, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task RemoveAsync(MailboxId id, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<MailboxCredential?> GetCredentialAsync(MailboxId mailboxId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task AddCredentialAsync(MailboxCredential credential, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task UpdateCredentialAsync(MailboxCredential credential, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<MailboxFolder>> GetFoldersAsync(MailboxId mailboxId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task AddFolderAsync(MailboxFolder folder, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task UpdateFolderAsync(MailboxFolder folder, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task RemoveFolderAsync(MailboxFolderId id, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FixedClock : IClock
    {
        public DateTimeOffset UtcNow => new(2026, 9, 20, 12, 0, 0, TimeSpan.Zero);

        public long GetTimestamp() => System.Diagnostics.Stopwatch.GetTimestamp();

        public TimeSpan GetElapsedTime(long startingTimestamp) =>
            System.Diagnostics.Stopwatch.GetElapsedTime(startingTimestamp);
    }
}
