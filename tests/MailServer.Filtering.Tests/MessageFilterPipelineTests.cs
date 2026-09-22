using System.Text;
using MailServer.Application.Abstractions.Filtering;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Filtering;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Filtering;
using MailServer.Infrastructure.Filtering.Checks;

namespace MailServer.Filtering.Tests;

public sealed class MessageFilterPipelineTests
{
    private static MessageFilterPipeline Build(
        FakeMessageStore store,
        IEnumerable<ISpamCheck> checks,
        FilterPolicy? policy = null,
        bool enabled = true,
        long maxContentBytes = FilterLimits.MaxContentBytes) =>
        new(
            checks,
            store,
            policy ?? FilterPolicy.Default,
            Fixture.Log<MessageFilterPipeline>(),
            enabled,
            FilterLimits.MaxHeaderBytes,
            maxContentBytes);

    [Fact]
    public async Task Accepts_an_ordinary_message()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.Ordinary);

        using MessageFilterPipeline pipeline = Build(
            store, [new HeaderHeuristicSpamCheck(), new AttachmentSpamCheck(AttachmentPolicy.Default)]);

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.Action.ShouldBe(FilterAction.Accept);
        verdict.Signals.ShouldBeEmpty();
    }

    [Fact]
    public async Task Does_nothing_at_all_when_it_is_switched_off()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.WithAttachment("filename=\"setup.exe\""));
        StubSpamCheck check = new("Stub", SpamCheckResult.Nothing);

        using MessageFilterPipeline pipeline = Build(store, [check], enabled: false);

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.ShouldBe(FilterVerdict.Clean);
        check.Inspections.ShouldBe(0);
        store.Reads.ShouldBe(0);
    }

    /// <summary>
    /// An executable attachment is held whatever else the message scored. Expressing that as a
    /// weight would work until somebody tuned a threshold.
    /// </summary>
    [Fact]
    public async Task Quarantines_an_executable_attachment_however_good_the_message_looks()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.WithAttachment("filename=\"setup.exe\""));

        using MessageFilterPipeline pipeline = Build(store, [
            new AuthenticationSpamCheck(),
            new HeaderHeuristicSpamCheck(),
            new AttachmentSpamCheck(AttachmentPolicy.Default),
        ]);

        FilterVerdict verdict = await pipeline.EvaluateAsync(
            Fixture.Request(message, Fixture.FullPass), CancellationToken.None);

        verdict.Action.ShouldBe(FilterAction.Quarantine);
        verdict.Signals.ShouldContain(s => s.Name == "BLOCKED_ATTACHMENT");
    }

    /// <summary>The decoder and the policy have to work together, or the policy is decorative.</summary>
    [Theory]
    [InlineData("filename=\"setup.exe\"")]
    [InlineData("filename*=utf-8''setup%2Eexe")]
    [InlineData("filename*0*=utf-8''set; filename*1*=up%2Eexe")]
    [InlineData("filename=\"=?utf-8?B?c2V0dXAuZXhl?=\"")]
    [InlineData("filename=\"setup.exe.  \"")]
    public async Task Catches_an_executable_however_its_name_was_written(string parameter)
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.WithAttachment(parameter));

        using MessageFilterPipeline pipeline = Build(store, [new AttachmentSpamCheck(AttachmentPolicy.Default)]);

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.Action.ShouldBe(FilterAction.Quarantine);
    }

    [Fact]
    public async Task Reads_the_message_once_however_many_checks_want_it()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.Ordinary);

        using MessageFilterPipeline pipeline = Build(store, [
            new HeaderHeuristicSpamCheck(),
            new AttachmentSpamCheck(AttachmentPolicy.Default),
            new AuthenticationSpamCheck(),
        ]);

        await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        store.Reads.ShouldBe(1);
    }

    /// <summary>
    /// A check with a bug must not stop mail. The rest run, and the message is judged on them.
    /// </summary>
    [Fact]
    public async Task Carries_on_when_a_check_throws()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.Ordinary);

        StubSpamCheck broken = new("Broken", SpamCheckResult.Nothing) { Throw = true };
        StubSpamCheck working = new("Working", SpamCheckResult.Weigh(
            [FilterSignal.Create("SOMETHING", 6.0, "detail")]));

        using MessageFilterPipeline pipeline = Build(store, [broken, working]);

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        working.Inspections.ShouldBe(1);
        verdict.Action.ShouldBe(FilterAction.Junk);
    }

    /// <summary>
    /// And a store that cannot be read is not a verdict about the message. Failing closed here
    /// would mean one broken file stops delivery.
    /// </summary>
    [Fact]
    public async Task Delivers_unfiltered_when_the_message_cannot_be_read()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.Ordinary);
        store.FailReads = true;

        using MessageFilterPipeline pipeline = Build(store, [new AttachmentSpamCheck(AttachmentPolicy.Default)]);

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.ShouldBe(FilterVerdict.Clean);
    }

    /// <summary>
    /// The bypass anybody would find first: if an oversized message skipped the checks that
    /// need a body and nothing said so, "send it big" would defeat the attachment policy.
    /// </summary>
    [Fact]
    public async Task Says_so_rather_than_passing_a_message_too_large_to_examine()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.AddClaimingSize(Fixture.Ordinary, 500L * 1024 * 1024);

        using MessageFilterPipeline pipeline = Build(
            store, [new AttachmentSpamCheck(AttachmentPolicy.Default)], maxContentBytes: 1024);

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.Signals.ShouldContain(s => s.Name == "ATTACHMENTS_NOT_EXAMINED");
        verdict.Action.ShouldBe(FilterAction.Junk);
    }

    /// <summary>An oversized message still gets its headers weighed.</summary>
    [Fact]
    public async Task Still_reads_the_headers_of_an_oversized_message()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.AddClaimingSize("""
            From: a@example.com
            From: b@evil.example
            To: c@example.net
            Date: Tue, 22 Sep 2026 11:58:00 +0000
            Message-ID: <x@example.com>

            body

            """, 500L * 1024 * 1024);

        using MessageFilterPipeline pipeline = Build(
            store, [new HeaderHeuristicSpamCheck()], maxContentBytes: 1024);

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.Signals.ShouldContain(s => s.Name == "MULTIPLE_FROM");
    }

    /// <summary>
    /// A message this server cannot find a header boundary in is weighed, not dropped: a parser
    /// bug of our own would otherwise quarantine everybody's mail.
    /// </summary>
    [Fact]
    public async Task Weighs_a_message_with_no_header_boundary()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add("no headers and no blank line at all");

        using MessageFilterPipeline pipeline = Build(store, [new HeaderHeuristicSpamCheck()]);

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.Signals.ShouldContain(s => s.Name == "UNPARSEABLE_HEADERS");
        verdict.Action.ShouldBe(FilterAction.Accept);
    }

    [Fact]
    public async Task A_verdict_with_no_checks_registered_is_clean()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.Ordinary);

        using MessageFilterPipeline pipeline = Build(store, []);

        (await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None))
            .ShouldBe(FilterVerdict.Clean);
    }
}

public sealed class MalwareCheckTests
{
    private static async Task<SpamCheckResult> RunAsync(
        IMalwareScanner scanner, bool failClosed = false, bool contentWasRead = true)
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.Ordinary);

        MessageFilterContext context = new(
            Fixture.Request(message),
            null,
            [],
            contentWasRead,
            ct => store.OpenReadAsync(message.Id, ct));

        MalwareSpamCheck check = new(scanner, Fixture.Log<MalwareSpamCheck>(), failClosed);

        return await check.InspectAsync(context, CancellationToken.None);
    }

    [Fact]
    public async Task Says_nothing_when_no_scanner_is_configured()
    {
        SpamCheckResult result = await RunAsync(new DisabledMalwareScanner());

        result.Signals.ShouldBeEmpty();
        result.Floor.ShouldBe(FilterAction.Accept);
    }

    /// <summary>
    /// The distinction the whole enumeration exists for: a no-op scanner must never be able to
    /// make a dashboard say a message was checked.
    /// </summary>
    [Fact]
    public async Task The_disabled_scanner_reports_not_scanned_rather_than_clean()
    {
        MalwareScanResult result = await new DisabledMalwareScanner()
            .ScanAsync(Stream.Null, CancellationToken.None);

        result.Outcome.ShouldBe(MalwareScanOutcome.NotScanned);
        result.Outcome.ShouldNotBe(MalwareScanOutcome.Clean);
    }

    [Fact]
    public async Task Quarantines_what_an_engine_detected()
    {
        SpamCheckResult result = await RunAsync(
            new FakeMalwareScanner(new MalwareScanResult(MalwareScanOutcome.Infected, "Eicar-Test-Signature")));

        result.Floor.ShouldBe(FilterAction.Quarantine);
        result.Signals.ShouldHaveSingleItem().Detail.ShouldContain("Eicar-Test-Signature");
    }

    [Fact]
    public async Task Says_nothing_when_an_engine_found_nothing()
    {
        SpamCheckResult result = await RunAsync(new FakeMalwareScanner(MalwareScanResult.Clean));

        result.Signals.ShouldBeEmpty();
    }

    /// <summary>
    /// An engine that fell over is not a clean message. Failing open is the default because a
    /// mail server that stops delivering when an optional component dies is the worse surprise.
    /// </summary>
    [Fact]
    public async Task Weighs_an_engine_that_could_not_answer()
    {
        SpamCheckResult result = await RunAsync(
            new FakeMalwareScanner(new MalwareScanResult(MalwareScanOutcome.Error, Diagnostic: "socket closed")));

        result.Floor.ShouldBe(FilterAction.Accept);
        result.Signals.ShouldHaveSingleItem().Name.ShouldBe("MALWARE_NOT_SCANNED");
    }

    [Fact]
    public async Task Holds_a_message_it_could_not_scan_when_the_operator_asked_for_that()
    {
        SpamCheckResult result = await RunAsync(
            new FakeMalwareScanner(new MalwareScanResult(MalwareScanOutcome.Error)), failClosed: true);

        result.Floor.ShouldBe(FilterAction.Quarantine);
    }

    /// <summary>An engine that throws is the same case as one that answered Error.</summary>
    [Fact]
    public async Task Treats_a_throwing_engine_as_one_that_could_not_answer()
    {
        FakeMalwareScanner scanner = new(MalwareScanResult.Clean) { Throw = true };

        SpamCheckResult result = await RunAsync(scanner);

        result.Signals.ShouldHaveSingleItem().Name.ShouldBe("MALWARE_NOT_SCANNED");
    }

    [Fact]
    public async Task Does_not_scan_a_message_it_could_not_read()
    {
        FakeMalwareScanner scanner = new(MalwareScanResult.Clean);

        SpamCheckResult result = await RunAsync(scanner, contentWasRead: false);

        scanner.Scans.ShouldBe(0);
        result.Signals.ShouldHaveSingleItem().Name.ShouldBe("MALWARE_NOT_SCANNED");
    }
}

public sealed class BlockListCheckTests
{
    private static async Task<SpamCheckResult> RunAsync(params ReputationListing[] listings)
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.Ordinary);

        MessageFilterContext context = new(
            Fixture.Request(message), null, [], true, ct => store.OpenReadAsync(message.Id, ct));

        BlockListSpamCheck check = new(
            new FakeReputationProvider(listings), Fixture.Log<BlockListSpamCheck>());

        return await check.InspectAsync(context, CancellationToken.None);
    }

    private static ReputationListing Listing(
        string provider, bool listed, ReputationListHealth health = ReputationListHealth.Healthy) =>
        new(provider, listed, [], null, health);

    [Fact]
    public async Task Says_nothing_when_no_lists_are_configured() =>
        (await RunAsync()).Signals.ShouldBeEmpty();

    [Fact]
    public async Task Says_nothing_when_the_host_is_not_listed() =>
        (await RunAsync(Listing("zen.example", listed: false))).Signals.ShouldBeEmpty();

    [Fact]
    public async Task Weighs_a_listing() =>
        (await RunAsync(Listing("zen.example", listed: true)))
            .Signals.ShouldHaveSingleItem().Name.ShouldBe("BLOCKLISTED");

    /// <summary>
    /// One list is one opinion, arrived at by criteria this server cannot see. Two independent
    /// lists agreeing is a different matter, and that is where the threshold sits.
    /// </summary>
    [Fact]
    public async Task One_list_is_not_enough_to_junk_a_message() =>
        (await RunAsync(Listing("zen.example", listed: true)))
            .Signals.Sum(s => s.Score).ShouldBeLessThan(FilterPolicy.Default.JunkThreshold);

    [Fact]
    public async Task Two_lists_agreeing_are()
    {
        SpamCheckResult result = await RunAsync(
            Listing("zen.example", listed: true), Listing("other.example", listed: true));

        result.Signals.Sum(s => s.Score).ShouldBeGreaterThanOrEqualTo(FilterPolicy.Default.JunkThreshold);
    }

    /// <summary>
    /// A cut-off or misconfigured list answers "listed" to everything. Believing one would junk
    /// the whole Internet's mail, which is exactly the failure the health check exists to catch.
    /// </summary>
    [Theory]
    [InlineData(ReputationListHealth.Unknown)]
    [InlineData(ReputationListHealth.NotAnswering)]
    [InlineData(ReputationListHealth.Unreliable)]
    public async Task Ignores_a_list_that_is_not_healthy(ReputationListHealth health) =>
        (await RunAsync(Listing("broken.example", listed: true, health))).Signals.ShouldBeEmpty();
}

/// <summary>
/// The exit criteria for this milestone name resource-exhaustion tests. These are the
/// filter's share of them: the per-message bound, and the bound on how many of those can
/// exist at once — which is the one that actually caps memory, because the per-message
/// bound multiplied by an unbounded number of concurrent inbound connections is unbounded.
/// </summary>
public sealed class FilterResourceBoundTests
{
    /// <summary>A store that reports how many reads overlapped.</summary>
    private sealed class CountingStore : IMessageStore
    {
        private readonly byte[] _content;
        private int _current;

        public CountingStore(byte[] content) => _content = content;

        /// <summary>The most reads that were ever open at the same moment.</summary>
        public int PeakConcurrent { get; private set; }

        public ValueTask<IMessageWriter> BeginWriteAsync(long maxSizeBytes, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public async ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken)
        {
            int now = Interlocked.Increment(ref _current);

            lock (this)
            {
                PeakConcurrent = Math.Max(PeakConcurrent, now);
            }

            // Long enough that every caller the gate admits is inside at once, and every
            // caller it does not is still waiting.
            await Task.Delay(40, cancellationToken);

            Interlocked.Decrement(ref _current);

            return new MemoryStream(_content, writable: false);
        }

        public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken) =>
            ValueTask.FromResult(true);

        public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken) =>
            ValueTask.FromResult(true);
    }

    [Fact]
    public async Task Never_holds_more_messages_at_once_than_the_gate_allows()
    {
        byte[] content = Encoding.ASCII.GetBytes(Fixture.Ordinary.ReplaceLineEndings("\r\n"));
        CountingStore store = new(content);

        using MessageFilterPipeline pipeline = new(
            [new AttachmentSpamCheck(AttachmentPolicy.Default)],
            store,
            FilterPolicy.Default,
            Fixture.Log<MessageFilterPipeline>());

        StoredMessage message = new(
            new StoredMessageId(Guid.NewGuid()),
            content.Length,
            Sha256Hash.FromBytes(System.Security.Cryptography.SHA256.HashData(content)),
            Fixture.Now);

        // Far more at once than the gate admits, which is what a burst of inbound connections
        // looks like.
        await Task.WhenAll(Enumerable.Range(0, 40).Select(_ =>
            pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None)));

        store.PeakConcurrent.ShouldBeLessThanOrEqualTo(FilterLimits.MaxConcurrentContentReads);
    }

    /// <summary>
    /// And every one of them still gets a verdict. A gate that shed load rather than queueing
    /// would make "be busy at it" the way past the filter.
    /// </summary>
    [Fact]
    public async Task Filters_every_message_in_a_burst_rather_than_shedding_any()
    {
        FakeMessageStore store = new();
        StoredMessage message = store.Add(Fixture.WithAttachment("filename=\"setup.exe\""));

        using MessageFilterPipeline pipeline = new(
            [new AttachmentSpamCheck(AttachmentPolicy.Default)],
            store,
            FilterPolicy.Default,
            Fixture.Log<MessageFilterPipeline>());

        FilterVerdict[] verdicts = await Task.WhenAll(Enumerable.Range(0, 40).Select(_ =>
            pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None)));

        verdicts.ShouldAllBe(v => v.Action == FilterAction.Quarantine);
    }

    /// <summary>
    /// The MIME tree's own bounds are what keep a deeply nested message from exhausting the
    /// stack during the walk. A message built to be pathological gets a verdict rather than
    /// taking the delivery path down with it.
    /// </summary>
    [Fact]
    public async Task Survives_a_deeply_nested_message()
    {
        StringBuilder nested = new();
        nested.Append("From: a@example.com\r\n");

        const int depth = 400;

        for (int i = 0; i < depth; i++)
        {
            nested.Append($"Content-Type: multipart/mixed; boundary=\"b{i}\"\r\n\r\n--b{i}\r\n");
        }

        nested.Append("Content-Type: text/plain\r\n\r\nbottom\r\n");

        for (int i = depth - 1; i >= 0; i--)
        {
            nested.Append($"--b{i}--\r\n");
        }

        FakeMessageStore store = new();
        StoredMessage message = store.Add(nested.ToString());

        using MessageFilterPipeline pipeline = new(
            [new AttachmentSpamCheck(AttachmentPolicy.Default), new HeaderHeuristicSpamCheck()],
            store,
            FilterPolicy.Default,
            Fixture.Log<MessageFilterPipeline>());

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.ShouldNotBeNull();
    }

    /// <summary>
    /// A message with an enormous number of parts must not make the attachment policy do
    /// unbounded work, and must not pass silently either.
    /// </summary>
    [Fact]
    public async Task Bounds_the_work_a_message_with_many_parts_can_ask_for()
    {
        StringBuilder many = new();
        many.Append("From: a@example.com\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n");

        for (int i = 0; i < 1_000; i++)
        {
            many.Append($"--b\r\nContent-Type: text/plain; name=\"part{i}.txt\"\r\n\r\nx\r\n");
        }

        many.Append("--b--\r\n");

        FakeMessageStore store = new();
        StoredMessage message = store.Add(many.ToString());

        AttachmentPolicy policy = new() { MaxAttachmentsExamined = 50 };

        using MessageFilterPipeline pipeline = new(
            [new AttachmentSpamCheck(policy)],
            store,
            FilterPolicy.Default,
            Fixture.Log<MessageFilterPipeline>());

        FilterVerdict verdict = await pipeline.EvaluateAsync(Fixture.Request(message), CancellationToken.None);

        verdict.Signals.ShouldContain(s => s.Detail.Contains("only the first 50"));
    }
}
