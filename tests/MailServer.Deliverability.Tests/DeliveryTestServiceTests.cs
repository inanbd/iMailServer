using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Deliverability;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Deliverability.Tests;

/// <summary>An MX answer, scripted.</summary>
internal sealed class ScriptedMxResolver(MxLookupResult result) : IDnsResolver
{
    public List<string> Asked { get; } = [];

    public Task<MxLookupResult> ResolveMxAsync(DomainName domain, CancellationToken cancellationToken)
    {
        Asked.Add(domain.Value);

        return Task.FromResult(result);
    }

    public Task<AddressLookupResult> ResolveAddressesAsync(
        string hostname,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

/// <summary>An in-memory message store that remembers what was written and what was removed.</summary>
internal sealed class RecordingMessageStore : IMessageStore
{
    private readonly Dictionary<Guid, byte[]> _content = [];

    public List<Guid> Deleted { get; } = [];

    /// <summary>
    /// Everything ever committed, which outlives the delete. The service removes its test
    /// message on the way out, so a test that wanted to read what was composed would otherwise
    /// have to race it.
    /// </summary>
    public List<string> Written { get; } = [];

    public int Count => _content.Count;

    public ValueTask<IMessageWriter> BeginWriteAsync(long maxSizeBytes, CancellationToken cancellationToken) =>
        ValueTask.FromResult<IMessageWriter>(new Writer(this));

    public ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult<Stream>(new MemoryStream(_content[id.Value]));

    public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_content.ContainsKey(id.Value));

    public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken)
    {
        Deleted.Add(id.Value);

        return ValueTask.FromResult(_content.Remove(id.Value));
    }

    private sealed class Writer(RecordingMessageStore store) : IMessageWriter
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
            store.Written.Add(Encoding.UTF8.GetString(bytes));

            return ValueTask.FromResult(new StoredMessage(
                Id,
                bytes.LongLength,
                Sha256Hash.FromBytes(SHA256.HashData(bytes)),
                DateTimeOffset.UnixEpoch));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

/// <summary>A delivery client that answers per host and records what it was asked.</summary>
/// <remarks>
/// <b>It really opens the stored message</b>, as the real client does during <c>DATA</c>. That
/// is not decoration: it is what makes a service that deleted the message before sending it
/// fail here rather than pass.
/// </remarks>
internal sealed class ScriptedDeliveryClient(
    IMessageStore store,
    Func<string, OutboundDeliveryResult> answer,
    Action<DeliveryTranscript>? write = null) : IOutboundDeliveryClient
{
    public List<OutboundDeliveryRequest> Requests { get; } = [];

    /// <summary>What was on the wire for each attempt.</summary>
    public List<string> Bodies { get; } = [];

    public async Task<OutboundDeliveryResult> DeliverAsync(
        OutboundDeliveryRequest request,
        CancellationToken cancellationToken)
    {
        Requests.Add(request);

        await using Stream content = await store
            .OpenReadAsync(request.MessageId, cancellationToken)
            .ConfigureAwait(false);

        using StreamReader reader = new(content);

        Bodies.Add(await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false));

        if (request.Transcript is { } transcript)
        {
            (write ?? Default)(transcript);
        }

        return answer(request.TargetHost);
    }

    private static void Default(DeliveryTranscript transcript)
    {
        transcript.Record(DeliveryStage.Connect, DateTimeOffset.UnixEpoch);
        transcript.Record(
            DeliveryStage.EndOfData,
            DateTimeOffset.UnixEpoch.AddMilliseconds(500),
            reply: new Domain.Smtp.SmtpReply(250, "2.0.0", "Queued"));
    }
}

internal sealed class StubServerIdentity : IServerIdentityProvider
{
    public string Hostname => "mail.example.com";

    public string ProductName => "AetherMail";

    public string? PublicIpAddress => "203.0.113.10";
}

/// <summary>
/// The delivery test's orchestration: what it resolves, what it sends, what it tries next, and
/// what it leaves behind.
/// </summary>
public sealed class DeliveryTestServiceTests
{
    private static readonly EmailAddress Sender = EmailAddress.Parse("postmaster@example.com");
    private static readonly EmailAddress Recipient = EmailAddress.Parse("someone@example.net");
    private static readonly DateTimeOffset Now = new(2026, 9, 20, 11, 30, 0, TimeSpan.Zero);

    private static MxLookupResult Mx(params MxHost[] hosts) =>
        new(DnsLookupStatus.Success, hosts, null);

    private static OutboundDeliveryResult Delivered() => new(
        DeliveryOutcome.Delivered, FailureClassification.None, null, true, "Tls13", null,
        null, null, 250, "2.0.0", "Queued", null);

    private static OutboundDeliveryResult Refused(int code, string text) => new(
        DeliveryOutcome.Bounced, FailureClassification.Permanent, null, false, null, null,
        null, null, code, null, text, null);

    private static OutboundDeliveryResult Deferred(string detail) => new(
        DeliveryOutcome.Deferred, FailureClassification.Temporary, null, false, null, null,
        null, null, null, null, null, detail);

    private static ScriptedMxResolver LastResolver { get; set; } = new(new MxLookupResult(
        DnsLookupStatus.Permanent, [], null));

    private static (DeliveryTestService Service, RecordingMessageStore Store, ScriptedDeliveryClient Client)
        Build(MxLookupResult mx, Func<string, OutboundDeliveryResult> answer, int port = 25)
    {
        RecordingMessageStore store = new();
        ScriptedDeliveryClient client = new(store, answer);
        LastResolver = new ScriptedMxResolver(mx);

        MailServerOptions settings = new();
        settings.Outbound.DeliveryPort = port;

        DeliveryTestService service = new(
            LastResolver,
            store,
            client,
            new StubServerIdentity(),
            new ProbeClock(Now),
            Options.Create(settings),
            NullLogger<DeliveryTestService>.Instance);

        return (service, store, client);
    }

    private static Task<DeliveryTestOutcome> RunAsync(DeliveryTestService service, bool requireTls = false) =>
        service.RunAsync(new DeliveryTestRequest(Sender, Recipient, requireTls), CancellationToken.None);

    // ---------------------------------------------------------------------------------------
    // The ordinary case.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_delivered_message_reports_the_host_it_reached_and_the_conversation()
    {
        (DeliveryTestService service, _, ScriptedDeliveryClient client) =
            Build(Mx(new MxHost("mx.example.net", 10)), _ => Delivered());

        DeliveryTestOutcome outcome = await RunAsync(service);

        outcome.Outcome.ShouldBe(DeliveryOutcome.Delivered);
        outcome.Diagnostic.ShouldBeNull();
        outcome.Candidates.ShouldBe([new MxHost("mx.example.net", 10)]);

        // The RECIPIENT's exchangers, which is where mail for them is delivered. Resolving the
        // sender's domain would send the test to this server's own inbox and report success.
        LastResolver.Asked.ShouldBe(["example.net"]);
        outcome.Decisive.ShouldNotBeNull().Host.Hostname.ShouldBe("mx.example.net");
        outcome.Latency.ShouldBe(TimeSpan.FromMilliseconds(500));

        client.Requests.ShouldHaveSingleItem().Transcript.ShouldNotBeNull();
    }

    /// <summary>The port and the TLS policy are the caller's, not this service's invention.</summary>
    [Theory]
    [InlineData(25, false)]
    [InlineData(2525, true)]
    public async Task The_request_carries_the_configured_port_and_the_chosen_tls_policy(int port, bool requireTls)
    {
        (DeliveryTestService service, _, ScriptedDeliveryClient client) =
            Build(Mx(new MxHost("mx.example.net", 10)), _ => Delivered(), port);

        await RunAsync(service, requireTls);

        OutboundDeliveryRequest request = client.Requests.ShouldHaveSingleItem();

        request.Port.ShouldBe(port);
        request.RequireTls.ShouldBe(requireTls);
        request.ReversePath.ShouldBe(Sender);
        request.RecipientAddress.ShouldBe(Recipient);
    }

    /// <summary>
    /// <b>The message id the operator is given is the one that went out.</b> It is the only
    /// handle they have for finding the message in the receiver's logs, and a reported id that
    /// differed from the sent one would send them looking for something that does not exist.
    /// </summary>
    [Fact]
    public async Task The_reported_message_id_is_the_one_in_the_message()
    {
        (DeliveryTestService service, RecordingMessageStore store, _) =
            Build(Mx(new MxHost("mx.example.net", 10)), _ => Delivered());

        DeliveryTestOutcome outcome = await RunAsync(service);

        outcome.MessageId.ShouldEndWith("@mail.example.com>");

        store.Written.ShouldHaveSingleItem()
            .ShouldContain($"Message-ID: {outcome.MessageId}\r\n");
    }

    /// <summary>
    /// What was composed is a real, well-formed message: the receiver applies its ordinary
    /// rules to it, and anything malformed would be judged as malformed rather than as this
    /// server's configuration.
    /// </summary>
    [Fact]
    public async Task The_composed_message_is_addressed_from_the_sender_the_operator_chose()
    {
        (DeliveryTestService service, RecordingMessageStore store, _) =
            Build(Mx(new MxHost("mx.example.net", 10)), _ => Delivered());

        await RunAsync(service);

        string text = store.Written.ShouldHaveSingleItem();

        text.ShouldContain("From: <postmaster@example.com>\r\n");
        text.ShouldContain("To: <someone@example.net>\r\n");
        text.ShouldContain("Auto-Submitted: auto-generated\r\n");
    }

    /// <summary>
    /// <b>The client reads the body from the store during <c>DATA</c>, so the message has to
    /// still be there when it does.</b> Removing it any earlier than the end would be worse than
    /// never storing it: the send would fail on a message this server composed itself.
    /// </summary>
    [Fact]
    public async Task The_message_is_still_in_the_store_while_it_is_being_sent()
    {
        (DeliveryTestService service, RecordingMessageStore store, ScriptedDeliveryClient client) =
            Build(Mx(new MxHost("mx.example.net", 10)), _ => Delivered());

        await RunAsync(service);

        client.Bodies.ShouldHaveSingleItem().ShouldBe(store.Written.ShouldHaveSingleItem());
    }

    // ---------------------------------------------------------------------------------------
    // Trying the exchangers in turn, as the queue does.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Reporting only the primary would tell an operator whose primary is briefly down that
    /// their mail cannot be delivered, when the queue would have used the secondary without
    /// comment.
    /// </summary>
    [Fact]
    public async Task A_primary_that_defers_is_followed_by_the_secondary()
    {
        (DeliveryTestService service, _, ScriptedDeliveryClient client) = Build(
            Mx(new MxHost("primary.example.net", 10), new MxHost("backup.example.net", 20)),
            host => host == "primary.example.net" ? Deferred("Try again later") : Delivered());

        DeliveryTestOutcome outcome = await RunAsync(service);

        outcome.Outcome.ShouldBe(DeliveryOutcome.Delivered);
        outcome.Attempts.Select(a => a.Host.Hostname)
            .ShouldBe(["primary.example.net", "backup.example.net"]);

        outcome.Decisive.ShouldNotBeNull().Host.Hostname.ShouldBe("backup.example.net");
        client.Requests.Count.ShouldBe(2);
    }

    /// <summary>
    /// And one that accepts ends it. Sending the same message twice would deliver it twice.
    /// </summary>
    [Fact]
    public async Task A_primary_that_accepts_is_the_only_one_tried()
    {
        (DeliveryTestService service, _, ScriptedDeliveryClient client) = Build(
            Mx(new MxHost("primary.example.net", 10), new MxHost("backup.example.net", 20)),
            _ => Delivered());

        DeliveryTestOutcome outcome = await RunAsync(service);

        outcome.Attempts.ShouldHaveSingleItem().Host.Hostname.ShouldBe("primary.example.net");
        client.Requests.ShouldHaveSingleItem();
    }

    /// <summary>
    /// Every attempt keeps its own transcript, because the conversation worth reading is usually
    /// the one that failed.
    /// </summary>
    [Fact]
    public async Task Every_attempt_keeps_its_own_transcript()
    {
        (DeliveryTestService service, _, _) = Build(
            Mx(new MxHost("primary.example.net", 10), new MxHost("backup.example.net", 20)),
            host => host == "primary.example.net" ? Refused(550, "No") : Delivered());

        DeliveryTestOutcome outcome = await RunAsync(service);

        outcome.Attempts.Count.ShouldBe(2);
        outcome.Attempts.ShouldAllBe(a => a.Transcript.Steps.Count > 0);

        // Two transcripts, not one shared between them.
        outcome.Attempts[0].Transcript.ShouldNotBeSameAs(outcome.Attempts[1].Transcript);
    }

    /// <summary>
    /// A last attempt that refused is the answer, and its reply is the diagnostic rather than a
    /// summary of it.
    /// </summary>
    [Fact]
    public async Task A_refusal_everywhere_is_reported_with_the_last_reply()
    {
        (DeliveryTestService service, _, _) = Build(
            Mx(new MxHost("mx.example.net", 10)),
            _ => Refused(550, "5.7.1 Message rejected"));

        DeliveryTestOutcome outcome = await RunAsync(service);

        outcome.Outcome.ShouldBe(DeliveryOutcome.Bounced);
        outcome.Diagnostic.ShouldNotBeNull().ShouldContain("5.7.1 Message rejected");
    }

    // ---------------------------------------------------------------------------------------
    // Nothing to connect to.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The same classification the queue applies. Conflating these is how a domain that does not
    /// exist earns an infinite retry loop, or a resolver blip bounces good mail —
    /// <c>docs/DNS.md</c>'s failure-semantics table.
    /// </summary>
    [Theory]
    [InlineData(DnsLookupStatus.Temporary, DeliveryOutcome.Deferred)]
    [InlineData(DnsLookupStatus.Permanent, DeliveryOutcome.Bounced)]
    public async Task A_failed_lookup_is_classified_the_way_the_queue_classifies_it(
        DnsLookupStatus status,
        DeliveryOutcome expected)
    {
        (DeliveryTestService service, RecordingMessageStore store, ScriptedDeliveryClient client) =
            Build(new MxLookupResult(status, [], "the resolver said so"), _ => Delivered());

        DeliveryTestOutcome outcome = await RunAsync(service);

        outcome.Outcome.ShouldBe(expected);
        outcome.Diagnostic.ShouldBe("the resolver said so");
        outcome.Attempts.ShouldBeEmpty();
        outcome.Candidates.ShouldBeEmpty();

        // Nothing was composed, stored or sent: there was nowhere to send it.
        client.Requests.ShouldBeEmpty();
        store.Count.ShouldBe(0);
        store.Deleted.ShouldBeEmpty();
    }

    /// <summary>
    /// A lookup that answered with no usable host is as good as a failure, and must not be
    /// reported as a success with nothing behind it.
    /// </summary>
    [Fact]
    public async Task A_lookup_that_answered_with_no_hosts_is_not_a_success()
    {
        (DeliveryTestService service, _, _) = Build(Mx(), _ => Delivered());

        DeliveryTestOutcome outcome = await RunAsync(service);

        outcome.Outcome.ShouldBe(DeliveryOutcome.Bounced);
        outcome.Attempts.ShouldBeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // What it leaves behind.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A test message is not mail anybody is keeping, and one left behind per run would grow the
    /// store for nothing.
    /// </summary>
    [Fact]
    public async Task The_stored_test_message_is_removed_afterwards()
    {
        (DeliveryTestService service, RecordingMessageStore store, _) =
            Build(Mx(new MxHost("mx.example.net", 10)), _ => Delivered());

        await RunAsync(service);

        store.Deleted.ShouldHaveSingleItem();
        store.Count.ShouldBe(0);
    }

    /// <summary>
    /// Including when the send throws. The message is already written by then, so an exception
    /// on the wire would otherwise leave it in the store for ever.
    /// </summary>
    [Fact]
    public async Task The_stored_test_message_is_removed_even_when_the_send_throws()
    {
        RecordingMessageStore store = new();

        MailServerOptions settings = new();

        DeliveryTestService service = new(
            new ScriptedMxResolver(Mx(new MxHost("mx.example.net", 10))),
            store,
            new ThrowingDeliveryClient(),
            new StubServerIdentity(),
            new ProbeClock(Now),
            Options.Create(settings),
            NullLogger<DeliveryTestService>.Instance);

        await Should.ThrowAsync<IOException>(() => RunAsync(service));

        store.Deleted.ShouldHaveSingleItem();
        store.Count.ShouldBe(0);
    }

    [Fact]
    public async Task The_service_refuses_a_null_request()
    {
        (DeliveryTestService service, _, _) = Build(Mx(), _ => Delivered());

        await Should.ThrowAsync<ArgumentNullException>(
            () => service.RunAsync(null!, CancellationToken.None));
    }

    private sealed class ThrowingDeliveryClient : IOutboundDeliveryClient
    {
        public Task<OutboundDeliveryResult> DeliverAsync(
            OutboundDeliveryRequest request,
            CancellationToken cancellationToken) =>
            throw new IOException("the socket died");
    }
}
