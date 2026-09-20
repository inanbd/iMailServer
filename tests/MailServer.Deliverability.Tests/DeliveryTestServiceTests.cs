using System.Text;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;
using MailServer.Infrastructure.Smtp.Outbound;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// The one check whose answer comes from somebody else.
/// </summary>
/// <remarks>
/// The interesting assertions are about what the test reports rather than about SMTP, which the
/// outbound client's own tests cover: a probe that never left because DNS had no answer must say
/// so as a DNS problem, and the transcript must never carry the message.
/// </remarks>
public sealed class DeliveryTestServiceTests
{
    private static readonly EmailAddress From = EmailAddress.Parse("postmaster@example.com");
    private static readonly EmailAddress To = EmailAddress.Parse("someone@example.net");

    private static DeliveryTestService Service(
        MxLookupResult? mx = null,
        OutboundDeliveryResult? delivery = null,
        RecordingOutbound? recorder = null)
    {
        RecordingOutbound outbound = recorder ?? new RecordingOutbound(delivery);
        InMemoryMessageStore store = new();

        // So the recorder can read the probe back out the way the real client streams it.
        outbound.Store = store;

        return new DeliveryTestService(
            new StubResolver(mx ?? MxLookupResult.Success([new MxHost("mx.example.net", 10)])),
            outbound,
            store,
            new FakeDomains(),
            new FakeDkimKeys(),
            new StubIdentity(),
            new StubClock(),
            NullLogger<DeliveryTestService>.Instance);
    }

    private static OutboundDeliveryResult Accepted() => new(
        DeliveryOutcome.Delivered,
        FailureClassification.None,
        IpAddressValue.Parse("198.51.100.25"),
        TlsActive: true,
        "Tls13",
        "TLS_AES_256_GCM_SHA384",
        "CN=mx.example.net",
        "CN=Example CA",
        250,
        "2.0.0",
        "OK",
        null);

    /// <summary>
    /// No exchanger means there is nothing to test against, and it is the commonest real answer
    /// for a mistyped domain. It must read as the DNS problem it is: the remedy is completely
    /// different from a delivery failure's.
    /// </summary>
    [Fact]
    public async Task A_domain_with_no_exchanger_fails_as_a_dns_problem_without_sending()
    {
        RecordingOutbound outbound = new(Accepted());

        DeliveryTestResult result = await Service(
                MxLookupResult.Permanent("NXDOMAIN"),
                recorder: outbound)
            .RunAsync(From, To, CancellationToken.None);

        result.Succeeded.ShouldBeFalse();
        result.ErrorDetail.ShouldNotBeNull().ShouldContain("No mail exchanger");
        result.ErrorDetail.ShouldNotBeNull().ShouldContain("NXDOMAIN");
        result.MxHost.ShouldBeNull();

        // Nothing was sent, which is the part that matters: a test that emitted traffic on the
        // way to reporting a DNS failure would be spending reputation to learn nothing.
        outbound.Requests.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_successful_delivery_reports_the_evidence_the_operator_needs()
    {
        DeliveryTestResult result = await Service(delivery: Accepted())
            .RunAsync(From, To, CancellationToken.None);

        result.Succeeded.ShouldBeTrue();
        result.MxHost.ShouldBe("mx.example.net");
        result.MxPreference.ShouldBe(10);
        result.RemoteAddress!.Value.ShouldBe("198.51.100.25");
        result.TlsProtocol.ShouldBe("Tls13");
        result.PeerCertificateSubject.ShouldBe("CN=mx.example.net");
        result.ReplyCode.ShouldBe(250);
        result.EnhancedStatus.ShouldBe("2.0.0");
        result.Recipient.ShouldBe(To);
    }

    /// <summary>
    /// A refusal is a result, not an error: the remote's own reply is the most useful thing the
    /// test can hand back, so it must survive rather than be flattened into "failed".
    /// </summary>
    [Fact]
    public async Task A_refusal_reports_the_remote_reply_rather_than_a_generic_failure()
    {
        OutboundDeliveryResult refused = Accepted() with
        {
            Outcome = DeliveryOutcome.Bounced,
            ReplyCode = 550,
            EnhancedStatus = "5.7.1",
            ReplyText = "Message rejected due to SPF policy",
        };

        DeliveryTestResult result = await Service(delivery: refused)
            .RunAsync(From, To, CancellationToken.None);

        result.Succeeded.ShouldBeFalse();
        result.ReplyCode.ShouldBe(550);
        result.EnhancedStatus.ShouldBe("5.7.1");
        result.ReplyText.ShouldNotBeNull().ShouldContain("SPF");
    }

    /// <summary>The probe must be findable at the far end, and identified as machine-generated.</summary>
    [Fact]
    public async Task The_probe_carries_a_message_id_and_says_it_is_automated()
    {
        RecordingOutbound outbound = new(Accepted());

        DeliveryTestResult result = await Service(recorder: outbound)
            .RunAsync(From, To, CancellationToken.None);

        result.MessageId.ShouldStartWith("<");
        result.MessageId.ShouldEndWith("@mail.example.com>");

        string probe = outbound.LastBody.ShouldNotBeNull();

        probe.ShouldContain($"Message-ID: {result.MessageId}");
        probe.ShouldContain("Auto-Submitted: auto-generated");
        probe.ShouldContain($"From: <{From.Value}>");
        probe.ShouldContain($"To: <{To.Value}>");

        // RFC 5321 §4.4 has each hop add a Received: on receipt. This message was never
        // received - it originates here - so claiming a hop would be a lie in the one message
        // whose purpose is to be checked by a receiver.
        probe.ShouldNotContain("Received:");
    }

    /// <summary>The transcript is what an operator pastes into a support ticket.</summary>
    [Fact]
    public async Task The_transcript_is_requested_and_carried_back()
    {
        OutboundDeliveryResult withTranscript = Accepted() with
        {
            Transcript = ["* Connected.", "< 220 mx.example.net ESMTP", "> EHLO mail.example.com"],
        };

        RecordingOutbound outbound = new(withTranscript);

        DeliveryTestResult result = await Service(recorder: outbound)
            .RunAsync(From, To, CancellationToken.None);

        outbound.Requests.ShouldHaveSingleItem().RecordTranscript.ShouldBeTrue();
        result.Transcript.Count.ShouldBe(3);
        result.Transcript[1].ShouldBe("< 220 mx.example.net ESMTP");
    }

    // ---- The transcript itself ------------------------------------------------------------

    /// <summary>
    /// The rule that makes a transcript safe to share: commands and replies, never content.
    /// </summary>
    [Fact]
    public void A_transcript_records_commands_and_replies_and_nothing_else()
    {
        SmtpTranscript transcript = new();

        transcript.Note("Connected to mx.example.net:25 at 198.51.100.25.");
        transcript.Sent("EHLO mail.example.com");
        transcript.Sent("MAIL FROM:<postmaster@example.com>");

        transcript.Lines.ShouldBe([
            "* Connected to mx.example.net:25 at 198.51.100.25.",
            "> EHLO mail.example.com",
            "> MAIL FROM:<postmaster@example.com>",
        ]);
    }

    /// <summary>
    /// A remote that answered every command with a long reply would otherwise decide how much
    /// memory a delivery test holds.
    /// </summary>
    [Fact]
    public void A_transcript_is_bounded_and_says_when_it_truncated()
    {
        SmtpTranscript transcript = new();

        for (int i = 0; i < SmtpTranscript.MaxLines * 2; i++)
        {
            transcript.Sent($"NOOP {i}");
        }

        transcript.Lines.Count.ShouldBe(SmtpTranscript.MaxLines);
        transcript.Lines[^1].ShouldContain("truncated");
    }

    [Fact]
    public void A_single_long_line_is_truncated_rather_than_kept_whole()
    {
        SmtpTranscript transcript = new();

        transcript.Sent(new string('x', SmtpTranscript.MaxLineLength * 3));

        transcript.Lines.ShouldHaveSingleItem()
            .Length.ShouldBeLessThanOrEqualTo(SmtpTranscript.MaxLineLength + 4);
    }

    // ---- Fakes ------------------------------------------------------------------------------

    private sealed class StubResolver(MxLookupResult mx) : IDnsResolver
    {
        public Task<MxLookupResult> ResolveMxAsync(DomainName domain, CancellationToken cancellationToken) =>
            Task.FromResult(mx);

        public Task<AddressLookupResult> ResolveAddressesAsync(
            string hostname,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class StubIdentity : IServerIdentityProvider
    {
        public string Hostname => "mail.example.com";

        public string? PublicIpAddress => "203.0.113.25";

        public string ProductName => "AetherMail";
    }

    private sealed class StubClock : IClock
    {
        public DateTimeOffset UtcNow => new(2026, 9, 20, 12, 0, 0, TimeSpan.Zero);

        public long GetTimestamp() => System.Diagnostics.Stopwatch.GetTimestamp();

        public TimeSpan GetElapsedTime(long startingTimestamp) =>
            System.Diagnostics.Stopwatch.GetElapsedTime(startingTimestamp);
    }

    /// <summary>Captures what the delivery test asked the outbound client to do.</summary>
    private sealed class RecordingOutbound(OutboundDeliveryResult? result) : IOutboundDeliveryClient
    {
        private readonly List<OutboundDeliveryRequest> _requests = [];

        public IReadOnlyList<OutboundDeliveryRequest> Requests => _requests;

        /// <summary>The probe's octets, read back out of the store the way the real client would.</summary>
        public string? LastBody { get; private set; }

        public InMemoryMessageStore? Store { get; set; }

        public async Task<OutboundDeliveryResult> DeliverAsync(
            OutboundDeliveryRequest request,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);

            _requests.Add(request);

            if (Store is not null)
            {
                await using Stream content = await Store.OpenReadAsync(request.MessageId, cancellationToken);
                using StreamReader reader = new(content);
                LastBody = await reader.ReadToEndAsync(cancellationToken);
            }

            return result ?? throw new NotSupportedException("No delivery result was configured.");
        }
    }

    private sealed class InMemoryMessageStore : IMessageStore
    {
        private readonly Dictionary<StoredMessageId, byte[]> _messages = [];

        public ValueTask<IMessageWriter> BeginWriteAsync(
            long maxSizeBytes,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<IMessageWriter>(new Writer(this));

        public ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken) =>
            ValueTask.FromResult<Stream>(new MemoryStream(_messages[id]));

        public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_messages.ContainsKey(id));

        public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_messages.Remove(id));

        private sealed class Writer(InMemoryMessageStore store) : IMessageWriter
        {
            private readonly MemoryStream _buffer = new();

            public StoredMessageId Id { get; } = StoredMessageId.New();

            public long BytesWritten => _buffer.Length;

            public async ValueTask WriteAsync(ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken) =>
                await _buffer.WriteAsync(chunk, cancellationToken);

            public ValueTask<StoredMessage> CommitAsync(CancellationToken cancellationToken)
            {
                byte[] octets = _buffer.ToArray();

                store._messages[Id] = octets;

                return ValueTask.FromResult(new StoredMessage(
                    Id,
                    octets.Length,
                    Sha256Hash.FromBytes(System.Security.Cryptography.SHA256.HashData(octets)),
                    DateTimeOffset.UtcNow));
            }

            public ValueTask DisposeAsync() => _buffer.DisposeAsync();
        }
    }
}
