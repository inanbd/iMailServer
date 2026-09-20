using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Certificates;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Dkim;
using MailServer.Infrastructure.Smtp.Outbound;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Outbound.Tests;

/// <summary>
/// <see cref="OutboundSmtpClient"/> driven end to end over a real loopback socket against
/// <see cref="FakeRemoteMta"/>: the client under test is the real production class, only the
/// remote end is a fake.
/// </summary>
public sealed class OutboundSmtpClientTests : IAsyncDisposable
{
    private readonly FakeServerIdentity _identity = new();
    private readonly FakeMessageStore _store = new();

    private OutboundSmtpClient CreateClient() =>
        new(
            _identity,
            _store,
            new CertificateChainValidator(NullLogger<CertificateChainValidator>.Instance),
            new FakeDomainRepository(),
            new FakeDkimKeyRepository(),
            new DkimMessageSigner(),
            new FakeClock(DateTimeOffset.UtcNow),
            Options.Create(new MailServerOptions
            {
                Outbound = new OutboundOptions
                {
                    ConnectTimeoutSeconds = 5,
                    CommandTimeoutSeconds = 5,
                    DataTimeoutSeconds = 5,
                },
            }),
            NullLogger<OutboundSmtpClient>.Instance);

    private async Task<StoredMessageId> StoreMessageAsync(string body)
    {
        await using IMessageWriter writer = await _store.BeginWriteAsync(1024 * 1024, CancellationToken.None);
        await writer.WriteAsync(System.Text.Encoding.ASCII.GetBytes(body), CancellationToken.None);
        StoredMessage stored = await writer.CommitAsync(CancellationToken.None);
        return stored.Id;
    }

    [Fact]
    public async Task A_message_accepted_by_the_remote_is_reported_delivered()
    {
        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync("Subject: hi\r\n\r\nHello there.\r\n");

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.Delivered);
        result.Classification.ShouldBe(FailureClassification.None);
        result.ReplyCode.ShouldBe(250);

        mta.ReceivedCommands.ShouldContain(c => c.StartsWith("MAIL FROM:<sender@origin.example>", StringComparison.Ordinal));
        mta.ReceivedCommands.ShouldContain(c => c.StartsWith("RCPT TO:<recipient@destination.example>", StringComparison.Ordinal));
        mta.ReceivedBody.ShouldNotBeNull().ShouldContain("Hello there.");
    }

    [Fact]
    public async Task A_null_reverse_path_is_sent_as_the_empty_mail_from()
    {
        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync("Subject: bounce\r\n\r\nBody.\r\n");

        await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, ReversePath: null,
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        mta.ReceivedCommands.ShouldContain("MAIL FROM:<>");
    }

    [Fact]
    public async Task A_5xx_at_rcpt_to_is_classified_permanent_and_bounces()
    {
        await using FakeRemoteMta mta = new() { Script = FakeMtaScript.RejectRecipient("550 5.1.1 no such user") };
        StoredMessageId messageId = await StoreMessageAsync("Subject: x\r\n\r\nBody.\r\n");

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("nobody@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.Bounced);
        result.Classification.ShouldBe(FailureClassification.Permanent);
        result.ReplyCode.ShouldBe(550);
    }

    [Fact]
    public async Task A_4xx_at_data_is_classified_temporary_and_deferred()
    {
        await using FakeRemoteMta mta = new() { Script = FakeMtaScript.RejectAtData("452 4.3.1 insufficient system storage") };
        StoredMessageId messageId = await StoreMessageAsync("Subject: x\r\n\r\nBody.\r\n");

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.Deferred);
        result.Classification.ShouldBe(FailureClassification.Temporary);
        result.ReplyCode.ShouldBe(452);
    }

    [Fact]
    public async Task A_body_line_starting_with_a_dot_is_stuffed_on_the_wire()
    {
        await using FakeRemoteMta mta = new();

        // The body genuinely contains a line that is just ".", which must arrive doubled on the
        // wire so the remote does not mistake it for the end-of-data marker. The fake server's
        // reader stops at the first bare "." line, so if stuffing failed this test would see a
        // truncated body instead of the full text below.
        StoredMessageId messageId = await StoreMessageAsync("Line one\r\n.\r\nLine three\r\n");

        await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        mta.ReceivedBody.ShouldNotBeNull().ShouldContain("Line three");
    }

    [Fact]
    public async Task Opportunistic_tls_is_negotiated_and_used_even_with_an_untrusted_certificate()
    {
        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync("Subject: x\r\n\r\nBody.\r\n");

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        mta.TlsWasNegotiated.ShouldBeTrue();
        result.Outcome.ShouldBe(DeliveryOutcome.Delivered);
        result.TlsActive.ShouldBeTrue();
        result.PeerCertificateSubject.ShouldNotBeNull().ShouldContain("fake-mx.example.test");
    }

    [Fact]
    public async Task Required_tls_against_an_untrusted_certificate_fails_rather_than_sending_in_plaintext()
    {
        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync("Subject: x\r\n\r\nBody.\r\n");

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: true),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.TlsRequiredFailure);

        // The conversation never reached RCPT TO/DATA: a downgrade to plaintext never happened.
        mta.ReceivedCommands.ShouldNotContain(c => c.StartsWith("RCPT TO", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Required_tls_against_a_destination_that_does_not_offer_starttls_fails_immediately()
    {
        await using FakeRemoteMta mta = new() { Script = FakeMtaScript.WithoutStartTls() };
        StoredMessageId messageId = await StoreMessageAsync("Subject: x\r\n\r\nBody.\r\n");

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: true),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.TlsRequiredFailure);
        mta.ReceivedCommands.ShouldNotContain("STARTTLS");
    }

    [Fact]
    public async Task Opportunistic_delivery_proceeds_in_plaintext_when_starttls_is_not_offered()
    {
        await using FakeRemoteMta mta = new() { Script = FakeMtaScript.WithoutStartTls() };
        StoredMessageId messageId = await StoreMessageAsync("Subject: x\r\n\r\nBody.\r\n");

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.Delivered);
        result.TlsActive.ShouldBeFalse();
    }

    [Fact]
    public async Task Connecting_to_a_closed_port_is_a_temporary_failure_not_an_exception()
    {
        using System.Net.Sockets.TcpListener probe = new(System.Net.IPAddress.Loopback, 0);
        probe.Start();
        int freePort = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        StoredMessageId messageId = await StoreMessageAsync("Subject: x\r\n\r\nBody.\r\n");

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", freePort, EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.Deferred);
        result.Classification.ShouldBe(FailureClassification.Temporary);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    // ---------------------------------------------------------------------------------------
    // The transcript, recorded on this same path rather than on a copy of it.
    // ---------------------------------------------------------------------------------------

    private async Task<(OutboundDeliveryResult Result, DeliveryTranscript Transcript)> DeliverWithTranscriptAsync(
        FakeRemoteMta mta,
        StoredMessageId messageId,
        bool requireTls = false)
    {
        DeliveryTranscript transcript = new();

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1",
                mta.Port,
                EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"),
                messageId,
                requireTls,
                transcript),
            CancellationToken.None);

        return (result, transcript);
    }

    /// <summary>
    /// Every stage of a successful delivery, in order. A transcript missing a command is worse
    /// than no transcript: an operator reading one trusts that what is not in it did not happen.
    /// </summary>
    [Fact]
    public async Task A_successful_delivery_records_every_stage_in_order()
    {
        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync("Subject: hi\r\n\r\nHello there.\r\n");

        (OutboundDeliveryResult result, DeliveryTranscript transcript) =
            await DeliverWithTranscriptAsync(mta, messageId);

        result.Outcome.ShouldBe(DeliveryOutcome.Delivered);

        transcript.Steps.Select(s => s.Stage).ShouldBe(
        [
            DeliveryStage.Connect,
            DeliveryStage.Banner,
            DeliveryStage.Ehlo,
            DeliveryStage.StartTls,
            DeliveryStage.Handshake,
            DeliveryStage.EhloAfterTls,
            DeliveryStage.MailFrom,
            DeliveryStage.RcptTo,
            DeliveryStage.Data,
            DeliveryStage.Body,
            DeliveryStage.EndOfData,
            DeliveryStage.Quit,
        ]);
    }

    /// <summary>
    /// The commands are recorded as issued, so the transcript can be read against the remote's
    /// own log line for line.
    /// </summary>
    [Fact]
    public async Task The_envelope_commands_are_recorded_as_they_went_out()
    {
        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync("Subject: hi\r\n\r\nHello there.\r\n");

        (_, DeliveryTranscript transcript) = await DeliverWithTranscriptAsync(mta, messageId);

        transcript.Steps.Single(s => s.Stage == DeliveryStage.MailFrom).Sent
            .ShouldBe("MAIL FROM:<sender@origin.example>");

        transcript.Steps.Single(s => s.Stage == DeliveryStage.RcptTo).Sent
            .ShouldBe("RCPT TO:<recipient@destination.example>");

        transcript.FinalReply.ShouldNotBeNull().Code.ShouldBe(250);
    }

    /// <summary>
    /// <b>The body is a count and never content.</b> A transcript is read under
    /// <c>ViewServerState</c> and message content is guarded by <c>ReadMessageContent</c>, so a
    /// transcript carrying body octets would be a way to read mail with the weaker of the two.
    /// Asserted against the whole rendering rather than against the body step alone, because the
    /// leak this guards against would be somewhere nobody thought to look.
    /// </summary>
    [Fact]
    public async Task The_transcript_never_carries_the_message_body()
    {
        const string Secret = "Salary-Review-Q3-CONFIDENTIAL";

        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync(
            $"Subject: hi\r\n\r\n{Secret}\r\n");

        (_, DeliveryTranscript transcript) = await DeliverWithTranscriptAsync(mta, messageId);

        // The fake remote really did receive it, so this is an absence in the transcript rather
        // than a message that was never sent.
        mta.ReceivedBody.ShouldNotBeNull().ShouldContain(Secret);

        transcript.Render().ShouldNotContain(Secret);
        transcript.Steps
            .SelectMany(step => new[] { step.Sent, step.Detail, step.Reply?.Text })
            .Where(text => text is not null)
            .ShouldNotContain(text => text!.Contains(Secret, StringComparison.Ordinal));

        transcript.Steps.Single(s => s.Stage == DeliveryStage.Body).Detail
            .ShouldNotBeNull()
            .ShouldContain("octets sent");
    }

    /// <summary>
    /// A conversation the remote cut short stops where it was cut. Where it stopped is the
    /// diagnosis — this one is the recipient, not the sender and not the message.
    /// </summary>
    [Fact]
    public async Task A_delivery_refused_at_rcpt_stops_there()
    {
        await using FakeRemoteMta mta = new()
        {
            Script = FakeMtaScript.RejectRecipient("550 5.1.1 No such user here"),
        };

        StoredMessageId messageId = await StoreMessageAsync("Subject: hi\r\n\r\nHello there.\r\n");

        (OutboundDeliveryResult result, DeliveryTranscript transcript) =
            await DeliverWithTranscriptAsync(mta, messageId);

        result.Outcome.ShouldBe(DeliveryOutcome.Bounced);

        transcript.LastStage.ShouldBe(DeliveryStage.RcptTo);
        transcript.Steps.ShouldNotContain(s => s.Stage == DeliveryStage.Body);
        transcript.FinalReply.ShouldBeNull();

        transcript.Steps.Single(s => s.Stage == DeliveryStage.RcptTo).Reply
            .ShouldNotBeNull().Code.ShouldBe(550);
    }

    /// <summary>
    /// The capabilities recorded are the ones learned after the handshake. RFC 3207 §4.2 has the
    /// client discard what it learned before it, and that earlier list is the one a network
    /// attacker can edit.
    /// </summary>
    [Fact]
    public async Task The_capabilities_reported_are_the_ones_learned_over_tls()
    {
        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync("Subject: hi\r\n\r\nHello there.\r\n");

        (_, DeliveryTranscript transcript) = await DeliverWithTranscriptAsync(mta, messageId);

        transcript.Steps.ShouldContain(s => s.Stage == DeliveryStage.EhloAfterTls);
        transcript.Capabilities.ShouldNotContain("STARTTLS");
    }

    /// <summary>
    /// The handshake is where a receiver's refusal most often actually lives, so the transcript
    /// carries what was negotiated and whether the chain validated — an opportunistic session
    /// proceeds encrypted either way, so "encrypted" alone does not answer the question.
    /// </summary>
    [Fact]
    public async Task The_handshake_records_what_was_negotiated()
    {
        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync("Subject: hi\r\n\r\nHello there.\r\n");

        (_, DeliveryTranscript transcript) = await DeliverWithTranscriptAsync(mta, messageId);

        string detail = transcript.Steps
            .Single(s => s.Stage == DeliveryStage.Handshake).Detail.ShouldNotBeNull();

        detail.ShouldContain("Tls1");
        detail.ShouldContain("chain NOT trusted", Case.Sensitive);
    }

    /// <summary>
    /// A conversation that never opened is the most common result of a delivery test against a
    /// host with no listener or a blocked port 25, and an empty transcript would look like the
    /// test had not run at all.
    /// </summary>
    [Fact]
    public async Task A_connection_that_never_opened_still_says_so()
    {
        StoredMessageId messageId = await StoreMessageAsync("Subject: hi\r\n\r\nHello there.\r\n");
        DeliveryTranscript transcript = new();

        OutboundDeliveryResult result = await CreateClient().DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1",
                Port: 9,
                EmailAddress.Parse("sender@origin.example"),
                EmailAddress.Parse("recipient@destination.example"),
                messageId,
                RequireTls: false,
                transcript),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.Deferred);

        transcript.LastStage.ShouldBe(DeliveryStage.Connect);
        transcript.Steps.ShouldHaveSingleItem().Detail
            .ShouldNotBeNull().ShouldContain("Could not connect");
    }
}
