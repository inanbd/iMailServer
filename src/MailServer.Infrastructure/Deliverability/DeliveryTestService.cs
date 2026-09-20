using System.Diagnostics;
using System.Text;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Sends one probe message down the production delivery path and records the conversation.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything here is the real path.</b> The same <see cref="IDnsResolver"/>, the same
/// <see cref="MxSelectionPolicy"/>, the same <see cref="IOutboundDeliveryClient"/> with the same
/// DKIM signing that ordinary mail goes through. A delivery test built on a parallel
/// implementation would prove that the parallel implementation works, which is not the question
/// anybody is asking. What this adds is a stopwatch and a transcript.
/// </para>
/// <para>
/// <b>The probe is deliberately dull.</b> A plain-text message with a subject that says what it
/// is, no attachments, nothing that a spam filter has to think hard about — because the result
/// should say something about this server's configuration rather than about the content. It is
/// still real mail: it lands in a real mailbox, from this server's real IP, and the operator
/// should be sending it to an address they own.
/// </para>
/// <para>
/// <b>It sends straight rather than through the queue.</b> The queue's retries and backoff are
/// exactly wrong for a diagnostic: an operator running a test wants to know what happened now,
/// not to have a failure retried quietly for the next six hours. So a transient failure is
/// reported as a failure, with the reply that caused it, and nothing is scheduled.
/// </para>
/// </remarks>
public sealed class DeliveryTestService(
    IDnsResolver resolver,
    IOutboundDeliveryClient outbound,
    IMessageStore messageStore,
    IDomainRepository domains,
    IDkimKeyRepository dkimKeys,
    IServerIdentityProvider serverIdentity,
    IClock clock,
    ILogger<DeliveryTestService> logger) : IDeliveryTestService
{
    /// <summary>
    /// The largest probe this will write.
    /// </summary>
    /// <remarks>
    /// The probe is a few hundred bytes of plain text; this exists so the writer has a bound at
    /// all rather than because anything is expected to approach it.
    /// </remarks>
    private const long MaxProbeBytes = 64 * 1024;

    public async Task<DeliveryTestResult> RunAsync(
        EmailAddress from,
        EmailAddress to,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(from);
        ArgumentNullException.ThrowIfNull(to);

        long startedAt = Stopwatch.GetTimestamp();
        string messageId = $"<{Guid.NewGuid():N}@{serverIdentity.Hostname}>";

        MxLookupResult mx = await resolver
            .ResolveMxAsync(to.Domain, cancellationToken)
            .ConfigureAwait(false);

        if (mx.Status != DnsLookupStatus.Success || mx.Hosts.Count == 0)
        {
            // No exchanger means there is nothing to test against, and it is the most common
            // real answer for a mistyped domain. Reported as the DNS failure it is rather than
            // as a delivery failure, because the two have completely different remedies.
            return Failed(
                to,
                messageId,
                startedAt,
                $"No mail exchanger could be resolved for {to.Domain.Value}: " +
                $"{mx.Diagnostic ?? mx.Status.ToString()}.");
        }

        MxHost chosen = new MxSelectionPolicy().OrderForAttempt(mx.Hosts)[0];

        string? selector = await ActiveSelectorAsync(from.Domain, cancellationToken).ConfigureAwait(false);

        StoredMessageId stored;

        try
        {
            stored = await WriteProbeAsync(from, to, messageId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or MessageTooLargeException)
        {
            return Failed(to, messageId, startedAt, $"The probe message could not be stored: {ex.Message}.");
        }

        OutboundDeliveryResult delivery = await outbound
            .DeliverAsync(
                new OutboundDeliveryRequest(
                    chosen.Hostname,
                    25,
                    from,
                    to,
                    stored,
                    RequireTls: false)
                {
                    RecordTranscript = true,
                },
                cancellationToken)
            .ConfigureAwait(false);

        TimeSpan elapsed = Stopwatch.GetElapsedTime(startedAt);

        logger.LogInformation(
            "Delivery test to {Recipient} via {MxHost} finished as {Outcome} in {Elapsed}.",
            to.Value,
            chosen.Hostname,
            delivery.Outcome,
            elapsed);

        return new DeliveryTestResult(
            delivery.Outcome == DeliveryOutcome.Delivered,
            to,
            messageId,
            chosen.Hostname,
            chosen.Preference,
            delivery.RemoteAddress,
            delivery.TlsProtocol,
            delivery.TlsCipher,
            delivery.PeerCertificateSubject,
            delivery.PeerCertificateIssuer,
            selector,
            delivery.ReplyCode,
            delivery.EnhancedStatus,
            delivery.ReplyText,
            delivery.ErrorDetail,
            elapsed,
            delivery.Transcript);
    }

    /// <summary>
    /// Writes the probe into the message store, so the outbound client can stream it as it does
    /// any other message.
    /// </summary>
    /// <remarks>
    /// <b>The body names the header without spelling it.</b> <c>NoUntrustedAuthenticationHeaderTrustTests</c>
    /// scans production source for the hyphenated header name outside a comment, because
    /// computing this server's own verdicts from one read off the wire is a complete
    /// authentication bypass — see <c>docs/DMARC.md</c>. This use is innocent prose in an
    /// outgoing body, but a string literal is not a comment and the guard cannot tell the
    /// difference; adding this file to the allowlist would disarm it here permanently, for a
    /// wording preference. The prose says the same thing and the guard stays armed.
    ///
    /// <b>No <c>Received:</c> header.</b> RFC 5321 §4.4 has each hop add one on receipt, and this
    /// message was never received — it originates here. Adding one would claim a hop that never
    /// happened, in a message whose whole purpose is to be read by a receiver checking whether
    /// this server tells the truth about itself.
    /// </remarks>
    private async Task<StoredMessageId> WriteProbeAsync(
        EmailAddress from,
        EmailAddress to,
        string messageId,
        CancellationToken cancellationToken)
    {
        string body =
            $"Date: {clock.UtcNow:r}\r\n" +
            $"From: <{from.Value}>\r\n" +
            $"To: <{to.Value}>\r\n" +
            $"Message-ID: {messageId}\r\n" +
            "Subject: Delivery test\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Auto-Submitted: auto-generated\r\n" +
            "\r\n" +
            "This is an automated delivery test sent by AetherMail Server.\r\n" +
            "\r\n" +
            "If you received it, delivery from this server to this address works. Look at the\r\n" +
            "authentication results your provider recorded in this message's headers for its\r\n" +
            "own verdict on SPF, DKIM and DMARC - that verdict is the receiver's, and it is\r\n" +
            "worth more than any check this server can run on itself.\r\n";

        await using IMessageWriter writer = await messageStore
            .BeginWriteAsync(MaxProbeBytes, cancellationToken)
            .ConfigureAwait(false);

        await writer.WriteAsync(Encoding.UTF8.GetBytes(body), cancellationToken).ConfigureAwait(false);

        StoredMessage committed = await writer.CommitAsync(cancellationToken).ConfigureAwait(false);

        return committed.Id;
    }

    /// <summary>
    /// The selector the probe will be signed with, for the report.
    /// </summary>
    /// <remarks>
    /// Read rather than assumed, and null when the domain is not hosted here or has no active
    /// key — which is itself the finding, since an unsigned probe is exactly what a receiver
    /// will report as <c>dkim=none</c>.
    /// </remarks>
    private async Task<string?> ActiveSelectorAsync(DomainName domain, CancellationToken cancellationToken)
    {
        MailDomain? hosted = await domains.GetByNameAsync(domain, cancellationToken).ConfigureAwait(false);

        if (hosted is null)
        {
            return null;
        }

        DkimKey? key = await dkimKeys
            .GetActiveForDomainAsync(hosted.Id, cancellationToken)
            .ConfigureAwait(false);

        return key?.Selector.Value;
    }

    private static DeliveryTestResult Failed(
        EmailAddress to,
        string messageId,
        long startedAt,
        string error) =>
        new(
            Succeeded: false,
            to,
            messageId,
            MxHost: null,
            MxPreference: null,
            RemoteAddress: null,
            TlsProtocol: null,
            TlsCipher: null,
            PeerCertificateSubject: null,
            PeerCertificateIssuer: null,
            DkimSelector: null,
            ReplyCode: null,
            EnhancedStatus: null,
            ReplyText: null,
            error,
            Stopwatch.GetElapsedTime(startedAt),
            []);
}
