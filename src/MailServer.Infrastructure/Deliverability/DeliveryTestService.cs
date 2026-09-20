using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Sends one real message and hands back the conversation.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every step is the one the queue takes.</b> The same <see cref="IDnsResolver"/> for MX,
/// the same <see cref="MxSelection.OrderForAttempt"/> ordering, the same
/// <see cref="IOutboundDeliveryClient"/>, the same port from the same options. What differs is
/// that this one carries a <see cref="DeliveryTranscript"/> and is not driven by a queue item —
/// and nothing else, because a test that took a different path would answer a question nobody
/// asked.
/// </para>
/// <para>
/// <b>The stored message is deleted afterwards, and the delete is the last thing to happen.</b>
/// A test message is not mail anybody is keeping, and leaving one behind per run would grow the
/// store for nothing. Deleting it before the send would be worse than not storing it at all —
/// the client streams the body from the store during <c>DATA</c>, so the octets have to still be
/// there.
/// </para>
/// <para>
/// <b>Nothing here retries.</b> The queue's job is to keep trying; this one's is to say what
/// happened once, so a temporary refusal is reported as a temporary refusal rather than
/// hidden behind a backoff the operator is not watching.
/// </para>
/// </remarks>
public sealed class DeliveryTestService(
    IDnsResolver dns,
    IMessageStore messageStore,
    IOutboundDeliveryClient client,
    IServerIdentityProvider serverIdentity,
    IClock clock,
    IOptions<MailServerOptions> options,
    ILogger<DeliveryTestService> logger) : IDeliveryTestService
{
    /// <summary>
    /// The same ordering the queue applies: ascending preference band, shuffled within a band.
    /// </summary>
    /// <remarks>
    /// Shared with <c>OutboundDeliveryHostedService</c> rather than reimplemented, because RFC
    /// 5321 §5.1's within-band shuffle is the reason a test run twice can pick a different host
    /// of equal preference — and an operator comparing two runs should be seeing the same rule
    /// the queue uses, not a tidier version of it.
    /// </remarks>
    private static readonly MxSelectionPolicy MxSelection = new();

    public async Task<DeliveryTestOutcome> RunAsync(
        DeliveryTestRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        string messageId = $"<{Guid.NewGuid():N}@{serverIdentity.Hostname}>";

        MxLookupResult mx = await dns
            .ResolveMxAsync(request.Recipient.Domain, cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyList<MxHost> candidates = mx.Status == DnsLookupStatus.Success
            ? MxSelection.OrderForAttempt(mx.Hosts)
            : [];

        if (candidates.Count == 0)
        {
            // The same classification the queue applies: a SERVFAIL is worth retrying and an
            // NXDOMAIN or a null MX never is, and conflating them is how a domain that does not
            // exist earns an infinite retry loop. See docs/DNS.md's failure-semantics table.
            return new DeliveryTestOutcome(
                mx.Status == DnsLookupStatus.Temporary ? DeliveryOutcome.Deferred : DeliveryOutcome.Bounced,
                request.Sender,
                request.Recipient,
                messageId,
                [],
                [],
                mx.Diagnostic ?? $"No mail exchanger could be resolved for {request.Recipient.Domain.Value}.");
        }

        StoredMessageId stored = await StoreAsync(request, messageId, cancellationToken)
            .ConfigureAwait(false);

        try
        {
            return await AttemptAsync(request, messageId, candidates, stored, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            await DiscardAsync(stored, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<StoredMessageId> StoreAsync(
        DeliveryTestRequest request,
        string messageId,
        CancellationToken cancellationToken)
    {
        string text = DeliveryTestMessage.Compose(
            request.Sender,
            request.Recipient,
            messageId,
            clock.UtcNow);

        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);

        await using IMessageWriter writer = await messageStore
            .BeginWriteAsync(bytes.Length, cancellationToken)
            .ConfigureAwait(false);

        await writer.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);

        StoredMessage message = await writer.CommitAsync(cancellationToken).ConfigureAwait(false);

        return message.Id;
    }

    private async Task<DeliveryTestOutcome> AttemptAsync(
        DeliveryTestRequest request,
        string messageId,
        IReadOnlyList<MxHost> candidates,
        StoredMessageId stored,
        CancellationToken cancellationToken)
    {
        List<DeliveryTestAttempt> attempts = [];

        foreach (MxHost host in candidates)
        {
            DeliveryTranscript transcript = new();

            OutboundDeliveryResult result = await client
                .DeliverAsync(
                    new OutboundDeliveryRequest(
                        host.Hostname,
                        options.Value.Outbound.DeliveryPort,
                        request.Sender,
                        request.Recipient,
                        stored,
                        request.RequireTls,
                        transcript),
                    cancellationToken)
                .ConfigureAwait(false);

            attempts.Add(new DeliveryTestAttempt(
                host,
                result.Outcome,
                transcript,
                result.ErrorDetail ?? (result.ReplyText is null ? null : $"{result.ReplyCode} {result.ReplyText}")));

            if (result.Outcome == DeliveryOutcome.Delivered)
            {
                break;
            }
        }

        DeliveryTestAttempt decisive = attempts[^1];

        return new DeliveryTestOutcome(
            decisive.Outcome,
            request.Sender,
            request.Recipient,
            messageId,
            candidates,
            attempts,
            decisive.Outcome == DeliveryOutcome.Delivered ? null : decisive.Diagnostic);
    }

    /// <summary>
    /// Removes the stored test message, and never lets that failure become the test's answer.
    /// </summary>
    /// <remarks>
    /// The message has already been delivered or refused by the time this runs, so a store that
    /// cannot delete it is an operational problem about disk rather than a fact about the
    /// operator's deliverability. Throwing here would replace a good answer with an unrelated
    /// error.
    /// </remarks>
    private async Task DiscardAsync(StoredMessageId stored, CancellationToken cancellationToken)
    {
        try
        {
            await messageStore.DeleteAsync(stored, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(
                ex,
                "The delivery-test message {MessageId} could not be removed from the store.",
                stored.Value);
        }
    }
}
