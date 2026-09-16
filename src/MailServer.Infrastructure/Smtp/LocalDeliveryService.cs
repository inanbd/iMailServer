using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Dkim;
using MailServer.Infrastructure.Dmarc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Smtp;

/// <summary>
/// Places an accepted message into local mailboxes.
/// </summary>
/// <remarks>
/// <para>
/// <b>The content file is committed before any of this runs.</b> That ordering is the whole
/// recovery story: a crash part-way through delivery leaves a file and possibly some rows, and
/// the worst case is a message delivered to some mailboxes and not others — recoverable, and
/// visible. The other ordering leaves rows naming a file that does not exist, which is a mailbox
/// its owner cannot open and nothing can repair.
/// </para>
/// <para>
/// <b>One file, many rows.</b> A message to three mailboxes is stored once and referenced three
/// times. Copying it would triple the disk a distribution list costs and would make deduplication
/// a background job that has to prove two files are identical.
/// </para>
/// <para>
/// Aliases are expanded here rather than at RCPT TO. The sender is told about the address it
/// wrote, not about the mailboxes behind it: naming them in a reply would turn every alias into
/// a way to enumerate the mailboxes it fronts.
/// </para>
/// </remarks>
public sealed class LocalDeliveryService(
    IDeliveryRepository deliveries,
    IMailboxRepository mailboxes,
    IAliasRepository aliases,
    IDomainRepository domains,
    IOutboundQueueRepository outboundQueue,
    IMessageStore messageStore,
    DkimMessageVerifier dkimVerifier,
    DmarcEvaluator dmarcEvaluator,
    AliasExpansionPolicy expansionPolicy,
    IOptions<MailServerOptions> options,
    IClock clock,
    ILogger<LocalDeliveryService> logger) : ILocalDeliveryService
{
    /// <inheritdoc />
    public async Task<DeliveryResult> DeliverAsync(
        DeliveryRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        DateTimeOffset now = clock.UtcNow;

        MessageRecord record = MessageRecord.Create(
            request.Message.Id,
            request.Message.SizeBytes,
            request.Message.ContentHash,
            request.ReversePath,
            request.RemoteAddress,
            request.GreetedName,
            request.ListenerRole,
            request.TlsActive,
            request.AuthenticatedAs,
            now);

        await deliveries.AddMessageAsync(record, cancellationToken).ConfigureAwait(false);

        // SPF's premise - does the sending IP match the domain's published record - is
        // meaningless for an authenticated client's IP, which can legitimately be anywhere. DKIM
        // and DMARC have no such caveat, but are still scoped to InboundMta here to keep every
        // mechanism's wiring symmetric and because a Submission message is this server's own
        // outbound signing's concern (OutboundSmtpClient), not something to re-verify on the way in.
        if (request.ListenerRole == SmtpListenerRole.InboundMta)
        {
            DmarcEvaluationOutcome? dmarcOutcome = await VerifyAuthenticationAsync(
                request.Message.Id, request.SpfOutcome, now, cancellationToken).ConfigureAwait(false);

            if (dmarcOutcome is { Disposition: DmarcPolicy.Reject })
            {
                logger.LogInformation(
                    "Message {MessageId} rejected: DMARC policy published at {PolicyDomain} requests reject for From: domain {FromDomain}.",
                    request.Message.Id.Value, dmarcOutcome.PolicyDomain!.Value, dmarcOutcome.FromDomain!.Value);

                return new DeliveryResult(
                    request.Message.Id,
                    [],
                    new DmarcRejection(
                        dmarcOutcome.PolicyDomain,
                        $"it fails DMARC alignment against {dmarcOutcome.FromDomain.Value} " +
                        $"(policy published at {dmarcOutcome.PolicyDomain.Value})"));
            }
        }

        // The alias graph is read once per message rather than once per recipient. A message to
        // twenty recipients in the same domain would otherwise re-read the same aliases twenty
        // times, on the delivery path, per message.
        IReadOnlyList<Alias> enabledAliases = await aliases
            .GetAllEnabledAsync(cancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, IReadOnlyList<EmailAddress>> aliasMap =
            new(StringComparer.OrdinalIgnoreCase);

        foreach (Alias alias in enabledAliases)
        {
            aliasMap[alias.Address.NormalizedValue] = alias.Targets;
        }

        List<RecipientOutcome> outcomes = [];

        foreach (AcceptedRecipient accepted in request.Recipients)
        {
            outcomes.Add(await DeliverRecipientAsync(
                request,
                accepted,
                aliasMap,
                now,
                cancellationToken).ConfigureAwait(false));
        }

        return new DeliveryResult(request.Message.Id, outcomes);
    }

    private async Task<RecipientOutcome> DeliverRecipientAsync(
        DeliveryRequest request,
        AcceptedRecipient accepted,
        Dictionary<string, IReadOnlyList<EmailAddress>> aliasMap,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        MessageRecipient recipient = MessageRecipient.Create(
            request.Message.Id,
            accepted.Address,
            accepted.Decision);

        await deliveries.AddRecipientAsync(recipient, cancellationToken).ConfigureAwait(false);

        if (accepted.Decision == RelayDecision.AcceptRelay)
        {
            // RequireTlsForOutbound is a property of the SENDING domain - the hosted domain
            // whose mailbox is relaying this mail out, not the destination - so it is looked up
            // from the envelope reverse path, snapshotted onto the queue item at enqueue time.
            bool requireTls = false;

            if (request.ReversePath is not null)
            {
                MailDomain? originDomain = await domains
                    .GetByNameAsync(request.ReversePath.Domain, cancellationToken)
                    .ConfigureAwait(false);

                requireTls = originDomain?.RequireTlsForOutbound ?? false;
            }

            OutboundQueueItem queueItem = OutboundQueueItem.Create(
                request.Message.Id,
                recipient.Id,
                accepted.Address,
                request.ReversePath,
                requireTls,
                isDsn: false,
                now);

            await outboundQueue.AddAsync(queueItem, cancellationToken).ConfigureAwait(false);

            logger.LogInformation(
                "Recipient {Recipient} of message {MessageId} queued for onward relay.",
                accepted.Address.Value,
                request.Message.Id.Value);

            return new RecipientOutcome(
                accepted.Address,
                MailboxesDelivered: 0,
                QueuedForRelay: true);
        }

        AliasExpansion expansion = expansionPolicy.Expand(
            accepted.Address,
            address => aliasMap.GetValueOrDefault(address.NormalizedValue));

        if (expansion.WasTruncated)
        {
            // Reported, never silently trimmed. Delivering to part of a distribution list and
            // telling nobody leaves the sender believing it reached everyone.
            logger.LogWarning(
                "Expansion of {Recipient} was truncated: {Diagnostic}",
                accepted.Address.Value,
                expansion.Diagnostic);
        }

        int delivered = 0;

        foreach (EmailAddress target in expansion.Recipients)
        {
            if (await DeliverToMailboxAsync(request, recipient, target, now, cancellationToken)
                .ConfigureAwait(false))
            {
                delivered++;
            }
        }

        return new RecipientOutcome(
            accepted.Address,
            delivered,
            QueuedForRelay: false,
            expansion.WasTruncated ? expansion.Diagnostic : null);
    }

    private async Task<bool> DeliverToMailboxAsync(
        DeliveryRequest request,
        MessageRecipient recipient,
        EmailAddress target,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        Mailbox? mailbox = await mailboxes
            .GetByAddressAsync(target, cancellationToken)
            .ConfigureAwait(false);

        if (mailbox is null)
        {
            // An alias target that is not a local mailbox. Reaching here means either the target
            // is external - forwarding, which the outbound queue will handle - or the alias
            // points at nothing. Both are the operator's to see, and neither justifies losing
            // the rest of the expansion.
            logger.LogWarning(
                "Alias target {Target} of message {MessageId} is not a local mailbox; not delivered.",
                target.Value,
                request.Message.Id.Value);

            return false;
        }

        if (!mailbox.AcceptsMail)
        {
            logger.LogInformation(
                "Mailbox {Mailbox} does not accept mail; message {MessageId} not delivered to it.",
                target.Value,
                request.Message.Id.Value);

            return false;
        }

        MailboxFolder? inbox = await deliveries
            .GetFolderAsync(mailbox.Id, FolderSpecialUse.Inbox, cancellationToken)
            .ConfigureAwait(false);

        if (inbox is null)
        {
            // Every mailbox gets an INBOX when it is created, so this is a repair problem rather
            // than a delivery one. Creating one here would paper over it and would race with
            // whatever else is doing the same.
            logger.LogError(
                "Mailbox {Mailbox} has no INBOX; message {MessageId} could not be delivered to it.",
                target.Value,
                request.Message.Id.Value);

            return false;
        }

        long uid = await deliveries
            .AllocateUidAsync(inbox.Id, cancellationToken)
            .ConfigureAwait(false);

        Delivery delivery = Delivery.Create(
            request.Message.Id,
            mailbox.Id,
            inbox.Id,
            uid,
            recipient.Id,
            now);

        await deliveries.AddDeliveryAsync(delivery, cancellationToken).ConfigureAwait(false);

        // Charged once per mailbox, because that is what the recipient's quota is about: how much
        // mail they are holding, not how many bytes are on this server's disk. Two mailboxes
        // sharing one file are each charged for it.
        await deliveries
            .AddStorageUsedAsync(mailbox.Id, request.Message.SizeBytes, cancellationToken)
            .ConfigureAwait(false);

        return true;
    }

    /// <summary>
    /// Verifies every DKIM-Signature header on a message, evaluates DMARC alignment from those
    /// results, and records one row per DKIM signature plus one DMARC row for the message.
    /// </summary>
    /// <remarks>
    /// <b>Fails open.</b> A subsystem failure (a malformed message this server could not even
    /// locate headers for, an unexpected exception) is logged and treated as "DMARC does not
    /// apply", never as a rejection — the one enforcement decision this step can make is a
    /// positive one (a successfully evaluated <see cref="DmarcPolicy.Reject"/>), never a default.
    /// Accepting a message a broken evaluator could not judge is safer than rejecting mail this
    /// server never actually found to violate anything.
    /// </remarks>
    private async Task<DmarcEvaluationOutcome?> VerifyAuthenticationAsync(
        StoredMessageId messageId, SpfEvaluationOutcome? spfOutcome, DateTimeOffset now, CancellationToken cancellationToken)
    {
        try
        {
            await using Stream content = await messageStore.OpenReadAsync(messageId, cancellationToken)
                .ConfigureAwait(false);

            RawMessageHeaders? headers = await MessageHeaderReader.TryReadHeadersAsync(
                content, options.Value.Limits.MaxHeaderBytes, cancellationToken).ConfigureAwait(false);

            if (headers is null)
            {
                logger.LogWarning(
                    "Could not locate the header/body boundary for message {MessageId}; DKIM/DMARC were not verified.",
                    messageId.Value);

                return null;
            }

            content.Seek(headers.HeaderBlockLength, SeekOrigin.Begin);

            IReadOnlyList<DkimVerifiedSignature> dkimResults = await dkimVerifier
                .VerifyAsync(headers, content, cancellationToken)
                .ConfigureAwait(false);

            for (int i = 0; i < dkimResults.Count; i++)
            {
                DkimVerifiedSignature result = dkimResults[i];

                DkimVerificationRecord verificationRecord = DkimVerificationRecord.Create(
                    messageId, i, result.Result, result.SigningDomain, result.Diagnostic, now);

                await deliveries.AddDkimVerificationAsync(verificationRecord, cancellationToken)
                    .ConfigureAwait(false);
            }

            DmarcEvaluationOutcome dmarcOutcome = await dmarcEvaluator
                .EvaluateAsync(headers, spfOutcome, dkimResults, cancellationToken)
                .ConfigureAwait(false);

            DmarcVerificationRecord dmarcRecord = DmarcVerificationRecord.Create(
                messageId,
                dmarcOutcome.Result,
                dmarcOutcome.Disposition,
                dmarcOutcome.AlignedMechanisms,
                dmarcOutcome.FromDomain,
                dmarcOutcome.PolicyDomain,
                dmarcOutcome.Diagnostic,
                now);

            await deliveries.AddDmarcVerificationAsync(dmarcRecord, cancellationToken).ConfigureAwait(false);

            return dmarcOutcome;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Failed to verify DKIM/DMARC for message {MessageId}.", messageId.Value);
            return null;
        }
    }
}
