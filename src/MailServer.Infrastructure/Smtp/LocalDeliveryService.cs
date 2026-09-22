using MailServer.Application.Abstractions.Filtering;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Filtering;
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
    IMessageFilter filter,
    IQuarantineRepository quarantine,
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

        MessageAuthenticationFacts authentication = new(request.SpfOutcome?.Result, null, null, null);

        // SPF's premise - does the sending IP match the domain's published record - is
        // meaningless for an authenticated client's IP, which can legitimately be anywhere. DKIM
        // and DMARC have no such caveat, but are still scoped to InboundMta here to keep every
        // mechanism's wiring symmetric and because a Submission message is this server's own
        // outbound signing's concern (OutboundSmtpClient), not something to re-verify on the way in.
        if (request.ListenerRole == SmtpListenerRole.InboundMta)
        {
            VerifiedAuthentication verified = await VerifyAuthenticationAsync(
                request.Message.Id, request.SpfOutcome, now, cancellationToken).ConfigureAwait(false);

            authentication = verified.Facts;

            if (verified.Dmarc is { Disposition: DmarcPolicy.Reject } dmarcOutcome)
            {
                logger.LogInformation(
                    "Message {MessageId} rejected: DMARC policy published at {PolicyDomain} requests reject for From: domain {FromDomain}.",
                    request.Message.Id.Value, dmarcOutcome.PolicyDomain!.Value, dmarcOutcome.FromDomain!.Value);

                await RemoveRejectedContentAsync(request.Message.Id, now, cancellationToken).ConfigureAwait(false);

                return new DeliveryResult(
                    request.Message.Id,
                    [],
                    new DeliveryRejection(
                        $"it fails DMARC alignment against {dmarcOutcome.FromDomain.Value} " +
                        $"(policy published at {dmarcOutcome.PolicyDomain.Value})",
                        dmarcOutcome.PolicyDomain));
            }
        }

        // The filter runs after DMARC enforcement and before anything is placed. After, because
        // a message the publishing domain asked to have rejected is gone already and filtering
        // it would be work for a verdict nobody reads. Before, because every action it can
        // return - a different folder, a hold, a refusal - has to be decided while there is
        // still nothing in a mailbox to undo.
        FilterVerdict verdict = request.ListenerRole == SmtpListenerRole.InboundMta
            ? await FilterAsync(request, authentication, now, cancellationToken).ConfigureAwait(false)
            : FilterVerdict.Clean;

        if (verdict.Action == FilterAction.Reject)
        {
            logger.LogInformation(
                "Message {MessageId} refused by the filter: {Summary}",
                request.Message.Id.Value,
                verdict.Summarise());

            await RemoveRejectedContentAsync(request.Message.Id, now, cancellationToken).ConfigureAwait(false);

            return new DeliveryResult(
                request.Message.Id, [], new DeliveryRejection("it was refused by this server's filter"));
        }

        Dictionary<string, IReadOnlyList<EmailAddress>> aliasMap =
            await ReadAliasMapAsync(cancellationToken).ConfigureAwait(false);

        // A held message still gets its recipient rows: they are the record of who it was for,
        // and they are what a release delivers against. Writing them only on delivery would
        // leave a quarantine full of messages nobody could release.
        FolderSpecialUse folder = verdict.Action == FilterAction.Junk
            ? FolderSpecialUse.Junk
            : FolderSpecialUse.Inbox;

        List<RecipientOutcome> outcomes = [];

        foreach (AcceptedRecipient accepted in request.Recipients)
        {
            outcomes.Add(await DeliverRecipientAsync(
                request,
                accepted,
                aliasMap,
                folder,
                place: verdict.Action != FilterAction.Quarantine,
                now,
                cancellationToken).ConfigureAwait(false));
        }

        if (verdict.Action == FilterAction.Quarantine)
        {
            await HoldAsync(request, verdict, now, cancellationToken).ConfigureAwait(false);
        }

        return new DeliveryResult(request.Message.Id, outcomes);
    }

    /// <summary>
    /// Asks the filter what to do with this message.
    /// </summary>
    /// <remarks>
    /// <b>Fails open, like the authentication step above it.</b> A filter that threw would
    /// otherwise stop mail flowing, and a message delivered unfiltered is a far smaller problem
    /// than a mail server that stopped delivering. The pipeline catches its own exceptions too;
    /// this is the backstop for the ones it cannot.
    /// </remarks>
    private async Task<FilterVerdict> FilterAsync(
        DeliveryRequest request,
        MessageAuthenticationFacts authentication,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!filter.IsEnabled)
        {
            return FilterVerdict.Clean;
        }

        try
        {
            return await filter
                .EvaluateAsync(
                    new MessageFilterRequest(
                        request.Message,
                        request.ReversePath,
                        request.RemoteAddress,
                        request.Recipients.Count,
                        authentication,
                        now),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex, "Filtering message {MessageId} failed; it was delivered unfiltered.", request.Message.Id.Value);

            return FilterVerdict.Clean;
        }
    }

    /// <summary>
    /// Records a held message.
    /// </summary>
    /// <remarks>
    /// <b>A failure to record the hold is not a failure to hold.</b> Nothing was placed in a
    /// mailbox, so the message is already where the verdict wanted it; what is lost is an
    /// operator's ability to find and release it. That is worth a loud warning and not worth
    /// turning into a delivery error the sending server would retry — a retry would re-deliver
    /// the same message, and hold it again, for as long as the quarantine stayed broken.
    /// </remarks>
    private async Task HoldAsync(
        DeliveryRequest request,
        FilterVerdict verdict,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        try
        {
            await quarantine.AddAsync(
                QuarantinedMessage.Create(
                    request.Message.Id,
                    request.ReversePath,
                    request.RemoteAddress,
                    verdict,
                    now,
                    TimeSpan.FromDays(options.Value.Filtering.QuarantineRetentionDays)),
                cancellationToken).ConfigureAwait(false);

            logger.LogInformation(
                "Message {MessageId} held: {Summary}", request.Message.Id.Value, verdict.Summarise());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex,
                "Message {MessageId} was held but could not be recorded in the quarantine; it was delivered to nobody and cannot be released.",
                request.Message.Id.Value);
        }
    }

    /// <inheritdoc />
    public async Task<DeliveryResult> DeliverReleasedAsync(
        ReleaseRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        DateTimeOffset now = clock.UtcNow;

        // The recipients come from the rows the original delivery wrote, never from the
        // message's own headers. A released message's To: line is whatever the sender chose to
        // put there, and delivering to it would let a held message name its own audience.
        IReadOnlyList<MessageRecipient> recipients = await deliveries
            .ListRecipientsAsync(request.Message.Id, cancellationToken)
            .ConfigureAwait(false);

        if (recipients.Count == 0)
        {
            logger.LogWarning(
                "Message {MessageId} was released but has no recipient rows; it was delivered to nobody.",
                request.Message.Id.Value);

            return new DeliveryResult(request.Message.Id, []);
        }

        Dictionary<string, IReadOnlyList<EmailAddress>> aliasMap =
            await ReadAliasMapAsync(cancellationToken).ConfigureAwait(false);

        // Released mail goes to the INBOX, never to Junk. An operator has looked at it and
        // decided it is legitimate; putting it where the recipient may never look would make
        // the release a gesture rather than a delivery.
        Placement placement = new(
            request.Message.Id, request.Message.SizeBytes, request.ReversePath, FolderSpecialUse.Inbox);

        List<RecipientOutcome> outcomes = [];

        foreach (MessageRecipient recipient in recipients)
        {
            outcomes.Add(await PlaceRecipientAsync(
                placement, recipient, aliasMap, now, cancellationToken).ConfigureAwait(false));
        }

        logger.LogInformation(
            "Released message {MessageId} reached {Count} mailboxes.",
            request.Message.Id.Value,
            outcomes.Sum(o => o.MailboxesDelivered));

        return new DeliveryResult(request.Message.Id, outcomes);
    }

    /// <summary>
    /// Reads the alias graph once.
    /// </summary>
    /// <remarks>
    /// Once per message rather than once per recipient: a message to twenty recipients in the
    /// same domain would otherwise re-read the same aliases twenty times, on the delivery path.
    /// </remarks>
    private async Task<Dictionary<string, IReadOnlyList<EmailAddress>>> ReadAliasMapAsync(
        CancellationToken cancellationToken)
    {
        IReadOnlyList<Alias> enabledAliases = await aliases
            .GetAllEnabledAsync(cancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, IReadOnlyList<EmailAddress>> aliasMap =
            new(StringComparer.OrdinalIgnoreCase);

        foreach (Alias alias in enabledAliases)
        {
            aliasMap[alias.Address.NormalizedValue] = alias.Targets;
        }

        return aliasMap;
    }

    private async Task<RecipientOutcome> DeliverRecipientAsync(
        DeliveryRequest request,
        AcceptedRecipient accepted,
        Dictionary<string, IReadOnlyList<EmailAddress>> aliasMap,
        FolderSpecialUse folder,
        bool place,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        MessageRecipient recipient = MessageRecipient.Create(
            request.Message.Id,
            accepted.Address,
            accepted.Decision);

        await deliveries.AddRecipientAsync(recipient, cancellationToken).ConfigureAwait(false);

        if (!place)
        {
            // A held message. The row above is written and nothing else is: it is the record of
            // who the message was for, and the only thing a release has to go on.
            return new RecipientOutcome(accepted.Address, MailboxesDelivered: 0, QueuedForRelay: false);
        }

        return await PlaceRecipientAsync(
            new Placement(request.Message.Id, request.Message.SizeBytes, request.ReversePath, folder),
            recipient,
            aliasMap,
            now,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The message-level facts placing one recipient needs.</summary>
    /// <remarks>
    /// Passed instead of the <see cref="DeliveryRequest"/> so that a release — which has no
    /// session, no greeting and no SPF result, because the conversation ended days ago — can
    /// take exactly the same path as an ordinary delivery.
    /// </remarks>
    /// <param name="Folder">
    /// Which special-use folder the message belongs in. <c>Junk</c> when the filter said so,
    /// <c>Inbox</c> otherwise — carried here rather than decided at the mailbox, so that one
    /// verdict decides one message's destination for every recipient rather than being
    /// re-derived per mailbox.
    /// </param>
    private sealed record Placement(
        StoredMessageId MessageId,
        long SizeBytes,
        EmailAddress? ReversePath,
        FolderSpecialUse Folder = FolderSpecialUse.Inbox);

    /// <summary>
    /// Expands one accepted recipient and puts the message wherever it belongs.
    /// </summary>
    /// <remarks>
    /// <b>The <c>MessageRecipients</c> row is the caller's business, not this method's.</b> An
    /// ordinary delivery writes one; a release is delivering against rows that already exist,
    /// and writing them again would double the recipient list every time an operator released
    /// a message.
    /// </remarks>
    private async Task<RecipientOutcome> PlaceRecipientAsync(
        Placement placement,
        MessageRecipient recipient,
        Dictionary<string, IReadOnlyList<EmailAddress>> aliasMap,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        AcceptedRecipient accepted = new(recipient.Address, recipient.Decision);

        if (accepted.Decision == RelayDecision.AcceptRelay)
        {
            // RequireTlsForOutbound is a property of the SENDING domain - the hosted domain
            // whose mailbox is relaying this mail out, not the destination - so it is looked up
            // from the envelope reverse path, snapshotted onto the queue item at enqueue time.
            bool requireTls = false;

            if (placement.ReversePath is not null)
            {
                MailDomain? originDomain = await domains
                    .GetByNameAsync(placement.ReversePath.Domain, cancellationToken)
                    .ConfigureAwait(false);

                requireTls = originDomain?.RequireTlsForOutbound ?? false;
            }

            OutboundQueueItem queueItem = OutboundQueueItem.Create(
                placement.MessageId,
                recipient.Id,
                accepted.Address,
                placement.ReversePath,
                requireTls,
                isDsn: false,
                now);

            await outboundQueue.AddAsync(queueItem, cancellationToken).ConfigureAwait(false);

            logger.LogInformation(
                "Recipient {Recipient} of message {MessageId} queued for onward relay.",
                accepted.Address.Value,
                placement.MessageId.Value);

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
            if (await DeliverToMailboxAsync(placement, recipient, target, now, cancellationToken)
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
        Placement placement,
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
                placement.MessageId.Value);

            return false;
        }

        if (!mailbox.AcceptsMail)
        {
            logger.LogInformation(
                "Mailbox {Mailbox} does not accept mail; message {MessageId} not delivered to it.",
                target.Value,
                placement.MessageId.Value);

            return false;
        }

        MailboxFolder? inbox = await deliveries
            .GetFolderAsync(mailbox.Id, placement.Folder, cancellationToken)
            .ConfigureAwait(false);

        if (inbox is null && placement.Folder != FolderSpecialUse.Inbox)
        {
            // Junk is optional: RFC 6154's \Junk is a folder a client may never have created.
            // Delivering to the INBOX instead is right - the message arrives, marked by its
            // verdict rather than by where it landed - and refusing to deliver because a folder
            // is missing would lose mail over a client's choice of layout.
            logger.LogDebug(
                "Mailbox {Mailbox} has no {Folder} folder; message {MessageId} went to the INBOX.",
                target.Value,
                placement.Folder,
                placement.MessageId.Value);

            inbox = await deliveries
                .GetFolderAsync(mailbox.Id, FolderSpecialUse.Inbox, cancellationToken)
                .ConfigureAwait(false);
        }

        if (inbox is null)
        {
            // Every mailbox gets an INBOX when it is created, so this is a repair problem rather
            // than a delivery one. Creating one here would paper over it and would race with
            // whatever else is doing the same.
            logger.LogError(
                "Mailbox {Mailbox} has no INBOX; message {MessageId} could not be delivered to it.",
                target.Value,
                placement.MessageId.Value);

            return false;
        }

        long uid = await deliveries
            .AllocateUidAsync(inbox.Id, cancellationToken)
            .ConfigureAwait(false);

        Delivery delivery = Delivery.Create(
            placement.MessageId,
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
            .AddStorageUsedAsync(mailbox.Id, placement.SizeBytes, cancellationToken)
            .ConfigureAwait(false);

        return true;
    }

    /// <summary>
    /// Deletes a DMARC-rejected message's stored content and records that removal.
    /// </summary>
    /// <remarks>
    /// A message refused by <c>p=reject</c> is never delivered to a mailbox or queued for relay,
    /// so its content serves no further purpose - keeping it indefinitely would be an unbounded
    /// disk-growth vector under repeated probing from a domain publishing a reject policy. The
    /// <c>Messages</c> row itself is kept, since <see cref="DmarcVerificationRecord"/>'s foreign
    /// key names it and an operator's record of what was rejected should outlive the bytes that
    /// were. Never throws: a cleanup failure must not turn a successful rejection into a delivery
    /// error, and a message a sweep fails to clean up today is exactly what a future housekeeping
    /// pass exists to catch.
    /// </remarks>
    private async Task RemoveRejectedContentAsync(StoredMessageId messageId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        try
        {
            await messageStore.DeleteAsync(messageId, cancellationToken).ConfigureAwait(false);
            await deliveries.MarkContentRemovedAsync(messageId, now, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Failed to remove stored content for DMARC-rejected message {MessageId}.", messageId.Value);
        }
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
    private async Task<VerifiedAuthentication> VerifyAuthenticationAsync(
        StoredMessageId messageId, SpfEvaluationOutcome? spfOutcome, DateTimeOffset now, CancellationToken cancellationToken)
    {
        MessageAuthenticationFacts unverified = new(spfOutcome?.Result, null, null, null);

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

                return new VerifiedAuthentication(null, unverified);
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

            return new VerifiedAuthentication(
                dmarcOutcome,
                new MessageAuthenticationFacts(
                    spfOutcome?.Result,
                    BestOf(dkimResults),
                    dmarcOutcome.Result,
                    dmarcOutcome.Disposition));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Failed to verify DKIM/DMARC for message {MessageId}.", messageId.Value);
            return new VerifiedAuthentication(null, unverified);
        }
    }

    /// <summary>What the authentication step concluded, for the caller and for the filter.</summary>
    private sealed record VerifiedAuthentication(
        DmarcEvaluationOutcome? Dmarc,
        MessageAuthenticationFacts Facts);

    /// <summary>
    /// The most favourable DKIM result among a message's signatures.
    /// </summary>
    /// <remarks>
    /// <b>One passing signature is a pass, however many others failed.</b> A message may carry
    /// several — a mailing list's alongside the author's — and a broken one usually means an
    /// intermediary rewrote a header the signer covered, not that anything is wrong with the
    /// message. Weighing the worst of them would score ordinary list traffic as forged.
    /// </remarks>
    private static DkimVerificationResult? BestOf(IReadOnlyList<DkimVerifiedSignature> results)
    {
        if (results.Count == 0)
        {
            return null;
        }

        if (results.Any(r => r.Result == DkimVerificationResult.Pass))
        {
            return DkimVerificationResult.Pass;
        }

        return results.Any(r => r.Result == DkimVerificationResult.Fail)
            ? DkimVerificationResult.Fail
            : results[0].Result;
    }
}
