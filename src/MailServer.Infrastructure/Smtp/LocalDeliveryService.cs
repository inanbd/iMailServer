using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

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
    AliasExpansionPolicy expansionPolicy,
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
            // Onward relay is the outbound queue's business, and the queue is Milestone 8. The
            // recipient row exists either way, so the message is not silently dropped and the
            // gap is visible in the database rather than only in this comment.
            logger.LogInformation(
                "Recipient {Recipient} of message {MessageId} is for onward relay; queued handling arrives with the outbound queue.",
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
}
