using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Filtering.Dtos;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Filtering;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Filtering.Commands;

/// <summary>
/// Delivers a held message to the recipients it was originally addressed to.
/// </summary>
/// <remarks>
/// <para>
/// <b>The other half of the quarantine's reason to exist.</b> A hold an operator cannot undo
/// is a deletion with extra steps; this is what makes holding a message the safe answer rather
/// than a destructive one.
/// </para>
/// <para>
/// <b><see cref="AdminPermission.ReadMessageContent"/> rather than
/// <see cref="AdminPermission.ManageSecurity"/>.</b> Releasing puts a message the filter judged
/// dangerous into somebody's mailbox, and the honest way to decide that is to have read it.
/// Asking for the anti-abuse permission instead would let an operator who cannot open the
/// message deliver it anyway, on the strength of a summary line.
/// </para>
/// <para>
/// Not <see cref="ITransactionalRequest"/>: the delivery it performs writes rows for each
/// recipient and mailbox, and a release that reached four mailboxes and failed on the fifth
/// should leave the four. Rolling them back would mean an operator retrying a release that
/// had already half-succeeded, with no way to tell which half.
/// </para>
/// </remarks>
public sealed record ReleaseQuarantinedMessageCommand : ICommand<QuarantineReleaseDto>, IAuthorizedRequest, IAuditableRequest
{
    /// <summary>The held message to release.</summary>
    public required Guid Id { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ReadMessageContent;

    public AuditDescriptor DescribeForAudit() =>
        new("Quarantine.Release", Id.ToString("D"), null);
}

/// <summary>
/// Discards a held message and removes its content.
/// </summary>
/// <remarks>
/// <b>The row stays; the bytes do not.</b> An operator asking "what did we discard, and who
/// decided?" six months later has an answer, and the answer costs a row rather than the
/// message. Keeping the content of everything ever discarded would make the quarantine a
/// permanent archive of exactly the mail nobody wanted kept.
/// </remarks>
public sealed record DiscardQuarantinedMessageCommand : ICommand<Unit>, IAuthorizedRequest, IAuditableRequest
{
    /// <summary>The held message to discard.</summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Discarding needs only the anti-abuse permission, where releasing needs the stronger one.
    /// </summary>
    /// <remarks>
    /// The asymmetry is deliberate and is the safe direction: refusing to deliver a message the
    /// filter already refused to deliver changes nothing about who can read mail, whereas
    /// releasing one does.
    /// </remarks>
    public AdminPermission RequiredPermission => AdminPermission.ManageSecurity;

    public AuditDescriptor DescribeForAudit() =>
        new("Quarantine.Discard", Id.ToString("D"), null);
}

internal sealed class ReleaseQuarantinedMessageCommandHandler(
    IQuarantineRepository quarantine,
    ILocalDeliveryService delivery,
    IMessageStore messageStore,
    IAdminContext adminContext,
    IClock clock,
    ILogger<ReleaseQuarantinedMessageCommandHandler> logger)
    : IRequestHandler<ReleaseQuarantinedMessageCommand, QuarantineReleaseDto>
{
    public async Task<QuarantineReleaseDto> Handle(
        ReleaseQuarantinedMessageCommand request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        QuarantinedMessageId id = new(request.Id);

        QuarantinedMessage held = await quarantine.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(QuarantinedMessage), request.Id.ToString("D"));

        if (!held.IsHeld)
        {
            throw new DomainRuleViolationException(
                "Quarantine.AlreadyResolved",
                $"This message was already {held.Status.ToString().ToLowerInvariant()} " +
                $"by {held.ResolvedBy} at {held.ResolvedUtc:u}.");
        }

        held.Release(adminContext.Administrator, clock.UtcNow);

        // Claimed before delivering, not after. Two administrators looking at the same
        // quarantine is the ordinary case, and whoever loses the claim must not go on to
        // deliver the message a second time.
        if (!await quarantine.TryResolveAsync(held, cancellationToken).ConfigureAwait(false))
        {
            throw new DomainRuleViolationException(
                "Quarantine.AlreadyResolved",
                "Another administrator resolved this message first; it was not released again.");
        }

        StoredMessage? stored = await ReadStoredAsync(held.MessageId, cancellationToken)
            .ConfigureAwait(false);

        if (stored is null)
        {
            // The row is already marked released and stays that way: the operator's decision
            // happened, and a row that flipped back to held would invite a second attempt at a
            // message whose content is gone.
            logger.LogWarning(
                "Quarantined message {MessageId} was released but its content is no longer in the store.",
                held.MessageId.Value);

            return new QuarantineReleaseDto(
                0, 0, "The message's stored content is no longer available, so nothing was delivered.");
        }

        DeliveryResult result = await delivery
            .DeliverReleasedAsync(new ReleaseRequest(stored, held.ReversePath), cancellationToken)
            .ConfigureAwait(false);

        string? diagnostic = result.TotalDeliveries == 0
            ? "The message was released but reached no mailbox; its recipients may no longer exist."
            : null;

        return new QuarantineReleaseDto(result.TotalDeliveries, result.Outcomes.Count, diagnostic);
    }

    /// <summary>
    /// Rebuilds the <see cref="StoredMessage"/> the delivery path wants from the store itself.
    /// </summary>
    /// <remarks>
    /// The size is read back rather than carried on the quarantine row, because it is the
    /// figure charged against each recipient's quota and the store is the authority on it. A
    /// number copied at hold time would charge whatever it said even if the file had changed.
    /// </remarks>
    private async Task<StoredMessage?> ReadStoredAsync(
        StoredMessageId messageId,
        CancellationToken cancellationToken)
    {
        if (!await messageStore.ExistsAsync(messageId, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        await using Stream content = await messageStore
            .OpenReadAsync(messageId, cancellationToken)
            .ConfigureAwait(false);

        byte[] hash = await System.Security.Cryptography.SHA256
            .HashDataAsync(content, cancellationToken)
            .ConfigureAwait(false);

        return new StoredMessage(messageId, content.Length, Sha256Hash.FromBytes(hash), clock.UtcNow);
    }
}

internal sealed class DiscardQuarantinedMessageCommandHandler(
    IQuarantineRepository quarantine,
    IMessageStore messageStore,
    IAdminContext adminContext,
    IClock clock,
    ILogger<DiscardQuarantinedMessageCommandHandler> logger)
    : IRequestHandler<DiscardQuarantinedMessageCommand, Unit>
{
    public async Task<Unit> Handle(
        DiscardQuarantinedMessageCommand request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        QuarantinedMessageId id = new(request.Id);

        QuarantinedMessage held = await quarantine.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(QuarantinedMessage), request.Id.ToString("D"));

        if (!held.IsHeld)
        {
            throw new DomainRuleViolationException(
                "Quarantine.AlreadyResolved",
                $"This message was already {held.Status.ToString().ToLowerInvariant()} " +
                $"by {held.ResolvedBy} at {held.ResolvedUtc:u}.");
        }

        held.Discard(adminContext.Administrator, clock.UtcNow);

        if (!await quarantine.TryResolveAsync(held, cancellationToken).ConfigureAwait(false))
        {
            throw new DomainRuleViolationException(
                "Quarantine.AlreadyResolved",
                "Another administrator resolved this message first; it was not discarded again.");
        }

        try
        {
            await messageStore.DeleteAsync(held.MessageId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The decision is recorded and the message is unreachable either way. A cleanup
            // failure must not turn a successful discard into an error the operator retries,
            // and a file a sweep fails to remove today is what a housekeeping pass is for.
            logger.LogWarning(
                ex, "Discarded message {MessageId}'s content could not be removed.", held.MessageId.Value);
        }

        return Unit.Value;
    }
}
