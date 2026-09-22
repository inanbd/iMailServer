using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Smtp;

/// <summary>The envelope and session facts a delivery needs.</summary>
/// <param name="Message">The content, already committed to the store.</param>
/// <param name="ReversePath">The envelope sender, or null for the null reverse path.</param>
/// <param name="Recipients">The recipients accepted at RCPT TO.</param>
/// <param name="RemoteAddress">The peer, from the transport.</param>
/// <param name="GreetedName">What the peer claimed in EHLO.</param>
/// <param name="ListenerRole">Which listener took the message.</param>
/// <param name="TlsActive">Whether the session was encrypted.</param>
/// <param name="AuthenticatedAs">The authenticated mailbox, when there was one.</param>
/// <param name="SpfOutcome">
/// The session's recorded SPF result, when SPF was evaluated at <c>MAIL FROM</c> time — DMARC's
/// own SPF alignment check needs it. Null for a Submission message, which never carries one.
/// </param>
public sealed record DeliveryRequest(
    StoredMessage Message,
    EmailAddress? ReversePath,
    IReadOnlyList<AcceptedRecipient> Recipients,
    IpAddressValue RemoteAddress,
    string? GreetedName,
    SmtpListenerRole ListenerRole,
    bool TlsActive,
    EmailAddress? AuthenticatedAs,
    SpfEvaluationOutcome? SpfOutcome = null);

/// <summary>What happened to one envelope recipient.</summary>
/// <param name="Address">The address the sender wrote.</param>
/// <param name="MailboxesDelivered">How many mailboxes it ultimately reached.</param>
/// <param name="QueuedForRelay">True when it was handed to the outbound queue instead.</param>
/// <param name="Diagnostic">Why it fell short, when it did.</param>
public sealed record RecipientOutcome(
    EmailAddress Address,
    int MailboxesDelivered,
    bool QueuedForRelay,
    string? Diagnostic = null);

/// <summary>
/// The message was refused outright, and no recipient was delivered to or queued.
/// </summary>
/// <remarks>
/// <para>
/// Two things reach this. RFC 7489's <c>p=reject</c>, once <c>pct=</c> sampling has selected
/// the message — the publishing domain's own instruction. And the filter, when an operator has
/// deliberately given it a finite reject threshold, which is off by default (see
/// <c>FilterPolicy.RejectThreshold</c> on why).
/// </para>
/// <para>
/// <b>Rejecting is the only outcome that leaves nothing behind.</b> That is its value — a
/// legitimate sender this server got wrong finds out immediately, which junking and
/// quarantining cannot offer — and its cost, which is why so little reaches it.
/// </para>
/// </remarks>
/// <param name="Diagnostic">Human-readable detail, for the SMTP reply and for logs.</param>
/// <param name="PolicyDomain">
/// The domain whose published DMARC policy asked for this, when that is what refused it. Null
/// when the filter did: a score is this server's own conclusion and names no publisher.
/// </param>
public sealed record DeliveryRejection(string Diagnostic, DomainName? PolicyDomain = null);

/// <summary>The result of delivering one message.</summary>
/// <param name="MessageId">The stored message.</param>
/// <param name="Outcomes">
/// One entry per envelope recipient, in the order they were accepted. Empty when
/// <paramref name="Rejection"/> is set — a DMARC-rejected message is delivered to nobody.
/// </param>
/// <param name="Rejection">Set when the message was refused outright; see <see cref="DeliveryRejection"/>.</param>
public sealed record DeliveryResult(
    StoredMessageId MessageId, IReadOnlyList<RecipientOutcome> Outcomes, DeliveryRejection? Rejection = null)
{
    /// <summary>Total mailboxes the message reached.</summary>
    public int TotalDeliveries => Outcomes.Sum(o => o.MailboxesDelivered);

    /// <summary>Whether every recipient reached a mailbox or the outbound queue.</summary>
    public bool EverythingPlaced =>
        Outcomes.All(o => o.MailboxesDelivered > 0 || o.QueuedForRelay);
}

/// <summary>What a release needs to deliver a message that was held.</summary>
/// <param name="Message">The held message, still in the store.</param>
/// <param name="ReversePath">The envelope sender, as it was recorded at hold time.</param>
/// <remarks>
/// <b>There is no recipient list here, deliberately.</b> The recipients come from the
/// <c>MessageRecipients</c> rows the original delivery wrote, read inside the implementation.
/// Passing them in would let a caller release a message to somebody it was never addressed to
/// — the caller is an administrator, and this is one of the few places where "the operator
/// asked for it" is not a sufficient reason.
/// </remarks>
public sealed record ReleaseRequest(StoredMessage Message, EmailAddress? ReversePath);

/// <summary>Places an accepted message into local mailboxes.</summary>
public interface ILocalDeliveryService
{
    /// <summary>Delivers one message to its accepted recipients.</summary>
    Task<DeliveryResult> DeliverAsync(DeliveryRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Delivers a message that was held, to the recipients it was originally accepted for.
    /// </summary>
    /// <remarks>
    /// <b>The same code path an ordinary delivery takes</b> — the same alias expansion, the
    /// same quota accounting, the same UID allocation. A release that wrote its own delivery
    /// rows would be a second implementation of the thing that puts mail in mailboxes, and the
    /// bug it eventually grew would only ever show up in released mail.
    /// </remarks>
    Task<DeliveryResult> DeliverReleasedAsync(ReleaseRequest request, CancellationToken cancellationToken);
}
