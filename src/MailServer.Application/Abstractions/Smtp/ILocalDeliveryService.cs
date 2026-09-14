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
public sealed record DeliveryRequest(
    StoredMessage Message,
    EmailAddress? ReversePath,
    IReadOnlyList<AcceptedRecipient> Recipients,
    IpAddressValue RemoteAddress,
    string? GreetedName,
    SmtpListenerRole ListenerRole,
    bool TlsActive,
    EmailAddress? AuthenticatedAs);

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

/// <summary>The result of delivering one message.</summary>
/// <param name="MessageId">The stored message.</param>
/// <param name="Outcomes">One entry per envelope recipient, in the order they were accepted.</param>
public sealed record DeliveryResult(StoredMessageId MessageId, IReadOnlyList<RecipientOutcome> Outcomes)
{
    /// <summary>Total mailboxes the message reached.</summary>
    public int TotalDeliveries => Outcomes.Sum(o => o.MailboxesDelivered);

    /// <summary>Whether every recipient reached a mailbox or the outbound queue.</summary>
    public bool EverythingPlaced =>
        Outcomes.All(o => o.MailboxesDelivered > 0 || o.QueuedForRelay);
}

/// <summary>Places an accepted message into local mailboxes.</summary>
public interface ILocalDeliveryService
{
    /// <summary>Delivers one message to its accepted recipients.</summary>
    Task<DeliveryResult> DeliverAsync(DeliveryRequest request, CancellationToken cancellationToken);
}
