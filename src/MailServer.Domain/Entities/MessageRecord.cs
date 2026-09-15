using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// What this server knows about one accepted message, other than its content.
/// </summary>
/// <remarks>
/// <para>
/// The envelope, not the headers. <c>From:</c> and <c>To:</c> are message content that the
/// sender wrote and may have made up entirely; the reverse path and the recipients are what
/// actually happened on the wire. Every later decision — where a bounce goes, whether DMARC
/// aligns, who to believe in an abuse report — needs the envelope, and by the time the question
/// is asked the headers are no substitute.
/// </para>
/// <para>
/// The content itself is a file, named by <see cref="Id"/>. This record is written only after
/// that file is committed.
/// </para>
/// </remarks>
public sealed class MessageRecord
{
    private MessageRecord(
        StoredMessageId id,
        long sizeBytes,
        Sha256Hash contentHash,
        EmailAddress? reversePath,
        IpAddressValue remoteAddress,
        string? greetedName,
        SmtpListenerRole listenerRole,
        bool tlsActive,
        EmailAddress? authenticatedAs,
        DateTimeOffset receivedUtc)
    {
        Id = id;
        SizeBytes = sizeBytes;
        ContentHash = contentHash;
        ReversePath = reversePath;
        RemoteAddress = remoteAddress;
        GreetedName = greetedName;
        ListenerRole = listenerRole;
        TlsActive = tlsActive;
        AuthenticatedAs = authenticatedAs;
        ReceivedUtc = receivedUtc;
    }

    /// <summary>Identifies both this record and the content file.</summary>
    public StoredMessageId Id { get; }

    /// <summary>Size of the stored content.</summary>
    public long SizeBytes { get; }

    /// <summary>SHA-256 of the stored content, as computed while it was written.</summary>
    public Sha256Hash ContentHash { get; }

    /// <summary>
    /// The envelope sender, or null for the null reverse path.
    /// </summary>
    /// <remarks>
    /// Null is a value, not an absence: <c>&lt;&gt;</c> is what a bounce uses as its sender,
    /// precisely so that a bounce cannot itself bounce and start a loop.
    /// </remarks>
    public EmailAddress? ReversePath { get; }

    /// <summary>The peer's address, from the transport. The one identifier that cannot be forged.</summary>
    public IpAddressValue RemoteAddress { get; }

    /// <summary>What the peer claimed in EHLO. Kept as evidence, not as fact.</summary>
    public string? GreetedName { get; }

    /// <summary>Which listener accepted the message.</summary>
    public SmtpListenerRole ListenerRole { get; }

    /// <summary>Whether the session was encrypted.</summary>
    public bool TlsActive { get; }

    /// <summary>The authenticated mailbox, when there was one.</summary>
    public EmailAddress? AuthenticatedAs { get; }

    /// <summary>When receipt completed.</summary>
    public DateTimeOffset ReceivedUtc { get; }

    /// <summary>When the content file was removed by retention, if it has been.</summary>
    /// <remarks>
    /// The record outlives the content. An abuse investigation months later needs to know that a
    /// message arrived, from where, and to whom — and none of that requires keeping the body.
    /// </remarks>
    public DateTimeOffset? ContentRemovedUtc { get; private set; }

    /// <summary>Records an accepted message.</summary>
    public static MessageRecord Create(
        StoredMessageId id,
        long sizeBytes,
        Sha256Hash contentHash,
        EmailAddress? reversePath,
        IpAddressValue remoteAddress,
        string? greetedName,
        SmtpListenerRole listenerRole,
        bool tlsActive,
        EmailAddress? authenticatedAs,
        DateTimeOffset receivedUtc)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sizeBytes);
        ArgumentNullException.ThrowIfNull(remoteAddress);

        return new MessageRecord(
            id,
            sizeBytes,
            contentHash,
            reversePath,
            remoteAddress,
            greetedName,
            listenerRole,
            tlsActive,
            authenticatedAs,
            receivedUtc);
    }

    /// <summary>Rehydrates from storage.</summary>
    public static MessageRecord Rehydrate(
        StoredMessageId id,
        long sizeBytes,
        Sha256Hash contentHash,
        EmailAddress? reversePath,
        IpAddressValue remoteAddress,
        string? greetedName,
        SmtpListenerRole listenerRole,
        bool tlsActive,
        EmailAddress? authenticatedAs,
        DateTimeOffset receivedUtc,
        DateTimeOffset? contentRemovedUtc)
    {
        MessageRecord record = Create(
            id, sizeBytes, contentHash, reversePath, remoteAddress, greetedName,
            listenerRole, tlsActive, authenticatedAs, receivedUtc);

        record.ContentRemovedUtc = contentRemovedUtc;

        return record;
    }

    /// <summary>Marks the content as removed by retention.</summary>
    public void MarkContentRemoved(DateTimeOffset when) => ContentRemovedUtc = when;
}

/// <summary>
/// One envelope recipient, as accepted.
/// </summary>
/// <remarks>
/// Get-only properties rather than a positional record. A positional record's <c>init</c>
/// accessors are public setters as far as reflection — and as far as an aggregate's invariants —
/// are concerned, and <see cref="Create"/> exists precisely so a denied recipient cannot be
/// constructed. An object that can be rebuilt with <c>with { Decision = Deny }</c> undoes that.
/// </remarks>
public sealed record MessageRecipient
{
    private MessageRecipient(
        Guid id,
        StoredMessageId messageId,
        EmailAddress address,
        RelayDecision decision)
    {
        Id = id;
        MessageId = messageId;
        Address = address;
        Decision = decision;
    }

    /// <summary>Identity of this recipient row.</summary>
    public Guid Id { get; }

    /// <summary>The message it belongs to.</summary>
    public StoredMessageId MessageId { get; }

    /// <summary>
    /// The address the sender wrote, before alias expansion.
    /// </summary>
    /// <remarks>
    /// A bounce has to name this, not the mailbox it resolved to: the sender cannot act on an
    /// internal name, and printing one leaks it.
    /// </remarks>
    public EmailAddress Address { get; }

    /// <summary>Local delivery or onward relay. Never <see cref="RelayDecision.Deny"/>.</summary>
    public RelayDecision Decision { get; }

    /// <summary>Records an accepted recipient.</summary>
    /// <exception cref="ArgumentException">The decision was a refusal.</exception>
    public static MessageRecipient Create(
        StoredMessageId messageId,
        EmailAddress address,
        RelayDecision decision)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (decision == RelayDecision.Deny)
        {
            // A refused recipient is refused at RCPT TO and never becomes a row. Making it
            // unconstructable here means the schema's CHECK constraint is a second line of
            // defence rather than the only one.
            throw new ArgumentException(
                "A denied recipient is never recorded against a message.",
                nameof(decision));
        }

        return new MessageRecipient(Guid.NewGuid(), messageId, address, decision);
    }

    /// <summary>Rehydrates from storage.</summary>
    public static MessageRecipient Rehydrate(
        Guid id,
        StoredMessageId messageId,
        EmailAddress address,
        RelayDecision decision) =>
        new(id, messageId, address, decision);
}

/// <summary>
/// One message placed in one folder.
/// </summary>
/// <remarks>
/// Get-only, for the same reason as <see cref="MessageRecipient"/>: <see cref="Create"/> refuses
/// UID 0, and a <c>with</c> expression that could set one back would make that refusal
/// decorative.
/// </remarks>
public sealed record Delivery
{
    private Delivery(
        Guid id,
        StoredMessageId messageId,
        MailboxId mailboxId,
        MailboxFolderId folderId,
        long uid,
        Guid? recipientId,
        DateTimeOffset internalDate)
    {
        Id = id;
        MessageId = messageId;
        MailboxId = mailboxId;
        FolderId = folderId;
        Uid = uid;
        RecipientId = recipientId;
        InternalDate = internalDate;
    }

    /// <summary>Identity of this delivery.</summary>
    public Guid Id { get; }

    /// <summary>The message delivered. The content is shared, not copied.</summary>
    public StoredMessageId MessageId { get; }

    /// <summary>The owning mailbox.</summary>
    public MailboxId MailboxId { get; }

    /// <summary>The folder it landed in.</summary>
    public MailboxFolderId FolderId { get; }

    /// <summary>
    /// The IMAP UID within the folder.
    /// </summary>
    /// <remarks>
    /// Assigned once and never reassigned: a client that cached UID 42 must still find the same
    /// message there, or its cache silently serves the wrong mail.
    /// </remarks>
    public long Uid { get; }

    /// <summary>The envelope recipient this came from, for tracing an expansion.</summary>
    public Guid? RecipientId { get; }

    /// <summary>
    /// IMAP INTERNALDATE — when this server took delivery.
    /// </summary>
    /// <remarks>
    /// Distinct from the message's own <c>Date:</c> header, which the sender wrote and may have
    /// got wrong by years.
    /// </remarks>
    public DateTimeOffset InternalDate { get; }

    /// <summary>Records a delivery.</summary>
    public static Delivery Create(
        StoredMessageId messageId,
        MailboxId mailboxId,
        MailboxFolderId folderId,
        long uid,
        Guid? recipientId,
        DateTimeOffset internalDate)
    {
        // UIDs start at 1; zero is not a valid IMAP UID and a folder that issued one would
        // confuse every client that spoke to it.
        ArgumentOutOfRangeException.ThrowIfLessThan(uid, 1);

        return new Delivery(Guid.NewGuid(), messageId, mailboxId, folderId, uid, recipientId, internalDate);
    }

    /// <summary>Rehydrates from storage.</summary>
    public static Delivery Rehydrate(
        Guid id,
        StoredMessageId messageId,
        MailboxId mailboxId,
        MailboxFolderId folderId,
        long uid,
        Guid? recipientId,
        DateTimeOffset internalDate) =>
        new(id, messageId, mailboxId, folderId, uid, recipientId, internalDate);
}
