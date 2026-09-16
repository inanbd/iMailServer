using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// The outcome of verifying one <c>DKIM-Signature</c> header found on a received message.
/// </summary>
/// <remarks>
/// <para>
/// One row per signature, not one row per message — a message can legitimately carry several
/// (a mailing list re-signing on top of the original sender's signature is the common case), and
/// DMARC alignment (Milestone 9's DMARC step) needs to know about every one of them, not just
/// whichever this server decided was "the" result.
/// </para>
/// <para>
/// <b>Never mutates the stored message.</b> This is metadata recorded alongside a message, the
/// same way a <see cref="DeliveryAttempt"/> is metadata recorded alongside an outbound queue
/// item — the original bytes this server received are exactly what a future IMAP <c>FETCH</c>
/// returns, byte for byte. An <c>Authentication-Results</c> header, when this product composes
/// one, is synthesized from rows like this at the point of use, never written into the archived
/// original.
/// </para>
/// <para>
/// Written once, after verification completes, never updated — the same store-then-record
/// discipline as every other fact this product records about a message it has already committed.
/// </para>
/// </remarks>
public sealed class DkimVerificationRecord
{
    private DkimVerificationRecord(
        Guid id,
        StoredMessageId messageId,
        int signatureIndex,
        DkimVerificationResult result,
        DomainName? signingDomain,
        string? diagnostic,
        DateTimeOffset createdUtc)
    {
        Id = id;
        MessageId = messageId;
        SignatureIndex = signatureIndex;
        Result = result;
        SigningDomain = signingDomain;
        Diagnostic = diagnostic;
        CreatedUtc = createdUtc;
    }

    public Guid Id { get; }

    public StoredMessageId MessageId { get; }

    /// <summary>0-based position among the message's DKIM-Signature headers, in wire order.</summary>
    public int SignatureIndex { get; }

    public DkimVerificationResult Result { get; }

    /// <summary>
    /// The signature's <c>d=</c> value, present whenever the signature at least parsed. What
    /// DMARC alignment compares against the <c>From:</c> header's domain.
    /// </summary>
    public DomainName? SigningDomain { get; }

    /// <summary>Human-readable detail, for a future Authentication-Results header and for logs.</summary>
    public string? Diagnostic { get; }

    public DateTimeOffset CreatedUtc { get; }

    public static DkimVerificationRecord Create(
        StoredMessageId messageId,
        int signatureIndex,
        DkimVerificationResult result,
        DomainName? signingDomain,
        string? diagnostic,
        DateTimeOffset now)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(signatureIndex);

        return new DkimVerificationRecord(
            Guid.NewGuid(), messageId, signatureIndex, result, signingDomain, diagnostic, now);
    }

    /// <summary>Rebuilds a record from persisted columns, without re-validating.</summary>
    public static DkimVerificationRecord Rehydrate(
        Guid id,
        StoredMessageId messageId,
        int signatureIndex,
        DkimVerificationResult result,
        DomainName? signingDomain,
        string? diagnostic,
        DateTimeOffset createdUtc) =>
        new(id, messageId, signatureIndex, result, signingDomain, diagnostic, createdUtc);
}
