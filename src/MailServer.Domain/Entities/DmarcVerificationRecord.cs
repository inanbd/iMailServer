using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// The outcome of evaluating DMARC alignment for one received message.
/// </summary>
/// <remarks>
/// <para>
/// One row per message, unlike <see cref="DkimVerificationRecord"/>'s one row per signature —
/// DMARC alignment is a single verdict for the message as a whole, computed from every DKIM
/// signature and the one SPF result together, not a per-mechanism fact.
/// </para>
/// <para>
/// <b>Never mutates the stored message</b>, for the same reason <see cref="DkimVerificationRecord"/>
/// does not: this is metadata recorded alongside a message. An <c>Authentication-Results</c>
/// header, when this product composes one, is synthesized from rows like this at the point of
/// use, never written into the archived original.
/// </para>
/// <para>
/// Written once, after evaluation completes, never updated.
/// </para>
/// </remarks>
public sealed class DmarcVerificationRecord
{
    private DmarcVerificationRecord(
        Guid id,
        StoredMessageId messageId,
        DmarcResult? result,
        DmarcPolicy disposition,
        DmarcAlignedMechanism alignedMechanisms,
        DomainName? fromDomain,
        DomainName? policyDomain,
        string? diagnostic,
        DateTimeOffset createdUtc)
    {
        Id = id;
        MessageId = messageId;
        Result = result;
        Disposition = disposition;
        AlignedMechanisms = alignedMechanisms;
        FromDomain = fromDomain;
        PolicyDomain = policyDomain;
        Diagnostic = diagnostic;
        CreatedUtc = createdUtc;
    }

    public Guid Id { get; }

    public StoredMessageId MessageId { get; }

    /// <summary>
    /// Null when DMARC did not apply to this message at all (no usable <c>From:</c> header, or no
    /// policy published anywhere along the discovery chain) — distinct from a Fail, which means a
    /// policy was found and evaluated but neither mechanism aligned.
    /// </summary>
    public DmarcResult? Result { get; }

    /// <summary>
    /// The disposition actually requested for this message, after <c>sp=</c>/<c>p=</c>
    /// resolution and <c>pct=</c> sampling. <see cref="DmarcPolicy.None"/> whenever
    /// <see cref="Result"/> is null or Pass, or sampling excluded this message.
    /// </summary>
    public DmarcPolicy Disposition { get; }

    public DmarcAlignedMechanism AlignedMechanisms { get; }

    /// <summary>The <c>From:</c> header's domain, when one could be extracted.</summary>
    public DomainName? FromDomain { get; }

    /// <summary>
    /// The domain a DMARC record was actually found at — <see cref="FromDomain"/> itself, or its
    /// organizational domain when discovery fell back to it. Null when no record was found.
    /// </summary>
    public DomainName? PolicyDomain { get; }

    /// <summary>Human-readable detail, for a future Authentication-Results header and for logs.</summary>
    public string? Diagnostic { get; }

    public DateTimeOffset CreatedUtc { get; }

    public static DmarcVerificationRecord Create(
        StoredMessageId messageId,
        DmarcResult? result,
        DmarcPolicy disposition,
        DmarcAlignedMechanism alignedMechanisms,
        DomainName? fromDomain,
        DomainName? policyDomain,
        string? diagnostic,
        DateTimeOffset now) =>
        new(Guid.NewGuid(), messageId, result, disposition, alignedMechanisms, fromDomain, policyDomain, diagnostic, now);

    /// <summary>Rebuilds a record from persisted columns, without re-validating.</summary>
    public static DmarcVerificationRecord Rehydrate(
        Guid id,
        StoredMessageId messageId,
        DmarcResult? result,
        DmarcPolicy disposition,
        DmarcAlignedMechanism alignedMechanisms,
        DomainName? fromDomain,
        DomainName? policyDomain,
        string? diagnostic,
        DateTimeOffset createdUtc) =>
        new(id, messageId, result, disposition, alignedMechanisms, fromDomain, policyDomain, diagnostic, createdUtc);
}
