using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Smtp;

/// <summary>What a generated DSN needs to say.</summary>
/// <param name="OriginalReversePath">
/// Who the DSN is addressed to. Never null - a caller must have already checked
/// <see cref="Domain.Entities.OutboundQueueItem.ShouldGenerateDsnOnFailure"/> before reaching here.
/// </param>
/// <param name="FailedRecipient">The address delivery was attempted to and failed for.</param>
/// <param name="OriginalMessageId">The message that could not be delivered, for the DSN's reference.</param>
/// <param name="IsDelayWarning">
/// True for a "delivery has been delayed" notice sent while retries continue; false for a final
/// failure notice sent once retries are exhausted or the failure was permanent.
/// </param>
/// <param name="ReplyCode">The remote's SMTP reply code, when there was a remote reply.</param>
/// <param name="EnhancedStatus">The RFC 3463 enhanced status, when the remote sent one.</param>
/// <param name="Diagnostic">Human-readable detail: the remote's reply text, or a local error.</param>
/// <param name="RemoteMta">The host the failing attempt was made against, when there was one.</param>
/// <param name="FirstQueuedUtc">When the original message was first queued for this recipient.</param>
/// <param name="NowUtc">When the DSN is being generated.</param>
public sealed record DsnRequest(
    EmailAddress OriginalReversePath,
    EmailAddress FailedRecipient,
    StoredMessageId OriginalMessageId,
    bool IsDelayWarning,
    int? ReplyCode,
    string? EnhancedStatus,
    string? Diagnostic,
    string? RemoteMta,
    DateTimeOffset FirstQueuedUtc,
    DateTimeOffset NowUtc);

/// <summary>A composed DSN, ready to be stored and queued like any other outbound message.</summary>
/// <param name="Content">The full message, headers and body, as bytes ready to write to the store.</param>
/// <param name="Recipient">Who it is addressed to - <see cref="DsnRequest.OriginalReversePath"/>.</param>
/// <param name="Subject">The subject line, for logging.</param>
public sealed record DsnMessage(byte[] Content, EmailAddress Recipient, string Subject);

/// <summary>
/// Composes a delivery status notification.
/// </summary>
/// <remarks>
/// <para>
/// <b>Plain text, not multipart/report.</b> RFC 3464 describes a three-part
/// <c>multipart/report</c> structure (human-readable part, machine-parsable
/// <c>message/delivery-status</c> part, and optionally the original message headers). Building
/// that correctly needs a MIME writer, and MIME support does not arrive until Milestone 9 - see
/// <c>docs/Standards.md</c>. A single human-readable <c>text/plain</c> body, honestly documented
/// as such, is what this milestone ships: every major client renders it as a legible bounce, and
/// no automated bounce-handling system that expects RFC 3464 is depended upon by this product
/// today. Full <c>multipart/report</c> is planned for Milestone 9, once MIME lands.
/// </para>
/// <para>
/// <b>One DSN per failed recipient, not batched per original message.</b> A message sent to
/// three recipients where two fail produces two separate DSNs rather than one bounce naming
/// both. This is simpler, and RFC 3464 permits either shape; batching would need to correlate
/// queue items back to their common origin at generation time, which is exactly the kind of
/// cross-item coordination the "one row per recipient" design in
/// <c>docs/Architecture.md</c> §8 exists to avoid needing.
/// </para>
/// <para>
/// Always sets <c>Auto-Submitted: auto-replied</c> (RFC 3834) and always uses the null reverse
/// path when the DSN is itself queued - see <c>docs/Architecture.md</c>'s bounce-loop-prevention
/// rule. Detecting an incoming <c>Auto-Submitted</c> header on the ORIGINAL message to suppress a
/// DSN needs header parsing, which is also gated on MIME/Milestone 9; only the null-reverse-path
/// half of bounce-loop prevention is enforced today - see
/// <see cref="Domain.Entities.OutboundQueueItem.ShouldGenerateDsnOnFailure"/>.
/// </para>
/// </remarks>
public interface IDsnComposer
{
    DsnMessage Compose(DsnRequest request);
}
