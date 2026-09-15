using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Smtp;

/// <summary>One attempt to deliver one message to one recipient, over one connection.</summary>
/// <param name="TargetHost">The MX (or implicit-MX fallback) hostname to connect to.</param>
/// <param name="Port">The port to connect to. 25 for direct-to-MX delivery.</param>
/// <param name="ReversePath">The envelope sender, or null for the null reverse path.</param>
/// <param name="RecipientAddress">The single envelope recipient for this attempt.</param>
/// <param name="MessageId">Identifies the stored message body to stream as <c>DATA</c>.</param>
/// <param name="RequireTls">
/// When true, the attempt must fail rather than send in plaintext if STARTTLS cannot be
/// negotiated or the peer's certificate is not trusted. See <c>docs/TLS.md</c>'s outbound
/// policy table.
/// </param>
public sealed record OutboundDeliveryRequest(
    string TargetHost,
    int Port,
    EmailAddress? ReversePath,
    EmailAddress RecipientAddress,
    StoredMessageId MessageId,
    bool RequireTls);

/// <summary>
/// Everything worth recording about one attempt, whether it succeeded or not.
/// </summary>
/// <remarks>
/// Deliberately shaped to map directly onto <see cref="Domain.Entities.DeliveryAttempt"/> - this
/// is the evidence a <see cref="Domain.Entities.DeliveryAttempt"/> row is built from.
/// </remarks>
public sealed record OutboundDeliveryResult(
    DeliveryOutcome Outcome,
    FailureClassification Classification,
    IpAddressValue? RemoteAddress,
    bool TlsActive,
    string? TlsProtocol,
    string? TlsCipher,
    string? PeerCertificateSubject,
    string? PeerCertificateIssuer,
    int? ReplyCode,
    string? EnhancedStatus,
    string? ReplyText,
    string? ErrorDetail);

/// <summary>
/// Speaks the client side of one SMTP conversation to a remote mail exchanger.
/// </summary>
/// <remarks>
/// <para>
/// The mirror image of the inbound listener: where <c>SmtpConnectionHandler</c> answers EHLO,
/// STARTTLS, MAIL FROM, RCPT TO and DATA, this issues them. Reused from the same domain layer
/// are <see cref="Domain.Smtp.SmtpReply"/>'s 2xx/4xx/5xx classification and
/// <see cref="Domain.Smtp.SmtpDotStuffing"/>'s outgoing dot-stuffing - the receiving half of
/// exactly the transformation this client performs on the way out.
/// </para>
/// <para>
/// One call delivers to exactly one recipient over one connection. A message with several
/// recipients on the same destination domain is not batched onto a single <c>RCPT TO</c>
/// sequence in this milestone: batching is a throughput optimisation, not a correctness
/// requirement, and each recipient already has its own queue item and its own retry schedule -
/// collapsing them back onto one connection would make one recipient's temporary failure block
/// another's successful delivery.
/// </para>
/// </remarks>
public interface IOutboundDeliveryClient
{
    Task<OutboundDeliveryResult> DeliverAsync(
        OutboundDeliveryRequest request,
        CancellationToken cancellationToken);
}
