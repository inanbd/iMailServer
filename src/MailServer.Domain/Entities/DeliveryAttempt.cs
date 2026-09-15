using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// The full record of one attempt to deliver one <see cref="OutboundQueueItem"/>.
/// </summary>
/// <remarks>
/// <para>
/// Written once, after the SMTP conversation with the remote MX has finished, never before —
/// the same store-then-commit discipline as message content: a row describing an attempt that
/// never happened is worse than no row, because it is evidence somebody will trust.
/// </para>
/// <para>
/// Everything here exists to answer one question months later: "why did Gmail reject this?"
/// The MX hostname, the remote address actually connected to, the negotiated TLS version and
/// cipher, the peer certificate's subject and issuer, and the full reply text are what turns
/// that question into an answer instead of a shrug.
/// </para>
/// </remarks>
public sealed class DeliveryAttempt
{
    private DeliveryAttempt(
        Guid id,
        QueueId queueItemId,
        int attemptNumber,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        string? mxHostname,
        IpAddressValue? remoteAddress,
        bool tlsActive,
        string? tlsProtocol,
        string? tlsCipher,
        string? peerCertificateSubject,
        string? peerCertificateIssuer,
        int? replyCode,
        string? enhancedStatus,
        string? replyText,
        DeliveryOutcome outcome,
        FailureClassification classification,
        string? errorDetail)
    {
        Id = id;
        QueueItemId = queueItemId;
        AttemptNumber = attemptNumber;
        StartedUtc = startedUtc;
        CompletedUtc = completedUtc;
        MxHostname = mxHostname;
        RemoteAddress = remoteAddress;
        TlsActive = tlsActive;
        TlsProtocol = tlsProtocol;
        TlsCipher = tlsCipher;
        PeerCertificateSubject = peerCertificateSubject;
        PeerCertificateIssuer = peerCertificateIssuer;
        ReplyCode = replyCode;
        EnhancedStatus = enhancedStatus;
        ReplyText = replyText;
        Outcome = outcome;
        Classification = classification;
        ErrorDetail = errorDetail;
    }

    public Guid Id { get; }

    /// <summary>The queue item this attempt belongs to.</summary>
    public QueueId QueueItemId { get; }

    /// <summary>1-based attempt number for this queue item.</summary>
    public int AttemptNumber { get; }

    public DateTimeOffset StartedUtc { get; }

    public DateTimeOffset CompletedUtc { get; }

    /// <summary>The MX (or fallback A/AAAA) hostname this attempt connected to, if it got that far.</summary>
    public string? MxHostname { get; }

    /// <summary>The resolved address actually connected to.</summary>
    public IpAddressValue? RemoteAddress { get; }

    /// <summary>Whether the session was encrypted.</summary>
    public bool TlsActive { get; }

    public string? TlsProtocol { get; }

    public string? TlsCipher { get; }

    /// <summary>
    /// The peer certificate's subject and issuer, recorded whether or not it was trusted.
    /// </summary>
    /// <remarks>
    /// Recorded even on an untrusted certificate. An operator diagnosing "why did this defer"
    /// needs to see what was actually presented, not just that something was wrong with it.
    /// </remarks>
    public string? PeerCertificateSubject { get; }

    public string? PeerCertificateIssuer { get; }

    /// <summary>The remote's SMTP reply code, when one was received.</summary>
    public int? ReplyCode { get; }

    /// <summary>The RFC 3463 enhanced status code, when the remote sent one.</summary>
    public string? EnhancedStatus { get; }

    /// <summary>The remote's reply text, verbatim.</summary>
    public string? ReplyText { get; }

    /// <summary>What this attempt concluded.</summary>
    public DeliveryOutcome Outcome { get; }

    /// <summary>Whether the failure, if any, is worth retrying.</summary>
    public FailureClassification Classification { get; }

    /// <summary>
    /// A local error, when the attempt failed before any reply arrived — a DNS failure, a
    /// connection refusal, a timeout, or a TLS handshake failure.
    /// </summary>
    public string? ErrorDetail { get; }

    public static DeliveryAttempt Create(
        QueueId queueItemId,
        int attemptNumber,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        string? mxHostname,
        IpAddressValue? remoteAddress,
        bool tlsActive,
        string? tlsProtocol,
        string? tlsCipher,
        string? peerCertificateSubject,
        string? peerCertificateIssuer,
        int? replyCode,
        string? enhancedStatus,
        string? replyText,
        DeliveryOutcome outcome,
        FailureClassification classification,
        string? errorDetail)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(attemptNumber, 1);

        return new DeliveryAttempt(
            Guid.NewGuid(), queueItemId, attemptNumber, startedUtc, completedUtc, mxHostname,
            remoteAddress, tlsActive, tlsProtocol, tlsCipher, peerCertificateSubject,
            peerCertificateIssuer, replyCode, enhancedStatus, replyText, outcome, classification,
            errorDetail);
    }

    public static DeliveryAttempt Rehydrate(
        Guid id,
        QueueId queueItemId,
        int attemptNumber,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        string? mxHostname,
        IpAddressValue? remoteAddress,
        bool tlsActive,
        string? tlsProtocol,
        string? tlsCipher,
        string? peerCertificateSubject,
        string? peerCertificateIssuer,
        int? replyCode,
        string? enhancedStatus,
        string? replyText,
        DeliveryOutcome outcome,
        FailureClassification classification,
        string? errorDetail) =>
        new(
            id, queueItemId, attemptNumber, startedUtc, completedUtc, mxHostname, remoteAddress,
            tlsActive, tlsProtocol, tlsCipher, peerCertificateSubject, peerCertificateIssuer,
            replyCode, enhancedStatus, replyText, outcome, classification, errorDetail);
}
