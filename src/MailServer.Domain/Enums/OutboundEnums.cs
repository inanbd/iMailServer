namespace MailServer.Domain.Enums;

/// <summary>Where one outbound queue item is in its lifecycle.</summary>
/// <remarks>
/// Explicit states rather than booleans, for the same reason <see cref="SmtpSessionState"/> is:
/// "due for retry, being worked on, leased by a crashed worker" is one question about position
/// in a lifecycle, and four independent flags would make a state nobody intended reachable.
/// </remarks>
public enum QueueStatus
{
    /// <summary>Waiting for its next attempt. The only status a worker may claim.</summary>
    Pending = 0,

    /// <summary>Claimed by a worker and leased. Reclaimed automatically once the lease expires.</summary>
    Processing = 1,

    /// <summary>
    /// A transient failure has scheduled a later attempt.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="Pending"/> only for reporting; both are claimable once
    /// <c>NextAttemptUtc</c> has passed. Kept separate so a queue grid can show "never attempted"
    /// apart from "failed once and waiting to retry" without inferring it from attempt count.
    /// </remarks>
    Deferred = 2,

    /// <summary>Delivered to the destination MX. Terminal.</summary>
    Delivered = 3,

    /// <summary>Permanently failed and a DSN has been generated (or bounce-loop rules suppressed one). Terminal.</summary>
    Bounced = 4,

    /// <summary>Withdrawn before delivery, e.g. by an administrator. Terminal.</summary>
    Cancelled = 5,
}

/// <summary>What happened when one delivery attempt ran to completion.</summary>
public enum DeliveryOutcome
{
    /// <summary>The remote MX accepted the message.</summary>
    Delivered = 0,

    /// <summary>A transient failure. The item is rescheduled per <see cref="Policies.RetryBackoffPolicy"/>.</summary>
    Deferred = 1,

    /// <summary>A permanent failure. Retried never; a DSN is generated instead.</summary>
    Bounced = 2,

    /// <summary>
    /// TLS was required for this destination and could not be established.
    /// </summary>
    /// <remarks>
    /// Kept apart from <see cref="Deferred"/> and <see cref="Bounced"/> because it is neither: it
    /// is not the remote's answer at all, and downgrading to plaintext to get an answer is
    /// exactly the "security policy that gives up when inconvenient" <c>docs/TLS.md</c> forbids.
    /// It is treated as transient (retried, in case the next MX host in rotation or a later
    /// attempt succeeds) rather than an immediate bounce, since a misconfigured single host is
    /// common and self-corrects on the receiving end far more often than a mailbox does.
    /// </remarks>
    TlsRequiredFailure = 3,

    /// <summary>The attempt was abandoned, e.g. by shutdown, without a remote answer.</summary>
    Cancelled = 4,
}

/// <summary>
/// Whether a failure is worth retrying.
/// </summary>
/// <remarks>
/// The single most consequential classification in the outbound path (see
/// <c>docs/Architecture.md</c> §29 item 13): confusing the two either bounces mail that would
/// have gone through on retry, or retries mail that will never succeed until the queue's
/// maximum lifetime silently absorbs the mistake.
/// </remarks>
public enum FailureClassification
{
    /// <summary>Not a failure; the attempt succeeded.</summary>
    None = 0,

    /// <summary>Worth retrying: a 4xx reply, a DNS timeout/SERVFAIL, a connection failure.</summary>
    Temporary = 1,

    /// <summary>Never worth retrying: a 5xx reply, NXDOMAIN, or a null MX.</summary>
    Permanent = 2,
}
