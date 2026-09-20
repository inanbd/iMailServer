using System.Globalization;
using System.Text;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>
/// Composes the message a delivery test sends.
/// </summary>
/// <remarks>
/// <para>
/// <b>A real message, not a probe.</b> The point of the test is that a receiver applies its
/// ordinary rules to it — SPF against the envelope sender, DKIM against the signature, DMARC
/// against the alignment of both with <c>From</c> — and then says what it thinks. Anything
/// short of a well-formed message would be judged as malformed rather than as this server's
/// configuration.
/// </para>
/// <para>
/// <b>It says what it is, in the subject and in the body.</b> Whoever receives it is a person
/// the operator nominated, quite possibly on a mailbox they do not control, and a message with
/// no explanation is indistinguishable from a probe by a stranger.
/// </para>
/// </remarks>
public static class DeliveryTestMessage
{
    /// <summary>The subject every test message carries.</summary>
    public const string Subject = "Mail delivery test";

    /// <summary>
    /// Composes the message.
    /// </summary>
    /// <param name="sender">
    /// The <c>From</c> address, which is also the envelope sender. The operator's choice: it
    /// decides which domain's SPF, DKIM and DMARC the receiver is about to judge, so defaulting
    /// it would test a domain nobody asked about.
    /// </param>
    /// <param name="recipient">Where it goes.</param>
    /// <param name="messageId">
    /// The <c>Message-ID</c>, already in angle brackets. Passed in rather than generated here so
    /// that this stays a pure function and the caller can report the same value it sent.
    /// </param>
    /// <param name="now">The instant for <c>Date</c>.</param>
    public static string Compose(
        EmailAddress sender,
        EmailAddress recipient,
        string messageId,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(sender);
        ArgumentNullException.ThrowIfNull(recipient);
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);

        StringBuilder message = new();

        message.Append("From: <").Append(sender.Value).Append(">\r\n");
        message.Append("To: <").Append(recipient.Value).Append(">\r\n");
        message.Append("Subject: ").Append(Subject).Append("\r\n");

        // RFC 5322 §3.3's date-time, in the fixed form every mail system writes: a
        // day-of-week name, a two-digit day, an English month abbreviation and a numeric
        // offset. Invariant, because a host with a Turkish or French locale would otherwise
        // produce month names no receiver parses.
        message.Append("Date: ")
            .Append(now.UtcDateTime.ToString("ddd, dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture))
            .Append(" +0000\r\n");

        message.Append("Message-ID: ").Append(messageId).Append("\r\n");

        // RFC 3834's field, with the value for something a machine produced that is not a reply.
        // Without it, a receiver running an out-of-office responder answers this message, and the
        // answer arrives at whatever address the test was sent from - which may be a mailbox
        // nobody reads, or a loop.
        message.Append("Auto-Submitted: auto-generated\r\n");

        message.Append("Content-Type: text/plain; charset=utf-8\r\n");
        message.Append("MIME-Version: 1.0\r\n");
        message.Append("\r\n");

        message.Append(
            "This is an automated test message, sent to check that mail from ")
            .Append(sender.Domain.Value)
            .Append(" is accepted.\r\n\r\n");

        message.Append(
            "No reply is needed. If this message was not expected, the administrator of ")
            .Append(sender.Domain.Value)
            .Append(" sent it by asking their mail server to test delivery to this address.\r\n\r\n");

        // The receiving system's own authentication header is what makes this message useful,
        // and it is deliberately not named here. NoUntrustedAuthenticationHeaderTrustTests scans
        // production source for that field name outside comments, because the bypass it guards
        // against - computing this server's own verdicts from a header read off the wire - is
        // hard to spot any other way. A string in an outgoing body cannot cause that bypass, but
        // allowlisting this file would loosen the guard on a file that could later grow a reader,
        // and a sentence phrased around the name costs nothing. docs/Deliverability.md names it.
        message.Append(
            "The useful part is the headers the receiving system added on the way in: they " +
            "record what it made of this message's SPF, DKIM and DMARC, which is the receiver's " +
            "verdict rather than the sender's opinion of it.\r\n");

        return message.ToString();
    }
}

/// <summary>One attempt against one exchanger.</summary>
/// <param name="Host">The exchanger tried.</param>
/// <param name="Outcome">What that attempt came to.</param>
/// <param name="Transcript">Its conversation.</param>
/// <param name="Diagnostic">Why it ended as it did, when the transcript does not already say.</param>
public sealed record DeliveryTestAttempt(
    MxHost Host,
    DeliveryOutcome Outcome,
    DeliveryTranscript Transcript,
    string? Diagnostic);

/// <summary>
/// What one delivery test established.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no queue latency here, and that is deliberate.</b> The test connects and sends,
/// rather than enqueuing and waiting: the whole value is seeing the conversation now, and a
/// queued test would answer "submitted" and leave the operator watching a queue.
/// </para>
/// <para>
/// <b>It tries the exchangers in the order the queue would, and stops at the first that
/// accepts.</b> Reporting only the primary would tell an operator whose primary is briefly down
/// that their mail cannot be delivered, when the queue would have delivered it to the secondary
/// without comment. Every attempt keeps its own transcript, because the conversation worth
/// reading is usually the one that failed.
/// </para>
/// <para>
/// The DKIM selector that actually signed is in each transcript's body step and is not repeated
/// as a field here: only the signer knows which key it used, and a second source for one fact
/// would disagree the moment a rotation landed between the two reads.
/// </para>
/// </remarks>
/// <param name="Outcome">
/// What the test came to overall, which is the last attempt's outcome. Classified exactly as a
/// queued delivery would be, because it is one — the same client, the same rules.
/// </param>
/// <param name="Sender">The address it was sent from.</param>
/// <param name="Recipient">The address it was sent to.</param>
/// <param name="MessageId">The <c>Message-ID</c> as sent, for finding it in the receiver's logs.</param>
/// <param name="Candidates">
/// Every exchanger the recipient's domain published, in the order this server would try them.
/// Reported in full even when the first one accepted: an operator whose mail is being refused
/// wants to know a secondary exists.
/// </param>
/// <param name="Attempts">
/// One per exchanger tried, in order. Empty when no exchanger was reachable to try — which is
/// what a domain with no MX and no address record looks like.
/// </param>
/// <param name="Diagnostic">
/// Why the test ended as it did, when no attempt explains it: a failed MX lookup, most often.
/// Null on a clean delivery.
/// </param>
public sealed record DeliveryTestOutcome(
    DeliveryOutcome Outcome,
    EmailAddress Sender,
    EmailAddress Recipient,
    string MessageId,
    IReadOnlyList<MxHost> Candidates,
    IReadOnlyList<DeliveryTestAttempt> Attempts,
    string? Diagnostic)
{
    /// <summary>
    /// The attempt that settled the outcome, or null when none was made.
    /// </summary>
    /// <remarks>
    /// The last one, because the loop stops at the first exchanger that accepts: so it is either
    /// the delivery or the final refusal, and never a failure that a later attempt recovered
    /// from.
    /// </remarks>
    public DeliveryTestAttempt? Decisive => Attempts.Count == 0 ? null : Attempts[^1];

    /// <summary>How long the decisive conversation took, or null when there was none.</summary>
    public TimeSpan? Latency => Decisive?.Transcript.Duration;
}
