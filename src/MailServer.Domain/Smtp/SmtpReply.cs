namespace MailServer.Domain.Smtp;

/// <summary>
/// An SMTP reply: a three-digit code, an RFC 3463 enhanced status code, and text.
/// </summary>
/// <remarks>
/// <para>
/// <b>Enhanced status codes are not decoration.</b> The three-digit code says whether something
/// failed; the enhanced code says <i>what</i>. A remote postmaster diagnosing why their mail
/// bounces gets "5.7.1 relaying denied" instead of "554 error", and automated bounce processing
/// can tell a full mailbox (5.2.2, stop retrying) from a temporary failure (4.2.2, retry).
/// </para>
/// <para>
/// A type rather than a formatted string, so a reply cannot be assembled ad hoc at a call site
/// with a code that does not match its text — and so the multi-line continuation format, which
/// is easy to get subtly wrong, is written once.
/// </para>
/// </remarks>
/// <param name="Code">The three-digit reply code.</param>
/// <param name="EnhancedStatus">The RFC 3463 status, e.g. <c>5.7.1</c>. Null where none applies.</param>
/// <param name="Text">The first line of human-readable text. Control characters are stripped when formatted.</param>
public sealed record SmtpReply(int Code, string? EnhancedStatus, string Text)
{
    /// <summary>True for 2xx.</summary>
    public bool IsSuccess => Code is >= 200 and < 300;

    /// <summary>True for 3xx — the server wants more input.</summary>
    public bool IsIntermediate => Code is >= 300 and < 400;

    /// <summary>
    /// True for 4xx. The sender should retry later.
    /// </summary>
    /// <remarks>
    /// The distinction from <see cref="IsPermanentFailure"/> decides whether a message is
    /// retried for days or bounced immediately, so choosing the wrong class either loses mail
    /// or wedges a queue.
    /// </remarks>
    public bool IsTransientFailure => Code is >= 400 and < 500;

    /// <summary>True for 5xx. The sender should give up and bounce.</summary>
    public bool IsPermanentFailure => Code >= 500;

    /// <summary>
    /// Lines that follow <see cref="Text"/> in a multi-line reply.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <b>only</b> way a reply becomes multi-line. EHLO needs it — one line per advertised
    /// extension — and nothing else does.
    /// </para>
    /// <para>
    /// Keeping it a separate list rather than letting <see cref="Text"/> carry embedded line
    /// breaks is what makes response splitting impossible by construction: reply text often
    /// quotes something the peer sent, and no amount of cleverness in that text can reach this
    /// property.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> ContinuationLines { get; init; } = [];

    /// <summary>
    /// Renders the reply in wire format, with CRLF line endings.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Control characters in the text are stripped, not escaped.</b> Some reply text
    /// includes values that originated with the peer — an unrecognised command, an address that
    /// failed to parse — and a CR or LF in one of those would let the peer inject an extra
    /// reply line into the stream. That is response splitting, and on a protocol where the
    /// client acts on reply codes it is a real attack rather than a tidiness problem.
    /// </para>
    /// <para>
    /// Multi-line replies use <c>code-line</c> for every line but the last, which uses
    /// <c>code line</c>. Getting the final space wrong makes a client wait forever for a
    /// continuation that never comes.
    /// </para>
    /// </remarks>
    public string Format()
    {
        System.Text.StringBuilder builder = new();

        for (int i = 0; i <= ContinuationLines.Count; i++)
        {
            bool isLast = i == ContinuationLines.Count;

            builder.Append(Code.ToString(System.Globalization.CultureInfo.InvariantCulture));
            builder.Append(isLast ? ' ' : '-');

            if (EnhancedStatus is not null)
            {
                builder.Append(EnhancedStatus);
                builder.Append(' ');
            }

            builder.Append(Sanitize(i == 0 ? Text : ContinuationLines[i - 1]));
            builder.Append("\r\n");
        }

        return builder.ToString();
    }

    /// <summary>
    /// Reduces one line of reply text to printable characters.
    /// </summary>
    /// <remarks>
    /// Every control character goes, LF and CR included. Line structure comes from
    /// <see cref="ContinuationLines"/> and from nowhere else, so text that originated with the
    /// peer cannot add a line to the reply however it is escaped.
    /// </remarks>
    private static string Sanitize(string text)
    {
        System.Text.StringBuilder builder = new(text.Length);

        foreach (char c in text)
        {
            if (!char.IsControl(c))
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }

    public override string ToString() => $"{Code} {EnhancedStatus} {Text}".Trim();
}

/// <summary>
/// The replies this server sends.
/// </summary>
/// <remarks>
/// Every reply in one place, so a reviewer can read the server's entire externally-visible
/// vocabulary without tracing call sites — and so a code and its enhanced status cannot drift
/// apart at one of them.
/// </remarks>
public static class SmtpReplies
{
    public static SmtpReply Ok(string text = "OK") => new(250, "2.0.0", text);

    public static SmtpReply Greeting(string hostname, string product) =>
        new(220, null, $"{hostname} ESMTP {product} ready");

    public static SmtpReply Closing(string hostname) =>
        new(221, "2.0.0", $"{hostname} closing connection");

    /// <summary>Sent after EHLO, listing the extensions currently permitted.</summary>
    /// <remarks>
    /// The capability list is assembled by the session, not here: what is advertised depends on
    /// the listener role and on whether TLS is already active, and advertising an extension
    /// that is not honoured is worse than not advertising it — peers make delivery decisions
    /// from this list.
    /// </remarks>
    public static SmtpReply EhloResponse(string hostname, IEnumerable<string> capabilities) =>
        new(250, null, $"{hostname} greets you")
        {
            ContinuationLines = [.. capabilities],
        };

    public static SmtpReply StartMailInput() =>
        new(354, null, "Start mail input; end with <CRLF>.<CRLF>");

    public static SmtpReply ReadyForTls() => new(220, "2.0.0", "Ready to start TLS");

    public static SmtpReply MessageAccepted(string messageId) =>
        new(250, "2.0.0", $"Message accepted for delivery: {messageId}");

    // ---- Refusals ---------------------------------------------------------------------------

    /// <summary>
    /// 554 5.7.1 — the relay refusal.
    /// </summary>
    /// <remarks>
    /// The most consequential reply this server sends, and the one most often seen by a
    /// legitimate operator who has misconfigured something. The text names what to check rather
    /// than merely refusing.
    /// </remarks>
    public static SmtpReply RelayDenied(string reason) =>
        new(554, "5.7.1", $"Relay access denied. {reason}");

    /// <summary>
    /// 450 4.3.2 — the recipient's domain is configured here but not yet in service.
    /// </summary>
    /// <remarks>
    /// Transient on purpose. A domain is created Pending and enabled once its DNS and signing
    /// are in place, and mail that arrives in between — from a sender that saw the new MX early
    /// — is worth retrying rather than bouncing. A permanent refusal here would lose mail during
    /// every cut-over. It does not claim the domain is not hosted here, because it is.
    /// </remarks>
    public static SmtpReply DomainNotYetInService(string address) =>
        new(450, "4.3.2", $"<{address}>: this domain is not accepting mail yet; try again later");

    public static SmtpReply MailboxNotFound(string address) =>
        new(550, "5.1.1", $"<{address}>: recipient address rejected: no such user here");

    public static SmtpReply MailboxDisabled(string address) =>
        new(550, "5.2.1", $"<{address}>: recipient address rejected: mailbox is disabled");

    /// <summary>
    /// 452 4.2.2 — over quota.
    /// </summary>
    /// <remarks>
    /// <b>Transient, not permanent.</b> A full mailbox is a condition the recipient can fix,
    /// and telling the sending server to retry keeps the message in their queue where it can
    /// still be delivered. Bouncing it permanently destroys mail that a few minutes of tidying
    /// would have let through.
    /// </remarks>
    public static SmtpReply MailboxFull(string address) =>
        new(452, "4.2.2", $"<{address}>: mailbox is full; try again later");

    public static SmtpReply MessageTooLarge(long limitBytes) =>
        new(552, "5.3.4", $"Message exceeds the {limitBytes}-byte size limit for this recipient");

    public static SmtpReply TooManyRecipients(int limit) =>
        new(452, "4.5.3", $"Too many recipients; at most {limit} per message");

    /// <summary>
    /// 550 5.7.1 — the authenticated session may not use that sender.
    /// </summary>
    /// <remarks>
    /// Permanent, because retrying with the same credentials and the same address will fail
    /// identically. The text names what to change, because the usual cause is a client
    /// configured with one address and authenticating with another — an ordinary misconfiguration
    /// that an unexplained refusal turns into a support call.
    /// </remarks>
    public static SmtpReply SenderNotPermitted(string reason) =>
        new(550, "5.7.1", $"Sender address rejected: {reason}");

    /// <summary>
    /// 451 4.7.1 — the mailbox has submitted too much, too recently.
    /// </summary>
    /// <remarks>
    /// <b>Transient.</b> The sender is over a rate limit, not wrong: the message is perfectly
    /// deliverable an hour from now, and a 5xx would destroy legitimate mail to enforce a
    /// throttle. A client that retries later succeeds, which is exactly the behaviour wanted.
    /// </remarks>
    public static SmtpReply SubmissionRateExceeded(int limit, TimeSpan window) =>
        new(451, "4.7.1", $"Submission rate limit reached ({limit} messages per {window.TotalHours:0.#} hour(s)); try again later");

    /// <summary>
    /// 451 4.4.3 — a DNS failure while evaluating SPF for the sender's domain.
    /// </summary>
    /// <remarks>
    /// <b>Transient, by RFC 7208 §8.6's own recommendation.</b> A <c>temperror</c> means
    /// evaluation could not complete, not that it completed and failed — accepting the message
    /// anyway would skip the check entirely, and rejecting it permanently would punish a sender
    /// for this server's resolver having a bad moment. A retry a few minutes later, when the
    /// lookup most likely succeeds, is the only response that treats both sides fairly.
    /// </remarks>
    public static SmtpReply SpfTemporaryError() =>
        new(451, "4.4.3", "Temporary error evaluating SPF for the sender's domain; please try again later");

    /// <summary>
    /// 550 5.7.1 — the message fails DMARC and its policy requests rejection.
    /// </summary>
    /// <remarks>
    /// Sent after the message is fully received: DMARC alignment can only be computed once the
    /// <c>From:</c> header and every signature are in hand, and RFC 5321 permits a permanent
    /// failure on the final "." of DATA exactly as it does mid-transaction — nothing has been
    /// "accepted" until this reply is sent, whatever this server did internally to get here.
    /// </remarks>
    public static SmtpReply DmarcRejected(string diagnostic) =>
        new(550, "5.7.1", $"Message rejected: {diagnostic}");

    public static SmtpReply SyntaxError(string detail) => new(501, "5.5.4", detail);

    public static SmtpReply CommandNotRecognised(string command) =>
        new(500, "5.5.1", $"Command not recognised: {command}");

    public static SmtpReply BadSequence(string detail) => new(503, "5.5.1", detail);

    public static SmtpReply CommandNotImplemented(string command) =>
        new(502, "5.5.1", $"Command not implemented: {command}");

    /// <summary>
    /// 530 5.7.0 — authentication required.
    /// </summary>
    /// <remarks>
    /// Sent on a submission listener before AUTH. Never sent on port 25, where the answer to
    /// an unauthenticated relay attempt is <see cref="RelayDenied"/> — offering authentication
    /// as the remedy there would be inviting something the listener does not support.
    /// </remarks>
    public static SmtpReply AuthenticationRequired() =>
        new(530, "5.7.0", "Authentication required");

    /// <summary>530 5.7.0 — STARTTLS required before this command.</summary>
    public static SmtpReply TlsRequired() =>
        new(530, "5.7.0", "Must issue a STARTTLS command first");

    /// <summary>
    /// 334 — the server's SASL challenge.
    /// </summary>
    /// <remarks>
    /// The challenge is base64 and is server-generated, so it is not sanitised away by
    /// <see cref="SmtpReply.Format"/> the way peer-supplied text is. An empty challenge is legal
    /// and common — PLAIN uses one.
    /// </remarks>
    public static SmtpReply AuthenticationChallenge(string challenge) =>
        new(334, null, challenge);

    /// <summary>235 2.7.0 — authentication accepted.</summary>
    public static SmtpReply AuthenticationSucceeded() =>
        new(235, "2.7.0", "Authentication successful");

    /// <summary>501 5.7.0 — the client abandoned the exchange.</summary>
    /// <remarks>
    /// RFC 4954 §4. Distinct from a failure, and deliberately so: a client that changed its mind
    /// has not guessed a password wrongly, and counting it as such would walk a hesitant client
    /// into a lockout it never earned.
    /// </remarks>
    public static SmtpReply AuthenticationCancelled() =>
        new(501, "5.7.0", "Authentication exchange cancelled");

    /// <summary>
    /// 504 5.5.4 — the requested mechanism is not one this server offers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The name is never echoed.</b> That looks over-cautious until you notice what a client
    /// can put there: <c>AUTH &lt;base64&gt;</c> with no mechanism is a malformed exchange but an
    /// easy one to produce, and the credential then arrives in the mechanism position. Quoting
    /// it back puts it in the client's logs, any intermediary's logs and a packet capture.
    /// </para>
    /// <para>
    /// The obvious mitigation — echo it only when it looks like a mechanism name — does not
    /// work. RFC 4422 §3.1 allows 1–20 characters of <c>A–Z 0–9 - _</c>, and a great many real
    /// passwords fit that exactly. There is no test that separates "a mechanism name a client
    /// mistyped" from "a password in the wrong field", so the name goes to the server's own log
    /// at debug level, where an operator can see it and the peer cannot.
    /// </para>
    /// </remarks>
    public static SmtpReply UnsupportedAuthenticationMechanism() =>
        new(504, "5.5.4", "The requested authentication mechanism is not supported");

    /// <summary>
    /// 421 4.7.0 — too many authentication attempts on one connection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Transient rather than permanent. A legitimate client whose user mistyped a password three
    /// times should reconnect and try again; a 5xx would tell it to stop for good.
    /// </para>
    /// <para>
    /// The connection closes after this. Bounding attempts per connection sits underneath the
    /// per-mailbox lockout: lockout protects one account across every connection, and this stops
    /// one connection being used to walk a dictionary across many accounts.
    /// </para>
    /// </remarks>
    public static SmtpReply TooManyAuthenticationAttempts() =>
        new(421, "4.7.0", "Too many authentication attempts; closing connection");

    public static SmtpReply AuthenticationFailed() =>
        new(535, "5.7.8", "Authentication credentials invalid");

    public static SmtpReply LineTooLong(int limitBytes) =>
        new(500, "5.5.2", $"Line exceeds the {limitBytes}-byte limit");

    public static SmtpReply Timeout() =>
        new(421, "4.4.2", "Timeout waiting for command; closing connection");

    public static SmtpReply TooManyConnections() =>
        new(421, "4.3.2", "Too many concurrent connections; try again later");

    /// <summary>
    /// 421 4.7.0 — this address has sent as much as it may for now, and the channel is closing.
    /// </summary>
    /// <remarks>
    /// Names neither the allowance nor its size. A sender that learns the rate it is held to
    /// learns how to pace itself just under it; a legitimate exchanger needs only to know the
    /// refusal is temporary, and queues the message and retries.
    /// </remarks>
    public static SmtpReply NotAcceptingMoreMail() =>
        new(421, "4.7.0", "Not accepting more mail from this address for now; try again later");

    public static SmtpReply ShuttingDown(string hostname) =>
        new(421, "4.3.2", $"{hostname} is shutting down; try again later");

    /// <summary>
    /// 451 4.3.0 — an unexpected local failure.
    /// </summary>
    /// <remarks>
    /// Transient by choice. When this server does not know what went wrong, telling the sender
    /// to retry risks a duplicate; telling them to give up risks losing the message. Mail is
    /// worth more than tidiness, so the ambiguous case retries.
    /// </remarks>
    public static SmtpReply LocalError(string correlationId) =>
        new(451, "4.3.0", $"Local error processing message; reference {correlationId}");
}
