using System.Globalization;
using System.Text;
using MailServer.Domain.Smtp;

namespace MailServer.Domain.Deliverability;

/// <summary>Where in one SMTP conversation a step happened.</summary>
/// <remarks>
/// Named for the protocol rather than for the code that issues them, because the whole point of
/// a transcript is that an operator can line it up against RFC 5321 §4.1 and against whatever
/// their receiver's support desk tells them.
/// </remarks>
public enum DeliveryStage
{
    /// <summary>The TCP connection, before the remote has said anything.</summary>
    Connect = 0,

    /// <summary>The remote's opening greeting — §4.2's 220.</summary>
    Banner = 1,

    /// <summary><c>EHLO</c>, or the <c>HELO</c> a remote that refused it gets instead.</summary>
    Ehlo = 2,

    /// <summary><c>STARTTLS</c> — RFC 3207 §2.</summary>
    StartTls = 3,

    /// <summary>The TLS handshake itself, which sends no SMTP command and earns no reply.</summary>
    Handshake = 4,

    /// <summary>
    /// The second <c>EHLO</c>, which RFC 3207 §4.2 requires: capabilities learned before the
    /// handshake must be discarded and re-learned over the encrypted channel.
    /// </summary>
    EhloAfterTls = 5,

    /// <summary><c>MAIL FROM</c>.</summary>
    MailFrom = 6,

    /// <summary><c>RCPT TO</c>.</summary>
    RcptTo = 7,

    /// <summary><c>DATA</c>, whose success is §4.2.1's intermediate 354 rather than a 2xx.</summary>
    Data = 8,

    /// <summary>
    /// The message octets. Recorded as a count and never as content — see
    /// <see cref="DeliveryTranscript"/>.
    /// </summary>
    Body = 9,

    /// <summary>The reply to the terminating dot, which is the one that decides delivery.</summary>
    EndOfData = 10,

    /// <summary><c>QUIT</c>.</summary>
    Quit = 11,
}

/// <summary>One thing that happened in an SMTP conversation.</summary>
/// <param name="Stage">Where in the conversation.</param>
/// <param name="Sent">
/// The command line as issued, or null for a stage that sends no command. <b>Never message
/// content</b>; see <see cref="DeliveryTranscript"/>.
/// </param>
/// <param name="Reply">
/// What the remote answered, or null for a stage that earns no reply. Carries the code, the
/// enhanced status, the text and — for <c>EHLO</c> — the capability lines, because RFC 5321
/// §4.1.1.1 puts them in the reply's continuation lines and nowhere else.
/// </param>
/// <param name="Detail">
/// Anything the protocol does not carry: the negotiated TLS version, a certificate's subject, a
/// body's length. Free text, because these differ per stage and inventing a field per stage
/// would give every other stage a column of nulls.
/// </param>
/// <param name="At">When it happened, for the per-step delays.</param>
public sealed record DeliveryStep(
    DeliveryStage Stage,
    string? Sent,
    SmtpReply? Reply,
    string? Detail,
    DateTimeOffset At);

/// <summary>One step with how long the conversation had been running when it happened.</summary>
/// <param name="Step">The step.</param>
/// <param name="Elapsed">
/// Since the first step. Elapsed rather than a delay from the previous step, because the thing
/// an operator is looking for is which single stage took the time — and a greylisting receiver
/// that pauses thirty seconds before its <c>RCPT TO</c> reply shows up as a jump in this column.
/// </param>
public sealed record DeliveryStepTiming(DeliveryStep Step, TimeSpan Elapsed);

/// <summary>
/// The whole SMTP conversation of one delivery, as it happened.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it is for.</b> <c>docs/Deliverability.md</c>: sending a real message and reading the
/// receiver's own verdict "is the fastest honest answer to 'is my setup correct?' — it is the
/// receiver's own verdict rather than our opinion of it." A score computed from DNS says what
/// should happen; this says what did.
/// </para>
/// <para>
/// <b>Recorded on the real delivery path, not a copy of it.</b> The same
/// <c>OutboundSmtpClient</c> that the queue uses fills this in, because a second client written
/// to be observable would be a second implementation of MX selection, STARTTLS policy, DKIM
/// signing and dot-stuffing — and a test of it would prove nothing about the one that carries
/// the mail.
/// </para>
/// <para>
/// <b>The message body is never in here, and that is a rule rather than an omission.</b> A
/// transcript is shown to whoever can run a delivery test and is the obvious thing to paste into
/// a support ticket. Message content is guarded by a different permission
/// (<c>ReadMessageContent</c>) than the one that runs this (<c>ViewServerState</c>), so a
/// transcript carrying body octets would be a way to read mail with the weaker of the two. The
/// <see cref="DeliveryStage.Body"/> step records how many octets went out and nothing else.
/// </para>
/// <para>
/// <b>Nor is anything a credential.</b> This is MX delivery, which does not authenticate — there
/// is no <c>AUTH</c> in the conversation to record. Were one ever added, its exchange would need
/// excluding here for the reason <c>ImapConnectionHandler</c> gives about its own authentication
/// loop: a line that is a password must not reach anything that formats it for display.
/// </para>
/// <para>Not thread-safe. One transcript belongs to one connection, like the session it records.</para>
/// </remarks>
public sealed class DeliveryTranscript
{
    private readonly List<DeliveryStep> _steps = [];

    /// <summary>Every step, in the order it happened.</summary>
    public IReadOnlyList<DeliveryStep> Steps => _steps;

    /// <summary>Records one step.</summary>
    /// <remarks>
    /// Takes the instant rather than reading a clock of its own, so that every step in one
    /// conversation is timed against the same clock the caller is using. Two clocks would make
    /// the elapsed column disagree with the delivery latency beside it.
    /// </remarks>
    /// <param name="stage">Where in the conversation.</param>
    /// <param name="at">When.</param>
    /// <param name="sent">The command issued, or null. Never message content.</param>
    /// <param name="reply">What the remote answered, or null.</param>
    /// <param name="detail">Anything the protocol does not carry.</param>
    public void Record(
        DeliveryStage stage,
        DateTimeOffset at,
        string? sent = null,
        SmtpReply? reply = null,
        string? detail = null)
    {
        _steps.Add(new DeliveryStep(stage, sent, reply, detail, at));
    }

    /// <summary>Every step with how long the conversation had been running.</summary>
    public IReadOnlyList<DeliveryStepTiming> Timed =>
        _steps.Count == 0
            ? []
            : [.. _steps.Select(s => new DeliveryStepTiming(s, s.At - _steps[0].At))];

    /// <summary>How long the whole conversation took, or null when nothing was recorded.</summary>
    public TimeSpan? Duration =>
        _steps.Count == 0 ? null : _steps[^1].At - _steps[0].At;

    /// <summary>The remote's opening greeting, or null when it never sent one.</summary>
    public string? Banner => Reply(DeliveryStage.Banner)?.Text;

    /// <summary>
    /// The capabilities the remote advertised, from the last <c>EHLO</c> of the conversation.
    /// </summary>
    /// <remarks>
    /// <b>The last, not the first.</b> RFC 3207 §4.2: after a successful handshake the client
    /// "MUST discard any knowledge obtained from the server" before it, so the pre-TLS list is
    /// not what this conversation ran on — and reporting it would show an operator capabilities
    /// their mail was never offered. That is also the list a network attacker can edit.
    /// </remarks>
    public IReadOnlyList<string> Capabilities =>
        Reply(DeliveryStage.EhloAfterTls)?.ContinuationLines ??
        Reply(DeliveryStage.Ehlo)?.ContinuationLines ??
        [];

    /// <summary>
    /// The reply that decided the delivery, or null when the conversation never got that far.
    /// </summary>
    /// <remarks>
    /// The one after the terminating dot. RFC 5321 §4.1.1.4 makes it the receiver's acceptance
    /// of responsibility for the message, so it is the only reply in the conversation that means
    /// the mail was delivered.
    /// </remarks>
    public SmtpReply? FinalReply => Reply(DeliveryStage.EndOfData);

    /// <summary>
    /// The stage the conversation reached, or null when nothing was recorded.
    /// </summary>
    /// <remarks>
    /// Where it stopped is the diagnosis. A conversation that ended at
    /// <see cref="DeliveryStage.RcptTo"/> was refused the recipient; one that ended at
    /// <see cref="DeliveryStage.MailFrom"/> was refused the sender, which is usually SPF or a
    /// blocklist; one that ended at <see cref="DeliveryStage.Banner"/> never got to speak.
    /// </remarks>
    public DeliveryStage? LastStage => _steps.Count == 0 ? null : _steps[^1].Stage;

    private SmtpReply? Reply(DeliveryStage stage) =>
        _steps.LastOrDefault(s => s.Stage == stage && s.Reply is not null)?.Reply;

    /// <summary>
    /// Renders the conversation the way a mail log reads, for pasting into a support ticket.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Sent lines are prefixed <c>&gt;</c> and received lines <c>&lt;</c>, which is the
    /// convention every SMTP log an operator has ever read uses. Stages that send nothing and
    /// receive nothing are rendered as a bare note, so the handshake and the body appear in the
    /// timeline rather than as gaps in it.
    /// </para>
    /// <para>
    /// The elapsed column is milliseconds, invariant, because this text is compared against
    /// somebody else's log and a decimal comma would make two operators' transcripts of the same
    /// conversation look different.
    /// </para>
    /// </remarks>
    public string Render()
    {
        StringBuilder text = new();

        foreach (DeliveryStepTiming timing in Timed)
        {
            DeliveryStep step = timing.Step;
            string at = ((long)timing.Elapsed.TotalMilliseconds)
                .ToString(CultureInfo.InvariantCulture)
                .PadLeft(6);

            if (step.Sent is { Length: > 0 } sent)
            {
                text.Append(CultureInfo.InvariantCulture, $"{at}ms > {sent}").AppendLine();
            }

            if (step.Reply is { } reply)
            {
                text.Append(CultureInfo.InvariantCulture, $"{at}ms < {reply.Code} {reply.Text}")
                    .AppendLine();

                foreach (string line in reply.ContinuationLines)
                {
                    text.Append(CultureInfo.InvariantCulture, $"{at}ms < {reply.Code}-{line}")
                        .AppendLine();
                }
            }

            if (step.Sent is null && step.Reply is null)
            {
                text.Append(CultureInfo.InvariantCulture, $"{at}ms   [{step.Stage}]");

                if (step.Detail is { Length: > 0 })
                {
                    text.Append(CultureInfo.InvariantCulture, $" {step.Detail}");
                }

                text.AppendLine();

                continue;
            }

            if (step.Detail is { Length: > 0 } detail)
            {
                text.Append(CultureInfo.InvariantCulture, $"{at}ms   [{step.Stage}] {detail}")
                    .AppendLine();
            }
        }

        return text.ToString();
    }
}
