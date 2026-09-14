using MailServer.Domain.Enums;

namespace MailServer.Domain.Smtp;

/// <summary>
/// Which commands are legal in which state, and where each one leads.
/// </summary>
/// <remarks>
/// <para>
/// An explicit table rather than a chain of conditions at the call site. The sequencing rules
/// of SMTP are small but not obvious — <c>RCPT</c> before <c>MAIL</c> is a 503, a second
/// <c>MAIL</c> inside an open transaction is a 503, <c>EHLO</c> mid-transaction silently
/// abandons it — and a server that answers those questions with scattered <c>if</c> statements
/// eventually answers one of them twice, differently.
/// </para>
/// <para>
/// The table is <b>total</b>: every state/verb pair has an answer, and a pair nobody thought
/// about is refused rather than permitted. A test asserts that totality, so adding a verb
/// without deciding what it means in each state fails the build rather than defaulting to
/// "allowed".
/// </para>
/// <para>
/// This is sequencing only. Whether a command is permitted <i>here and now</i> also depends on
/// the listener role, on whether TLS is active and on whether the session has authenticated;
/// that is the session's business, because it needs configuration this layer must not see.
/// </para>
/// </remarks>
public static class SmtpStateMachine
{
    /// <summary>Every verb the sequencing table covers.</summary>
    /// <remarks>Kept here so the totality test can enumerate without reflection over the enum's ordering.</remarks>
    public static IReadOnlyList<SmtpVerb> AllVerbs { get; } = Enum.GetValues<SmtpVerb>();

    /// <summary>Every state the sequencing table covers.</summary>
    public static IReadOnlyList<SmtpSessionState> AllStates { get; } = Enum.GetValues<SmtpSessionState>();

    /// <summary>Whether <paramref name="verb"/> is in sequence in <paramref name="state"/>.</summary>
    /// <remarks>
    /// False earns a 503. It does not mean the command is unknown — that is a 500 — nor that it
    /// is forbidden by policy, which is a 530 or a 554. Answering the wrong one of those three
    /// misleads the operator on the other end, who is usually trying to work out why their mail
    /// will not go through.
    /// </remarks>
    public static bool IsInSequence(SmtpSessionState state, SmtpVerb verb) => state switch
    {
        // Nothing is in flight and the client has not identified itself.
        SmtpSessionState.Connected => verb switch
        {
            SmtpVerb.Ehlo or SmtpVerb.Helo => true,
            SmtpVerb.Quit or SmtpVerb.Noop or SmtpVerb.Rset => true,

            // Refused wherever they appear, but refused as "not implemented", not as "out of
            // sequence" - the client has not got the sequence wrong.
            SmtpVerb.Help or SmtpVerb.Vrfy or SmtpVerb.Expn => true,

            // RFC 3207 §4 and RFC 4954 §4: both follow EHLO, because the client is meant to
            // have seen the capability advertised before using it.
            SmtpVerb.StartTls or SmtpVerb.Auth => false,

            SmtpVerb.MailFrom or SmtpVerb.RcptTo or SmtpVerb.Data => false,
            SmtpVerb.Unknown => false,
            _ => false,
        },

        // Greeted, no transaction open.
        SmtpSessionState.Greeted => verb switch
        {
            SmtpVerb.Ehlo or SmtpVerb.Helo => true,
            SmtpVerb.StartTls or SmtpVerb.Auth => true,
            SmtpVerb.MailFrom => true,
            SmtpVerb.Quit or SmtpVerb.Noop or SmtpVerb.Rset => true,
            SmtpVerb.Help or SmtpVerb.Vrfy or SmtpVerb.Expn => true,

            SmtpVerb.RcptTo or SmtpVerb.Data => false,
            SmtpVerb.Unknown => false,
            _ => false,
        },

        // A transaction is open and has a sender but no recipients yet.
        SmtpSessionState.MailFromAccepted => verb switch
        {
            SmtpVerb.RcptTo => true,
            SmtpVerb.Ehlo or SmtpVerb.Helo => true,
            SmtpVerb.Quit or SmtpVerb.Noop or SmtpVerb.Rset => true,
            SmtpVerb.Help or SmtpVerb.Vrfy or SmtpVerb.Expn => true,

            // A second MAIL FROM would mean either a nested transaction or a silently replaced
            // sender. Neither exists in SMTP.
            SmtpVerb.MailFrom => false,

            // DATA with no recipients has nowhere to deliver to.
            SmtpVerb.Data => false,

            // Renegotiating TLS or authenticating mid-transaction would raise the question of
            // what happens to the envelope collected under the old security context. Refusing
            // means the question never arises.
            SmtpVerb.StartTls or SmtpVerb.Auth => false,

            SmtpVerb.Unknown => false,
            _ => false,
        },

        // A transaction is open with at least one recipient.
        SmtpSessionState.RecipientsAccepted => verb switch
        {
            SmtpVerb.RcptTo or SmtpVerb.Data => true,
            SmtpVerb.Ehlo or SmtpVerb.Helo => true,
            SmtpVerb.Quit or SmtpVerb.Noop or SmtpVerb.Rset => true,
            SmtpVerb.Help or SmtpVerb.Vrfy or SmtpVerb.Expn => true,

            SmtpVerb.MailFrom => false,
            SmtpVerb.StartTls or SmtpVerb.Auth => false,
            SmtpVerb.Unknown => false,
            _ => false,
        },

        // Inside DATA every octet is message content. Nothing that arrives here is a command,
        // which is exactly why this row is empty: a "command" seen in this state is either a
        // caller bug or the beginning of an injection.
        SmtpSessionState.ReceivingData => false,

        // The session is going away. Accepting a command now would mean continuing after QUIT.
        SmtpSessionState.Closing => false,

        _ => false,
    };

    /// <summary>Where a successfully executed command leaves the session.</summary>
    /// <remarks>
    /// Only for commands that actually succeeded. A refused <c>RCPT TO</c> leaves the state
    /// alone: a recipient that was rejected must not advance the session to
    /// <see cref="SmtpSessionState.RecipientsAccepted"/>, or a following <c>DATA</c> would be
    /// accepted for a transaction with no recipients.
    /// </remarks>
    public static SmtpSessionState NextOnSuccess(SmtpSessionState state, SmtpVerb verb) => verb switch
    {
        // A new greeting abandons any open transaction (RFC 5321 §4.1.4) and returns the
        // session to the state just after greeting.
        SmtpVerb.Ehlo or SmtpVerb.Helo => SmtpSessionState.Greeted,

        SmtpVerb.MailFrom => SmtpSessionState.MailFromAccepted,
        SmtpVerb.RcptTo => SmtpSessionState.RecipientsAccepted,
        SmtpVerb.Data => SmtpSessionState.ReceivingData,

        // RSET clears the transaction but not the greeting. Sending the client back to
        // Connected would make it re-EHLO, which no client expects to have to do.
        SmtpVerb.Rset => SmtpSessionState.Greeted,

        SmtpVerb.Quit => SmtpSessionState.Closing,

        // STARTTLS does not move through this function. The handshake resets the session to
        // Connected wholesale; see SmtpSessionContext.ResetAfterTlsHandshake.
        SmtpVerb.StartTls => SmtpSessionState.Connected,

        _ => state,
    };

    /// <summary>Where the session goes when a message finishes, whether or not it was accepted.</summary>
    /// <remarks>
    /// Back to <see cref="SmtpSessionState.Greeted"/>, with the envelope discarded. A client may
    /// send another message on the same connection, and it must not inherit a recipient from
    /// the last one.
    /// </remarks>
    public static SmtpSessionState AfterMessage() => SmtpSessionState.Greeted;
}
