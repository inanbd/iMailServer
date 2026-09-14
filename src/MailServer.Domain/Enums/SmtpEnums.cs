namespace MailServer.Domain.Enums;

/// <summary>
/// What a listener is for.
/// </summary>
/// <remarks>
/// <para>
/// <b>Distinct roles rather than one listener with flags.</b> Conflating MTA receipt with
/// client submission is the root cause of most open relays in the wild: a single listener
/// with a "allow relay" switch is one misconfiguration away from relaying for the Internet,
/// and the switch is always set by someone solving a different problem.
/// </para>
/// <para>
/// The role is fixed when the listener is constructed and is never derived from anything the
/// remote end says. A peer cannot talk its way from port 25 into submission privileges.
/// </para>
/// </remarks>
public enum SmtpListenerRole
{
    /// <summary>
    /// Port 25. Mail from the Internet, for local domains only.
    /// </summary>
    /// <remarks>
    /// AUTH is never offered here, which means it can never be used here: rule 105's "no
    /// plaintext SMTP AUTH over Internet" is enforced by not advertising the capability rather
    /// than by rejecting an attempt. STARTTLS is offered but cannot be required — a large
    /// number of legitimate MTAs still do not support it, and refusing them loses mail
    /// silently.
    /// </remarks>
    InboundMta = 0,

    /// <summary>
    /// Port 587. Authenticated client submission, STARTTLS required before AUTH.
    /// </summary>
    Submission = 1,

    /// <summary>Port 465. Authenticated client submission, TLS from the first byte.</summary>
    ImplicitTlsSubmission = 2,
}

/// <summary>Where an SMTP session has got to.</summary>
/// <remarks>
/// Explicit states rather than a collection of booleans. "Has the client greeted, and
/// negotiated TLS, and authenticated, and given a sender" is one question about position in a
/// protocol, and answering it with four independent flags is how a state nobody intended
/// becomes reachable.
/// </remarks>
public enum SmtpSessionState
{
    /// <summary>Connected; the banner has been sent and nothing else has happened.</summary>
    Connected = 0,

    /// <summary>EHLO or HELO accepted.</summary>
    Greeted = 1,

    /// <summary>MAIL FROM accepted; a transaction is open.</summary>
    MailFromAccepted = 2,

    /// <summary>At least one RCPT TO accepted.</summary>
    RecipientsAccepted = 3,

    /// <summary>Inside DATA, reading the message.</summary>
    ReceivingData = 4,

    /// <summary>The session is closing.</summary>
    Closing = 5,
}

/// <summary>What to do with a recipient.</summary>
/// <remarks>
/// Three outcomes rather than a boolean, because "accept for a local mailbox" and "accept for
/// onward relay" are different operations with different consequences, and collapsing them
/// into "accepted" is how a relay decision stops being auditable.
/// </remarks>
public enum RelayDecision
{
    /// <summary>
    /// Refused. The fall-through, and the only outcome reachable without an explicit reason.
    /// </summary>
    Deny = 0,

    /// <summary>The recipient is in a domain this server hosts.</summary>
    AcceptLocal = 1,

    /// <summary>The recipient is elsewhere and this session is permitted to relay.</summary>
    AcceptRelay = 2,
}
