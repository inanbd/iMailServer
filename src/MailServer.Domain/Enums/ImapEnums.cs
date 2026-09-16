namespace MailServer.Domain.Enums;

/// <summary>Which IMAP listener a connection arrived on.</summary>
/// <remarks>
/// The IMAP counterpart of <see cref="SmtpListenerRole"/>, and it exists for the same reason:
/// what may be offered to a connection depends on how that connection was made, and a decision
/// that depends on the port must not be re-derived from a socket somewhere deep in a handler.
/// Two values rather than SMTP's three, because IMAP has no equivalent of port 25's
/// "anonymous peers deliver mail here" role — every IMAP connection is a mailbox owner
/// reaching their own mail, so the only question is whether TLS started before the greeting.
/// </remarks>
public enum ImapListenerRole
{
    /// <summary>Port 143. Cleartext on connect; TLS is reached through <c>STARTTLS</c>.</summary>
    /// <remarks>
    /// RFC 2595 §3.2 requires a server implementing <c>STARTTLS</c> to advertise
    /// <c>LOGINDISABLED</c> on an unencrypted connection, and RFC 3501 §6.2.3 requires a
    /// configuration in which <c>LOGIN</c> is then actually refused. Both are how this listener
    /// avoids being a place where a password crosses the network in the clear.
    /// </remarks>
    Cleartext = 0,

    /// <summary>Port 993. TLS from the first byte, before the greeting.</summary>
    /// <remarks>
    /// RFC 8314 §3 prefers this over <c>STARTTLS</c> on 143: there is no cleartext phase for a
    /// stripping attacker to interfere with, because the handshake precedes the protocol
    /// entirely. <c>STARTTLS</c> is never legal here — there is no honest moment on 993 when it
    /// would be.
    /// </remarks>
    ImplicitTls = 1,
}

/// <summary>Where an IMAP session has got to. RFC 3501 §3.</summary>
/// <remarks>
/// Three real states plus logout, in the same shape as <see cref="SmtpSessionState"/>: a command
/// legal in one state is often a protocol error in another, and a state machine that can only
/// move forward through them (never fabricate a jump) is what makes that enforceable in one
/// place rather than re-litigated at every command.
/// </remarks>
public enum ImapSessionState
{
    /// <summary>Connected; <c>LOGIN</c>/<c>AUTHENTICATE</c> has not yet succeeded.</summary>
    NotAuthenticated = 0,

    /// <summary>Logged in; no mailbox is open.</summary>
    Authenticated = 1,

    /// <summary>A mailbox is open, via <c>SELECT</c> or <c>EXAMINE</c>.</summary>
    Selected = 2,

    /// <summary><c>LOGOUT</c> has been issued, or the connection is closing.</summary>
    Logout = 3,
}

/// <summary>
/// IMAP message flags — RFC 3501 §2.3.2's system flags, as a bitmask matching the
/// <c>Deliveries.Flags</c> column reserved for them since the Milestone 6 message-storage schema.
/// </summary>
[Flags]
public enum MessageFlags
{
    None = 0,

    /// <summary><c>\Seen</c> — the message has been read.</summary>
    Seen = 1,

    /// <summary><c>\Answered</c> — the message has been replied to.</summary>
    Answered = 2,

    /// <summary><c>\Flagged</c> — marked "urgent" or otherwise needing attention.</summary>
    Flagged = 4,

    /// <summary><c>\Deleted</c> — marked for removal by the next <c>EXPUNGE</c>.</summary>
    Deleted = 8,

    /// <summary><c>\Draft</c> — the message is a draft, not a delivered one.</summary>
    Draft = 16,

    /// <summary>
    /// <c>\Recent</c> — reserved, never set by this product.
    /// </summary>
    /// <remarks>
    /// RFC 3501 gives <c>\Recent</c> session-relative semantics no other flag has: it is not
    /// settable by a client via <c>STORE</c>, and correctly reporting it requires exactly one
    /// session to "claim" a newly-arrived message the first time any session selects the folder
    /// after it arrives — a piece of shared, racy, cross-connection bookkeeping. Most modern
    /// clients ignore the flag entirely and rely on <c>EXISTS</c> growing (and, once built,
    /// <c>IDLE</c>) for new-mail awareness instead. Per <c>docs/IMAP.md</c>, reporting <c>\Recent</c>
    /// conservatively — which here means never reporting it at all — beats reporting it
    /// incorrectly. The bit position is reserved so a future, fully-correct implementation has
    /// somewhere to live without a schema change.
    /// </remarks>
    Recent = 32,
}
