using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Imap;

/// <summary>
/// Everything an IMAP session knows, and the one place it forgets it.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="Smtp.SmtpSessionContext"/>'s shape deliberately: one object, explicit
/// transitions, nothing reachable through a path the state machine does not allow. RFC 3501 §3's
/// three real states (plus logout) gate which commands are legal at all — <c>SELECT</c> before
/// <c>LOGIN</c>, or <c>FETCH</c> with no mailbox selected, become protocol errors the state
/// machine makes unrepresentable rather than something every command handler re-checks for
/// itself.
/// </para>
/// <para>
/// <b><see cref="AuthenticatedMailboxId"/> is cached, deliberately, unlike most of this session's
/// other server-side knowledge.</b> A mailbox's identity cannot change for the life of a
/// connection once <c>LOGIN</c>/<c>AUTHENTICATE</c> succeeds, unlike a folder's message count or
/// next UID — which is why <see cref="SelectedFolderUidValidity"/> is cached too (it is fixed for
/// the folder's whole life, not merely this session's) while nothing about a folder's *contents*
/// is. Resolving the mailbox by address again on every <c>FETCH</c> of a long-lived, possibly
/// <c>IDLE</c>-ing connection would be a repeated, pointless round trip for a value that is
/// already known to be constant.
/// </para>
/// <para>Not thread-safe. One context belongs to one connection.</para>
/// </remarks>
public sealed class ImapSessionContext
{
    /// <summary>Starts a session, from a remote address.</summary>
    /// <param name="remoteAddress">The peer. From the transport, so the peer cannot change it.</param>
    /// <param name="startedAt">When the connection opened, for the session timeout.</param>
    /// <param name="isTlsActive">True on the implicit-TLS listener (993), where TLS precedes the greeting.</param>
    public ImapSessionContext(IpAddressValue remoteAddress, DateTimeOffset startedAt, bool isTlsActive)
    {
        ArgumentNullException.ThrowIfNull(remoteAddress);

        RemoteAddress = remoteAddress;
        StartedAt = startedAt;
        IsTlsActive = isTlsActive;
    }

    // ---- Fixed for the life of the connection -----------------------------------------------

    /// <summary>The peer's address, from the transport.</summary>
    public IpAddressValue RemoteAddress { get; }

    /// <summary>When the connection opened.</summary>
    public DateTimeOffset StartedAt { get; }

    // ---- Security context -------------------------------------------------------------------

    /// <summary>Whether TLS is active.</summary>
    public bool IsTlsActive { get; private set; }

    /// <summary>The authenticated mailbox's address, or null.</summary>
    public EmailAddress? AuthenticatedMailbox { get; private set; }

    /// <summary>The authenticated mailbox's identity, or null. See the class remarks on caching this.</summary>
    public MailboxId? AuthenticatedMailboxId { get; private set; }

    /// <summary>
    /// Failed <c>LOGIN</c>/<c>AUTHENTICATE</c> attempts on this connection.
    /// </summary>
    /// <remarks>
    /// Deliberately not cleared by any transition here, for the same reason
    /// <see cref="Smtp.SmtpSessionContext.FailedAuthenticationAttempts"/> is not: it is this
    /// server's own accounting of the connection, not knowledge obtained from the client, so
    /// nothing the client does should be able to buy back another guess.
    /// </remarks>
    public int FailedAuthenticationAttempts { get; private set; }

    // ---- Protocol position ------------------------------------------------------------------

    /// <summary>Where the session has got to.</summary>
    public ImapSessionState State { get; private set; } = ImapSessionState.NotAuthenticated;

    /// <summary>The folder open in the <see cref="ImapSessionState.Selected"/> state, or null.</summary>
    public MailboxFolderId? SelectedFolderId { get; private set; }

    /// <summary>
    /// The selected folder's UIDVALIDITY, cached at <c>SELECT</c>/<c>EXAMINE</c> time.
    /// </summary>
    /// <remarks>
    /// Safe to cache for the reason <see cref="MailboxFolder"/>'s own remarks give: it is assigned
    /// once, at folder creation, and never changes — caching it is not a staleness risk the way
    /// caching a message count would be.
    /// </remarks>
    public long SelectedFolderUidValidity { get; private set; }

    /// <summary>Whether the mailbox was opened with <c>EXAMINE</c> rather than <c>SELECT</c>.</summary>
    /// <remarks>
    /// RFC 3501 §6.3.2: <c>EXAMINE</c> is identical to <c>SELECT</c> except that the mailbox is
    /// opened read-only — no flag change, and in particular no <c>EXPUNGE</c>, may occur.
    /// </remarks>
    public bool IsSelectedReadOnly { get; private set; }

    // ---- Transitions -------------------------------------------------------------------------

    /// <summary>Records a successful TLS handshake.</summary>
    /// <remarks>
    /// RFC 3501 §6.2.1: after <c>STARTTLS</c> succeeds, the server MUST discard any knowledge
    /// obtained from the client that was not transmitted inside the TLS negotiation itself — the
    /// same rule, and the same command-injection risk (CVE-2011-0411 and its relatives) that
    /// <see cref="Smtp.SmtpSessionContext.CompleteTlsHandshake"/> guards against for SMTP.
    /// <c>STARTTLS</c> is only ever legal in <see cref="ImapSessionState.NotAuthenticated"/>
    /// (the caller must check <see cref="State"/> before calling this), so there is nothing this
    /// state machine has collected in the clear to discard yet — but that is a fact about today's
    /// state machine, not a reason to skip resetting: a future pre-auth command that adds state
    /// here must be discarded in this method too, not merely today's empty list of them.
    /// </remarks>
    /// <exception cref="InvalidOperationException">TLS is already active.</exception>
    public void CompleteTlsHandshake()
    {
        if (IsTlsActive)
        {
            throw new InvalidOperationException("TLS is already active on this session.");
        }

        IsTlsActive = true;
    }

    /// <summary>Records a successful <c>LOGIN</c> or <c>AUTHENTICATE</c>.</summary>
    /// <exception cref="InvalidOperationException">TLS is not active, or the session is not <see cref="ImapSessionState.NotAuthenticated"/>.</exception>
    public void Authenticate(MailboxId mailboxId, EmailAddress mailbox)
    {
        ArgumentNullException.ThrowIfNull(mailbox);

        if (!IsTlsActive)
        {
            // The last line of defence for "no plaintext IMAP authentication over the Internet",
            // the same way SmtpSessionContext.Authenticate is for SMTP AUTH — a defence that
            // depends only on capability advertisement never offering LOGIN/AUTHENTICATE without
            // TLS is not a defence.
            throw new InvalidOperationException(
                "Authentication without TLS is refused; credentials must never cross the network in the clear.");
        }

        if (State != ImapSessionState.NotAuthenticated)
        {
            // RFC 3501 §6.1.2/6.1.3: LOGIN and AUTHENTICATE are only valid in the
            // Not Authenticated state — a client does not get to re-authenticate as someone else
            // mid-session.
            throw new InvalidOperationException(
                "LOGIN/AUTHENTICATE is only legal in the not-authenticated state.");
        }

        AuthenticatedMailboxId = mailboxId;
        AuthenticatedMailbox = mailbox;
        State = ImapSessionState.Authenticated;
    }

    /// <summary>Records a failed authentication attempt.</summary>
    public int RecordFailedAuthentication() => ++FailedAuthenticationAttempts;

    /// <summary>Opens a mailbox via <c>SELECT</c> or <c>EXAMINE</c>, deselecting any previous one first.</summary>
    /// <remarks>
    /// RFC 3501 §6.3.1: "the SELECT command automatically deselects any currently selected
    /// mailbox before attempting the new selection" — unlike <c>CLOSE</c>, this never expunges;
    /// switching straight from one selected mailbox to another is legal and ordinary.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The session is not authenticated.</exception>
    public void Select(MailboxFolderId folderId, long uidValidity, bool readOnly)
    {
        if (State is not (ImapSessionState.Authenticated or ImapSessionState.Selected))
        {
            throw new InvalidOperationException("SELECT/EXAMINE requires an authenticated session.");
        }

        SelectedFolderId = folderId;
        SelectedFolderUidValidity = uidValidity;
        IsSelectedReadOnly = readOnly;
        ReportedExists = 0;
        FlagWatch = null;
        State = ImapSessionState.Selected;
    }

    /// <summary>
    /// How many messages the client has been told the selected folder holds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What the client believes, not what the folder holds.</b> RFC 3501 §7.3.1 makes
    /// <c>EXISTS</c> "the number of messages in the mailbox" and requires that "the update from
    /// the EXISTS response MUST be recorded by the client", and §7.4.1 says an <c>EXPUNGE</c>
    /// "also decrements the number of messages in the mailbox; it is not necessary to send an
    /// EXISTS response with the new value". So the client's count moves only when the server
    /// tells it to, and this is that count.
    /// </para>
    /// <para>
    /// It exists so that an idling connection can push what the client has not been told rather
    /// than what has changed since the idle began. A message that arrives between <c>SELECT</c>
    /// and <c>IDLE</c> is news to the client either way.
    /// </para>
    /// </remarks>
    public long ReportedExists { get; private set; }

    /// <summary>
    /// Records that the client has been told the folder's size.
    /// </summary>
    /// <remarks>
    /// <b>Only ever called where a response actually says so</b> — an <c>EXISTS</c> line, or the
    /// <c>EXPUNGE</c> lines that §7.4.1 makes equivalent to one. A count taken from the database
    /// and recorded here without being sent would leave the client permanently behind by
    /// whatever arrived in between.
    /// </remarks>
    public void ReportExists(long count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        ReportedExists = count;
    }

    /// <summary>
    /// The flag watch running over the selected folder, or null when none is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>On the session rather than inside the idle loop, so that it survives <c>DONE</c>.</b>
    /// RFC 2177 §3 tells a client to re-issue <c>IDLE</c> periodically — "at least every 29
    /// minutes to avoid being logged off" — and the ordinary way to do that is <c>DONE</c>
    /// followed immediately by another <c>IDLE</c>. A watch that began again from the folder
    /// each time would take whatever had changed in between as its starting point and never
    /// report it, which is the race RFC 3501 §6.4.6 exists to close.
    /// </para>
    /// <para>
    /// <b>Discarded by every other command, which is what keeps it honest.</b> A watch holds
    /// the client's own list of messages, and this session's <c>EXPUNGE</c>, <c>STORE</c>,
    /// <c>MOVE</c> or <c>CLOSE</c> all change that list — <c>EXPUNGE</c> renumbers it outright.
    /// Enumerating which commands those are would be one forgotten verb away from reporting a
    /// flag against the wrong message, so the rule is inverted: anything but <c>IDLE</c> ends
    /// the watch and the next <c>IDLE</c> starts a fresh one.
    /// </para>
    /// </remarks>
    public ImapFlagWatch? FlagWatch { get; private set; }

    /// <summary>Begins watching the selected folder's flags.</summary>
    /// <exception cref="InvalidOperationException">No mailbox is selected.</exception>
    public void StartFlagWatch(ImapFlagWatch watch)
    {
        ArgumentNullException.ThrowIfNull(watch);

        if (SelectedFolderId is null)
        {
            throw new InvalidOperationException(
                "A flag watch is a watch over the selected folder; there is none.");
        }

        FlagWatch = watch;
    }

    /// <summary>Ends any flag watch, so that the next one starts from the folder as it stands.</summary>
    /// <remarks>Idempotent: called on every command, and most of them never started one.</remarks>
    public void EndFlagWatch() => FlagWatch = null;

    /// <summary>Closes the selected mailbox, returning to the authenticated state.</summary>
    /// <remarks>
    /// Callers implementing <c>CLOSE</c> (which also expunges) or an unselecting error path both
    /// go through here; which one applies is a decision for whatever expunges, not for this state
    /// machine.
    /// </remarks>
    public void Deselect()
    {
        SelectedFolderId = null;
        SelectedFolderUidValidity = 0;
        IsSelectedReadOnly = false;
        ReportedExists = 0;
        FlagWatch = null;

        if (State == ImapSessionState.Selected)
        {
            State = ImapSessionState.Authenticated;
        }
    }

    /// <summary>Records <c>LOGOUT</c>.</summary>
    public void Logout()
    {
        Deselect();
        State = ImapSessionState.Logout;
    }
}
