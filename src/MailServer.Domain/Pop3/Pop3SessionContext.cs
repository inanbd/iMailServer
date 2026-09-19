using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Pop3;

/// <summary>Which listener a POP3 connection arrived on.</summary>
/// <remarks>
/// The same split IMAP makes, and for the same reason: whether TLS precedes the greeting is
/// fixed by the socket that accepted the connection and is never derived from anything the peer
/// says.
/// </remarks>
public enum Pop3ListenerRole
{
    /// <summary>Port 110. Cleartext on connect; TLS is reached through <c>STLS</c>.</summary>
    /// <remarks>
    /// RFC 2595 §4 adds <c>STLS</c> "to POP3 servers. If this is implemented, the POP3 extension
    /// mechanism [POP3EXT] MUST also be implemented to avoid the need for client probing of
    /// multiple commands." The <c>USER</c> capability is withheld until TLS is active, which is
    /// the POP3 counterpart of IMAP's <c>LOGINDISABLED</c>: RFC 2449 §6.2 makes that capability
    /// mean "the USER and PASS commands are supported", so not announcing it is how a server says
    /// they are not.
    /// </remarks>
    Cleartext = 0,

    /// <summary>Port 995. TLS from the first byte, before the greeting.</summary>
    /// <remarks>
    /// RFC 8314 §3.1: "When a TCP connection is established for the "pop3s" service (default port
    /// 995), a TLS handshake begins immediately. […] After the server sends an +OK greeting, the
    /// server and client MUST enter the AUTHORIZATION state, even if a client certificate was
    /// supplied during the TLS handshake." §3 prefers this over <c>STLS</c> outright.
    /// </remarks>
    ImplicitTls = 1,
}

/// <summary>Where a POP3 session has got to. RFC 1939 §3.</summary>
public enum Pop3SessionState
{
    /// <summary>
    /// Before authentication. §3: "In this state, the client must identify itself to the POP3
    /// server."
    /// </summary>
    Authorization = 0,

    /// <summary>
    /// Authenticated, with the maildrop open. §3: "In this state, the client requests actions on
    /// the part of the POP3 server."
    /// </summary>
    Transaction = 1,

    /// <summary>
    /// After <c>QUIT</c> from <see cref="Transaction"/>. §3: "the POP3 server releases any
    /// resources acquired during the TRANSACTION state and says goodbye."
    /// </summary>
    Update = 2,
}

/// <summary>
/// Everything a POP3 session knows, and the one place it forgets it.
/// </summary>
/// <remarks>
/// <para>
/// The same shape as <see cref="Imap.ImapSessionContext"/>: one object, explicit transitions,
/// nothing reachable through a path the state machine does not allow. RFC 1939 §3 makes the
/// states load-bearing — "A server MUST respond to a command issued when the session is in an
/// incorrect state by responding with a negative status indicator" — so a state machine that can
/// only move forward is what makes that one check rather than one per command.
/// </para>
/// <para>
/// <b>The UPDATE state is reached only by <c>QUIT</c> from TRANSACTION.</b> §6: "Note that if the
/// client issues the QUIT command from the AUTHORIZATION state, the POP3 session terminates but
/// does NOT enter the UPDATE state", and "If a session terminates for some reason other than a
/// client-issued QUIT command, the POP3 session does NOT enter the UPDATE state and MUST not
/// remove any messages from the maildrop." Those two sentences are the whole reason deletion is
/// a transition here rather than a flag anywhere else: a dropped connection cannot reach the one
/// state that removes mail.
/// </para>
/// <para>Not thread-safe. One context belongs to one connection.</para>
/// </remarks>
public sealed class Pop3SessionContext
{
    /// <summary>Starts a session.</summary>
    /// <param name="remoteAddress">The peer. From the transport, so the peer cannot change it.</param>
    /// <param name="startedAt">When the connection opened, for the inactivity timer.</param>
    /// <param name="isTlsActive">True on the implicit-TLS listener, where TLS precedes the greeting.</param>
    public Pop3SessionContext(
        IpAddressValue remoteAddress,
        DateTimeOffset startedAt,
        bool isTlsActive)
    {
        ArgumentNullException.ThrowIfNull(remoteAddress);

        RemoteAddress = remoteAddress;
        StartedAt = startedAt;
        IsTlsActive = isTlsActive;
    }

    /// <summary>The peer's address, from the transport.</summary>
    public IpAddressValue RemoteAddress { get; }

    /// <summary>When the connection opened.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>Whether TLS is active.</summary>
    public bool IsTlsActive { get; private set; }

    /// <summary>Where the session has got to.</summary>
    public Pop3SessionState State { get; private set; } = Pop3SessionState.Authorization;

    /// <summary>
    /// The name a <c>USER</c> command supplied, waiting for its <c>PASS</c>.
    /// </summary>
    /// <remarks>
    /// §7: <c>PASS</c> "may only be given in the AUTHORIZATION state immediately after a
    /// successful USER command", so the pair is a two-step exchange with state between them.
    /// Cleared on every outcome — success, failure, and a second <c>USER</c> — because a
    /// <c>PASS</c> that could reuse a name from an earlier failed attempt would let a client
    /// authenticate as someone it no longer claimed to be.
    /// </remarks>
    public string? PendingUser { get; private set; }

    /// <summary>The authenticated mailbox's address, or null.</summary>
    public EmailAddress? AuthenticatedMailbox { get; private set; }

    /// <summary>The authenticated mailbox's identity, or null.</summary>
    public MailboxId? AuthenticatedMailboxId { get; private set; }

    /// <summary>The folder the maildrop is served from, or null.</summary>
    public MailboxFolderId? MaildropFolderId { get; private set; }

    /// <summary>The session's snapshot of the maildrop, or null before authentication.</summary>
    public Pop3Maildrop? Maildrop { get; private set; }

    /// <summary>
    /// How many credentials have been refused on this connection.
    /// </summary>
    /// <remarks>
    /// Counted for the same reason IMAP counts them: a connection is a free retry budget unless
    /// someone bounds it, and an unbounded one turns a mail server into an offline password
    /// cracker that answers over the network.
    /// </remarks>
    public int FailedAuthenticationAttempts { get; private set; }

    /// <summary>Records that TLS is now active.</summary>
    /// <remarks>
    /// RFC 2595 §4: "The STLS command is only permitted in AUTHORIZATION state and the server
    /// remains in AUTHORIZATION state, even if client credentials are supplied during the TLS
    /// negotiation." So this changes the security context and never the state.
    /// </remarks>
    public void ActivateTls()
    {
        if (IsTlsActive)
        {
            throw new InvalidOperationException("TLS is already active on this session.");
        }

        IsTlsActive = true;

        // Anything the client said before the handshake was said in the clear and may have been
        // said by somebody else. The name is discarded with the rest of it.
        PendingUser = null;
    }

    /// <summary>Records the name a <c>USER</c> command supplied.</summary>
    public void BeginAuthentication(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (State != Pop3SessionState.Authorization)
        {
            throw new InvalidOperationException("USER requires the AUTHORIZATION state.");
        }

        PendingUser = name;
    }

    /// <summary>Forgets a pending name, after any outcome.</summary>
    public void ForgetPendingUser() => PendingUser = null;

    /// <summary>Records a refused credential.</summary>
    public void RecordFailedAuthentication()
    {
        FailedAuthenticationAttempts++;
        PendingUser = null;
    }

    /// <summary>
    /// Opens the maildrop and enters the TRANSACTION state.
    /// </summary>
    /// <remarks>
    /// §4: "Once the POP3 server has determined through the use of any authentication command
    /// that the client should be given access to the appropriate maildrop, the POP3 server then
    /// acquires an exclusive-access lock on the maildrop […] If the lock is successfully
    /// acquired, the POP3 server responds with a positive status indicator. The POP3 session now
    /// enters the TRANSACTION state, with no messages marked as deleted."
    /// </remarks>
    public void OpenMaildrop(
        EmailAddress mailbox,
        MailboxId mailboxId,
        MailboxFolderId folderId,
        Pop3Maildrop maildrop)
    {
        ArgumentNullException.ThrowIfNull(mailbox);
        ArgumentNullException.ThrowIfNull(maildrop);

        if (State != Pop3SessionState.Authorization)
        {
            throw new InvalidOperationException("A maildrop can only be opened from AUTHORIZATION.");
        }

        AuthenticatedMailbox = mailbox;
        AuthenticatedMailboxId = mailboxId;
        MaildropFolderId = folderId;
        Maildrop = maildrop;
        PendingUser = null;
        State = Pop3SessionState.Transaction;
    }

    /// <summary>
    /// Enters the UPDATE state, which only a <c>QUIT</c> from TRANSACTION may do.
    /// </summary>
    /// <remarks>
    /// The transition is the licence to remove mail, so it is a method rather than an assignment:
    /// §6's "MUST not remove any messages" for every other ending is enforced by there being no
    /// other way to reach this state.
    /// </remarks>
    public void EnterUpdate()
    {
        if (State != Pop3SessionState.Transaction)
        {
            throw new InvalidOperationException("UPDATE is only reachable by QUIT from TRANSACTION.");
        }

        State = Pop3SessionState.Update;
    }
}
