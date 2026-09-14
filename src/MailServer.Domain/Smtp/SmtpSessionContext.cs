using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Smtp;

/// <summary>A recipient the session has accepted, and what kind of acceptance it was.</summary>
/// <param name="Address">The recipient as given in RCPT TO.</param>
/// <param name="Decision">Local delivery or onward relay. Recorded so the decision is auditable later.</param>
public sealed record AcceptedRecipient(EmailAddress Address, RelayDecision Decision);

/// <summary>
/// Everything an SMTP session knows, and the two places it forgets it.
/// </summary>
/// <remarks>
/// <para>
/// The state lives in one object with explicit reset methods rather than in fields scattered
/// across the session loop, because the correctness of STARTTLS depends on <i>everything</i>
/// being discarded and a field that lives somewhere else is a field somebody forgets.
/// </para>
/// <para>Not thread-safe. One context belongs to one connection.</para>
/// </remarks>
public sealed class SmtpSessionContext
{
    private readonly List<AcceptedRecipient> _recipients = [];

    /// <summary>Starts a session on a listener, from a remote address.</summary>
    /// <param name="role">Fixed by the listener. Never derived from anything the peer says.</param>
    /// <param name="remoteAddress">The peer. From the transport, so the peer cannot change it.</param>
    /// <param name="startedAt">When the connection opened, for the session timeout.</param>
    /// <param name="isTlsActive">True on an implicit-TLS listener, where TLS precedes the banner.</param>
    public SmtpSessionContext(
        SmtpListenerRole role,
        IpAddressValue remoteAddress,
        DateTimeOffset startedAt,
        bool isTlsActive)
    {
        ArgumentNullException.ThrowIfNull(remoteAddress);

        Role = role;
        RemoteAddress = remoteAddress;
        StartedAt = startedAt;
        IsTlsActive = isTlsActive;
    }

    // ---- Fixed for the life of the connection -------------------------------------------
    //
    // These survive the STARTTLS reset because none of them is something the client told us.
    // The role comes from which socket was accepted, the address from the TCP layer, the clock
    // from the host.

    /// <summary>Which listener the peer reached.</summary>
    public SmtpListenerRole Role { get; }

    /// <summary>The peer's address, from the transport.</summary>
    public IpAddressValue RemoteAddress { get; }

    /// <summary>When the connection opened.</summary>
    public DateTimeOffset StartedAt { get; }

    // ---- Security context ----------------------------------------------------------------

    /// <summary>Whether TLS is active.</summary>
    public bool IsTlsActive { get; private set; }

    /// <summary>Whether the session has authenticated.</summary>
    public bool IsAuthenticated { get; private set; }

    /// <summary>The authenticated mailbox, or null.</summary>
    public EmailAddress? AuthenticatedMailbox { get; private set; }

    /// <summary>
    /// Failed AUTH attempts on this connection.
    /// </summary>
    /// <remarks>
    /// <b>Deliberately not cleared by any reset.</b> It is not knowledge obtained from the
    /// client — it is this server's own accounting — and clearing it would turn any resettable
    /// event into a way to buy another three password guesses.
    /// </remarks>
    public int FailedAuthenticationAttempts { get; private set; }

    // ---- Protocol position -----------------------------------------------------------------

    /// <summary>Where the session has got to.</summary>
    public SmtpSessionState State { get; private set; } = SmtpSessionState.Connected;

    /// <summary>The name the client gave in EHLO or HELO, or null.</summary>
    /// <remarks>
    /// A claim, not a fact — it is whatever the client typed, and it appears in the Received
    /// header as such. It is discarded on STARTTLS because it arrived in the clear.
    /// </remarks>
    public string? GreetedName { get; private set; }

    /// <summary>Whether the client used EHLO rather than HELO.</summary>
    public bool UsedExtendedGreeting { get; private set; }

    // ---- Envelope --------------------------------------------------------------------------

    /// <summary>Whether MAIL FROM has been accepted, opening a transaction.</summary>
    /// <remarks>
    /// Separate from <see cref="ReversePath"/> being null, because the null reverse path
    /// <c>&lt;&gt;</c> is a real, accepted sender — a bounce — and "no MAIL FROM yet" and "MAIL
    /// FROM with an empty path" are different situations that a single nullable field cannot
    /// tell apart.
    /// </remarks>
    public bool HasTransaction { get; private set; }

    /// <summary>The envelope sender, or null for the null reverse path.</summary>
    public EmailAddress? ReversePath { get; private set; }

    /// <summary>The size the sender declared in <c>SIZE=</c>, if any. Advisory.</summary>
    public long? DeclaredMessageSize { get; private set; }

    /// <summary>Recipients accepted so far.</summary>
    public IReadOnlyList<AcceptedRecipient> Recipients => _recipients;

    // ---- Transitions -------------------------------------------------------------------------

    /// <summary>Records a successful EHLO or HELO.</summary>
    /// <remarks>
    /// A greeting mid-transaction abandons the transaction (RFC 5321 §4.1.4). Doing that here,
    /// rather than expecting the caller to remember, is the point of putting the state in one
    /// object.
    /// </remarks>
    public void Greet(string name, bool extended)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        GreetedName = name;
        UsedExtendedGreeting = extended;
        State = SmtpSessionState.Greeted;

        ResetTransaction();
    }

    /// <summary>Records a successful TLS handshake and forgets everything that preceded it.</summary>
    /// <remarks>
    /// <para>
    /// <b>This is the most security-critical method in the SMTP implementation.</b> RFC 3207 §4:
    /// after the handshake the server MUST discard all knowledge obtained from the client that
    /// was not transmitted inside the TLS negotiation itself.
    /// </para>
    /// <para>
    /// Failing to do so is CVE-2011-0411 and its relatives — the STARTTLS command-injection
    /// class. An attacker on the wire appends plaintext commands to the <c>STARTTLS</c> line;
    /// a server that keeps its pre-handshake state, or its pre-handshake read buffer, executes
    /// those commands as though they had arrived inside the tunnel, with whatever authority the
    /// real client later establishes.
    /// </para>
    /// <para>
    /// The reset here covers the session's own state. The <b>buffered input</b> is the other
    /// half of the same bug and belongs to the reader, which is why the caller must also discard
    /// that before handing the socket to the TLS layer.
    /// </para>
    /// </remarks>
    public void CompleteTlsHandshake()
    {
        if (IsTlsActive)
        {
            // A second handshake inside the first is not a thing SMTP does, and would raise the
            // question of which security context the envelope belongs to.
            throw new InvalidOperationException("TLS is already active on this session.");
        }

        IsTlsActive = true;

        // Everything the client said in the clear goes. The greeting was unauthenticated
        // hearsay; the envelope was collected outside the tunnel; any authentication - which
        // should have been impossible before TLS - is void.
        GreetedName = null;
        UsedExtendedGreeting = false;
        IsAuthenticated = false;
        AuthenticatedMailbox = null;

        ResetTransaction();

        // Back to the very beginning: the client must EHLO again inside the tunnel. RFC 3207
        // requires it, and it is what makes the discarded greeting unobservable.
        State = SmtpSessionState.Connected;
    }

    /// <summary>Records a successful authentication.</summary>
    public void Authenticate(EmailAddress mailbox)
    {
        ArgumentNullException.ThrowIfNull(mailbox);

        if (!IsTlsActive)
        {
            // Unreachable if capability advertisement is correct, and asserted anyway: this is
            // the last line of defence for "no plaintext SMTP AUTH over Internet", and a defence
            // that depends on another component being right is not a defence.
            throw new InvalidOperationException(
                "Authentication without TLS is refused; credentials must never cross the network in the clear.");
        }

        IsAuthenticated = true;
        AuthenticatedMailbox = mailbox;
    }

    /// <summary>Records a failed authentication attempt.</summary>
    public int RecordFailedAuthentication() => ++FailedAuthenticationAttempts;

    /// <summary>Opens a transaction with an accepted sender.</summary>
    /// <param name="reversePath">The sender, or null for the null reverse path.</param>
    /// <param name="declaredSize">The sender's <c>SIZE=</c> claim, if any.</param>
    public void BeginTransaction(EmailAddress? reversePath, long? declaredSize)
    {
        HasTransaction = true;
        ReversePath = reversePath;
        DeclaredMessageSize = declaredSize;
        State = SmtpSessionState.MailFromAccepted;

        _recipients.Clear();
    }

    /// <summary>Adds an accepted recipient.</summary>
    /// <remarks>
    /// Only ever called for a recipient that was actually accepted. A rejected recipient must
    /// not advance the state, or a following DATA would be accepted for a transaction that has
    /// nowhere to deliver.
    /// </remarks>
    public void AcceptRecipient(EmailAddress address, RelayDecision decision)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (decision == RelayDecision.Deny)
        {
            throw new ArgumentException(
                "A denied recipient must never be added to the envelope.",
                nameof(decision));
        }

        if (!HasTransaction)
        {
            throw new InvalidOperationException("There is no open transaction to add a recipient to.");
        }

        _recipients.Add(new AcceptedRecipient(address, decision));
        State = SmtpSessionState.RecipientsAccepted;
    }

    /// <summary>Moves into DATA.</summary>
    public void BeginData()
    {
        if (_recipients.Count == 0)
        {
            throw new InvalidOperationException("DATA with no accepted recipients has nowhere to deliver.");
        }

        State = SmtpSessionState.ReceivingData;
    }

    /// <summary>Ends a message and clears the envelope, ready for another on the same connection.</summary>
    public void CompleteMessage()
    {
        ResetTransaction();
        State = SmtpStateMachine.AfterMessage();
    }

    /// <summary>Handles RSET: clears the transaction, keeps the greeting and the security context.</summary>
    public void Reset()
    {
        ResetTransaction();

        // Only back to Greeted if the client has greeted. RSET before EHLO is legal and must
        // not fabricate a greeting that never happened.
        State = GreetedName is null ? SmtpSessionState.Connected : SmtpSessionState.Greeted;
    }

    /// <summary>Marks the session as closing.</summary>
    public void Close() => State = SmtpSessionState.Closing;

    /// <summary>Builds the relay context for a recipient decision.</summary>
    /// <remarks>
    /// One place that assembles it, so a call site cannot pass a context that flatters the
    /// session — an <c>IsAuthenticated</c> that was never set, say.
    /// </remarks>
    public RelayContext ToRelayContext() =>
        new(Role, IsAuthenticated, AuthenticatedMailbox, RemoteAddress, IsTlsActive);

    private void ResetTransaction()
    {
        HasTransaction = false;
        ReversePath = null;
        DeclaredMessageSize = null;
        _recipients.Clear();
    }
}
