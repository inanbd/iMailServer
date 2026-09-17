using MailServer.Domain.Enums;

namespace MailServer.Domain.Imap;

/// <summary>
/// Which commands are legal in which IMAP state.
/// </summary>
/// <remarks>
/// <para>
/// An explicit table, for the reason <see cref="Smtp.SmtpStateMachine"/> gives for SMTP's: the
/// sequencing rules are small but not obvious, and a server that answers them with scattered
/// <c>if</c> statements eventually answers one of them twice, differently.
/// </para>
/// <para>
/// The table is <b>total</b>: every state/verb pair has an explicit answer, and a pair nobody
/// thought about is refused rather than permitted. A test asserts that totality, so adding a
/// verb without deciding what it means in each state fails the build rather than defaulting to
/// "allowed".
/// </para>
/// <para>
/// <b>Selected is a superset of Authenticated, and this is the single most common place to get
/// an IMAP state table wrong.</b> RFC 3501 §6.4's selected-state commands are <i>additional</i>
/// to §6.3's, not a replacement for them: a session with a mailbox open may still <c>CREATE</c>,
/// <c>LIST</c>, <c>STATUS</c> or <c>APPEND</c>, and every real client does exactly that — an
/// <c>APPEND</c> of a sent message into Sent while Inbox is the selected mailbox is ordinary
/// traffic, not a protocol error. A table that treats the two states as disjoint refuses it, and
/// the client's copy of the message it just sent is silently never saved.
/// </para>
/// <para>
/// This is sequencing only, exactly as it is for SMTP. Whether a command is permitted <i>here
/// and now</i> also depends on whether TLS is active and on what the mailbox's own state allows
/// — <c>STARTTLS</c> is in sequence in <see cref="ImapSessionState.NotAuthenticated"/> but must
/// not be honoured a second time inside the tunnel it created, and <c>STORE</c> or
/// <c>EXPUNGE</c> is in sequence in <see cref="ImapSessionState.Selected"/> but is refused on a
/// mailbox opened read-only by <c>EXAMINE</c> (RFC 3501 §6.3.2). Both of those need
/// configuration or session knowledge this layer must not see; they are the session's business,
/// and <see cref="ImapSessionContext.IsSelectedReadOnly"/> is what answers the second.
/// </para>
/// <para>
/// There is no <c>NextOnSuccess</c> counterpart to <see cref="Smtp.SmtpStateMachine"/>'s.
/// IMAP's state transitions are not a function of the verb alone — <c>SELECT</c> on a mailbox
/// that does not exist leaves the session authenticated and, per RFC 3501 §6.3.1, actually
/// deselects whatever was open first — so the transitions live in
/// <see cref="ImapSessionContext"/>, where the outcome is known, rather than in a table that
/// would have to guess at it.
/// </para>
/// </remarks>
public static class ImapStateMachine
{
    /// <summary>Every verb the sequencing table covers.</summary>
    /// <remarks>Kept here so the totality test can enumerate without reflecting over the enum's ordering.</remarks>
    public static IReadOnlyList<ImapVerb> AllVerbs { get; } = Enum.GetValues<ImapVerb>();

    /// <summary>Every state the sequencing table covers.</summary>
    public static IReadOnlyList<ImapSessionState> AllStates { get; } = Enum.GetValues<ImapSessionState>();

    /// <summary>
    /// Whether <paramref name="verb"/> is in sequence in <paramref name="state"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// False earns a tagged <c>BAD</c>. RFC 3501 §7.1.3 defines <c>BAD</c> as indicating "an
    /// error message from the server" for a command that was not understood, and §6 organises
    /// every command by the state it is "valid in" — §6.3's preamble lists the authenticated
    /// state's commands, §6.4's the selected state's — without naming the response a server owes
    /// a command sent outside its state.
    /// </para>
    /// <para>
    /// So <b>choosing <c>BAD</c> over <c>NO</c> is this product's decision, not a rule the RFC
    /// states</b>, and the reason is what the two words tell a client to do next. <c>NO</c>
    /// means the server understood the command and declined to perform it, which says the
    /// request was well-formed and invites a retry — and a client told <c>NO</c> for a command
    /// it sent in the wrong state will retry it in the wrong state. <c>BAD</c> says the request
    /// itself was wrong, which is what a client needs to hear in order to stop.
    /// </para>
    /// </remarks>
    public static bool IsInSequence(ImapSessionState state, ImapVerb verb) => state switch
    {
        // Connected, not yet logged in. RFC 3501 §6.2.
        ImapSessionState.NotAuthenticated => verb switch
        {
            // §6.1 - valid in any state.
            ImapVerb.Capability or ImapVerb.Noop or ImapVerb.Logout => true,

            ImapVerb.StartTls or ImapVerb.Authenticate or ImapVerb.Login => true,

            // Everything that needs an identity to mean anything.
            ImapVerb.Select or ImapVerb.Examine or ImapVerb.Create or ImapVerb.Delete or
                ImapVerb.Rename or ImapVerb.Subscribe or ImapVerb.Unsubscribe or ImapVerb.List or
                ImapVerb.Lsub or ImapVerb.Status or ImapVerb.Append => false,

            ImapVerb.Check or ImapVerb.Close or ImapVerb.Expunge or ImapVerb.Search or
                ImapVerb.Fetch or ImapVerb.Store or ImapVerb.Copy or ImapVerb.Move or
                ImapVerb.Unselect => false,

            ImapVerb.Idle or ImapVerb.Namespace => false,

            ImapVerb.Unknown => false,
            _ => false,
        },

        // Logged in, no mailbox open. RFC 3501 §6.3.
        ImapSessionState.Authenticated => verb switch
        {
            ImapVerb.Capability or ImapVerb.Noop or ImapVerb.Logout => true,

            ImapVerb.Select or ImapVerb.Examine or ImapVerb.Create or ImapVerb.Delete or
                ImapVerb.Rename or ImapVerb.Subscribe or ImapVerb.Unsubscribe or ImapVerb.List or
                ImapVerb.Lsub or ImapVerb.Status or ImapVerb.Append => true,

            // RFC 2177 states IDLE's legality only in its formal syntax (§4), as a comment on
            // the command production: ";; Valid only in Authenticated or Selected state". §3,
            // the specification proper, never says which state the command belongs to - so the
            // grammar is the normative statement here, not prose.
            ImapVerb.Idle => true,

            // RFC 2342 §4: "The NAMESPACE command is valid in the Authenticated and Selected
            // state."
            ImapVerb.Namespace => true,

            // §6.2: a client does not get to re-authenticate as someone else mid-session. The
            // session context refuses this a second time - see ImapSessionContext.Authenticate -
            // because a rule enforced in one place only is a rule with one bug between it and an
            // account takeover.
            ImapVerb.Login or ImapVerb.Authenticate => false,

            // RFC 3501 §6.2.1: STARTTLS is a not-authenticated-state command. Beyond sequencing,
            // negotiating TLS after credentials have already crossed the connection secures
            // nothing that mattered.
            ImapVerb.StartTls => false,

            ImapVerb.Check or ImapVerb.Close or ImapVerb.Expunge or ImapVerb.Search or
                ImapVerb.Fetch or ImapVerb.Store or ImapVerb.Copy or ImapVerb.Move or
                ImapVerb.Unselect => false,

            ImapVerb.Unknown => false,
            _ => false,
        },

        // A mailbox is open. RFC 3501 §6.4 - additional to §6.3, never instead of it; see the
        // class remarks.
        ImapSessionState.Selected => verb switch
        {
            ImapVerb.Capability or ImapVerb.Noop or ImapVerb.Logout => true,

            ImapVerb.Check or ImapVerb.Close or ImapVerb.Expunge or ImapVerb.Search or
                ImapVerb.Fetch or ImapVerb.Store or ImapVerb.Copy => true,

            // RFC 6851 §3.1: MOVE is a selected-state command.
            ImapVerb.Move => true,

            // RFC 3691 §2: UNSELECT "frees server's resources associated with the selected
            // mailbox and returns the server to the authenticated state" - CLOSE without the
            // implicit expunge.
            ImapVerb.Unselect => true,

            // Everything §6.3 allows, still allowed. RFC 3501 §6.3.1: SELECT while a mailbox is
            // already open deselects the old one first, which is how a client switches folders.
            ImapVerb.Select or ImapVerb.Examine or ImapVerb.Create or ImapVerb.Delete or
                ImapVerb.Rename or ImapVerb.Subscribe or ImapVerb.Unsubscribe or ImapVerb.List or
                ImapVerb.Lsub or ImapVerb.Status or ImapVerb.Append => true,

            ImapVerb.Idle or ImapVerb.Namespace => true,

            ImapVerb.Login or ImapVerb.Authenticate or ImapVerb.StartTls => false,

            ImapVerb.Unknown => false,
            _ => false,
        },

        // LOGOUT has been issued. RFC 3501 §6.1.3: the server sends an untagged BYE and closes.
        // Accepting anything now would mean continuing a session that has been told it is over.
        ImapSessionState.Logout => false,

        _ => false,
    };
}
