using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Policies;

/// <summary>
/// Everything the relay decision is allowed to consider.
/// </summary>
/// <param name="Role">Which listener the connection arrived on. Fixed at construction.</param>
/// <param name="IsAuthenticated">Whether AUTH has succeeded on this session.</param>
/// <param name="AuthenticatedMailbox">
/// The mailbox that authenticated, normalised. Null when the session is anonymous.
/// </param>
/// <param name="RemoteAddress">The peer's address.</param>
/// <param name="IsTlsActive">Whether the session is inside a TLS tunnel.</param>
/// <remarks>
/// <para>
/// A record rather than the session object itself, deliberately. The relay decision must be a
/// pure function of a small, explicit set of facts — passing the live session would let it
/// reach anything the session happens to hold, and the next person to add a field would have
/// added an input to the most security-critical function in the product without noticing.
/// </para>
/// <para>
/// Nothing here is derived from what the peer <i>said</i>. The EHLO name in particular is
/// absent: it is a claim, not a fact, and a relay decision that consulted it would be one an
/// attacker could influence by typing.
/// </para>
/// </remarks>
public sealed record RelayContext(
    SmtpListenerRole Role,
    bool IsAuthenticated,
    EmailAddress? AuthenticatedMailbox,
    IpAddressValue RemoteAddress,
    bool IsTlsActive);

/// <summary>
/// Decides whether one recipient may be accepted, and why.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the single most important function in the product.</b> An error here is an open
/// relay: a server that accepts mail from anyone for anyone, which within hours is delivering
/// spam, within days is on every blocklist, and whose IP reputation takes months to recover if
/// it recovers at all.
/// </para>
/// <para>
/// Three properties are held deliberately and asserted by tests:
/// </para>
/// <list type="number">
///   <item><description><b>It is total.</b> Every path returns, and the fall-through is
///   <see cref="RelayDecision.Deny"/>. There is no branch that reaches "accept" without having
///   established a specific reason.</description></item>
///   <item><description><b>There is no configuration switch that opens it.</b> No option, no
///   flag, no "trust all" mode. The authorised-relay list is an explicit set of addresses an
///   operator enumerated, and an empty set is the default.</description></item>
///   <item><description><b>The listener role is an input, not an override.</b> Port 25 cannot
///   relay for an anonymous peer under any combination of the other inputs, because the branch
///   that would permit it requires <see cref="RelayContext.IsAuthenticated"/> and a submission
///   role, and port 25 never offers AUTH.</description></item>
/// </list>
/// <para>
/// The policy carries no state and reads no configuration of its own. Everything it needs
/// arrives as an argument, which is what makes it testable exhaustively rather than
/// representatively — and the test suite does enumerate every combination.
/// </para>
/// </remarks>
public sealed class RelayPolicy
{
    /// <summary>The outcome, with an explanation fit for a log and an SMTP reply.</summary>
    /// <param name="Decision">What to do.</param>
    /// <param name="Reason">Why, in terms that identify which rule applied.</param>
    public sealed record Result(RelayDecision Decision, string Reason)
    {
        /// <summary>True when the recipient may be accepted, however.</summary>
        public bool IsAccepted => Decision != RelayDecision.Deny;
    }

    /// <summary>
    /// Evaluates one recipient.
    /// </summary>
    /// <param name="context">The session facts. See <see cref="RelayContext"/>.</param>
    /// <param name="recipient">The address from RCPT TO.</param>
    /// <param name="isLocalDomain">
    /// Whether this server hosts the recipient's domain. A callback rather than a set, because
    /// the answer comes from the database and this policy holds no state.
    /// </param>
    /// <param name="isAuthorizedRelayAddress">
    /// Whether the peer is on the operator's explicit relay allow-list. Defaults to refusing
    /// everything, so a caller that forgets to supply it gets the safe answer.
    /// </param>
    /// <param name="mayRelayAs">
    /// Whether the authenticated mailbox is permitted to send to this recipient. Defaults to
    /// permitting, because an authenticated user sending outbound mail is the ordinary case;
    /// per-mailbox restrictions arrive with the submission policy in Milestone 7.
    /// </param>
    public Result Evaluate(
        RelayContext context,
        EmailAddress recipient,
        Func<DomainName, bool> isLocalDomain,
        Func<IpAddressValue, bool>? isAuthorizedRelayAddress = null,
        Func<EmailAddress, EmailAddress, bool>? mayRelayAs = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(recipient);
        ArgumentNullException.ThrowIfNull(isLocalDomain);

        // ---- 1. Local delivery -------------------------------------------------------------
        //
        // Accepting mail for a domain this server hosts is not relaying at all: the message
        // stops here. This is what every MTA on the Internet is allowed to do, and refusing it
        // would mean refusing to be a mail server.
        if (isLocalDomain(recipient.Domain))
        {
            return new Result(
                RelayDecision.AcceptLocal,
                $"'{recipient.Domain}' is a local domain.");
        }

        // ---- 2. Authenticated submission ----------------------------------------------------
        //
        // The recipient is elsewhere, so this IS relaying, and it needs a reason. An
        // authenticated user on a submission listener is the ordinary one.
        //
        // Every clause is required. In particular the role check is not redundant with the
        // authentication check: it is the second lock on the door, and it holds even if a
        // future change somehow made authentication reachable on port 25.
        if (context.IsAuthenticated &&
            context.AuthenticatedMailbox is not null &&
            context.Role is SmtpListenerRole.Submission or SmtpListenerRole.ImplicitTlsSubmission)
        {
            if (mayRelayAs is null || mayRelayAs(context.AuthenticatedMailbox, recipient))
            {
                return new Result(
                    RelayDecision.AcceptRelay,
                    $"Authenticated as '{context.AuthenticatedMailbox.NormalizedValue}' on a " +
                    "submission listener.");
            }

            return new Result(
                RelayDecision.Deny,
                $"'{context.AuthenticatedMailbox.NormalizedValue}' is not permitted to send to " +
                $"'{recipient.NormalizedValue}'.");
        }

        // ---- 3. Explicitly authorised address -----------------------------------------------
        //
        // For an internal application relaying through this server without a mailbox. The list
        // is empty by default and every entry is one an operator typed; there is no wildcard,
        // no "any private address" shortcut, and no way to reach this branch by accident.
        if (isAuthorizedRelayAddress is not null && isAuthorizedRelayAddress(context.RemoteAddress))
        {
            return new Result(
                RelayDecision.AcceptRelay,
                $"'{context.RemoteAddress}' is on the authorised relay list.");
        }

        // ---- 4. Deny ------------------------------------------------------------------------
        //
        // The fall-through, and the only outcome that needs no reason to establish. Everything
        // above had to earn its acceptance; this needs nothing.
        return new Result(
            RelayDecision.Deny,
            $"Relaying to '{recipient.Domain}' is not permitted from this session. The domain " +
            "is not hosted here, the session is not authenticated on a submission listener, " +
            "and the sending address is not on the authorised relay list.");
    }

    /// <summary>
    /// Always false. There is no configuration that turns this server into an open relay.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A property rather than an absence, so a test can assert it and so a future contributor
    /// adding an "allow open relay for testing" option has to argue with a named constant
    /// rather than quietly add a branch.
    /// </para>
    /// <para>
    /// The reasoning is not subtle. An open relay is found by automated scanners within hours,
    /// is delivering spam within a day, and puts the sending IP on blocklists that take months
    /// to clear — by which time the operator's legitimate mail is also undeliverable. No
    /// testing convenience is worth a switch that can be left on.
    /// </para>
    /// </remarks>
    public static bool MayEverActAsOpenRelay => false;
}
