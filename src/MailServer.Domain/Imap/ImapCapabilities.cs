using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;

namespace MailServer.Domain.Imap;

/// <summary>What this connection may be told about.</summary>
/// <param name="Role">The listener the client reached.</param>
/// <param name="IsTlsActive">Whether the connection is already encrypted.</param>
/// <param name="State">
/// Where the session has got to. Unlike <see cref="SmtpCapabilityContext"/>, this is required —
/// see <see cref="ImapCapabilities"/>'s remarks on why an IMAP capability list is
/// state-dependent and an ESMTP one is not.
/// </param>
/// <param name="IsAuthenticationAvailable">
/// Whether <c>LOGIN</c>/<c>AUTHENTICATE</c> are implemented and enabled. False until the IMAP
/// authentication handler exists with passing tests.
/// </param>
/// <param name="IsChildrenAvailable">
/// Whether RFC 3348's <c>\HasChildren</c> and <c>\HasNoChildren</c> are sent on <c>LIST</c>.
/// </param>
/// <param name="IsIdleAvailable">Whether RFC 2177 <c>IDLE</c> is implemented and enabled.</param>
/// <param name="IsNamespaceAvailable">Whether RFC 2342 <c>NAMESPACE</c> is implemented and enabled.</param>
/// <param name="IsUnselectAvailable">Whether RFC 3691 <c>UNSELECT</c> is implemented and enabled.</param>
/// <param name="IsMoveAvailable">Whether RFC 6851 <c>MOVE</c> is implemented and enabled.</param>
/// <param name="IsLiteralMinusAvailable">
/// Whether RFC 7888 <c>LITERAL-</c> is implemented and enabled. Note <c>LITERAL-</c>, not
/// <c>LITERAL+</c>; see <see cref="ImapCapabilities.LiteralCapability"/>.
/// </param>
public sealed record ImapCapabilityContext(
    ImapListenerRole Role,
    bool IsTlsActive,
    ImapSessionState State,
    bool IsAuthenticationAvailable,
    bool IsChildrenAvailable = false,
    bool IsIdleAvailable = false,
    bool IsNamespaceAvailable = false,
    bool IsUnselectAvailable = false,
    bool IsMoveAvailable = false,
    bool IsLiteralMinusAvailable = false);

/// <summary>
/// Builds the <c>CAPABILITY</c> listing.
/// </summary>
/// <remarks>
/// <para>
/// <b>Advertising an extension that is not honoured is worse than not advertising it</b>, for
/// the reason <see cref="SmtpCapabilities"/> gives and then some: an IMAP client does not merely
/// make a delivery decision from this list, it rearranges how it talks to the server for the
/// rest of the connection. A client told <c>IDLE</c> stops polling and waits. A client told
/// <c>UIDPLUS</c> reads <c>APPENDUID</c> out of a response that will not contain one. So every
/// optional atom is behind a flag that is only turned on when the commands it names have passing
/// tests — the same mechanism, and the same discipline, as
/// <see cref="SmtpCapabilityContext.IsChunkingAvailable"/>.
/// </para>
/// <para>
/// <b>There is deliberately no UIDPLUS flag.</b> Every other extension here is one whose
/// commands this server can already at least parse, so turning its flag on is the only step
/// between "unimplemented" and "implemented". RFC 4315 is not: its <c>UID EXPUNGE</c> form is
/// refused by <see cref="ImapCommand.SupportsUidPrefix"/>, so a flag for it would let a future
/// implementer advertise an extension whose central command the parser answers <c>BAD</c> —
/// with the build staying green, because a flag that is off is a flag nothing tests. An
/// extension gets a flag once the parser can carry it, and not before.
/// </para>
/// <para>
/// <b>The list is state-dependent, and this is the structural difference from ESMTP's.</b> RFC
/// 3501 §6.2 makes <c>STARTTLS</c>, <c>AUTHENTICATE</c> and <c>LOGIN</c> not-authenticated-state
/// commands — all three of them. Every security-relevant atom here therefore describes a command
/// that is illegal once the session has logged in, so continuing to advertise them to an
/// authenticated client advertises three commands that would now all be answered <c>BAD</c>.
/// ESMTP has no equivalent: <c>EHLO</c> may be re-issued at any point and RFC 4954 does not
/// require the <c>AUTH</c> line to disappear afterwards, which is why
/// <see cref="SmtpCapabilityContext"/> needs no state field and this one does. The mistake is
/// quiet if made — no client complains, it simply never uses the atoms.
/// </para>
/// <para>
/// <b><c>LOGINDISABLED</c> is the atom that keeps a password off the wire</b>, and it is the
/// inverse of how SMTP does the same job. SMTP's defence is silence: <c>AUTH</c> is simply never
/// advertised without TLS, and a client never offered a mechanism does not send credentials.
/// IMAP cannot use silence, because <c>LOGIN</c> is not an extension — it is a mandatory
/// IMAP4rev1 command every client already knows exists, so its absence from this list says
/// nothing at all. RFC 2595 §3.2 supplies the missing signal and makes it a MUST: "An IMAP
/// server which implements STARTTLS MUST implement support for the LOGINDISABLED capability on
/// unencrypted connections", and a complying client "MUST NOT issue the LOGIN command if this
/// capability is present". RFC 3501 §6.2.3 requires the matching refusal, so the atom is a
/// promise about behaviour, not a hint.
/// </para>
/// <para>
/// <c>LOGINDISABLED</c> and an <c>AUTH=</c> atom are mutually exclusive by construction here,
/// which is deliberate: obeying RFC 2595 §3.2 while still offering <c>AUTH=PLAIN</c> in the
/// clear would advertise the refusal and leak the password anyway, through the other command.
/// RFC 2595 §9's rule on PLAIN is that it "MUST NOT be advertised or used unless a suitable TLS
/// encryption layer is active or backwards compatibility dictates otherwise" — and this product
/// declines the escape clause. "Backwards compatibility dictates otherwise" is an allowance for
/// servers with existing users on clients that cannot do TLS; a server shipping its first IMAP
/// listener has no such users, so there is nothing here for it to excuse.
/// </para>
/// </remarks>
public static class ImapCapabilities
{
    /// <summary>The mandatory atom. RFC 3501 §7.2.1: the listing MUST include it.</summary>
    public const string Imap4Rev1 = "IMAP4rev1";

    /// <summary>
    /// The RFC 1730 compatibility atom, which this server never emits.
    /// </summary>
    /// <remarks>
    /// Named here so it can be tested for and refused rather than merely omitted by accident.
    /// RFC 3501 §9's grammar carries the only first-position requirement in the whole listing:
    /// "Servers which offer RFC 1730 compatibility MUST list <c>IMAP4</c> as the first
    /// capability." This server offers no such compatibility — IMAP4 is a 1994 protocol with
    /// incompatible <c>FETCH</c> semantics — so emitting the atom would claim support for a
    /// protocol nothing here implements.
    /// </remarks>
    public const string Imap4Legacy = "IMAP4";

    /// <summary>
    /// RFC 7888's bounded non-synchronising literals.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>LITERAL-</c>, deliberately, and not <c>LITERAL+</c>.</b> RFC 7888 §1 defines both:
    /// they permit the same <c>{n+}</c> syntax, but <c>LITERAL-</c> caps a non-synchronising
    /// literal at 4096 octets while <c>LITERAL+</c> places no bound on one at all. §5 forbids
    /// advertising both at once.
    /// </para>
    /// <para>
    /// <c>docs/IMAP.md</c> settled the behaviour long before the atom was chosen: "<c>{n}</c> and
    /// <c>{n+}</c> need hard caps … without a cap is a trivial memory exhaustion". A server that
    /// caps literals has therefore already decided it is not a <c>LITERAL+</c> server, whatever
    /// vocabulary the surrounding documentation grew up using. Advertising <c>LITERAL+</c> and
    /// then enforcing a cap leaves only the two exits RFC 7888 §4 spells out — read every
    /// declared byte and refuse the command anyway, wasting exactly the bandwidth an attacker
    /// wanted spent, or send <c>BYE</c> and drop the connection, which §4 notes "some naive
    /// clients are known to blindly reconnect" from, "introducing an infinite loop". That is a
    /// reconnect loop built into a denial-of-service defence. <c>LITERAL-</c> states the cap up
    /// front instead, and a complying client sends a synchronising literal above it, which this
    /// server can refuse before a single octet of it arrives.
    /// </para>
    /// </remarks>
    public const string LiteralCapability = "LITERAL-";

    /// <summary>
    /// The SASL mechanisms offered once authentication is available and TLS is up.
    /// </summary>
    /// <remarks>
    /// One list for both protocols, not a second copy. The mechanisms themselves are
    /// protocol-independent — RFC 3501 §6.2.2 only specifies that this protocol's SASL service
    /// name is <c>imap</c>, and neither PLAIN (RFC 4616) nor LOGIN carries a service name — and
    /// <see cref="SaslMechanisms.IsSupported"/> already reads the same property, so joining that
    /// arrangement is what keeps the advertised set and the implemented set from drifting apart
    /// in one protocol and not the other.
    /// </remarks>
    public static IReadOnlyList<string> SaslMechanisms => SmtpCapabilities.SaslMechanisms;

    /// <summary>Builds the listing, in the order it is sent.</summary>
    /// <remarks>
    /// <para>
    /// <see cref="Imap4Rev1"/> is emitted first. RFC 3501 §9's grammar — <c>capability-data =
    /// "CAPABILITY" *(SP capability) SP "IMAP4rev1" *(SP capability)</c> — permits it anywhere,
    /// so this is an interoperability choice rather than a conformance requirement, and worth
    /// naming as one: every example in §6.1.1 and §7.2.1 shows it first, and clients, proxies
    /// and anyone reading a packet capture check the first atom more often than they scan the
    /// list.
    /// </para>
    /// <para>
    /// Every atom here is either an IMAP4rev1 atom or a registered extension. RFC 3501 §7.2.1:
    /// "A server MUST NOT offer unregistered or non-standard capability names, unless such names
    /// are prefixed with an <c>X</c>." This server emits no <c>X</c> atoms; there is nothing here
    /// it invented. Note "registered" rather than "standards-track": <c>AUTH=LOGIN</c> names a
    /// SASL mechanism that is registered with IANA but never became a standards-track RFC, which
    /// is a fair description of how widely clients implement it and not a claim about its status.
    /// </para>
    /// <para>
    /// Total over every state, including <see cref="ImapSessionState.Logout"/>, which should
    /// never reach this method — a <c>CAPABILITY</c> after <c>LOGOUT</c> is not a thing. It
    /// answers rather than throwing for the reason <see cref="ImapStateMachine"/> is total:
    /// turning a harmless protocol oddity into a dropped connection is a worse failure than
    /// answering it.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> For(ImapCapabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        List<string> capabilities = [Imap4Rev1];

        if (context.IsLiteralMinusAvailable)
        {
            capabilities.Add(LiteralCapability);
        }

        // RFC 3348 §3: "IMAP4 servers that support this extension MUST list the keyword CHILDREN
        // in their CAPABILITY response." So this is not optional decoration - it is the licence
        // to send the two attributes at all, and ImapMailboxAttribute.HasChildren's remarks
        // record the contrast with RFC 6154's special-use attributes, which need no capability.
        if (context.IsChildrenAvailable)
        {
            capabilities.Add("CHILDREN");
        }

        if (context.IsIdleAvailable)
        {
            capabilities.Add("IDLE");
        }

        if (context.IsNamespaceAvailable)
        {
            capabilities.Add("NAMESPACE");
        }

        if (context.IsUnselectAvailable)
        {
            capabilities.Add("UNSELECT");
        }

        if (context.IsMoveAvailable)
        {
            capabilities.Add("MOVE");
        }

        if (MayOfferStartTls(context))
        {
            capabilities.Add("STARTTLS");
        }

        // Only one of these two ever appears, and only before the session has logged in. See the
        // class remarks: advertising the refusal while still offering a cleartext mechanism
        // would leak the password through the other command.
        if (context.State == ImapSessionState.NotAuthenticated)
        {
            if (MayOfferAuthentication(context))
            {
                foreach (string mechanism in SaslMechanisms)
                {
                    // One atom per mechanism - "AUTH=PLAIN AUTH=LOGIN". Not ESMTP's single
                    // "AUTH PLAIN LOGIN" line, which inside an IMAP listing would parse as three
                    // unregistered atoms and advertise nothing usable.
                    capabilities.Add($"AUTH={mechanism}");
                }
            }
            else
            {
                capabilities.Add("LOGINDISABLED");
            }
        }

        return capabilities;
    }

    /// <summary>Whether <c>STARTTLS</c> may be offered.</summary>
    /// <remarks>
    /// Three conditions. Not once TLS is active — offering it inside the tunnel it created
    /// invites a nested handshake, and RFC 3501 §6.2.1 leaves the session in the
    /// not-authenticated state afterwards, so the state check alone would not stop a second one.
    /// Not on the implicit-TLS listener, where the connection was encrypted before the greeting.
    /// And not once the session has identified itself, because §6.2 makes it a
    /// not-authenticated-state command and TLS negotiated after the credentials have already
    /// crossed the connection secures nothing that mattered.
    /// </remarks>
    public static bool MayOfferStartTls(ImapCapabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return !context.IsTlsActive &&
               context.Role != ImapListenerRole.ImplicitTls &&
               context.State == ImapSessionState.NotAuthenticated;
    }

    /// <summary>
    /// Whether a SASL mechanism may be offered.
    /// </summary>
    /// <remarks>
    /// Three conditions, all required, and dropping any one of them is an incident. Without the
    /// TLS check, credentials cross the network in the clear — RFC 2595 §9's MUST NOT. Without
    /// the availability check, the server advertises a mechanism it cannot perform. Without the
    /// state check, it advertises one to a session that may no longer use it.
    /// <para>
    /// There is no listener-role condition, and that is the one difference from
    /// <see cref="SmtpCapabilities.MayOfferAuthentication"/>. SMTP needs one because port 25
    /// exists to accept mail from anonymous peers, and an authenticating port 25 is an open
    /// relay waiting to happen. IMAP has no such listener: both ports exist so a mailbox owner
    /// can reach their own mail, and neither has anything to offer a client that has not proven
    /// who it is. The TLS condition is what distinguishes them, and it already does.
    /// </para>
    /// </remarks>
    public static bool MayOfferAuthentication(ImapCapabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.IsAuthenticationAvailable)
        {
            return false;
        }

        if (context.State != ImapSessionState.NotAuthenticated)
        {
            return false;
        }

        return context.IsTlsActive;
    }

    /// <summary>
    /// Whether <c>LOGINDISABLED</c> must be advertised.
    /// </summary>
    /// <remarks>
    /// Exactly when the session could still issue <c>LOGIN</c> and this server would refuse it:
    /// RFC 2595 §3.2's condition, stated as the one thing it actually means rather than as a
    /// second, independently maintained set of conditions that could drift from
    /// <see cref="MayOfferAuthentication"/>'s.
    /// </remarks>
    public static bool MustDisableLogin(ImapCapabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.State == ImapSessionState.NotAuthenticated && !MayOfferAuthentication(context);
    }
}
