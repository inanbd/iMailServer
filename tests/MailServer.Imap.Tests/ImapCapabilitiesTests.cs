using MailServer.Domain.Enums;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapCapabilitiesTests
{
    private static ImapCapabilityContext Context(
        ImapListenerRole role = ImapListenerRole.Cleartext,
        bool tls = false,
        ImapSessionState state = ImapSessionState.NotAuthenticated,
        bool authAvailable = true,
        bool children = false) =>
        new(role, tls, state, authAvailable, IsChildrenAvailable: children);

    public static TheoryData<ImapListenerRole, bool, ImapSessionState> EveryRoleTlsAndState()
    {
        TheoryData<ImapListenerRole, bool, ImapSessionState> data = [];

        foreach (ImapListenerRole role in Enum.GetValues<ImapListenerRole>())
        {
            foreach (bool tls in new[] { false, true })
            {
                foreach (ImapSessionState state in Enum.GetValues<ImapSessionState>())
                {
                    data.Add(role, tls, state);
                }
            }
        }

        return data;
    }

    // ---------------------------------------------------------------------------------------
    // The mandatory atom.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void Imap4rev1_is_always_advertised(ImapListenerRole role, bool tls, ImapSessionState state)
    {
        // RFC 3501 section 7.2.1's one hard MUST: "The capability listing MUST include the atom
        // IMAP4rev1."
        ImapCapabilities.For(Context(role, tls, state)).ShouldContain(ImapCapabilities.Imap4Rev1);
    }

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void Imap4rev1_is_advertised_first(ImapListenerRole role, bool tls, ImapSessionState state)
    {
        // RFC 3501 section 9's grammar permits it anywhere in the listing, so this is an
        // interoperability choice rather than a conformance requirement - clients, proxies and
        // packet-capture readers check the first atom more often than they scan the list.
        ImapCapabilities.For(Context(role, tls, state))[0].ShouldBe(ImapCapabilities.Imap4Rev1);
    }

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void The_rfc_1730_compatibility_atom_is_never_advertised(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state)
    {
        // RFC 3501 section 9: a server offering RFC 1730 compatibility MUST list IMAP4 first.
        // This server offers none - IMAP4 has incompatible FETCH semantics - so emitting the
        // atom would claim support for a protocol nothing here implements.
        ImapCapabilities.For(Context(role, tls, state)).ShouldNotContain(ImapCapabilities.Imap4Legacy);
    }

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void No_capability_name_is_invented(ImapListenerRole role, bool tls, ImapSessionState state)
    {
        // RFC 3501 section 7.2.1: "A server MUST NOT offer unregistered or non-standard
        // capability names, unless such names are prefixed with an X." Every atom this server
        // can emit is IMAP4rev1's own or a registered extension. "Registered" rather than
        // "standards-track": AUTH=LOGIN names a SASL mechanism that is registered with IANA but
        // never became a standards-track RFC.
        string[] registered =
        [
            "IMAP4rev1", "STARTTLS", "LOGINDISABLED", "AUTH=PLAIN", "AUTH=LOGIN",
            "IDLE", "NAMESPACE", "UNSELECT", "MOVE", "LITERAL-",
        ];

        ImapCapabilityContext context = new(
            role, tls, state,
            IsAuthenticationAvailable: true,
            IsIdleAvailable: true,
            IsNamespaceAvailable: true,
            IsUnselectAvailable: true,
            IsMoveAvailable: true,
            IsLiteralMinusAvailable: true);

        foreach (string capability in ImapCapabilities.For(context))
        {
            registered.ShouldContain(capability);
        }
    }

    // ---------------------------------------------------------------------------------------
    // LOGINDISABLED and AUTH. Together, these are what keep a password off the wire.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Logindisabled_is_advertised_on_a_cleartext_connection()
    {
        // RFC 2595 section 3.2: "An IMAP server which implements STARTTLS MUST implement support
        // for the LOGINDISABLED capability on unencrypted connections." Unlike SMTP, silence is
        // not an option here: LOGIN is a mandatory IMAP4rev1 command every client already knows
        // exists, so its absence from the listing says nothing at all.
        ImapCapabilities.For(Context(ImapListenerRole.Cleartext, tls: false))
            .ShouldContain("LOGINDISABLED");
    }

    [Fact]
    public void No_authentication_mechanism_is_advertised_on_a_cleartext_connection()
    {
        // RFC 2595 section 9: PLAIN "MUST NOT be advertised or used unless a suitable TLS
        // encryption layer is active or backwards compatibility dictates otherwise" - and this
        // product declines that escape clause, having no pre-existing users to be compatible
        // with.
        ImapCapabilities.For(Context(ImapListenerRole.Cleartext, tls: false))
            .ShouldNotContain(c => c.StartsWith("AUTH=", StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void Logindisabled_and_an_authentication_mechanism_are_never_advertised_together(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state)
    {
        // The test this file exists for. A server that obeyed RFC 2595 section 3.2 and still
        // offered AUTHENTICATE PLAIN in the clear would advertise the refusal and leak the
        // password anyway, through the other command.
        IReadOnlyList<string> capabilities = ImapCapabilities.For(Context(role, tls, state));

        bool disabled = capabilities.Contains("LOGINDISABLED");
        bool offersMechanism = capabilities.Any(c => c.StartsWith("AUTH=", StringComparison.Ordinal));

        (disabled && offersMechanism).ShouldBeFalse(
            $"role {role}, tls {tls}, state {state} advertised both.");
    }

    [Fact]
    public void Authentication_replaces_logindisabled_once_tls_is_active()
    {
        IReadOnlyList<string> capabilities =
            ImapCapabilities.For(Context(ImapListenerRole.Cleartext, tls: true));

        capabilities.ShouldContain("AUTH=PLAIN");
        capabilities.ShouldContain("AUTH=LOGIN");
        capabilities.ShouldNotContain("LOGINDISABLED");
    }

    [Fact]
    public void Authentication_is_advertised_on_the_implicit_tls_listener()
    {
        // Port 993 is encrypted from the first octet, so the TLS condition is met before the
        // greeting is sent.
        ImapCapabilities.For(Context(ImapListenerRole.ImplicitTls, tls: true))
            .ShouldContain("AUTH=PLAIN");
    }

    [Fact]
    public void Logindisabled_is_advertised_even_inside_tls_while_authentication_is_unimplemented()
    {
        // The atom describes what this server will do, not merely whether the connection is
        // encrypted. Until the handler exists with tests, LOGIN is refused, so saying so is the
        // truth.
        IReadOnlyList<string> capabilities =
            ImapCapabilities.For(Context(ImapListenerRole.ImplicitTls, tls: true, authAvailable: false));

        capabilities.ShouldContain("LOGINDISABLED");
        capabilities.ShouldNotContain(c => c.StartsWith("AUTH=", StringComparison.Ordinal));
    }

    [Fact]
    public void An_authentication_mechanism_is_one_atom_each()
    {
        // RFC 3501 section 6.1.1: "A capability name which begins with AUTH= indicates that the
        // server supports that particular authentication mechanism." ESMTP's single
        // "AUTH PLAIN LOGIN" line copied into an IMAP listing would parse as three unregistered
        // atoms and advertise nothing usable.
        IReadOnlyList<string> capabilities =
            ImapCapabilities.For(Context(ImapListenerRole.Cleartext, tls: true));

        capabilities.ShouldContain("AUTH=PLAIN");
        capabilities.ShouldContain("AUTH=LOGIN");
        capabilities.ShouldNotContain("AUTH PLAIN LOGIN");
        capabilities.ShouldNotContain(c => c.Contains(' ', StringComparison.Ordinal));
    }

    [Fact]
    public void The_advertised_mechanisms_are_the_ones_the_server_implements()
    {
        // One list for both protocols rather than a second copy that could drift.
        ImapCapabilities.SaslMechanisms.ShouldBe(Domain.Smtp.SmtpCapabilities.SaslMechanisms);
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Starttls_is_advertised_on_a_cleartext_connection()
    {
        ImapCapabilities.For(Context(ImapListenerRole.Cleartext, tls: false))
            .ShouldContain("STARTTLS");
    }

    [Fact]
    public void Starttls_is_not_advertised_once_tls_is_active()
    {
        // Offering it inside the tunnel it created invites a nested handshake. The state check
        // would not stop this on its own: RFC 3501 section 6.2.1 leaves the session in the
        // not-authenticated state after a successful STARTTLS.
        ImapCapabilities.For(Context(ImapListenerRole.Cleartext, tls: true))
            .ShouldNotContain("STARTTLS");
    }

    [Theory]
    [InlineData(ImapSessionState.Authenticated)]
    [InlineData(ImapSessionState.Selected)]
    [InlineData(ImapSessionState.Logout)]
    public void Starttls_is_not_advertised_to_a_session_that_has_already_logged_in(ImapSessionState state)
    {
        // Cleartext AND already authenticated: the one shape that distinguishes the state
        // condition from the TLS condition. Without this case, deleting
        // "State == NotAuthenticated" from MayOfferStartTls leaves the whole suite green - the
        // other STARTTLS tests either set tls:true (so !IsTlsActive already fails) or use the
        // implicit-TLS role (so the role check already fails), and neither reaches the state
        // check at all.
        //
        // What it would mean in practice: a session that logged in over a cleartext 143
        // connection keeps being offered a command RFC 3501 section 6.2 makes illegal in its
        // state, and every attempt at it is answered BAD.
        ImapCapabilities.For(Context(ImapListenerRole.Cleartext, tls: false, state))
            .ShouldNotContain("STARTTLS");
    }

    [Fact]
    public void Starttls_is_advertised_only_while_the_session_could_still_use_it()
    {
        // The predicate stated as one property over the whole matrix, so no single condition can
        // be removed without a failure here.
        foreach (ImapListenerRole role in Enum.GetValues<ImapListenerRole>())
        {
            foreach (bool tls in new[] { false, true })
            {
                foreach (ImapSessionState state in Enum.GetValues<ImapSessionState>())
                {
                    bool expected = !tls &&
                                    role == ImapListenerRole.Cleartext &&
                                    state == ImapSessionState.NotAuthenticated;

                    ImapCapabilities.For(Context(role, tls, state)).Contains("STARTTLS").ShouldBe(
                        expected,
                        $"role {role}, tls {tls}, state {state}");
                }
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Starttls_is_never_advertised_on_the_implicit_tls_listener(bool tls)
    {
        // There is no honest moment on port 993 when STARTTLS is legal.
        ImapCapabilities.For(Context(ImapListenerRole.ImplicitTls, tls))
            .ShouldNotContain("STARTTLS");
    }

    // ---------------------------------------------------------------------------------------
    // State dependence. This is the structural difference from the ESMTP capability list.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapSessionState.Authenticated)]
    [InlineData(ImapSessionState.Selected)]
    [InlineData(ImapSessionState.Logout)]
    public void The_not_authenticated_state_commands_stop_being_advertised_after_login(
        ImapSessionState state)
    {
        // RFC 3501 section 6.2 makes STARTTLS, AUTHENTICATE and LOGIN not-authenticated-state
        // commands, all three. Continuing to advertise them would advertise three commands that
        // would now all be answered BAD - a mistake no client complains about, because it simply
        // never uses the atoms.
        IReadOnlyList<string> capabilities =
            ImapCapabilities.For(Context(ImapListenerRole.Cleartext, tls: true, state));

        capabilities.ShouldNotContain("STARTTLS");
        capabilities.ShouldNotContain("LOGINDISABLED");
        capabilities.ShouldNotContain(c => c.StartsWith("AUTH=", StringComparison.Ordinal));
    }

    [Fact]
    public void An_authenticated_session_is_still_told_what_the_server_can_do()
    {
        ImapCapabilityContext context = new(
            ImapListenerRole.ImplicitTls,
            IsTlsActive: true,
            ImapSessionState.Selected,
            IsAuthenticationAvailable: true,
            IsIdleAvailable: true);

        IReadOnlyList<string> capabilities = ImapCapabilities.For(context);

        capabilities.ShouldContain(ImapCapabilities.Imap4Rev1);
        capabilities.ShouldContain("IDLE");
    }

    [Fact]
    public void The_builder_answers_for_a_logged_out_session_rather_than_throwing()
    {
        // CAPABILITY after LOGOUT is not a thing, and the builder should never be reached. It
        // answers anyway for the reason ImapStateMachine is total: turning a harmless protocol
        // oddity into a dropped connection is the worse failure.
        Should.NotThrow(() => ImapCapabilities.For(Context(state: ImapSessionState.Logout)));
    }

    // ---------------------------------------------------------------------------------------
    // Nothing unimplemented is advertised.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void Nothing_unimplemented_is_advertised(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state)
    {
        // The flags default false and stay false until the commands they name have passing
        // tests. An IMAP client does not merely make a delivery decision from this list, it
        // rearranges how it talks to the server: one told IDLE stops polling and waits.
        IReadOnlyList<string> capabilities = ImapCapabilities.For(Context(role, tls, state));

        capabilities.ShouldNotContain("IDLE");
        capabilities.ShouldNotContain("NAMESPACE");
        capabilities.ShouldNotContain("UNSELECT");
        capabilities.ShouldNotContain("MOVE");
        capabilities.ShouldNotContain("UIDPLUS");
        capabilities.ShouldNotContain(ImapCapabilities.LiteralCapability);
    }

    [Fact]
    public void The_literal_capability_is_the_bounded_one()
    {
        // RFC 7888 section 1 defines both LITERAL+ (no bound on a non-synchronising literal) and
        // LITERAL- (4096 octets). docs/IMAP.md requires a hard cap, so this is not a LITERAL+
        // server. Advertising LITERAL+ and capping anyway leaves only RFC 7888 section 4's two
        // exits: read every declared byte and refuse anyway, or send BYE - which section 4 notes
        // "some naive clients are known to blindly reconnect" from, "introducing an infinite
        // loop". That is a reconnect loop inside a denial-of-service defence.
        ImapCapabilities.LiteralCapability.ShouldBe("LITERAL-");
    }

    [Fact]
    public void The_two_literal_capabilities_are_never_advertised_together()
    {
        // RFC 7888 section 5: "IMAP servers MUST NOT advertise both of these capabilities at the
        // same time."
        ImapCapabilityContext context = new(
            ImapListenerRole.Cleartext,
            IsTlsActive: true,
            ImapSessionState.NotAuthenticated,
            IsAuthenticationAvailable: true,
            IsLiteralMinusAvailable: true);

        IReadOnlyList<string> capabilities = ImapCapabilities.For(context);

        capabilities.ShouldContain("LITERAL-");
        capabilities.ShouldNotContain("LITERAL+");
    }

    // ---------------------------------------------------------------------------------------
    // The predicates, asserted directly.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void Login_is_disabled_exactly_when_no_mechanism_is_offered(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state)
    {
        // The expectation is spelled out from the RFCs rather than computed by calling
        // MayOfferAuthentication - which is what MustDisableLogin is implemented in terms of, so
        // asking it would make this "A == A" and it would survive the TLS check being deleted.
        // LOGIN is refused, and so must be declared refused, exactly when the session could
        // still issue it (RFC 3501 section 6.2 - not-authenticated state only) and this server
        // would not accept it (no TLS, per RFC 2595 section 9, or no implementation yet).
        ImapCapabilityContext context = Context(role, tls, state, authAvailable: true);

        bool expected = state == ImapSessionState.NotAuthenticated && !tls;

        ImapCapabilities.MustDisableLogin(context).ShouldBe(expected, $"{role}/{tls}/{state}");
        ImapCapabilities.For(context).Contains("LOGINDISABLED").ShouldBe(expected);
    }

    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void Login_stays_disabled_while_authentication_is_unimplemented(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state)
    {
        // The other half of the same predicate, held apart from it: with no implementation, the
        // refusal stands whatever the transport says.
        ImapCapabilityContext context = Context(role, tls, state, authAvailable: false);

        bool expected = state == ImapSessionState.NotAuthenticated;

        ImapCapabilities.MustDisableLogin(context).ShouldBe(expected, $"{role}/{tls}/{state}");
    }

    [Fact]
    public void The_builder_rejects_a_null_context()
    {
        Should.Throw<ArgumentNullException>(() => ImapCapabilities.For(null!));
        Should.Throw<ArgumentNullException>(() => ImapCapabilities.MayOfferStartTls(null!));
        Should.Throw<ArgumentNullException>(() => ImapCapabilities.MayOfferAuthentication(null!));
        Should.Throw<ArgumentNullException>(() => ImapCapabilities.MustDisableLogin(null!));
    }
    // ---------------------------------------------------------------------------------------
    // CHILDREN, which the attributes depend on.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3348 §3: "IMAP4 servers that support this extension MUST list the keyword CHILDREN
    /// in their CAPABILITY response." So the keyword is the licence to send \HasChildren at all,
    /// and a server sending the attribute without it is claiming an extension it has not
    /// announced.
    /// </summary>
    [Fact]
    public void Children_is_advertised_when_the_attributes_will_be_sent() =>
        ImapCapabilities.For(Context(children: true)).ShouldContain("CHILDREN");

    [Fact]
    public void Children_is_withheld_when_the_attributes_will_not_be_sent() =>
        ImapCapabilities.For(Context(children: false)).ShouldNotContain("CHILDREN");

    /// <summary>
    /// Unlike STARTTLS and LOGINDISABLED, this one does not depend on where the session has got
    /// to: LIST is an authenticated command, but a client reads CAPABILITY before logging in and
    /// decides then whether it can trust the absence of \HasChildren.
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryRoleTlsAndState))]
    public void Children_does_not_depend_on_the_session_state(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state) =>
        ImapCapabilities.For(Context(role, tls, state, children: true))
            .ShouldContain("CHILDREN");

    /// <summary>
    /// RFC 6154 §2: "There is no capability string related to the support of special-use
    /// attributes on the non-extended LIST command." The contrast with CHILDREN is the whole
    /// reason the two are not treated alike, so it is asserted rather than left in a comment.
    /// </summary>
    [Fact]
    public void No_special_use_capability_is_advertised()
    {
        IReadOnlyList<string> capabilities = ImapCapabilities.For(Context(children: true));

        capabilities.ShouldNotContain("SPECIAL-USE");
        capabilities.ShouldNotContain("LIST-EXTENDED");
    }
}
