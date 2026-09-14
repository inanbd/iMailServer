using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;

namespace MailServer.Smtp.Tests;

public sealed class SmtpCapabilitiesTests
{
    private const long Limit = 36_700_160;

    private static SmtpCapabilityContext Context(
        SmtpListenerRole role,
        bool tls = false,
        bool authAvailable = true) =>
        new(role, tls, authAvailable, Limit);

    public static TheoryData<SmtpListenerRole, bool> EveryRoleAndTlsState()
    {
        TheoryData<SmtpListenerRole, bool> data = [];

        foreach (SmtpListenerRole role in Enum.GetValues<SmtpListenerRole>())
        {
            data.Add(role, false);
            data.Add(role, true);
        }

        return data;
    }

    // ---------------------------------------------------------------------------------------
    // AUTH. This is the capability that enforces "no plaintext SMTP AUTH over Internet".
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Auth_is_never_advertised_on_port_25(bool tls)
    {
        // Not even inside TLS. Port 25 is the MTA listener: it accepts mail for local domains
        // from strangers and has no business authenticating anyone. Offering AUTH there turns
        // the Internet-facing listener into a relay one credential away.
        IReadOnlyList<string> capabilities =
            SmtpCapabilities.For(Context(SmtpListenerRole.InboundMta, tls));

        capabilities.ShouldNotContain(c => c.StartsWith("AUTH", StringComparison.Ordinal));
    }

    [Fact]
    public void Auth_is_not_advertised_on_submission_before_tls()
    {
        // The whole defence. A client that is never offered AUTH does not send credentials in
        // the clear, so there is nothing on the wire to intercept.
        SmtpCapabilities.For(Context(SmtpListenerRole.Submission, tls: false))
            .ShouldNotContain(c => c.StartsWith("AUTH", StringComparison.Ordinal));
    }

    [Fact]
    public void Auth_is_advertised_on_submission_once_tls_is_active()
    {
        SmtpCapabilities.For(Context(SmtpListenerRole.Submission, tls: true))
            .ShouldContain("AUTH PLAIN LOGIN");
    }

    [Fact]
    public void Auth_is_advertised_on_implicit_tls_submission()
    {
        // Port 465 is encrypted from the first octet, so the TLS condition is met before the
        // banner is sent.
        SmtpCapabilities.For(Context(SmtpListenerRole.ImplicitTlsSubmission, tls: true))
            .ShouldContain("AUTH PLAIN LOGIN");
    }

    [Fact]
    public void Auth_is_not_advertised_while_authentication_is_not_implemented()
    {
        // Advertising a mechanism the server cannot perform sends clients into a failure they
        // cannot diagnose. The flag comes off when SASL lands with its own tests, in Milestone 7.
        SmtpCapabilities.For(Context(SmtpListenerRole.Submission, tls: true, authAvailable: false))
            .ShouldNotContain(c => c.StartsWith("AUTH", StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(EveryRoleAndTlsState))]
    public void Auth_appears_only_where_all_three_conditions_hold(SmtpListenerRole role, bool tls)
    {
        // Stated once over the whole matrix, so no combination goes untested.
        bool isSubmission = role is SmtpListenerRole.Submission or SmtpListenerRole.ImplicitTlsSubmission;
        bool shouldOffer = isSubmission && tls;

        bool offered = SmtpCapabilities.For(Context(role, tls))
            .Any(c => c.StartsWith("AUTH", StringComparison.Ordinal));

        offered.ShouldBe(shouldOffer, $"role {role}, TLS {tls}");
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(SmtpListenerRole.InboundMta)]
    [InlineData(SmtpListenerRole.Submission)]
    public void Starttls_is_advertised_before_tls_on_explicit_tls_listeners(SmtpListenerRole role)
    {
        SmtpCapabilities.For(Context(role, tls: false)).ShouldContain("STARTTLS");
    }

    [Theory]
    [MemberData(nameof(EveryRoleAndTlsState))]
    public void Starttls_is_never_advertised_once_tls_is_active(SmtpListenerRole role, bool tls)
    {
        // RFC 3207 §4.2. Offering it inside the tunnel invites a nested handshake, and a client
        // that took the offer would be renegotiating inside an existing session.
        if (!tls)
        {
            return;
        }

        SmtpCapabilities.For(Context(role, tls: true)).ShouldNotContain("STARTTLS");
    }

    [Fact]
    public void Starttls_is_not_advertised_on_the_implicit_tls_listener()
    {
        SmtpCapabilities.For(Context(SmtpListenerRole.ImplicitTlsSubmission, tls: true))
            .ShouldNotContain("STARTTLS");
    }

    // ---------------------------------------------------------------------------------------
    // The rest.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(EveryRoleAndTlsState))]
    public void The_always_available_extensions_are_always_advertised(SmtpListenerRole role, bool tls)
    {
        IReadOnlyList<string> capabilities = SmtpCapabilities.For(Context(role, tls));

        capabilities.ShouldContain("PIPELINING");
        capabilities.ShouldContain("8BITMIME");
        capabilities.ShouldContain("ENHANCEDSTATUSCODES");
        capabilities.ShouldContain($"SIZE {Limit}");
    }

    [Fact]
    public void Size_reflects_the_effective_limit_for_this_connection()
    {
        // A sender that sees SIZE refuses locally rather than transmitting megabytes it will be
        // told to discard, so a wrong number here wastes bandwidth on both sides.
        SmtpCapabilities.For(new SmtpCapabilityContext(SmtpListenerRole.InboundMta, false, false, 1_048_576))
            .ShouldContain("SIZE 1048576");
    }

    [Fact]
    public void A_zero_or_negative_size_limit_is_refused_rather_than_advertised()
    {
        // "SIZE 0" means "this server accepts no mail", which is never what an operator meant
        // to configure, and would be obeyed by every well-behaved sender on the Internet.
        Should.Throw<ArgumentOutOfRangeException>(
            () => SmtpCapabilities.For(new SmtpCapabilityContext(SmtpListenerRole.InboundMta, false, false, 0)));
    }

    [Theory]
    [MemberData(nameof(EveryRoleAndTlsState))]
    public void Nothing_unimplemented_is_advertised(SmtpListenerRole role, bool tls)
    {
        // docs/Standards.md: SMTPUTF8 is Partial and CHUNKING is not built. Advertising either
        // would have peers send what this server cannot yet handle - SMTPUTF8 in particular
        // makes a sender use addresses that would otherwise be downgraded.
        IReadOnlyList<string> capabilities = SmtpCapabilities.For(Context(role, tls));

        capabilities.ShouldNotContain("SMTPUTF8");
        capabilities.ShouldNotContain("CHUNKING");
        capabilities.ShouldNotContain("BDAT");
        capabilities.ShouldNotContain("DSN");
        capabilities.ShouldNotContain("BINARYMIME");
    }

    [Fact]
    public void An_extension_appears_only_when_its_flag_is_set()
    {
        SmtpCapabilityContext context = new(
            SmtpListenerRole.InboundMta,
            IsTlsActive: false,
            IsAuthenticationAvailable: false,
            MaxMessageSizeBytes: Limit,
            IsSmtpUtf8Available: true,
            IsChunkingAvailable: true);

        IReadOnlyList<string> capabilities = SmtpCapabilities.For(context);

        capabilities.ShouldContain("SMTPUTF8");
        capabilities.ShouldContain("CHUNKING");
    }

    [Fact]
    public void No_capability_line_contains_a_space_before_its_keyword_or_a_line_ending()
    {
        // EHLO keywords are parsed positionally by every client on the Internet. Whitespace or
        // a line ending in one of these ends the capability list early at the far end.
        foreach (SmtpListenerRole role in Enum.GetValues<SmtpListenerRole>())
        {
            foreach (string capability in SmtpCapabilities.For(Context(role, tls: false)))
            {
                capability.ShouldNotStartWith(" ");
                capability.ShouldNotContain("\r");
                capability.ShouldNotContain("\n");
                capability.Trim().ShouldBe(capability);
            }
        }
    }
}
