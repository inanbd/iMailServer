using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.Smtp;

/// <summary>
/// The open-relay suite.
/// </summary>
/// <remarks>
/// <para>
/// Milestone 6's stated exit criterion. An error in the relay decision is an open relay: a
/// server that accepts mail from anyone for anyone, which within hours is delivering spam,
/// within days is on every blocklist, and whose IP reputation takes months to recover.
/// </para>
/// <para>
/// These tests are <b>exhaustive rather than representative</b>. The combination space is
/// small — three listener roles, authenticated or not, TLS or not, local or remote recipient —
/// so every combination is enumerated and asserted rather than a few being sampled. The point
/// of the exercise is that no combination is left unconsidered.
/// </para>
/// </remarks>
public sealed class RelayPolicyTests
{
    private readonly RelayPolicy _policy = new();

    private static readonly EmailAddress LocalRecipient =
        EmailAddress.Parse("alice@example.com");

    private static readonly EmailAddress RemoteRecipient =
        EmailAddress.Parse("victim@elsewhere.test");

    private static readonly EmailAddress Sender =
        EmailAddress.Parse("bob@example.com");

    private static readonly IpAddressValue Peer =
        IpAddressValue.Parse("198.51.100.7");

    /// <summary>example.com is hosted here; everything else is not.</summary>
    private static bool IsLocal(DomainName domain) =>
        domain.Value.Equals("example.com", StringComparison.OrdinalIgnoreCase);

    private static RelayContext Context(
        SmtpListenerRole role,
        bool authenticated = false,
        bool tls = false) =>
        new(role, authenticated, authenticated ? Sender : null, Peer, tls);

    // ---- The matrix -------------------------------------------------------------------------

    public static TheoryData<SmtpListenerRole, bool, bool> EveryCombination
    {
        get
        {
            TheoryData<SmtpListenerRole, bool, bool> data = [];

            foreach (SmtpListenerRole role in Enum.GetValues<SmtpListenerRole>())
            {
                foreach (bool authenticated in (bool[])[false, true])
                {
                    foreach (bool tls in (bool[])[false, true])
                    {
                        data.Add(role, authenticated, tls);
                    }
                }
            }

            return data;
        }
    }

    /// <summary>
    /// A local recipient is always accepted. This is what being a mail server means.
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryCombination))]
    public void A_local_recipient_is_accepted_in_every_session_state(
        SmtpListenerRole role,
        bool authenticated,
        bool tls)
    {
        RelayPolicy.Result result = _policy.Evaluate(
            Context(role, authenticated, tls),
            LocalRecipient,
            IsLocal);

        result.Decision.ShouldBe(RelayDecision.AcceptLocal);
    }

    /// <summary>
    /// <b>The test this milestone exists to pass.</b> An unauthenticated session may never
    /// relay, whatever listener it arrived on and whether or not TLS is active.
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryCombination))]
    public void An_unauthenticated_session_can_never_relay(
        SmtpListenerRole role,
        bool authenticated,
        bool tls)
    {
        if (authenticated)
        {
            return;
        }

        RelayPolicy.Result result = _policy.Evaluate(
            Context(role, authenticated: false, tls),
            RemoteRecipient,
            IsLocal);

        result.Decision.ShouldBe(
            RelayDecision.Deny,
            $"an anonymous session on {role} with TLS={tls} must not relay");
    }

    /// <summary>
    /// Port 25 may never relay, even for a session that has somehow authenticated.
    /// </summary>
    /// <remarks>
    /// AUTH is never advertised on port 25, so this state should be unreachable. The check
    /// exists anyway: it is the second lock on the door, and it holds even if a future change
    /// made authentication reachable there. A defence that depends on one other component
    /// staying correct is not a defence.
    /// </remarks>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Port_25_never_relays_even_if_the_session_claims_to_be_authenticated(bool tls)
    {
        RelayPolicy.Result result = _policy.Evaluate(
            Context(SmtpListenerRole.InboundMta, authenticated: true, tls),
            RemoteRecipient,
            IsLocal);

        result.Decision.ShouldBe(RelayDecision.Deny);
    }

    [Theory]
    [InlineData(SmtpListenerRole.Submission)]
    [InlineData(SmtpListenerRole.ImplicitTlsSubmission)]
    public void An_authenticated_submission_session_may_relay(SmtpListenerRole role)
    {
        RelayPolicy.Result result = _policy.Evaluate(
            Context(role, authenticated: true, tls: true),
            RemoteRecipient,
            IsLocal);

        result.Decision.ShouldBe(RelayDecision.AcceptRelay);
        result.Reason.ShouldContain(Sender.NormalizedValue);
    }

    /// <summary>
    /// A session flagged authenticated but carrying no mailbox must not relay.
    /// </summary>
    /// <remarks>
    /// An inconsistent state that should be unreachable, which is exactly why it is asserted:
    /// "authenticated" with nobody to attribute the mail to is a bug, and the safe response to
    /// a bug in an authentication flag is to refuse.
    /// </remarks>
    [Fact]
    public void An_authenticated_session_with_no_mailbox_may_not_relay()
    {
        RelayContext inconsistent = new(
            SmtpListenerRole.Submission,
            IsAuthenticated: true,
            AuthenticatedMailbox: null,
            Peer,
            IsTlsActive: true);

        _policy.Evaluate(inconsistent, RemoteRecipient, IsLocal)
            .Decision.ShouldBe(RelayDecision.Deny);
    }

    // ---- The authorised relay list ------------------------------------------------------------

    [Fact]
    public void An_address_on_the_authorised_relay_list_may_relay()
    {
        RelayPolicy.Result result = _policy.Evaluate(
            Context(SmtpListenerRole.InboundMta),
            RemoteRecipient,
            IsLocal,
            isAuthorizedRelayAddress: ip => ip == Peer);

        result.Decision.ShouldBe(RelayDecision.AcceptRelay);
        result.Reason.ShouldContain("authorised relay list");
    }

    /// <summary>
    /// The default is refusal: a caller that does not supply the list gets the safe answer.
    /// </summary>
    [Fact]
    public void Omitting_the_authorised_relay_list_refuses_everything()
    {
        _policy.Evaluate(Context(SmtpListenerRole.InboundMta), RemoteRecipient, IsLocal)
            .Decision.ShouldBe(RelayDecision.Deny);
    }

    [Fact]
    public void An_address_not_on_the_list_may_not_relay()
    {
        _policy.Evaluate(
                Context(SmtpListenerRole.InboundMta),
                RemoteRecipient,
                IsLocal,
                isAuthorizedRelayAddress: static _ => false)
            .Decision.ShouldBe(RelayDecision.Deny);
    }

    // ---- Per-mailbox restriction ----------------------------------------------------------------

    [Fact]
    public void A_mailbox_refused_by_the_submission_policy_may_not_relay()
    {
        RelayPolicy.Result result = _policy.Evaluate(
            Context(SmtpListenerRole.Submission, authenticated: true, tls: true),
            RemoteRecipient,
            IsLocal,
            mayRelayAs: static (_, _) => false);

        result.Decision.ShouldBe(RelayDecision.Deny);
        result.Reason.ShouldContain("not permitted to send to");
    }

    /// <summary>
    /// A per-mailbox refusal must not fall through into the authorised-address branch.
    /// </summary>
    /// <remarks>
    /// The subtle failure this guards: if the submission branch merely declined to return
    /// rather than returning Deny, a refused mailbox sending from an allow-listed address
    /// would be relayed anyway — and the refusal would appear to work everywhere it was tested
    /// from a different address.
    /// </remarks>
    [Fact]
    public void A_refused_mailbox_does_not_fall_through_to_the_address_list()
    {
        RelayPolicy.Result result = _policy.Evaluate(
            Context(SmtpListenerRole.Submission, authenticated: true, tls: true),
            RemoteRecipient,
            IsLocal,
            isAuthorizedRelayAddress: static _ => true,
            mayRelayAs: static (_, _) => false);

        result.Decision.ShouldBe(RelayDecision.Deny);
    }

    // ---- Structural guarantees --------------------------------------------------------------

    /// <summary>
    /// The rule that must never change, asserted rather than merely documented.
    /// </summary>
    [Fact]
    public void There_is_no_configuration_that_makes_this_an_open_relay()
    {
        RelayPolicy.MayEverActAsOpenRelay.ShouldBeFalse();
    }

    /// <summary>
    /// Deny is the default of the enum, so a zero-initialised or un-assigned decision refuses.
    /// </summary>
    /// <remarks>
    /// Not an accident and worth pinning. A struct field that was never set, a deserialised
    /// value with a missing property, or a switch that fell through all produce the enum's
    /// zero value — and the safe thing for all three is refusal.
    /// </remarks>
    [Fact]
    public void The_default_relay_decision_is_deny()
    {
        default(RelayDecision).ShouldBe(RelayDecision.Deny);
    }

    /// <summary>
    /// Subdomains of a local domain are not automatically local.
    /// </summary>
    /// <remarks>
    /// <c>mail.example.com</c> is a different domain from <c>example.com</c> as far as delivery
    /// is concerned, and treating one as the other would accept mail for addresses this server
    /// has no mailboxes for — which then bounces, from a server that already said yes.
    /// </remarks>
    [Fact]
    public void A_subdomain_of_a_local_domain_is_not_automatically_local()
    {
        _policy.Evaluate(
                Context(SmtpListenerRole.InboundMta),
                EmailAddress.Parse("alice@sub.example.com"),
                IsLocal)
            .Decision.ShouldBe(RelayDecision.Deny);
    }

    [Fact]
    public void Local_domain_matching_is_case_insensitive()
    {
        _policy.Evaluate(
                Context(SmtpListenerRole.InboundMta),
                EmailAddress.Parse("alice@EXAMPLE.COM"),
                IsLocal)
            .Decision.ShouldBe(RelayDecision.AcceptLocal);
    }

    /// <summary>
    /// Every refusal explains which rule applied, because a bounce that says only "relay
    /// denied" tells a legitimate sender nothing about what to fix.
    /// </summary>
    [Fact]
    public void A_refusal_explains_why()
    {
        RelayPolicy.Result result = _policy.Evaluate(
            Context(SmtpListenerRole.InboundMta),
            RemoteRecipient,
            IsLocal);

        result.Reason.ShouldContain("not hosted here");
        result.Reason.ShouldContain("not authenticated");
        result.Reason.ShouldContain("authorised relay list");
    }
}
