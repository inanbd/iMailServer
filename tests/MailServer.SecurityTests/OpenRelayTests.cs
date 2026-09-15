using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.SecurityTests;

/// <summary>
/// A directory that hosts one domain and nothing else.
/// </summary>
/// <remarks>
/// It cannot express an acceptance — <see cref="ISmtpDirectory"/> has no method that returns
/// one. That is the point of the port's shape, and it means this fake cannot open a relay even
/// if it were written maliciously.
/// </remarks>
internal sealed class SingleDomainDirectory : ISmtpDirectory
{
    public HashSet<string> AuthorizedRelayAddresses { get; } = [];

    public ValueTask<bool> IsLocalDomainAsync(DomainName domain, CancellationToken cancellationToken) =>
        ValueTask.FromResult(string.Equals(domain.Value, "example.com", StringComparison.OrdinalIgnoreCase));

    public ValueTask<LocalRecipientStatus> InspectLocalRecipientAsync(
        EmailAddress recipient,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(LocalRecipientStatus.Deliverable);

    public ValueTask<bool> IsAuthorizedRelayAddressAsync(
        IpAddressValue address,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(AuthorizedRelayAddresses.Contains(address.Value));

    public ValueTask<bool> MayRelayAsAsync(
        EmailAddress authenticatedMailbox,
        EmailAddress recipient,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(true);
}

/// <summary>
/// The open-relay suite. An exit criterion for Milestone 6.
/// </summary>
/// <remarks>
/// <para>
/// <c>docs/SMTP.md</c>: "The test suite attempts a relay through every listener role in every
/// authentication state." That is what this does — not by reasoning about the relay policy, but
/// by driving the command processor the way a spammer drives it and asserting on the reply code
/// that comes back.
/// </para>
/// <para>
/// <c>RelayPolicyTests</c> in the Domain suite proves the decision function is correct.
/// These tests prove the server actually asks it, which is the half that a refactor breaks.
/// </para>
/// </remarks>
public sealed class OpenRelayTests
{
    private const string ForeignRecipient = "victim@elsewhere.example";
    private const string LocalRecipient = "user@example.com";

    private readonly SingleDomainDirectory _directory = new();

    /// <summary>Every role, crossed with every security state a session can reach.</summary>
    public static TheoryData<SmtpListenerRole, bool, bool> EveryRoleAndSecurityState()
    {
        TheoryData<SmtpListenerRole, bool, bool> data = [];

        foreach (SmtpListenerRole role in Enum.GetValues<SmtpListenerRole>())
        {
            foreach (bool tls in (bool[])[false, true])
            {
                foreach (bool authenticated in (bool[])[false, true])
                {
                    // Authenticating without TLS is refused by the session itself, so the
                    // combination is unreachable rather than untested.
                    if (authenticated && !tls)
                    {
                        continue;
                    }

                    data.Add(role, tls, authenticated);
                }
            }
        }

        return data;
    }

    private (SmtpCommandProcessor Processor, SmtpSessionContext Session) Build(
        SmtpListenerRole role,
        bool tls,
        bool authenticated,
        string remoteAddress = "203.0.113.7")
    {
        SmtpSessionContext session = new(
            role,
            IpAddressValue.Parse(remoteAddress),
            new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero),
            tls);

        if (authenticated)
        {
            session.Authenticate(EmailAddress.Parse("insider@example.com"));
        }

        SmtpCommandProcessor processor = new(
            session,
            new SmtpProcessorOptions("mail.example.com", "AetherMail", 100, 1_000_000, IsAuthenticationAvailable: true),
            _directory,
            new RelayPolicy(),
            NullLogger.Instance);

        return (processor, session);
    }

    private static async Task<SmtpReply> SendAsync(SmtpCommandProcessor processor, string line) =>
        (await processor.ExecuteAsync(SmtpCommand.Parse(line), default)).Reply;

    /// <summary>Attempts to relay to a foreign domain and returns the reply to RCPT TO.</summary>
    private static async Task<SmtpReply> AttemptRelayAsync(
        SmtpCommandProcessor processor,
        string recipient = ForeignRecipient)
    {
        await SendAsync(processor, "EHLO spammer.example.net");
        await SendAsync(processor, "MAIL FROM:<spammer@example.net>");

        return await SendAsync(processor, $"RCPT TO:<{recipient}>");
    }

    // ---------------------------------------------------------------------------------------
    // The matrix.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(EveryRoleAndSecurityState))]
    public async Task An_unauthenticated_session_can_never_relay(
        SmtpListenerRole role,
        bool tls,
        bool authenticated)
    {
        if (authenticated)
        {
            return;
        }

        (SmtpCommandProcessor processor, SmtpSessionContext session) = Build(role, tls, authenticated: false);

        SmtpReply reply = await AttemptRelayAsync(processor);

        reply.IsSuccess.ShouldBeFalse(
            $"role {role}, TLS {tls}: an unauthenticated session relayed to a foreign domain.");

        session.Recipients.ShouldBeEmpty(
            $"role {role}, TLS {tls}: a refused recipient reached the envelope.");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Port_25_can_never_relay_however_the_session_presents_itself(bool tls)
    {
        // The MTA listener accepts mail for local domains from strangers. It has no
        // authentication to offer and no relaying to do, and no state a peer can reach changes
        // that.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls, authenticated: false);

        SmtpReply reply = await AttemptRelayAsync(processor);

        reply.Code.ShouldBe(554);
        reply.EnhancedStatus.ShouldBe("5.7.1");
        session.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public async Task An_authenticated_session_on_port_25_still_cannot_relay()
    {
        // Unreachable in practice - AUTH is never advertised there - and refused anyway. The
        // relay policy is told the role, not asked to infer it, so a session that somehow
        // authenticated on the MTA listener is still not a submission session.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: true, authenticated: true);

        SmtpReply reply = await AttemptRelayAsync(processor);

        reply.Code.ShouldBe(554);
        session.Recipients.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(SmtpListenerRole.Submission)]
    [InlineData(SmtpListenerRole.ImplicitTlsSubmission)]
    public async Task A_submission_listener_refuses_an_unauthenticated_sender_outright(SmtpListenerRole role)
    {
        // Refused at MAIL FROM, before a recipient is even named. A submission port that
        // accepted unauthenticated mail for local domains would be a port 25 nobody audited.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(role, tls: true, authenticated: false);

        await SendAsync(processor, "EHLO spammer.example.net");

        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<spammer@example.net>");

        reply.Code.ShouldBe(530);
        session.HasTransaction.ShouldBeFalse();
    }

    [Theory]
    [InlineData(SmtpListenerRole.Submission)]
    [InlineData(SmtpListenerRole.ImplicitTlsSubmission)]
    public async Task An_authenticated_submission_session_may_relay(SmtpListenerRole role)
    {
        // The one case that SHOULD succeed. A suite that only proved refusals would pass just as
        // well against a server that refused everything, which is not a mail server.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(role, tls: true, authenticated: true);

        SmtpReply reply = await AttemptRelayAsync(processor);

        reply.IsSuccess.ShouldBeTrue();
        session.Recipients.Single().Decision.ShouldBe(RelayDecision.AcceptRelay);
    }

    [Theory]
    [MemberData(nameof(EveryRoleAndSecurityState))]
    public async Task Local_delivery_is_never_refused_as_relaying(
        SmtpListenerRole role,
        bool tls,
        bool authenticated)
    {
        // The other direction. A server that refused mail for its own domains would be safe and
        // useless, and this suite has to be able to tell the two apart.
        (SmtpCommandProcessor processor, SmtpSessionContext session) = Build(role, tls, authenticated);

        bool submissionWithoutAuth =
            role is SmtpListenerRole.Submission or SmtpListenerRole.ImplicitTlsSubmission && !authenticated;

        SmtpReply reply = await AttemptRelayAsync(processor, LocalRecipient);

        if (submissionWithoutAuth)
        {
            // Refused earlier, at MAIL FROM, and not as a relay refusal.
            reply.Code.ShouldBe(503);
            return;
        }

        reply.IsSuccess.ShouldBeTrue($"role {role}, TLS {tls}, authenticated {authenticated}");
        session.Recipients.Single().Decision.ShouldBe(RelayDecision.AcceptLocal);
    }

    // ---------------------------------------------------------------------------------------
    // Ways an attacker might try to talk their way into relaying.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("victim@elsewhere.example")]                     // the plain case
    [InlineData("victim@ELSEWHERE.EXAMPLE")]                     // casing
    [InlineData("victim@example.com.elsewhere.example")]         // hosted name as a LABEL, not the domain
    [InlineData("victim@sub.example.com")]                       // a subdomain is a different domain
    [InlineData("\"victim@example.com\"@elsewhere.example")]      // hosted name inside a quoted local-part
    public async Task A_recipient_dressed_up_as_local_is_refused_as_a_relay(string recipient)
    {
        // Classic attempts to make a relay look like a local delivery. Each must be refused as a
        // RELAY - 554 5.7.1 - and not merely happen to fail on parsing, which would make this
        // test pass for a reason that has nothing to do with the relay decision.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false);

        SmtpReply reply = await AttemptRelayAsync(processor, recipient);

        reply.Code.ShouldBe(
            554,
            $"'{recipient}' was not refused as a relay. A 501 here would mean the address never " +
            "reached the relay decision, so this case proves nothing.");

        reply.EnhancedStatus.ShouldBe("5.7.1");
        session.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_trailing_root_dot_names_the_same_domain_and_is_a_local_delivery()
    {
        // "example.com." and "example.com" are the SAME name - the trailing dot is the DNS root
        // label, which every fully-qualified name has implicitly. Refusing it would bounce mail
        // from any sender that writes names fully qualified, and treating it as a different
        // domain would be a bug in the opposite direction.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false);

        SmtpReply reply = await AttemptRelayAsync(processor, "victim@example.com.");

        reply.IsSuccess.ShouldBeTrue();
        session.Recipients.Single().Decision.ShouldBe(RelayDecision.AcceptLocal);
        session.Recipients.Single().Address.Domain.Value.ShouldBe("example.com");
    }

    [Fact]
    public async Task The_percent_hack_is_a_local_mailbox_and_not_a_route()
    {
        // "victim%elsewhere.example@example.com" relayed for a decade on servers that RESOLVED
        // the percent into a route to elsewhere.example. Here it is simply a local mailbox with
        // an odd local-part: the domain is the hosted one, so it is a delivery, and the percent
        // means nothing.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false);

        SmtpReply reply = await AttemptRelayAsync(processor, "victim%elsewhere.example@example.com");

        reply.IsSuccess.ShouldBeTrue();

        session.Recipients.Single().Decision.ShouldBe(
            RelayDecision.AcceptLocal,
            "The percent-hack address was treated as a route rather than as a local mailbox.");

        session.Recipients.Single().Address.Domain.Value.ShouldBe("example.com");
    }

    [Fact]
    public async Task A_source_route_cannot_nominate_a_third_party_to_relay_through()
    {
        // RFC 5321 §F.2. Honouring a source route lets the sender pick the next hop, which is an
        // open relay with extra steps. The route is stripped and the real address judged.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false);

        SmtpReply reply = await AttemptRelayAsync(
            processor,
            "@relay.example.net,@hop.example:victim@elsewhere.example");

        reply.Code.ShouldBe(554);
        session.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_second_recipient_is_judged_on_its_own_merits()
    {
        // Accepting one local recipient must not put the session into a state where the next one
        // rides through. Each RCPT is a fresh decision.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false);

        await SendAsync(processor, "EHLO spammer.example.net");
        await SendAsync(processor, "MAIL FROM:<spammer@example.net>");

        (await SendAsync(processor, $"RCPT TO:<{LocalRecipient}>")).IsSuccess.ShouldBeTrue();
        (await SendAsync(processor, $"RCPT TO:<{ForeignRecipient}>")).Code.ShouldBe(554);

        session.Recipients.Count.ShouldBe(1);
        session.Recipients.Single().Address.Value.ShouldBe(LocalRecipient);
    }

    [Fact]
    public async Task A_sender_claiming_a_local_domain_does_not_earn_relaying()
    {
        // The oldest trick: MAIL FROM a domain the server hosts, in the hope that it treats its
        // own users as trusted. The reverse path is a claim; nothing is authenticated by it.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false);

        await SendAsync(processor, "EHLO spammer.example.net");
        await SendAsync(processor, "MAIL FROM:<insider@example.com>");

        (await SendAsync(processor, $"RCPT TO:<{ForeignRecipient}>")).Code.ShouldBe(554);
        session.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public async Task An_ehlo_name_claiming_to_be_this_server_does_not_earn_relaying()
    {
        // The EHLO name is whatever the client typed. A server that trusted it would relay for
        // anyone willing to type its own hostname.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false);

        await SendAsync(processor, "EHLO mail.example.com");
        await SendAsync(processor, "MAIL FROM:<spammer@example.net>");

        (await SendAsync(processor, $"RCPT TO:<{ForeignRecipient}>")).Code.ShouldBe(554);
        session.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public async Task Loopback_is_not_trusted_by_default()
    {
        // "It came from localhost" is not authorisation. A web application on the same host with
        // a server-side request forgery is exactly how that assumption gets exploited.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false, remoteAddress: "127.0.0.1");

        (await AttemptRelayAsync(processor)).Code.ShouldBe(554);
        session.Recipients.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("10.0.0.5")]
    [InlineData("192.168.1.10")]
    [InlineData("172.16.0.3")]
    public async Task A_private_address_is_not_trusted_by_default(string address)
    {
        // "The local network" is bigger than whoever wrote the rule believed, and it is how an
        // open relay gets configured by accident. Nothing is on the allow-list until an operator
        // types an address.
        (SmtpCommandProcessor processor, SmtpSessionContext session) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false, remoteAddress: address);

        (await AttemptRelayAsync(processor)).Code.ShouldBe(554);
        session.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public async Task Only_the_exact_address_an_operator_listed_may_relay()
    {
        _directory.AuthorizedRelayAddresses.Add("192.0.2.50");

        (SmtpCommandProcessor listed, SmtpSessionContext listedSession) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false, remoteAddress: "192.0.2.50");

        (await AttemptRelayAsync(listed)).IsSuccess.ShouldBeTrue();
        listedSession.Recipients.Single().Decision.ShouldBe(RelayDecision.AcceptRelay);

        // One octet away, and refused. The list is addresses, not a subnet.
        (SmtpCommandProcessor neighbour, _) =
            Build(SmtpListenerRole.InboundMta, tls: false, authenticated: false, remoteAddress: "192.0.2.51");

        (await AttemptRelayAsync(neighbour)).Code.ShouldBe(554);
    }

    // ---------------------------------------------------------------------------------------
    // Structural: there is no switch.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_product_states_outright_that_it_never_acts_as_an_open_relay()
    {
        RelayPolicy.MayEverActAsOpenRelay.ShouldBeFalse();
    }

    [Fact]
    public void A_relay_decision_that_was_never_made_is_a_refusal()
    {
        // RelayDecision.Deny is 0, so a zero-initialised or forgotten decision refuses. An enum
        // whose default was "accept" would turn every missed assignment into an open relay.
        default(RelayDecision).ShouldBe(RelayDecision.Deny);
    }

    [Fact]
    public void No_smtp_configuration_option_can_turn_a_listener_into_a_relay()
    {
        // There is no "AllowRelay", "OpenRelay" or "TrustLocalNetwork" setting, and this test
        // exists so that adding one is a deliberate act that fails the build rather than a
        // plausible-looking convenience somebody merges.
        string[] forbidden =
        [
            "AllowRelay", "EnableRelay", "OpenRelay", "RelayAll", "TrustLocalNetwork",
            "AllowRelayFromLocalhost", "RelayForAll", "PermitRelay",
        ];

        string[] properties =
        [
            .. typeof(MailServer.Infrastructure.Configuration.SmtpOptions)
                .GetProperties()
                .Select(p => p.Name),
            .. typeof(MailServer.Infrastructure.Configuration.SmtpListenerOptions)
                .GetProperties()
                .Select(p => p.Name),
        ];

        foreach (string name in forbidden)
        {
            properties.ShouldNotContain(
                p => p.Contains(name, StringComparison.OrdinalIgnoreCase),
                $"A configuration option resembling '{name}' exists. There is no switch that " +
                "turns this server into an open relay, and there must never be one.");
        }
    }

    [Fact]
    public void The_relay_allow_list_is_empty_by_default()
    {
        MailServer.Infrastructure.Configuration.SmtpOptions options = new();

        options.AuthorizedRelayAddresses.ShouldBeEmpty(
            "The relay allow-list must start empty. A default entry is an open relay nobody chose.");
    }

    [Fact]
    public void Submission_listeners_are_disabled_until_authentication_exists()
    {
        // A submission listener with no way to authenticate refuses every sender - correct, but
        // the reason it is off is that a port advertised and unusable is worse than one absent.
        MailServer.Infrastructure.Configuration.SmtpOptions options = new();

        options.EnableAuthentication.ShouldBeFalse();
        options.Submission.Enabled.ShouldBeFalse();
        options.ImplicitTlsSubmission.Enabled.ShouldBeFalse();
    }
}
