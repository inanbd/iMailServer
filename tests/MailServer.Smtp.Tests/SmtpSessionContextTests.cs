using System.Collections;
using System.Reflection;
using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;

namespace MailServer.Smtp.Tests;

public sealed class SmtpSessionContextTests
{
    private static readonly DateTimeOffset Start = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private static SmtpSessionContext Context(
        SmtpListenerRole role = SmtpListenerRole.Submission,
        bool isTlsActive = false) =>
        new(role, IpAddressValue.Parse("198.51.100.20"), Start, isTlsActive);

    /// <summary>Drives a session as far as it can go before TLS: greeted, sender, recipients.</summary>
    private static SmtpSessionContext PopulatedBeforeTls()
    {
        SmtpSessionContext context = Context();

        context.Greet("client.attacker.example", extended: true);
        context.RecordFailedAuthentication();
        context.BeginTransaction(EmailAddress.Parse("sender@example.net"), 4096);
        context.AcceptRecipient(EmailAddress.Parse("victim@example.com"), RelayDecision.AcceptLocal);

        return context;
    }

    // ---------------------------------------------------------------------------------------
    // The STARTTLS reset.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_tls_handshake_discards_the_greeting()
    {
        SmtpSessionContext context = PopulatedBeforeTls();

        context.CompleteTlsHandshake();

        context.GreetedName.ShouldBeNull();
        context.UsedExtendedGreeting.ShouldBeFalse();
    }

    [Fact]
    public void The_tls_handshake_discards_the_envelope()
    {
        // The envelope was collected in the clear, where anyone on the path could have written
        // it. Keeping it would mean a message delivered inside the tunnel to a recipient chosen
        // outside it.
        SmtpSessionContext context = PopulatedBeforeTls();

        context.CompleteTlsHandshake();

        context.HasTransaction.ShouldBeFalse();
        context.ReversePath.ShouldBeNull();
        context.DeclaredMessageSize.ShouldBeNull();
        context.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public void The_tls_handshake_returns_the_session_to_the_beginning()
    {
        // RFC 3207 §4.2: the client must issue EHLO again inside the tunnel. Anything less and
        // the discarded greeting is still observable in the session's behaviour.
        SmtpSessionContext context = PopulatedBeforeTls();

        context.CompleteTlsHandshake();

        context.State.ShouldBe(SmtpSessionState.Connected);
        context.IsTlsActive.ShouldBeTrue();
    }

    [Fact]
    public void The_tls_handshake_keeps_what_the_client_did_not_say()
    {
        // The transport's facts are not the client's claims. Discarding the remote address
        // would lose the only trustworthy identifier the session has.
        SmtpSessionContext context = PopulatedBeforeTls();

        context.CompleteTlsHandshake();

        context.Role.ShouldBe(SmtpListenerRole.Submission);
        context.RemoteAddress.Value.ShouldBe("198.51.100.20");
        context.StartedAt.ShouldBe(Start);
    }

    [Fact]
    public void The_tls_handshake_does_not_refund_failed_authentication_attempts()
    {
        // A reset that cleared the counter would be a way to buy another round of password
        // guesses. The counter is this server's accounting, not knowledge obtained from the
        // client, so RFC 3207's discard requirement does not reach it.
        SmtpSessionContext context = PopulatedBeforeTls();

        context.FailedAuthenticationAttempts.ShouldBe(1);

        context.CompleteTlsHandshake();

        context.FailedAuthenticationAttempts.ShouldBe(1);
    }

    [Fact]
    public void A_second_handshake_is_refused()
    {
        SmtpSessionContext context = Context(isTlsActive: true);

        Should.Throw<InvalidOperationException>(context.CompleteTlsHandshake);
    }

    /// <summary>
    /// Every piece of session state is accounted for after the handshake — by name.
    /// </summary>
    /// <remarks>
    /// The tests above check the fields that exist today. This one checks the fields that will
    /// exist tomorrow: adding a property to <see cref="SmtpSessionContext"/> without deciding
    /// whether the STARTTLS reset clears it fails here, rather than quietly becoming the next
    /// STARTTLS injection bug. That is the whole reason the state lives in one object.
    /// </remarks>
    [Fact]
    public void Every_property_is_explicitly_classified_as_cleared_or_surviving()
    {
        // Deliberate decisions, each with its reason in SmtpSessionContext's remarks.
        HashSet<string> survivesHandshake =
        [
            nameof(SmtpSessionContext.Role),                          // from the listener
            nameof(SmtpSessionContext.RemoteAddress),                 // from the transport
            nameof(SmtpSessionContext.StartedAt),                     // from the host clock
            nameof(SmtpSessionContext.FailedAuthenticationAttempts),  // our accounting, not their claim
            nameof(SmtpSessionContext.IsTlsActive),                   // set BY the handshake
        ];

        SmtpSessionContext populated = PopulatedBeforeTls();
        SmtpSessionContext pristine = Context(isTlsActive: true);

        populated.CompleteTlsHandshake();

        PropertyInfo[] properties = typeof(SmtpSessionContext)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance);

        properties.Length.ShouldBeGreaterThan(10, "Reflection found suspiciously little state.");

        foreach (PropertyInfo property in properties)
        {
            if (survivesHandshake.Contains(property.Name))
            {
                continue;
            }

            object? actual = property.GetValue(populated);
            object? expected = property.GetValue(pristine);

            if (actual is IEnumerable actualSequence and not string)
            {
                actualSequence.Cast<object>().ShouldBeEmpty(
                    $"'{property.Name}' still holds pre-handshake data after STARTTLS.");

                continue;
            }

            actual.ShouldBe(
                expected,
                $"'{property.Name}' is neither cleared by the STARTTLS reset nor listed as " +
                "deliberately surviving it. Decide which it is, in SmtpSessionContext and here.");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Ordinary transitions.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_new_greeting_abandons_an_open_transaction()
    {
        // RFC 5321 §4.1.4. A client that re-EHLOs mid-transaction is starting over, and a
        // server that kept the recipients would deliver the next message to them.
        SmtpSessionContext context = PopulatedBeforeTls();

        context.Greet("client.example", extended: true);

        context.HasTransaction.ShouldBeFalse();
        context.Recipients.ShouldBeEmpty();
        context.State.ShouldBe(SmtpSessionState.Greeted);
    }

    [Fact]
    public void Reset_clears_the_transaction_but_not_the_greeting()
    {
        SmtpSessionContext context = PopulatedBeforeTls();

        context.Reset();

        context.HasTransaction.ShouldBeFalse();
        context.Recipients.ShouldBeEmpty();
        context.GreetedName.ShouldBe("client.attacker.example");
        context.State.ShouldBe(SmtpSessionState.Greeted);
    }

    [Fact]
    public void Reset_before_a_greeting_does_not_fabricate_one()
    {
        SmtpSessionContext context = Context();

        context.Reset();

        context.State.ShouldBe(SmtpSessionState.Connected);
        context.GreetedName.ShouldBeNull();
    }

    [Fact]
    public void A_completed_message_leaves_no_envelope_for_the_next_one()
    {
        // Connections carry several messages. A recipient that survived into the next
        // transaction is a delivery to someone the sender never addressed.
        SmtpSessionContext context = PopulatedBeforeTls();

        context.BeginData();
        context.CompleteMessage();

        context.Recipients.ShouldBeEmpty();
        context.ReversePath.ShouldBeNull();
        context.HasTransaction.ShouldBeFalse();
        context.State.ShouldBe(SmtpSessionState.Greeted);
    }

    [Fact]
    public void The_null_reverse_path_is_a_transaction_with_no_sender()
    {
        // "<>" is an accepted sender, not a missing one. A server that used "ReversePath is
        // null" to mean "no MAIL FROM yet" would reject every bounce on the Internet.
        SmtpSessionContext context = Context();

        context.Greet("bounce.example", extended: true);
        context.BeginTransaction(reversePath: null, declaredSize: null);

        context.HasTransaction.ShouldBeTrue();
        context.ReversePath.ShouldBeNull();
        context.State.ShouldBe(SmtpSessionState.MailFromAccepted);
    }

    [Fact]
    public void A_denied_recipient_can_never_be_added_to_the_envelope()
    {
        SmtpSessionContext context = Context();

        context.Greet("client.example", extended: true);
        context.BeginTransaction(EmailAddress.Parse("a@b.example"), null);

        Should.Throw<ArgumentException>(
            () => context.AcceptRecipient(EmailAddress.Parse("victim@elsewhere.example"), RelayDecision.Deny));

        context.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public void A_recipient_cannot_be_added_without_a_transaction()
    {
        SmtpSessionContext context = Context();

        context.Greet("client.example", extended: true);

        Should.Throw<InvalidOperationException>(
            () => context.AcceptRecipient(EmailAddress.Parse("a@b.example"), RelayDecision.AcceptLocal));
    }

    [Fact]
    public void Data_without_recipients_is_refused()
    {
        SmtpSessionContext context = Context();

        context.Greet("client.example", extended: true);
        context.BeginTransaction(EmailAddress.Parse("a@b.example"), null);

        Should.Throw<InvalidOperationException>(context.BeginData);
    }

    // ---------------------------------------------------------------------------------------
    // Authentication.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Authentication_without_tls_is_refused_by_the_context_itself()
    {
        // Capability advertisement should make this unreachable. It is asserted anyway: a
        // defence that depends on another component being correct is not a defence.
        SmtpSessionContext context = Context(isTlsActive: false);

        context.Greet("client.example", extended: true);

        Should.Throw<InvalidOperationException>(
            () => context.Authenticate(EmailAddress.Parse("user@example.com")));

        context.IsAuthenticated.ShouldBeFalse();
    }

    [Fact]
    public void The_relay_context_reports_the_session_as_it_actually_is()
    {
        // Assembled in one place so that no call site can hand the relay policy a context that
        // flatters the session.
        SmtpSessionContext context = Context(isTlsActive: true);

        context.Greet("client.example", extended: true);
        context.Authenticate(EmailAddress.Parse("user@example.com"));

        var relay = context.ToRelayContext();

        relay.Role.ShouldBe(SmtpListenerRole.Submission);
        relay.IsAuthenticated.ShouldBeTrue();
        relay.AuthenticatedMailbox!.ToString().ShouldBe("user@example.com");
        relay.IsTlsActive.ShouldBeTrue();
        relay.RemoteAddress.Value.ShouldBe("198.51.100.20");
    }

    [Fact]
    public void An_unauthenticated_session_says_so_to_the_relay_policy()
    {
        var relay = Context(SmtpListenerRole.InboundMta).ToRelayContext();

        relay.IsAuthenticated.ShouldBeFalse();
        relay.AuthenticatedMailbox.ShouldBeNull();
    }
}
