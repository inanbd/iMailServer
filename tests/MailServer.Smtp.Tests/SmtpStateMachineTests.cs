using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;

namespace MailServer.Smtp.Tests;

public sealed class SmtpStateMachineTests
{
    /// <summary>
    /// The sequencing table, written out a second time.
    /// </summary>
    /// <remarks>
    /// Deliberate double entry. <see cref="SmtpStateMachine"/> holds the decision the server
    /// acts on; this holds the decision a reader of the specification would expect. A change to
    /// either that is not made to the other is a change nobody meant to make, and the tests
    /// below compare them pair by pair.
    /// </remarks>
    private static readonly Dictionary<SmtpSessionState, SmtpVerb[]> Expected = new()
    {
        [SmtpSessionState.Connected] =
        [
            SmtpVerb.Ehlo, SmtpVerb.Helo,
            SmtpVerb.Quit, SmtpVerb.Noop, SmtpVerb.Rset,
            SmtpVerb.Help, SmtpVerb.Vrfy, SmtpVerb.Expn,
        ],
        [SmtpSessionState.Greeted] =
        [
            SmtpVerb.Ehlo, SmtpVerb.Helo,
            SmtpVerb.StartTls, SmtpVerb.Auth, SmtpVerb.MailFrom,
            SmtpVerb.Quit, SmtpVerb.Noop, SmtpVerb.Rset,
            SmtpVerb.Help, SmtpVerb.Vrfy, SmtpVerb.Expn,
        ],
        [SmtpSessionState.MailFromAccepted] =
        [
            SmtpVerb.RcptTo,
            SmtpVerb.Ehlo, SmtpVerb.Helo,
            SmtpVerb.Quit, SmtpVerb.Noop, SmtpVerb.Rset,
            SmtpVerb.Help, SmtpVerb.Vrfy, SmtpVerb.Expn,
        ],
        [SmtpSessionState.RecipientsAccepted] =
        [
            SmtpVerb.RcptTo, SmtpVerb.Data,
            SmtpVerb.Ehlo, SmtpVerb.Helo,
            SmtpVerb.Quit, SmtpVerb.Noop, SmtpVerb.Rset,
            SmtpVerb.Help, SmtpVerb.Vrfy, SmtpVerb.Expn,
        ],
        [SmtpSessionState.ReceivingData] = [],
        [SmtpSessionState.Closing] = [],
    };

    public static TheoryData<SmtpSessionState, SmtpVerb> EveryPair()
    {
        TheoryData<SmtpSessionState, SmtpVerb> data = [];

        foreach (SmtpSessionState state in SmtpStateMachine.AllStates)
        {
            foreach (SmtpVerb verb in SmtpStateMachine.AllVerbs)
            {
                data.Add(state, verb);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryPair))]
    public void Every_state_and_verb_pair_matches_the_specification(SmtpSessionState state, SmtpVerb verb)
    {
        bool expected = Expected[state].Contains(verb);

        SmtpStateMachine.IsInSequence(state, verb).ShouldBe(
            expected,
            $"{verb} in state {state} should {(expected ? string.Empty : "not ")}be in sequence.");
    }

    [Fact]
    public void The_table_covers_every_state_and_every_verb()
    {
        // Adding a verb or a state without deciding what it means in each row fails here rather
        // than falling through to a default. A default in a protocol state machine is a
        // decision made by whoever wrote the fall-through, not by whoever added the verb.
        Expected.Keys.ShouldBe(SmtpStateMachine.AllStates, ignoreOrder: true);

        SmtpVerb[] mentioned = [.. Expected.Values.SelectMany(v => v).Distinct()];
        SmtpVerb[] unmentioned = [.. SmtpStateMachine.AllVerbs.Except(mentioned)];

        // Unknown is the only verb allowed nowhere: it is what an unrecognised command parses
        // to, and it earns a 500 rather than a 503.
        unmentioned.ShouldBe([SmtpVerb.Unknown]);
    }

    [Fact]
    public void Nothing_is_in_sequence_while_data_is_being_received()
    {
        // Inside DATA every octet is content. A "command" seen here is either a caller bug or
        // the start of an injection, and neither should be executed.
        foreach (SmtpVerb verb in SmtpStateMachine.AllVerbs)
        {
            SmtpStateMachine.IsInSequence(SmtpSessionState.ReceivingData, verb).ShouldBeFalse(
                $"{verb} must not be accepted inside DATA.");
        }
    }

    [Fact]
    public void Nothing_is_in_sequence_once_the_session_is_closing()
    {
        foreach (SmtpVerb verb in SmtpStateMachine.AllVerbs)
        {
            SmtpStateMachine.IsInSequence(SmtpSessionState.Closing, verb).ShouldBeFalse(
                $"{verb} must not be accepted after QUIT.");
        }
    }

    // ---------------------------------------------------------------------------------------
    // The individual rules, named so a failure says what broke rather than which cell differed.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Mail_from_requires_a_greeting_first()
    {
        SmtpStateMachine.IsInSequence(SmtpSessionState.Connected, SmtpVerb.MailFrom).ShouldBeFalse();
        SmtpStateMachine.IsInSequence(SmtpSessionState.Greeted, SmtpVerb.MailFrom).ShouldBeTrue();
    }

    [Fact]
    public void Rcpt_to_requires_a_sender_first()
    {
        SmtpStateMachine.IsInSequence(SmtpSessionState.Greeted, SmtpVerb.RcptTo).ShouldBeFalse();
        SmtpStateMachine.IsInSequence(SmtpSessionState.MailFromAccepted, SmtpVerb.RcptTo).ShouldBeTrue();
    }

    [Fact]
    public void Data_requires_a_recipient_first()
    {
        SmtpStateMachine.IsInSequence(SmtpSessionState.MailFromAccepted, SmtpVerb.Data).ShouldBeFalse();
        SmtpStateMachine.IsInSequence(SmtpSessionState.RecipientsAccepted, SmtpVerb.Data).ShouldBeTrue();
    }

    [Fact]
    public void A_second_mail_from_inside_a_transaction_is_out_of_sequence()
    {
        // SMTP has no nested transactions, and silently replacing the sender would change who a
        // message appears to be from after its recipients were already accepted.
        SmtpStateMachine.IsInSequence(SmtpSessionState.MailFromAccepted, SmtpVerb.MailFrom).ShouldBeFalse();
        SmtpStateMachine.IsInSequence(SmtpSessionState.RecipientsAccepted, SmtpVerb.MailFrom).ShouldBeFalse();
    }

    [Fact]
    public void Starttls_and_auth_require_a_greeting_and_no_open_transaction()
    {
        // RFC 3207 §4 and RFC 4954 §4: the client is meant to have seen the capability
        // advertised. Mid-transaction they are refused so that the question of which security
        // context an already-collected envelope belongs to never arises.
        foreach (SmtpVerb verb in (SmtpVerb[])[SmtpVerb.StartTls, SmtpVerb.Auth])
        {
            SmtpStateMachine.IsInSequence(SmtpSessionState.Connected, verb).ShouldBeFalse();
            SmtpStateMachine.IsInSequence(SmtpSessionState.Greeted, verb).ShouldBeTrue();
            SmtpStateMachine.IsInSequence(SmtpSessionState.MailFromAccepted, verb).ShouldBeFalse();
            SmtpStateMachine.IsInSequence(SmtpSessionState.RecipientsAccepted, verb).ShouldBeFalse();
        }
    }

    [Fact]
    public void Quit_noop_and_rset_are_always_in_sequence_while_a_session_is_live()
    {
        foreach (SmtpSessionState state in (SmtpSessionState[])
        [
            SmtpSessionState.Connected,
            SmtpSessionState.Greeted,
            SmtpSessionState.MailFromAccepted,
            SmtpSessionState.RecipientsAccepted,
        ])
        {
            SmtpStateMachine.IsInSequence(state, SmtpVerb.Quit).ShouldBeTrue();
            SmtpStateMachine.IsInSequence(state, SmtpVerb.Noop).ShouldBeTrue();
            SmtpStateMachine.IsInSequence(state, SmtpVerb.Rset).ShouldBeTrue();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Transitions.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(SmtpVerb.Ehlo, SmtpSessionState.Greeted)]
    [InlineData(SmtpVerb.Helo, SmtpSessionState.Greeted)]
    [InlineData(SmtpVerb.MailFrom, SmtpSessionState.MailFromAccepted)]
    [InlineData(SmtpVerb.RcptTo, SmtpSessionState.RecipientsAccepted)]
    [InlineData(SmtpVerb.Data, SmtpSessionState.ReceivingData)]
    [InlineData(SmtpVerb.Quit, SmtpSessionState.Closing)]
    public void A_successful_command_moves_the_session_on(SmtpVerb verb, SmtpSessionState expected)
    {
        SmtpStateMachine.NextOnSuccess(SmtpSessionState.Greeted, verb).ShouldBe(expected);
    }

    [Fact]
    public void Reset_returns_to_greeted_not_to_connected()
    {
        // Sending the client back to Connected would make it re-EHLO after every RSET, which no
        // client expects and which would break pipelined submission.
        SmtpStateMachine.NextOnSuccess(SmtpSessionState.RecipientsAccepted, SmtpVerb.Rset)
            .ShouldBe(SmtpSessionState.Greeted);
    }

    [Fact]
    public void A_greeting_mid_transaction_returns_to_greeted()
    {
        // RFC 5321 §4.1.4: the transaction is abandoned.
        SmtpStateMachine.NextOnSuccess(SmtpSessionState.RecipientsAccepted, SmtpVerb.Ehlo)
            .ShouldBe(SmtpSessionState.Greeted);
    }

    [Theory]
    [InlineData(SmtpVerb.Noop)]
    [InlineData(SmtpVerb.Help)]
    [InlineData(SmtpVerb.Vrfy)]
    [InlineData(SmtpVerb.Expn)]
    [InlineData(SmtpVerb.Unknown)]
    public void Commands_that_change_nothing_leave_the_state_alone(SmtpVerb verb)
    {
        // NOOP mid-transaction must not abandon the transaction: clients send it as a keepalive.
        SmtpStateMachine.NextOnSuccess(SmtpSessionState.MailFromAccepted, verb)
            .ShouldBe(SmtpSessionState.MailFromAccepted);
    }

    [Fact]
    public void A_finished_message_returns_to_greeted()
    {
        SmtpStateMachine.AfterMessage().ShouldBe(SmtpSessionState.Greeted);
    }
}
