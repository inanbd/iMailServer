using MailServer.Domain.Enums;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapStateMachineTests
{
    /// <summary>
    /// What RFC 3501 section 6 says, written out independently of the implementation.
    /// </summary>
    /// <remarks>
    /// Deliberately a second copy of the rules rather than a reference to the first. A test that
    /// asked the state machine what it permits and then asserted that it permits it would pass
    /// for any table at all.
    /// </remarks>
    private static readonly Dictionary<ImapSessionState, ImapVerb[]> Expected = new()
    {
        // Section 6.1 (any state) plus section 6.2 (not authenticated).
        [ImapSessionState.NotAuthenticated] =
        [
            ImapVerb.Capability, ImapVerb.Noop, ImapVerb.Logout,
            ImapVerb.StartTls, ImapVerb.Authenticate, ImapVerb.Login,
        ],

        // Section 6.1 plus section 6.3, plus the two extensions that are authenticated-state
        // commands: IDLE (RFC 2177 section 3) and NAMESPACE (RFC 2342 section 5).
        [ImapSessionState.Authenticated] =
        [
            ImapVerb.Capability, ImapVerb.Noop, ImapVerb.Logout,
            ImapVerb.Select, ImapVerb.Examine, ImapVerb.Create, ImapVerb.Delete,
            ImapVerb.Rename, ImapVerb.Subscribe, ImapVerb.Unsubscribe, ImapVerb.List,
            ImapVerb.Lsub, ImapVerb.Status, ImapVerb.Append,
            ImapVerb.Idle, ImapVerb.Namespace,
        ],

        // Everything the authenticated state allows, plus section 6.4's own commands, plus
        // UNSELECT (RFC 3691 section 2) and MOVE (RFC 6851 section 3.1). Section 6.4's commands
        // are additional to section 6.3's, never a replacement for them.
        [ImapSessionState.Selected] =
        [
            ImapVerb.Capability, ImapVerb.Noop, ImapVerb.Logout,
            ImapVerb.Select, ImapVerb.Examine, ImapVerb.Create, ImapVerb.Delete,
            ImapVerb.Rename, ImapVerb.Subscribe, ImapVerb.Unsubscribe, ImapVerb.List,
            ImapVerb.Lsub, ImapVerb.Status, ImapVerb.Append,
            ImapVerb.Idle, ImapVerb.Namespace,
            ImapVerb.Check, ImapVerb.Close, ImapVerb.Expunge, ImapVerb.Search,
            ImapVerb.Fetch, ImapVerb.Store, ImapVerb.Copy,
            ImapVerb.Move, ImapVerb.Unselect,
        ],

        // Section 6.1.3: the server has sent an untagged BYE and is closing.
        [ImapSessionState.Logout] = [],
    };

    public static TheoryData<ImapSessionState, ImapVerb> EveryPair()
    {
        TheoryData<ImapSessionState, ImapVerb> data = [];

        foreach (ImapSessionState state in ImapStateMachine.AllStates)
        {
            foreach (ImapVerb verb in ImapStateMachine.AllVerbs)
            {
                data.Add(state, verb);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryPair))]
    public void Every_state_and_verb_pair_matches_the_specification(ImapSessionState state, ImapVerb verb)
    {
        bool expected = Expected[state].Contains(verb);

        ImapStateMachine.IsInSequence(state, verb).ShouldBe(
            expected,
            $"{verb} in state {state} should {(expected ? string.Empty : "not ")}be in sequence.");
    }

    [Fact]
    public void The_table_covers_every_state_and_every_verb()
    {
        // Adding a verb or a state without deciding what it means in each row fails here rather
        // than falling through to a default. A default in a protocol state machine is a decision
        // made by whoever wrote the fall-through, not by whoever added the verb.
        Expected.Keys.ShouldBe(ImapStateMachine.AllStates, ignoreOrder: true);

        ImapVerb[] mentioned = [.. Expected.Values.SelectMany(v => v).Distinct()];
        ImapVerb[] unmentioned = [.. ImapStateMachine.AllVerbs.Except(mentioned)];

        // Unknown is the only verb in sequence nowhere: it is what an unrecognised command
        // parses to, and it earns a tagged BAD in every state.
        unmentioned.ShouldBe([ImapVerb.Unknown]);
    }

    // ---------------------------------------------------------------------------------------
    // The rule most often got wrong.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Selected_permits_everything_authenticated_permits()
    {
        // RFC 3501 section 6.4's commands are additional to section 6.3's. A table that treated
        // the two states as disjoint would refuse an APPEND into Sent while Inbox is selected -
        // which is exactly what a client does after sending a message, so the user's copy of the
        // mail they just sent is silently never saved.
        foreach (ImapVerb verb in ImapStateMachine.AllVerbs)
        {
            if (!ImapStateMachine.IsInSequence(ImapSessionState.Authenticated, verb))
            {
                continue;
            }

            ImapStateMachine.IsInSequence(ImapSessionState.Selected, verb).ShouldBeTrue(
                $"{verb} is legal with no mailbox open, so it must stay legal with one open.");
        }
    }

    [Theory]
    [InlineData(ImapVerb.Append)]
    [InlineData(ImapVerb.Create)]
    [InlineData(ImapVerb.List)]
    [InlineData(ImapVerb.Status)]
    [InlineData(ImapVerb.Select)]
    public void A_selected_session_may_still_manage_mailboxes(ImapVerb verb) =>
        ImapStateMachine.IsInSequence(ImapSessionState.Selected, verb).ShouldBeTrue();

    // ---------------------------------------------------------------------------------------
    // Authentication sequencing.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapSessionState.Authenticated)]
    [InlineData(ImapSessionState.Selected)]
    public void Re_authentication_is_out_of_sequence(ImapSessionState state)
    {
        // RFC 3501 section 6.2: a client does not get to become someone else mid-session.
        // ImapSessionContext.Authenticate refuses this too; a rule enforced in one place only is
        // a rule with one bug between it and an account takeover.
        ImapStateMachine.IsInSequence(state, ImapVerb.Login).ShouldBeFalse();
        ImapStateMachine.IsInSequence(state, ImapVerb.Authenticate).ShouldBeFalse();
    }

    [Theory]
    [InlineData(ImapSessionState.Authenticated)]
    [InlineData(ImapSessionState.Selected)]
    public void Starttls_is_out_of_sequence_once_the_session_has_identified_itself(ImapSessionState state)
    {
        // RFC 3501 section 6.2.1 makes STARTTLS a not-authenticated-state command. Negotiating
        // TLS after the credentials have already crossed the connection secures nothing that
        // mattered.
        ImapStateMachine.IsInSequence(state, ImapVerb.StartTls).ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // Mailbox commands before a mailbox exists to act on.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapVerb.Select)]
    [InlineData(ImapVerb.List)]
    [InlineData(ImapVerb.Append)]
    [InlineData(ImapVerb.Fetch)]
    [InlineData(ImapVerb.Status)]
    [InlineData(ImapVerb.Idle)]
    [InlineData(ImapVerb.Namespace)]
    public void Nothing_that_needs_an_identity_is_in_sequence_before_login(ImapVerb verb) =>
        ImapStateMachine.IsInSequence(ImapSessionState.NotAuthenticated, verb).ShouldBeFalse();

    [Theory]
    [InlineData(ImapVerb.Fetch)]
    [InlineData(ImapVerb.Store)]
    [InlineData(ImapVerb.Copy)]
    [InlineData(ImapVerb.Search)]
    [InlineData(ImapVerb.Expunge)]
    [InlineData(ImapVerb.Close)]
    [InlineData(ImapVerb.Check)]
    [InlineData(ImapVerb.Move)]
    [InlineData(ImapVerb.Unselect)]
    public void Nothing_that_needs_a_mailbox_is_in_sequence_without_one(ImapVerb verb) =>
        ImapStateMachine.IsInSequence(ImapSessionState.Authenticated, verb).ShouldBeFalse();

    // ---------------------------------------------------------------------------------------
    // Any state, and no state.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapVerb.Capability)]
    [InlineData(ImapVerb.Noop)]
    [InlineData(ImapVerb.Logout)]
    public void The_any_state_commands_are_in_sequence_everywhere_but_logout(ImapVerb verb)
    {
        // RFC 3501 section 6.1. A client must always be able to ask what the server can do, keep
        // the connection alive, and leave.
        ImapStateMachine.IsInSequence(ImapSessionState.NotAuthenticated, verb).ShouldBeTrue();
        ImapStateMachine.IsInSequence(ImapSessionState.Authenticated, verb).ShouldBeTrue();
        ImapStateMachine.IsInSequence(ImapSessionState.Selected, verb).ShouldBeTrue();
    }

    [Fact]
    public void Nothing_is_in_sequence_once_the_session_has_logged_out()
    {
        // Accepting anything now would mean continuing a session that has been told it is over.
        foreach (ImapVerb verb in ImapStateMachine.AllVerbs)
        {
            ImapStateMachine.IsInSequence(ImapSessionState.Logout, verb).ShouldBeFalse(
                $"{verb} must not be accepted after LOGOUT.");
        }
    }

    [Fact]
    public void An_unrecognised_command_is_never_in_sequence()
    {
        foreach (ImapSessionState state in ImapStateMachine.AllStates)
        {
            ImapStateMachine.IsInSequence(state, ImapVerb.Unknown).ShouldBeFalse(
                $"Unknown must not be in sequence in {state}.");
        }
    }
}
