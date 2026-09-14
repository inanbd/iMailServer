using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.Policies;

/// <summary>
/// Alias expansion, with the cases that matter being the ones that must terminate.
/// </summary>
/// <remarks>
/// This runs on the SMTP delivery path for every message to an aliased address. A cycle that
/// is not caught is not a wrong answer — it is a hang, per message, in the component that
/// accepts mail.
/// </remarks>
public sealed class AliasExpansionPolicyTests
{
    private readonly AliasExpansionPolicy _policy = new();

    /// <summary>Builds a resolver over a simple alias table.</summary>
    private static Func<EmailAddress, IReadOnlyList<EmailAddress>?> Graph(
        Dictionary<string, string[]> aliases) =>
        address => aliases.TryGetValue(address.NormalizedValue, out string[]? targets)
            ? [.. targets.Select(EmailAddress.Parse)]
            : null;

    private static EmailAddress Address(string value) => EmailAddress.Parse(value);

    private static string[] Expanded(AliasExpansion expansion) =>
        [.. expansion.Recipients.Select(static r => r.NormalizedValue)];

    [Fact]
    public void A_plain_mailbox_expands_to_itself()
    {
        AliasExpansion result = _policy.Expand(
            Address("bob@example.com"),
            Graph([]));

        Expanded(result).ShouldBe(["bob@example.com"]);
        result.WasTruncated.ShouldBeFalse();
    }

    [Fact]
    public void An_alias_expands_to_its_targets()
    {
        AliasExpansion result = _policy.Expand(
            Address("sales@example.com"),
            Graph(new() { ["sales@example.com"] = ["alice@example.com", "bob@example.com"] }));

        Expanded(result).ShouldBe(["alice@example.com", "bob@example.com"], ignoreOrder: true);
    }

    [Fact]
    public void A_nested_alias_expands_through_both_levels()
    {
        AliasExpansion result = _policy.Expand(
            Address("everyone@example.com"),
            Graph(new()
            {
                ["everyone@example.com"] = ["sales@example.com", "support@example.com"],
                ["sales@example.com"] = ["alice@example.com"],
                ["support@example.com"] = ["bob@example.com"],
            }));

        Expanded(result).ShouldBe(["alice@example.com", "bob@example.com"], ignoreOrder: true);
        result.WasTruncated.ShouldBeFalse();
    }

    /// <summary>
    /// Someone reachable by two routes is one recipient, not two.
    /// </summary>
    /// <remarks>
    /// The common real case: a person on both <c>sales@</c> and <c>support@</c>, and someone
    /// mails <c>everyone@</c>. Delivering twice is the kind of small wrongness that trains
    /// people to filter the alias out.
    /// </remarks>
    [Fact]
    public void A_recipient_reachable_twice_is_delivered_to_once()
    {
        AliasExpansion result = _policy.Expand(
            Address("everyone@example.com"),
            Graph(new()
            {
                ["everyone@example.com"] = ["sales@example.com", "support@example.com"],
                ["sales@example.com"] = ["alice@example.com"],
                ["support@example.com"] = ["alice@example.com"],
            }));

        Expanded(result).ShouldBe(["alice@example.com"]);
    }

    // ---- Termination ------------------------------------------------------------------------

    /// <summary>
    /// The case this policy exists for: A → B → A.
    /// </summary>
    [Fact]
    public void A_two_alias_cycle_terminates()
    {
        AliasExpansion result = _policy.Expand(
            Address("a@example.com"),
            Graph(new()
            {
                ["a@example.com"] = ["b@example.com"],
                ["b@example.com"] = ["a@example.com"],
            }));

        // Terminates, and delivers to nobody: every address in the cycle is an alias, so there
        // is no mailbox at the end of it.
        result.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public void A_cycle_with_a_real_recipient_still_delivers_to_them()
    {
        AliasExpansion result = _policy.Expand(
            Address("a@example.com"),
            Graph(new()
            {
                ["a@example.com"] = ["b@example.com", "alice@example.com"],
                ["b@example.com"] = ["a@example.com"],
            }));

        // The cycle is skipped by the visited set; the reachable mailbox is unaffected.
        Expanded(result).ShouldBe(["alice@example.com"]);
    }

    [Fact]
    public void A_long_chain_beyond_the_depth_limit_is_truncated_and_says_so()
    {
        Dictionary<string, string[]> chain = [];

        for (int i = 0; i < 30; i++)
        {
            chain[$"a{i}@example.com"] = [$"a{i + 1}@example.com"];
        }

        AliasExpansion result = _policy.Expand(Address("a0@example.com"), Graph(chain));

        result.WasTruncated.ShouldBeTrue();
        result.Diagnostic.ShouldNotBeNull().ShouldContain("hop limit");

        // Reported, never silently trimmed: delivering to some of a list and telling nobody is
        // worse than refusing, because the sender believes it reached everyone.
        result.Diagnostic!.ShouldContain("cycle");
    }

    [Fact]
    public void A_fan_out_beyond_the_recipient_limit_is_truncated_and_says_so()
    {
        string[] many = [.. Enumerable.Range(0, 250).Select(i => $"user{i}@example.com")];

        AliasExpansion result = _policy.Expand(
            Address("all@example.com"),
            Graph(new() { ["all@example.com"] = many }));

        result.WasTruncated.ShouldBeTrue();
        result.Recipients.Count.ShouldBe(_policy.MaxRecipients);
        result.Diagnostic.ShouldNotBeNull().ShouldContain("recipient limit");
    }

    /// <summary>
    /// A graph that fans out at every level is the amplification shape: one message in,
    /// exponentially many deliveries out.
    /// </summary>
    [Fact]
    public void An_exponentially_branching_graph_is_bounded()
    {
        Dictionary<string, string[]> branching = [];

        for (int level = 0; level < 12; level++)
        {
            for (int node = 0; node < 1 << level; node++)
            {
                branching[$"l{level}n{node}@example.com"] =
                [
                    $"l{level + 1}n{node * 2}@example.com",
                    $"l{level + 1}n{(node * 2) + 1}@example.com",
                ];
            }
        }

        AliasExpansion result = _policy.Expand(Address("l0n0@example.com"), Graph(branching));

        result.Recipients.Count.ShouldBeLessThanOrEqualTo(_policy.MaxRecipients);
        result.WasTruncated.ShouldBeTrue();
    }

    /// <summary>
    /// A self-referencing alias should be impossible — the aggregate refuses one — but the
    /// resolver must survive a row that predates that rule or was written by hand.
    /// </summary>
    [Fact]
    public void A_self_referencing_alias_terminates()
    {
        AliasExpansion result = _policy.Expand(
            Address("loop@example.com"),
            Graph(new() { ["loop@example.com"] = ["loop@example.com"] }));

        result.Recipients.ShouldBeEmpty();
    }

    [Fact]
    public void Expansion_is_case_insensitive()
    {
        AliasExpansion result = _policy.Expand(
            Address("Sales@Example.com"),
            Graph(new() { ["sales@example.com"] = ["Alice@Example.com", "alice@example.com"] }));

        // One recipient: the two spellings are the same address.
        Expanded(result).ShouldBe(["alice@example.com"]);
    }

    [Fact]
    public void The_limits_are_generous_enough_for_real_structures_and_tight_enough_to_bound()
    {
        _policy.MaxDepth.ShouldBeInRange(5, 20);
        _policy.MaxRecipients.ShouldBeInRange(50, 500);
    }
}
