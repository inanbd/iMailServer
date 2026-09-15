using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.Policies;

public sealed class MxSelectionPolicyTests
{
    private static double NoShuffle() => 0d;

    [Fact]
    public void Hosts_are_ordered_by_ascending_preference()
    {
        MxSelectionPolicy policy = new();

        MxHost[] hosts =
        [
            new MxHost("mx2.example.com", 20),
            new MxHost("mx1.example.com", 10),
            new MxHost("mx3.example.com", 30),
        ];

        IReadOnlyList<MxHost> ordered = policy.OrderForAttempt(hosts, NoShuffle);

        ordered.Select(h => h.Hostname).ShouldBe(
            ["mx1.example.com", "mx2.example.com", "mx3.example.com"]);
    }

    [Fact]
    public void Hosts_sharing_a_preference_are_shuffled_within_their_band_only()
    {
        MxSelectionPolicy policy = new();

        MxHost[] hosts =
        [
            new MxHost("a.example.com", 10),
            new MxHost("b.example.com", 10),
            new MxHost("c.example.com", 20),
        ];

        // A random source that always picks the last candidate reverses the first band's
        // order but must never move the lower-preference host ahead of it.
        IReadOnlyList<MxHost> ordered = policy.OrderForAttempt(hosts, static () => 0.999);

        ordered[2].Hostname.ShouldBe("c.example.com");
        ordered.Take(2).Select(h => h.Hostname).ShouldBe(["a.example.com", "b.example.com"], ignoreOrder: true);
    }

    [Fact]
    public void An_empty_list_produces_an_empty_result()
    {
        MxSelectionPolicy policy = new();

        policy.OrderForAttempt([]).ShouldBeEmpty();
    }

    [Fact]
    public void A_single_host_is_returned_unchanged()
    {
        MxSelectionPolicy policy = new();

        MxHost[] hosts = [new MxHost("mail.example.com", 0)];

        policy.OrderForAttempt(hosts, NoShuffle).ShouldBe(hosts);
    }

    [Fact]
    public void Every_host_supplied_appears_exactly_once_in_the_result()
    {
        MxSelectionPolicy policy = new();

        MxHost[] hosts =
        [
            new MxHost("a.example.com", 10),
            new MxHost("b.example.com", 10),
            new MxHost("c.example.com", 20),
            new MxHost("d.example.com", 5),
        ];

        IReadOnlyList<MxHost> ordered = policy.OrderForAttempt(hosts, static () => Random.Shared.NextDouble());

        ordered.Count.ShouldBe(hosts.Length);
        ordered.ShouldBe(hosts, ignoreOrder: true);
    }
}
