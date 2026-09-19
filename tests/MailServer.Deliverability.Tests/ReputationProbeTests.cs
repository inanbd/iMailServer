using MailServer.Application.Abstractions.Deliverability;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>A provider that answers from a script and records what it was asked.</summary>
internal sealed class ScriptedReputationProvider(
    IReadOnlyList<string> lists,
    IReadOnlyList<ReputationListing>? addressAnswer = null,
    IReadOnlyList<ReputationListing>? domainAnswer = null) : IReputationProvider
{
    public List<string> Asked { get; } = [];

    public IReadOnlyList<string> Lists => lists;

    public Task<IReadOnlyList<ReputationListing>> CheckAddressAsync(
        IpAddressValue address,
        CancellationToken cancellationToken)
    {
        Asked.Add($"address:{address}");

        return Task.FromResult(addressAnswer ?? []);
    }

    public Task<IReadOnlyList<ReputationListing>> CheckDomainAsync(
        DomainName domain,
        CancellationToken cancellationToken)
    {
        Asked.Add($"domain:{domain.Value}");

        return Task.FromResult(domainAnswer ?? []);
    }
}

public sealed class ReputationProbeTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");
    private static readonly IpAddressValue Address = IpAddressValue.Parse("203.0.113.10");

    /// <summary>
    /// With no list configured, the checks are handed null rather than an empty list.
    /// </summary>
    /// <remarks>
    /// The one decision this layer makes, and the distinction the whole report rests on: an
    /// empty list would mean "queried, and nobody has anything against you", which is a clean
    /// bill of health nobody issued. Null means not tested, and the checks say so.
    /// </remarks>
    [Fact]
    public async Task With_no_list_configured_the_checks_are_unjudged()
    {
        ScriptedReputationProvider provider = new([]);

        ReputationFacts facts = await new ReputationProbe(provider)
            .GatherAsync(Domain, Address, CancellationToken.None);

        facts.IpListings.ShouldBeNull();
        facts.DomainListings.ShouldBeNull();
        provider.Asked.ShouldBeEmpty();

        foreach (DeliverabilityCheck check in ReputationChecks.Evaluate(facts))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, check.Id);
        }
    }

    /// <summary>With lists configured, both identities are asked about.</summary>
    [Fact]
    public async Task With_lists_configured_both_identities_are_asked_about()
    {
        ScriptedReputationProvider provider = new(["bl.example.net"]);

        await new ReputationProbe(provider).GatherAsync(Domain, Address, CancellationToken.None);

        provider.Asked.ShouldBe(["address:203.0.113.10", "domain:example.com"]);
    }

    /// <summary>
    /// With no known sending address, only the domain is asked about.
    /// </summary>
    /// <remarks>
    /// There is nothing to ask, and the address check reports the absence itself. Passing
    /// something made up would put a stranger's address into a query to a third party.
    /// </remarks>
    [Fact]
    public async Task Without_a_known_address_only_the_domain_is_asked_about()
    {
        ScriptedReputationProvider provider = new(["bl.example.net"]);

        ReputationFacts facts = await new ReputationProbe(provider)
            .GatherAsync(Domain, null, CancellationToken.None);

        provider.Asked.ShouldBe(["domain:example.com"]);
        facts.IpListings.ShouldBeNull();
        facts.DomainListings.ShouldNotBeNull();
    }

    /// <summary>The answers are carried through to the checks unchanged.</summary>
    [Fact]
    public async Task The_answers_are_carried_through_to_the_checks()
    {
        ScriptedReputationProvider provider = new(
            ["bl.example.net"],
            addressAnswer: [new ReputationListing("bl.example.net", true, ["127.0.0.2"], "Spam source", ReputationListHealth.Healthy)],
            domainAnswer: [new ReputationListing("dbl.example.net", false, [], null, ReputationListHealth.Healthy)]);

        ReputationFacts facts = await new ReputationProbe(provider)
            .GatherAsync(Domain, Address, CancellationToken.None);

        IReadOnlyList<DeliverabilityCheck> checks = ReputationChecks.Evaluate(facts);

        DeliverabilityCheck ip = checks.Single(c => c.Id == ReputationChecks.IpNotListedId);

        ip.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        ip.Detail.ShouldContain("Spam source");

        checks.Single(c => c.Id == ReputationChecks.DomainNotListedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }
}
