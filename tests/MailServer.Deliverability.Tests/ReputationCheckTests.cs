using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

public sealed class ReputationCheckTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");
    private static readonly IpAddressValue Address = IpAddressValue.Parse("203.0.113.10");

    private static ReputationListing Clean(string provider) =>
        new(provider, false, [], null, ReputationListHealth.Healthy);

    private static ReputationListing Listed(
        string provider,
        string code = "127.0.0.2",
        string? reason = null) =>
        new(provider, true, [code], reason, ReputationListHealth.Healthy);

    private static ReputationFacts Facts(
        IReadOnlyList<ReputationListing>? ip = null,
        IReadOnlyList<ReputationListing>? domain = null,
        IpAddressValue? address = null) =>
        new(
            Domain,
            address ?? Address,
            ip ?? [Clean("zen.example.net"), Clean("bl.example.org")],
            domain ?? [Clean("dbl.example.net")]);

    private static DeliverabilityCheck Check(ReputationFacts facts, string id) =>
        ReputationChecks.Evaluate(facts).Single(c => c.Id == id);

    // ---------------------------------------------------------------------------------------
    // Shape.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Every_reputation_check_is_in_the_reputation_category()
    {
        foreach (DeliverabilityCheck check in ReputationChecks.Evaluate(Facts()))
        {
            check.Category.ShouldBe(DeliverabilityCategory.Reputation);
        }
    }

    /// <summary>The weights add up to the category's share.</summary>
    [Fact]
    public void The_reputation_weights_sum_to_ten()
    {
        ReputationChecks.Evaluate(Facts()).Sum(c => c.Weight)
            .ShouldBe(DeliverabilityCategories.WeightOf(DeliverabilityCategory.Reputation));
    }

    [Fact]
    public void Reputation_check_ids_are_unique()
    {
        IReadOnlyList<DeliverabilityCheck> checks = ReputationChecks.Evaluate(Facts());

        checks.Select(c => c.Id).Distinct().Count().ShouldBe(checks.Count);
    }

    [Fact]
    public void A_clean_server_passes_every_reputation_check()
    {
        foreach (DeliverabilityCheck check in ReputationChecks.Evaluate(Facts()))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Pass, check.Id);
        }
    }

    /// <summary>Anything that is not a pass says what to do about it.</summary>
    [Fact]
    public void Every_reputation_finding_carries_a_remedy()
    {
        ReputationFacts[] broken =
        [
            Facts(ip: [Listed("zen.example.net")]),
            Facts(domain: [Listed("dbl.example.net")]),
            Facts(ip: [new("zen.example.net", true, [], null, ReputationListHealth.Unreliable)]),
            Facts(ip: [new("zen.example.net", false, [], null, ReputationListHealth.NotAnswering)]),
        ];

        foreach (ReputationFacts facts in broken)
        {
            foreach (DeliverabilityCheck check in ReputationChecks.Evaluate(facts))
            {
                if (check.Outcome is DeliverabilityOutcome.Warn or DeliverabilityOutcome.Fail)
                {
                    check.Remedy.ShouldNotBeNullOrWhiteSpace(check.Id);
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Listings.
    // ---------------------------------------------------------------------------------------

    /// <summary>A listing fails, and the finding names the list.</summary>
    [Fact]
    public void A_listed_address_fails_and_names_the_list()
    {
        DeliverabilityCheck check = Check(
            Facts(ip: [Clean("bl.example.org"), Listed("zen.example.net")]),
            ReputationChecks.IpNotListedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("zen.example.net");
        check.Detail.ShouldContain("203.0.113.10");
    }

    /// <summary>
    /// The list's own reason is carried into the finding.
    /// </summary>
    /// <remarks>
    /// RFC 5782 §2.1: the TXT record "describes the reason that the IP address is listed". It is
    /// usually the only actionable part of a listing, and an operator sent to go and find it for
    /// themselves has been told nothing this report already knew.
    /// </remarks>
    [Fact]
    public void A_listings_reason_is_carried_into_the_finding()
    {
        Check(
                Facts(ip: [Listed("zen.example.net", reason: "Dynamic address range")]),
                ReputationChecks.IpNotListedId)
            .Detail.ShouldContain("Dynamic address range");
    }

    /// <summary>
    /// The A-record codes are reported, not treated as addresses.
    /// </summary>
    /// <remarks>
    /// §2.1: "The contents of the A record MUST NOT be used as an IP address." They are the
    /// list's sublist codes, and an operator needs them to look up which sublist they are on.
    /// </remarks>
    [Fact]
    public void The_listing_codes_are_reported_as_codes()
    {
        Check(Facts(ip: [Listed("zen.example.net", code: "127.0.0.4")]), ReputationChecks.IpNotListedId)
            .Evidence.ShouldNotBeNull().Found.ShouldNotBeNull().ShouldContain("127.0.0.4");
    }

    /// <summary>The domain listing is judged separately from the address.</summary>
    [Fact]
    public void A_listed_domain_fails_independently_of_the_address()
    {
        ReputationFacts facts = Facts(domain: [Listed("dbl.example.net")]);

        Check(facts, ReputationChecks.DomainNotListedId).Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        Check(facts, ReputationChecks.IpNotListedId).Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>The remedy says to fix the cause before asking for delisting.</summary>
    [Fact]
    public void The_delisting_remedy_says_to_fix_the_cause_first()
    {
        Check(Facts(ip: [Listed("zen.example.net")]), ReputationChecks.IpNotListedId)
            .Remedy.ShouldNotBeNull().ShouldContain("fix what caused the listing");
    }

    /// <summary>With no known sending address there is nothing to look up.</summary>
    [Fact]
    public void Without_a_known_address_the_ip_check_is_unjudged()
    {
        Check(new ReputationFacts(Domain, null, null, null), ReputationChecks.IpNotListedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>Lists that were never queried leave the checks unjudged, not clean.</summary>
    [Fact]
    public void Lists_that_were_never_queried_leave_the_checks_unjudged()
    {
        ReputationFacts facts = new(Domain, Address, null, null);

        foreach (DeliverabilityCheck check in ReputationChecks.Evaluate(facts))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, check.Id);
        }
    }

    // ---------------------------------------------------------------------------------------
    // List health — the part that stops a false positive costing an operator a week.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A listing from a list that failed RFC 5782 §5's test is not a listing.
    /// </summary>
    /// <remarks>
    /// §5: "IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes. IPv4-based
    /// DNSxLs MUST NOT contain an entry for 127.0.0.1." A list queried through a public resolver,
    /// or past a free-use quota, answers "listed" for everything — and that answer is
    /// indistinguishable from a real listing unless the test entries are asked about too.
    /// Believing it sends an operator to file delisting requests with several organisations for
    /// a problem they do not have.
    /// </remarks>
    [Fact]
    public void A_listing_from_an_unreliable_list_is_not_believed()
    {
        ReputationFacts facts = Facts(ip:
        [
            new("broken.example.net", true, ["127.0.0.2"], null, ReputationListHealth.Unreliable),
            Clean("zen.example.net"),
        ]);

        Check(facts, ReputationChecks.IpNotListedId).Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// But it is not silently dropped either.
    /// </summary>
    /// <remarks>
    /// A clean bill of health from lists that never answered is the other way to mislead. The
    /// health check reports it, with a remedy pointing at the resolver rather than at anything
    /// the operator publishes.
    /// </remarks>
    [Fact]
    public void An_unreliable_list_is_reported_rather_than_dropped()
    {
        DeliverabilityCheck check = Check(
            Facts(ip: [new("broken.example.net", true, [], null, ReputationListHealth.Unreliable)]),
            ReputationChecks.ListsUsableId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("broken.example.net");
        check.Remedy.ShouldNotBeNull().ShouldContain("resolver");
    }

    /// <summary>A list that did not answer is reported as silent, not as unreliable.</summary>
    [Fact]
    public void A_silent_list_is_reported_as_silent()
    {
        DeliverabilityCheck check = Check(
            Facts(ip: [new("quiet.example.net", false, [], null, ReputationListHealth.NotAnswering)]),
            ReputationChecks.ListsUsableId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("did not answer");
    }

    /// <summary>
    /// With no believable list at all, the verdict is unknown rather than clean.
    /// </summary>
    /// <remarks>
    /// The distinction the whole report rests on, applied here: "nobody listed you" and "nobody
    /// answered" are different facts, and only the first is good news.
    /// </remarks>
    [Fact]
    public void With_no_believable_list_the_verdict_is_unknown()
    {
        DeliverabilityCheck check = Check(
            Facts(ip:
            [
                new("a.example.net", false, [], null, ReputationListHealth.NotAnswering),
                new("b.example.net", true, [], null, ReputationListHealth.Unreliable),
            ]),
            ReputationChecks.IpNotListedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
        check.Detail.ShouldContain("answered reliably");
    }

    /// <summary>An untested list is not believed either.</summary>
    [Fact]
    public void An_untested_list_is_not_believed()
    {
        Check(
                Facts(ip: [new("unknown.example.net", true, [], null, ReputationListHealth.Unknown)]),
                ReputationChecks.IpNotListedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>One healthy list among broken ones is enough to judge on.</summary>
    [Fact]
    public void One_healthy_list_is_enough_to_judge_on()
    {
        ReputationFacts facts = Facts(ip:
        [
            new("broken.example.net", false, [], null, ReputationListHealth.Unreliable),
            Listed("zen.example.net"),
        ]);

        Check(facts, ReputationChecks.IpNotListedId).Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    // ---------------------------------------------------------------------------------------
    // The category as a whole.
    // ---------------------------------------------------------------------------------------

    /// <summary>A listed server is Not ready, whatever else it scores.</summary>
    [Fact]
    public void A_listed_server_is_not_ready()
    {
        DeliverabilityReport report = DeliverabilityReport.From(
            ReputationChecks.Evaluate(Facts(ip: [Listed("zen.example.net")])),
            new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));

        report.Readiness.ShouldBe(DeliverabilityReadiness.NotReady);
    }
}
