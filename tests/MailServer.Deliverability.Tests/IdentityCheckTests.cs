using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

public sealed class IdentityCheckTests
{
    private static readonly DomainName Hostname = DomainName.Parse("mail.example.com");
    private static readonly IpAddressValue Sender = IpAddressValue.Parse("203.0.113.10");
    private static readonly IpAddressValue Other = IpAddressValue.Parse("198.51.100.7");

    /// <summary>
    /// A correct configuration, with one aspect replaced.
    /// </summary>
    /// <remarks>
    /// Every parameter's null means "leave this correct", so a test that needs a lookup to have
    /// <i>not answered</i> — which the production type spells as null — builds the record
    /// directly instead. The two meanings cannot share one helper without one of them being
    /// silently unreachable, which is how a test passes for the wrong reason.
    /// </remarks>
    private static IdentityFacts Facts(
        IReadOnlyList<IpAddressValue>? hostnameAddresses = null,
        IReadOnlyList<string>? pointerNames = null,
        IReadOnlyDictionary<string, IReadOnlyList<IpAddressValue>>? forward = null,
        DomainName? hostname = null) =>
        new(
            hostname ?? Hostname,
            Sender,
            hostnameAddresses ?? [Sender],
            pointerNames ?? ["mail.example.com"],
            forward ?? new Dictionary<string, IReadOnlyList<IpAddressValue>>
            {
                ["mail.example.com"] = [Sender],
            });

    private static DeliverabilityCheck Check(IdentityFacts facts, string id) =>
        IdentityChecks.Evaluate(facts).Single(c => c.Id == id);

    /// <summary>Every check belongs to the category it is weighted under.</summary>
    [Fact]
    public void Every_identity_check_is_in_the_identity_category() =>
        IdentityChecks.Evaluate(Facts())
            .ShouldAllBe(c => c.Category == DeliverabilityCategory.Identity);

    /// <summary>A correct configuration passes everything.</summary>
    [Fact]
    public void A_correct_configuration_passes_every_identity_check() =>
        IdentityChecks.Evaluate(Facts())
            .ShouldAllBe(c => c.Outcome == DeliverabilityOutcome.Pass);

    // ---------------------------------------------------------------------------------------
    // The hostname.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A hostname that resolves to nothing fails every downstream expectation at once: the MX
    /// target cannot point at it usefully, a receiver's forward lookup on the EHLO name finds
    /// nothing, and the certificate names something that does not exist.
    /// </summary>
    [Fact]
    public void A_hostname_that_resolves_to_nothing_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(hostnameAddresses: []),
            IdentityChecks.HostnameResolvesId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence!.Found.ShouldBeNull();
        check.Remedy!.ShouldContain("A record");
    }

    /// <summary>
    /// A lookup that did not answer is inconclusive, not a failure: a resolver timeout is not a
    /// fact about the operator's configuration.
    /// </summary>
    [Fact]
    public void A_hostname_lookup_that_did_not_answer_is_inconclusive()
    {
        // Built directly: a null here means "the lookup did not answer", which the helper's
        // defaults cannot express.
        IdentityFacts facts = new(
            Hostname,
            Sender,
            HostnameAddresses: null,
            PointerNames: ["mail.example.com"],
            new Dictionary<string, IReadOnlyList<IpAddressValue>>());

        DeliverabilityCheck check = Check(facts, IdentityChecks.HostnameResolvesId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
        check.Remedy.ShouldBeNull();
    }

    /// <summary>
    /// A PTR lookup that did not answer is inconclusive for the same reason — and so is the
    /// round trip that depends on it.
    /// </summary>
    [Fact]
    public void A_pointer_lookup_that_did_not_answer_is_inconclusive()
    {
        IdentityFacts facts = new(
            Hostname,
            Sender,
            [Sender],
            PointerNames: null,
            new Dictionary<string, IReadOnlyList<IpAddressValue>>());

        Check(facts, IdentityChecks.PointerId).Outcome
            .ShouldBe(DeliverabilityOutcome.Inconclusive);
        Check(facts, IdentityChecks.ForwardConfirmedId).Outcome
            .ShouldBe(DeliverabilityOutcome.Inconclusive);
        Check(facts, IdentityChecks.HeloMatchesPointerId).Outcome
            .ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    // ---------------------------------------------------------------------------------------
    // PTR.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// docs/DNS.md: "Major receivers reject or spam-folder mail from IPs without correct FCrDNS.
    /// It is not optional, it cannot be fixed in your own DNS zone, and it is the single most
    /// common reason a self-hosted server cannot deliver to Gmail."
    /// </summary>
    [Fact]
    public void An_address_with_no_reverse_dns_fails()
    {
        DeliverabilityCheck check = Check(Facts(pointerNames: []), IdentityChecks.PointerId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("no reverse DNS");
    }

    /// <summary>
    /// The remedy names the address's owner rather than the operator's DNS panel. The reverse
    /// zone belongs to whoever assigned the address; telling an operator to "add a PTR record"
    /// sends them somewhere they have no authority, and they conclude the tool is wrong.
    /// </summary>
    [Fact]
    public void The_reverse_dns_remedy_names_the_addresss_owner()
    {
        string remedy = Check(Facts(pointerNames: []), IdentityChecks.PointerId).Remedy.ShouldNotBeNull();

        remedy.ShouldContain("hosting provider");
        remedy.ShouldContain("cannot be fixed in your own DNS zone");
    }

    /// <summary>
    /// PTR is the heaviest check in the category, because it is the one thing correct SPF, DKIM
    /// and DMARC cannot compensate for.
    /// </summary>
    [Fact]
    public void Reverse_dns_outweighs_the_other_identity_checks()
    {
        IReadOnlyList<DeliverabilityCheck> checks = IdentityChecks.Evaluate(Facts());

        int pointer = checks.Single(c => c.Id == IdentityChecks.PointerId).Weight;

        checks.Single(c => c.Id == IdentityChecks.HostnameResolvesId).Weight
            .ShouldBeLessThan(pointer);
        checks.Single(c => c.Id == IdentityChecks.HeloMatchesPointerId).Weight
            .ShouldBeLessThan(pointer);
    }

    /// <summary>A sending address that could not be determined is not a configuration finding.</summary>
    [Fact]
    public void An_unknown_sending_address_makes_the_address_checks_inconclusive()
    {
        IdentityFacts facts = new(
            Hostname,
            PublicAddress: null,
            [Sender],
            ["mail.example.com"],
            new Dictionary<string, IReadOnlyList<IpAddressValue>>
            {
                ["mail.example.com"] = [Sender],
            });

        Check(facts, IdentityChecks.PointerId).Outcome
            .ShouldBe(DeliverabilityOutcome.Inconclusive);
        Check(facts, IdentityChecks.ForwardConfirmedId).Outcome
            .ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    // ---------------------------------------------------------------------------------------
    // Forward-confirmed reverse DNS.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// docs/DNS.md: "Forward-Confirmed reverse DNS means the PTR for your sending IP resolves to
    /// a name, and that name resolves back to the same IP."
    /// </summary>
    [Fact]
    public void A_name_that_does_not_resolve_back_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(forward: new Dictionary<string, IReadOnlyList<IpAddressValue>>
            {
                ["mail.example.com"] = [Other],
            }),
            IdentityChecks.ForwardConfirmedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence!.Found!.ShouldContain("198.51.100.7");
    }

    /// <summary>
    /// One confirming name is enough. An address may legitimately have several PTR records, and
    /// a receiver checking FCrDNS is satisfied by finding one that round-trips; requiring all of
    /// them would fail a correct configuration.
    /// </summary>
    [Fact]
    public void One_name_resolving_back_is_enough()
    {
        DeliverabilityCheck check = Check(
            Facts(
                pointerNames: ["old.example.com", "mail.example.com"],
                forward: new Dictionary<string, IReadOnlyList<IpAddressValue>>
                {
                    ["old.example.com"] = [Other],
                    ["mail.example.com"] = [Sender],
                }),
            IdentityChecks.ForwardConfirmedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// With no PTR record there is nothing to confirm, and the PTR check has already said so.
    /// Failing here as well would charge an operator twice for one missing record.
    /// </summary>
    [Fact]
    public void Without_a_pointer_record_there_is_nothing_to_confirm()
    {
        DeliverabilityCheck check = Check(Facts(pointerNames: []), IdentityChecks.ForwardConfirmedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
        check.Detail.ShouldContain("see the reverse DNS check");
    }

    /// <summary>
    /// A forward lookup that did not answer at all is a resolver problem rather than a finding.
    /// </summary>
    [Fact]
    public void A_forward_lookup_that_did_not_answer_is_inconclusive()
    {
        DeliverabilityCheck check = Check(
            Facts(forward: new Dictionary<string, IReadOnlyList<IpAddressValue>>()),
            IdentityChecks.ForwardConfirmedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// A name that answered with no addresses is a finding, not a resolver problem: the name
    /// exists and does not point back.
    /// </summary>
    [Fact]
    public void A_name_that_resolves_to_nothing_fails_the_round_trip()
    {
        DeliverabilityCheck check = Check(
            Facts(forward: new Dictionary<string, IReadOnlyList<IpAddressValue>>
            {
                ["mail.example.com"] = [],
            }),
            IdentityChecks.ForwardConfirmedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence!.Found!.ShouldContain("nothing");
    }

    // ---------------------------------------------------------------------------------------
    // EHLO agreement.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// docs/DNS.md: "The EHLO name, the PTR record, the TLS certificate SAN and the MX target
    /// must all agree." A disagreement is scored against the sender by some receivers, but mail
    /// still flows — so it warns rather than fails.
    /// </summary>
    [Fact]
    public void An_ehlo_name_that_differs_from_the_pointer_warns()
    {
        DeliverabilityCheck check = Check(
            Facts(pointerNames: ["host-203-0-113-10.provider.test"]),
            IdentityChecks.HeloMatchesPointerId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);

        string remedy = check.Remedy.ShouldNotBeNull();

        remedy.ShouldContain("host-203-0-113-10.provider.test");
        remedy.ShouldContain("certificate");
    }

    /// <summary>
    /// DNS names are case-insensitive and a PTR record conventionally carries a trailing dot.
    /// Neither is a disagreement, and reporting one would send an operator to change a record
    /// that is already correct.
    /// </summary>
    [Theory]
    [InlineData("mail.example.com.")]
    [InlineData("MAIL.EXAMPLE.COM")]
    [InlineData("Mail.Example.Com.")]
    public void Case_and_a_trailing_dot_are_not_a_disagreement(string pointer) =>
        Check(Facts(pointerNames: [pointer]), IdentityChecks.HeloMatchesPointerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);

    /// <summary>Any one of several PTR names matching is agreement.</summary>
    [Fact]
    public void One_matching_pointer_name_is_agreement() =>
        Check(
            Facts(pointerNames: ["other.example.com", "mail.example.com"]),
            IdentityChecks.HeloMatchesPointerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);

    // ---------------------------------------------------------------------------------------
    // Evidence.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// docs/Deliverability.md requires evidence on every check that concluded: "the record
    /// actually found, the value expected". A verdict an operator cannot act on is not a check.
    /// </summary>
    [Fact]
    public void Every_check_that_concluded_carries_evidence()
    {
        foreach (DeliverabilityCheck check in IdentityChecks.Evaluate(Facts(pointerNames: [])))
        {
            if (check.IsJudged)
            {
                check.Evidence.ShouldNotBeNull($"{check.Id} concluded without evidence");
                check.Evidence.Expected.ShouldNotBeNullOrWhiteSpace();
            }
        }
    }

    /// <summary>Every check that found a problem says what to do about it.</summary>
    [Fact]
    public void Every_failing_check_carries_a_remedy()
    {
        IdentityFacts broken = Facts(
            hostnameAddresses: [],
            pointerNames: ["elsewhere.example.com"],
            forward: new Dictionary<string, IReadOnlyList<IpAddressValue>>
            {
                ["elsewhere.example.com"] = [Other],
            });

        foreach (DeliverabilityCheck check in IdentityChecks.Evaluate(broken))
        {
            if (check.Outcome is DeliverabilityOutcome.Fail or DeliverabilityOutcome.Warn)
            {
                check.Remedy.ShouldNotBeNullOrWhiteSpace($"{check.Id} has no remedy");
            }
        }
    }

    /// <summary>A passing check has nothing to remedy.</summary>
    [Fact]
    public void A_passing_check_carries_no_remedy() =>
        IdentityChecks.Evaluate(Facts())
            .Where(c => c.Outcome == DeliverabilityOutcome.Pass)
            .ShouldAllBe(c => c.Remedy == null);

    /// <summary>The ids are stable and distinct, because a UI and an operator refer to them.</summary>
    [Fact]
    public void The_check_ids_are_distinct()
    {
        IReadOnlyList<DeliverabilityCheck> checks = IdentityChecks.Evaluate(Facts());

        checks.Select(c => c.Id).Distinct().Count().ShouldBe(checks.Count);
        checks.Select(c => c.Id).ShouldBe(
        [
            IdentityChecks.HostnameResolvesId,
            IdentityChecks.PointerId,
            IdentityChecks.ForwardConfirmedId,
            IdentityChecks.HeloMatchesPointerId,
        ]);
    }

    /// <summary>
    /// The worst realistic case — no PTR at all — still produces a report, and it is Not ready
    /// rather than merely low-scoring.
    /// </summary>
    [Fact]
    public void A_server_with_no_reverse_dns_is_reported_as_not_ready()
    {
        DeliverabilityReport report = DeliverabilityReport.From(
            IdentityChecks.Evaluate(Facts(pointerNames: [])),
            DateTimeOffset.UnixEpoch);

        report.Readiness.ShouldBe(DeliverabilityReadiness.NotReady);
        report.Failures.Select(c => c.Id).ShouldContain(IdentityChecks.PointerId);
    }
}
