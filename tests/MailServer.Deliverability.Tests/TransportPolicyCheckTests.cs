using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

public sealed class TransportPolicyCheckTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");

    private const string GoodRecord = "v=STSv1; id=20260919T120000";
    private const string GoodRpt = "v=TLSRPTv1; rua=mailto:tlsrpt@example.com";

    private static string PolicyText(
        string mode = "enforce",
        string mx = "mail.example.com",
        long maxAge = 604800) =>
        $"version: STSv1\r\nmode: {mode}\r\nmx: {mx}\r\nmax_age: {maxAge}\r\n";

    private static TransportPolicyFacts Facts(
        IReadOnlyList<string>? mxHosts = null,
        IReadOnlyList<string>? sts = null,
        MtaStsFetchOutcome outcome = MtaStsFetchOutcome.Fetched,
        string? policy = null,
        IReadOnlyList<string>? rpt = null) =>
        new(
            Domain,
            mxHosts ?? ["mail.example.com"],
            sts ?? [GoodRecord],
            outcome,
            policy ?? PolicyText(),
            rpt ?? [GoodRpt]);

    private static DeliverabilityCheck Check(TransportPolicyFacts facts, string id) =>
        TransportPolicyChecks.Evaluate(facts).Single(c => c.Id == id);

    // ---------------------------------------------------------------------------------------
    // Shape.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Every_transport_policy_check_is_in_the_tls_category()
    {
        foreach (DeliverabilityCheck check in TransportPolicyChecks.Evaluate(Facts()))
        {
            check.Category.ShouldBe(DeliverabilityCategory.Tls);
        }
    }

    /// <summary>
    /// Six points, which with <see cref="TlsChecks"/>' fourteen makes the category's twenty.
    /// </summary>
    [Fact]
    public void The_transport_policy_weights_sum_to_six()
    {
        TransportPolicyChecks.Evaluate(Facts()).Sum(c => c.Weight).ShouldBe(6);
    }

    /// <summary>The two halves of the TLS category between them weigh exactly twenty.</summary>
    [Fact]
    public void The_two_halves_of_the_tls_category_sum_to_twenty()
    {
        int transport = TransportPolicyChecks.Evaluate(Facts()).Sum(c => c.Weight);

        int certificate = TlsChecks.Evaluate(new TlsFacts(
            DomainName.Parse("mail.example.com"),
            null,
            null,
            null,
            new Domain.Policies.CertificateRenewalPolicy(),
            DateTimeOffset.UnixEpoch)).Sum(c => c.Weight);

        (transport + certificate).ShouldBe(
            DeliverabilityCategories.WeightOf(DeliverabilityCategory.Tls));
    }

    [Fact]
    public void A_fully_configured_domain_passes_every_transport_policy_check()
    {
        foreach (DeliverabilityCheck check in TransportPolicyChecks.Evaluate(Facts()))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Pass, check.Id);
        }
    }

    /// <summary>Anything that is not a pass says what to do about it.</summary>
    [Fact]
    public void Every_transport_policy_finding_carries_a_remedy()
    {
        TransportPolicyFacts[] broken =
        [
            Facts(sts: []),
            Facts(sts: [GoodRecord, "v=STSv1; id=other"]),
            Facts(sts: ["v=STSv1"]),
            Facts(outcome: MtaStsFetchOutcome.Unreachable),
            Facts(outcome: MtaStsFetchOutcome.NotFound),
            Facts(outcome: MtaStsFetchOutcome.TlsFailed),
            Facts(outcome: MtaStsFetchOutcome.WrongMediaType),
            Facts(policy: "not a policy"),
            Facts(policy: PolicyText(mode: "testing")),
            Facts(policy: PolicyText(mode: "none", mx: "mail.example.com")),
            Facts(policy: PolicyText(maxAge: 3600)),
            Facts(policy: PolicyText(mx: "other.example.net")),
            Facts(rpt: []),
            Facts(rpt: ["v=TLSRPTv1"]),
        ];

        foreach (TransportPolicyFacts facts in broken)
        {
            foreach (DeliverabilityCheck check in TransportPolicyChecks.Evaluate(facts))
            {
                if (check.Outcome is DeliverabilityOutcome.Warn or DeliverabilityOutcome.Fail)
                {
                    check.Remedy.ShouldNotBeNullOrWhiteSpace(check.Id);
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // The record.
    // ---------------------------------------------------------------------------------------

    /// <summary>No MTA-STS record warns; it is opt-in, not something broken.</summary>
    [Fact]
    public void No_mta_sts_record_warns()
    {
        Check(Facts(sts: []), TransportPolicyChecks.MtaStsRecordId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>
    /// Two records fail, because senders treat them as no policy at all.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.1: "If the number of resulting records is not one […] senders MUST assume the
    /// recipient domain does not have an available MTA-STS Policy and skip the remaining steps
    /// of policy discovery." The operator sees a correct-looking record and believes MTA-STS is
    /// on, which is why this is worse than the absence the check above merely warns about.
    /// </remarks>
    [Fact]
    public void Two_mta_sts_records_fail()
    {
        DeliverabilityCheck check = Check(
            Facts(sts: [GoodRecord, "v=STSv1; id=20260101T000000"]),
            TransportPolicyChecks.MtaStsRecordId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("no policy at all");
    }

    /// <summary>
    /// A record with no id fails: senders cannot tell a revision from what they cached.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.1 makes id required, and says why: it "MUST uniquely identify a given instance
    /// of a policy, such that senders can determine when the policy has been updated by comparing
    /// to the 'id' of a previously seen policy."
    /// </remarks>
    [Fact]
    public void An_mta_sts_record_without_an_id_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(sts: ["v=STSv1"]),
            TransportPolicyChecks.MtaStsRecordId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("no id tag");
    }

    /// <summary>An empty id is no id.</summary>
    [Fact]
    public void An_empty_id_is_not_an_id()
    {
        Check(Facts(sts: ["v=STSv1; id="]), TransportPolicyChecks.MtaStsRecordId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// The version is matched as a whole token and case-sensitively.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.1's ABNF spells it <c>sts-version = %s"v=STSv1"</c> — the <c>%s</c> prefix of
    /// RFC 7405 is what makes an ABNF string case-sensitive. A record spelled another way is one
    /// senders discard, so counting it would report a policy nobody applies.
    /// </remarks>
    [Theory]
    [InlineData("v=STSv10; id=abc")]
    [InlineData("v=stsv1; id=abc")]
    public void A_record_that_is_not_v_equals_stsv1_is_not_an_mta_sts_record(string record)
    {
        Check(Facts(sts: [record]), TransportPolicyChecks.MtaStsRecordId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>An unanswered lookup is not an absent record.</summary>
    [Fact]
    public void An_unanswered_sts_lookup_leaves_the_record_unjudged()
    {
        Check(
                new TransportPolicyFacts(Domain, ["mail.example.com"], null, MtaStsFetchOutcome.NotAttempted, null, []),
                TransportPolicyChecks.MtaStsRecordId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    // ---------------------------------------------------------------------------------------
    // The policy resource.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// With no record there is no policy fetch, so nothing more to report.
    /// </summary>
    /// <remarks>
    /// Charging a domain that has not adopted MTA-STS twice — once for the record and once for
    /// the policy — would make opting out cost four points where opting in badly costs two.
    /// </remarks>
    [Fact]
    public void With_no_record_the_policy_check_is_not_charged()
    {
        Check(Facts(sts: []), TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// A record with no reachable policy fails.
    /// </summary>
    /// <remarks>
    /// Worse than publishing neither: every sender follows the record, spends a request per
    /// refresh and gets nothing, while the operator sees a correct TXT record and concludes
    /// MTA-STS is working.
    /// </remarks>
    [Theory]
    [InlineData(MtaStsFetchOutcome.Unreachable)]
    [InlineData(MtaStsFetchOutcome.NotFound)]
    [InlineData(MtaStsFetchOutcome.TlsFailed)]
    [InlineData(MtaStsFetchOutcome.WrongMediaType)]
    public void A_record_whose_policy_cannot_be_read_fails(MtaStsFetchOutcome outcome)
    {
        Check(Facts(outcome: outcome), TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// A failed TLS handshake with the policy host gets its own finding.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.3 makes it fatal, and it is uniquely easy to miss: a browser that clicks
    /// through the warning shows the file perfectly. The remedy also has to say the policy host
    /// needs a certificate of its own, since the mail server's does not cover it.
    /// </remarks>
    [Fact]
    public void A_policy_host_with_a_bad_certificate_says_so()
    {
        DeliverabilityCheck check = Check(
            Facts(outcome: MtaStsFetchOutcome.TlsFailed),
            TransportPolicyChecks.MtaStsPolicyId);

        check.Detail.ShouldContain("browser");
        check.Remedy.ShouldNotBeNull().ShouldContain("mta-sts.example.com");
    }

    /// <summary>A policy that does not parse is no policy.</summary>
    [Fact]
    public void A_policy_that_does_not_parse_fails()
    {
        Check(Facts(policy: "version: STSv1\r\nmode: enforce\r\n"), TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// Testing mode warns, and the remedy names the next step rather than a fault.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §5: in testing "messages may be delivered as though there were no MTA-STS
    /// validation failure". It is the mode to publish first, precisely because it cannot lose
    /// mail — so an operator who has done the right thing should not be told they got it wrong.
    /// </remarks>
    [Fact]
    public void Testing_mode_warns_and_names_the_next_step()
    {
        DeliverabilityCheck check = Check(
            Facts(policy: PolicyText(mode: "testing")),
            TransportPolicyChecks.MtaStsPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("right first step");
        check.Remedy.ShouldNotBeNull().ShouldContain("enforce");
    }

    /// <summary>Mode none warns: it is how a policy is withdrawn.</summary>
    [Fact]
    public void Mode_none_warns()
    {
        Check(Facts(policy: PolicyText(mode: "none")), TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>
    /// A policy omitting a live MX host fails — the one MTA-STS fault that loses mail.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §5: in enforce mode senders "MUST NOT deliver the message to hosts that fail MX
    /// matching". A domain whose MX names a host its own policy omits is instructing senders to
    /// use a host and then refusing it.
    /// </remarks>
    [Fact]
    public void A_policy_that_omits_a_live_mx_host_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(mxHosts: ["mail.example.com", "mx2.example.com"]),
            TransportPolicyChecks.MtaStsPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("mx2.example.com");
        check.Remedy.ShouldNotBeNull().ShouldContain("mx: mx2.example.com");
    }

    /// <summary>
    /// A wildcard in the policy covers one label, as RFC 8461 §4.1 restricts it to.
    /// </summary>
    /// <remarks>
    /// §4.1: "the mx pattern '*.example.com' matches 'mail.example.com' but not 'example.com' or
    /// 'foo.bar.example.com'."
    /// </remarks>
    [Theory]
    [InlineData("mail.example.com", DeliverabilityOutcome.Pass)]
    [InlineData("example.com", DeliverabilityOutcome.Fail)]
    [InlineData("foo.bar.example.com", DeliverabilityOutcome.Fail)]
    public void A_policy_wildcard_matches_exactly_one_label(string host, DeliverabilityOutcome expected)
    {
        Check(
                Facts(mxHosts: [host], policy: PolicyText(mx: "*.example.com")),
                TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>
    /// A short max_age warns although the policy is otherwise correct.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.2: "To mitigate the risks of attacks at policy refresh time, it is expected
    /// that this value typically be in the range of weeks or greater." Each refetch is an
    /// opening for whoever can block it.
    /// </remarks>
    [Fact]
    public void A_short_max_age_warns()
    {
        DeliverabilityCheck check = Check(
            Facts(policy: PolicyText(maxAge: 3600)),
            TransportPolicyChecks.MtaStsPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("weeks or greater");
    }

    /// <summary>
    /// Coverage is judged before the mode, because it is the worse fault.
    /// </summary>
    /// <remarks>
    /// A testing-mode policy that omits a live MX is on its way to losing mail the moment the
    /// operator does what the other finding tells them and moves to enforce. Reporting only
    /// "you are in testing mode" would send them straight into it.
    /// </remarks>
    [Fact]
    public void An_uncovered_host_is_reported_ahead_of_the_mode()
    {
        Check(
                Facts(mxHosts: ["mx2.example.com"], policy: PolicyText(mode: "testing")),
                TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>Without the MX hosts, coverage cannot be judged — but the mode still can.</summary>
    [Fact]
    public void Without_the_mx_hosts_the_mode_is_still_judged()
    {
        Check(
                Facts(mxHosts: null, policy: PolicyText(mode: "testing")),
                TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    // ---------------------------------------------------------------------------------------
    // TLS-RPT.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// No TLS-RPT record warns, and the finding says what it costs.
    /// </summary>
    /// <remarks>
    /// RFC 8460 §3's rua is "A URI specifying the endpoint to which aggregate information about
    /// policy validation results should be sent". Without it a sender's failure is reported to
    /// nobody, and moving MTA-STS to enforce is done blind.
    /// </remarks>
    [Fact]
    public void No_tls_rpt_record_warns()
    {
        DeliverabilityCheck check = Check(Facts(rpt: []), TransportPolicyChecks.TlsReportingId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("blind");
    }

    /// <summary>A record with no rua names nowhere to send reports.</summary>
    [Fact]
    public void A_tls_rpt_record_without_rua_warns()
    {
        Check(Facts(rpt: ["v=TLSRPTv1"]), TransportPolicyChecks.TlsReportingId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>An https endpoint is a valid rua, which RFC 8460 §3 allows alongside mailto.</summary>
    [Fact]
    public void An_https_rua_is_accepted()
    {
        Check(
                Facts(rpt: ["v=TLSRPTv1; rua=https://reports.example.com/tlsrpt"]),
                TransportPolicyChecks.TlsReportingId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>An unanswered lookup is not an absent record.</summary>
    [Fact]
    public void An_unanswered_tls_rpt_lookup_leaves_the_check_unjudged()
    {
        Check(
                new TransportPolicyFacts(Domain, ["mail.example.com"], [GoodRecord], MtaStsFetchOutcome.Fetched, PolicyText(), null),
                TransportPolicyChecks.TlsReportingId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }
}
