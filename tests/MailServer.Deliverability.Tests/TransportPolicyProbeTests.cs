using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>A fetcher that answers from a script and records whether it was called.</summary>
internal sealed class ScriptedPolicyFetcher(
    MtaStsFetchOutcome outcome = MtaStsFetchOutcome.Fetched,
    string? text = null) : IMtaStsPolicyFetcher
{
    public int Calls { get; private set; }

    public Task<MtaStsPolicyFetch> FetchAsync(DomainName domain, CancellationToken cancellationToken)
    {
        Calls++;

        return Task.FromResult(new MtaStsPolicyFetch(outcome, text, null));
    }
}

public sealed class TransportPolicyProbeTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");

    private const string Policy =
        "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 604800\r\n";

    private static Task<TransportPolicyFacts> Gather(
        ScriptedDiagnosticsService dns,
        ScriptedPolicyFetcher fetcher,
        IReadOnlyList<string>? mxHosts = null) =>
        new TransportPolicyProbe(dns, fetcher)
            .GatherAsync(Domain, mxHosts ?? ["mail.example.com"], CancellationToken.None);

    /// <summary>The two names, spelled the way RFC 8461 §3.1 and RFC 8460 §3 spell them.</summary>
    [Fact]
    public async Task The_probe_asks_about_the_sts_and_tls_rpt_names()
    {
        ScriptedDiagnosticsService dns = new();

        await Gather(dns, new ScriptedPolicyFetcher());

        dns.Asked.ShouldBe(
        [
            ("_mta-sts.example.com", DnsDiagnosticRecordType.Txt),
            ("_smtp._tls.example.com", DnsDiagnosticRecordType.Txt),
        ]);
    }

    /// <summary>
    /// With no record, no request is made to the domain's policy host.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.1 has senders "skip the remaining steps of policy discovery" without a usable
    /// record. Fetching anyway would be an outbound request to a host named by the domain under
    /// test, on the strength of nothing that domain published.
    /// </remarks>
    [Fact]
    public async Task With_no_record_the_policy_host_is_not_contacted()
    {
        ScriptedPolicyFetcher fetcher = new();

        TransportPolicyFacts facts = await Gather(new ScriptedDiagnosticsService(), fetcher);

        fetcher.Calls.ShouldBe(0);
        facts.PolicyOutcome.ShouldBe(MtaStsFetchOutcome.NotAttempted);
    }

    /// <summary>
    /// A name that answers with no TXT record is an empty list, and that is a finding.
    /// </summary>
    /// <remarks>
    /// The distinction the whole report rests on, in the one place it is easiest to lose: both
    /// "no record" and "no answer" skip the fetch, so a probe that collapsed them would look
    /// correct from the fetch side while turning "you have not adopted MTA-STS" — something the
    /// operator can act on — into "not tested".
    /// </remarks>
    [Fact]
    public async Task A_domain_with_no_mta_sts_record_yields_an_empty_list_not_a_null()
    {
        TransportPolicyFacts facts = await Gather(
            new ScriptedDiagnosticsService(),
            new ScriptedPolicyFetcher());

        facts.StsTxtRecords.ShouldNotBeNull().ShouldBeEmpty();
        facts.TlsRptTxtRecords.ShouldNotBeNull().ShouldBeEmpty();

        IReadOnlyList<DeliverabilityCheck> checks = TransportPolicyChecks.Evaluate(facts);

        checks.Single(c => c.Id == TransportPolicyChecks.MtaStsRecordId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);

        checks.Single(c => c.Id == TransportPolicyChecks.TlsReportingId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>A record present means the policy is fetched.</summary>
    [Fact]
    public async Task A_record_present_means_the_policy_is_fetched()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("_mta-sts.example.com", DnsDiagnosticRecordType.Txt, "v=STSv1; id=abc");

        ScriptedPolicyFetcher fetcher = new(MtaStsFetchOutcome.Fetched, Policy);

        TransportPolicyFacts facts = await Gather(dns, fetcher);

        fetcher.Calls.ShouldBe(1);
        facts.PolicyOutcome.ShouldBe(MtaStsFetchOutcome.Fetched);
        facts.PolicyText.ShouldBe(Policy);
    }

    /// <summary>
    /// A fetch that failed is carried through as the reason it failed.
    /// </summary>
    /// <remarks>
    /// Each outcome is a distinct finding with a distinct remedy — flattening them to "no policy"
    /// would tell an operator with a bad certificate on their policy host to go and write a file
    /// that is already there.
    /// </remarks>
    [Theory]
    [InlineData(MtaStsFetchOutcome.Unreachable)]
    [InlineData(MtaStsFetchOutcome.NotFound)]
    [InlineData(MtaStsFetchOutcome.TlsFailed)]
    [InlineData(MtaStsFetchOutcome.WrongMediaType)]
    public async Task A_failed_fetch_is_carried_through_as_its_reason(MtaStsFetchOutcome outcome)
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("_mta-sts.example.com", DnsDiagnosticRecordType.Txt, "v=STSv1; id=abc");

        TransportPolicyFacts facts = await Gather(dns, new ScriptedPolicyFetcher(outcome));

        facts.PolicyOutcome.ShouldBe(outcome);

        TransportPolicyChecks.Evaluate(facts)
            .Single(c => c.Id == TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>Each record is attached to the check that reads it.</summary>
    [Fact]
    public async Task Each_record_is_attached_to_the_right_name()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("_mta-sts.example.com", DnsDiagnosticRecordType.Txt, "v=STSv1; id=abc")
            .With("_smtp._tls.example.com", DnsDiagnosticRecordType.Txt, "v=TLSRPTv1; rua=mailto:t@example.com");

        TransportPolicyFacts facts = await Gather(dns, new ScriptedPolicyFetcher(MtaStsFetchOutcome.Fetched, Policy));

        facts.StsTxtRecords.ShouldBe(["v=STSv1; id=abc"]);
        facts.TlsRptTxtRecords.ShouldBe(["v=TLSRPTv1; rua=mailto:t@example.com"]);

        foreach (DeliverabilityCheck check in TransportPolicyChecks.Evaluate(facts))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Pass, check.Id);
        }
    }

    /// <summary>The MX hosts are passed through so the policy's coverage can be judged.</summary>
    [Fact]
    public async Task The_mx_hosts_are_passed_through()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("_mta-sts.example.com", DnsDiagnosticRecordType.Txt, "v=STSv1; id=abc");

        TransportPolicyFacts facts = await Gather(
            dns,
            new ScriptedPolicyFetcher(MtaStsFetchOutcome.Fetched, Policy),
            mxHosts: ["mail.example.com", "mx2.example.com"]);

        facts.MxHosts.ShouldBe(["mail.example.com", "mx2.example.com"]);

        TransportPolicyChecks.Evaluate(facts)
            .Single(c => c.Id == TransportPolicyChecks.MtaStsPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>An unanswered lookup yields null, and the check goes unjudged.</summary>
    [Fact]
    public async Task An_unanswered_lookup_yields_null()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .WithNoAnswer("_mta-sts.example.com", DnsDiagnosticRecordType.Txt)
            .WithNoAnswer("_smtp._tls.example.com", DnsDiagnosticRecordType.Txt);

        TransportPolicyFacts facts = await Gather(dns, new ScriptedPolicyFetcher());

        facts.StsTxtRecords.ShouldBeNull();
        facts.TlsRptTxtRecords.ShouldBeNull();

        foreach (DeliverabilityCheck check in TransportPolicyChecks.Evaluate(facts))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, check.Id);
        }
    }

    /// <summary>
    /// A lookup that did not answer does not trigger the fetch either.
    /// </summary>
    /// <remarks>
    /// "The resolver did not answer" is not "there is a record", and a probe that fetched on an
    /// unknown would contact a policy host on the strength of a timeout.
    /// </remarks>
    [Fact]
    public async Task An_unanswered_lookup_does_not_trigger_the_fetch()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .WithNoAnswer("_mta-sts.example.com", DnsDiagnosticRecordType.Txt);

        ScriptedPolicyFetcher fetcher = new();

        await Gather(dns, fetcher);

        fetcher.Calls.ShouldBe(0);
    }

    /// <summary>The URL is the one RFC 8461 §3.2 fixes.</summary>
    [Fact]
    public void The_policy_url_is_the_one_the_rfc_fixes()
    {
        MtaStsPolicyFetcher.UrlFor(Domain)
            .ShouldBe("https://mta-sts.example.com/.well-known/mta-sts.txt");
    }
}
