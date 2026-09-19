using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

public sealed class AuthenticationProbeTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");

    private static DkimSelector Selector(string value) => DkimSelector.Parse(value);

    // ---------------------------------------------------------------------------------------
    // The names it asks about.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The three names, spelled the way the RFCs spell them.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.1 puts the policy at <c>_dmarc</c> beneath the domain; RFC 6376 §3.6.2.1 puts
    /// a key at <c>selector._domainkey.domain</c>, in that order. A probe that inverted the two
    /// DKIM labels would find nothing and report every domain as unsigned.
    /// </remarks>
    [Fact]
    public async Task The_probe_asks_about_the_domain_the_dmarc_name_and_each_selector()
    {
        ScriptedDiagnosticsService dns = new();

        await new AuthenticationProbe(dns).GatherAsync(
            Domain,
            [Selector("mail2026"), Selector("mail2025")],
            CancellationToken.None);

        dns.Asked.ShouldBe(
        [
            ("example.com", DnsDiagnosticRecordType.Txt),
            ("_dmarc.example.com", DnsDiagnosticRecordType.Txt),
            ("mail2026._domainkey.example.com", DnsDiagnosticRecordType.Txt),
            ("mail2025._domainkey.example.com", DnsDiagnosticRecordType.Txt),
        ]);
    }

    /// <summary>A server that signs with nothing asks about no selector, and says so.</summary>
    [Fact]
    public async Task No_selectors_means_no_selector_lookups()
    {
        ScriptedDiagnosticsService dns = new();

        AuthenticationFacts facts = await new AuthenticationProbe(dns)
            .GatherAsync(Domain, [], CancellationToken.None);

        facts.Selectors.ShouldBeEmpty();
        dns.Asked.Count.ShouldBe(2);
    }

    // ---------------------------------------------------------------------------------------
    // What it carries back.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Every TXT record at a name is carried, not only the recognisable one.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §4.5 makes two <c>v=spf1</c> records a permanent error, and the checks can only
    /// notice if they are handed both. Filtering here would make the most consequential SPF
    /// fault in the category undetectable — and would do it silently, since the surviving record
    /// is perfectly valid on its own.
    /// </remarks>
    [Fact]
    public async Task Every_txt_record_at_the_domain_is_carried_back()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Txt,
                "v=spf1 mx -all",
                "google-site-verification=abc",
                "v=spf1 include:_spf.example.net ~all");

        AuthenticationFacts facts = await new AuthenticationProbe(dns)
            .GatherAsync(Domain, [], CancellationToken.None);

        facts.DomainTxtRecords.ShouldNotBeNull().Count.ShouldBe(3);

        AuthenticationChecks.Evaluate(facts)
            .Single(c => c.Id == AuthenticationChecks.SpfPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>The DMARC record comes from <c>_dmarc</c>, not from the domain itself.</summary>
    [Fact]
    public async Task The_dmarc_record_is_read_from_the_dmarc_name()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Txt, "v=spf1 mx -all")
            .With("_dmarc.example.com", DnsDiagnosticRecordType.Txt, "v=DMARC1; p=reject");

        AuthenticationFacts facts = await new AuthenticationProbe(dns)
            .GatherAsync(Domain, [], CancellationToken.None);

        facts.DomainTxtRecords.ShouldBe(["v=spf1 mx -all"]);
        facts.DmarcTxtRecords.ShouldBe(["v=DMARC1; p=reject"]);
    }

    /// <summary>A selector's records are attached to that selector, by name.</summary>
    [Fact]
    public async Task Each_selectors_records_are_attached_to_that_selector()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("new._domainkey.example.com", DnsDiagnosticRecordType.Txt, "v=DKIM1; k=rsa; p=AAAA")
            .With("old._domainkey.example.com", DnsDiagnosticRecordType.Txt, "v=DKIM1; k=rsa; p=");

        AuthenticationFacts facts = await new AuthenticationProbe(dns)
            .GatherAsync(Domain, [Selector("new"), Selector("old")], CancellationToken.None);

        facts.Selectors.Count.ShouldBe(2);

        facts.Selectors[0].Selector.ShouldBe("new");
        facts.Selectors[0].TxtRecords.ShouldBe(["v=DKIM1; k=rsa; p=AAAA"]);

        facts.Selectors[1].Selector.ShouldBe("old");
        facts.Selectors[1].TxtRecords.ShouldBe(["v=DKIM1; k=rsa; p="]);
    }

    // ---------------------------------------------------------------------------------------
    // The distinction the whole report rests on.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A name that exists with no TXT record answers with nothing; that is a fact.
    /// </summary>
    /// <remarks>
    /// The empty list is what becomes "you have not published this". Collapsing it into null
    /// would leave the check unjudged and the operator with no finding to act on — a domain
    /// publishing no SPF at all would report as "not tested".
    /// </remarks>
    [Fact]
    public async Task An_empty_answer_is_an_empty_list_and_not_a_null()
    {
        ScriptedDiagnosticsService dns = new();

        AuthenticationFacts facts = await new AuthenticationProbe(dns)
            .GatherAsync(Domain, [Selector("s")], CancellationToken.None);

        facts.DomainTxtRecords.ShouldNotBeNull().ShouldBeEmpty();
        facts.DmarcTxtRecords.ShouldNotBeNull().ShouldBeEmpty();
        facts.Selectors[0].TxtRecords.ShouldNotBeNull().ShouldBeEmpty();

        AuthenticationChecks.Evaluate(facts)
            .Single(c => c.Id == AuthenticationChecks.SpfPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// A resolver that did not answer yields null, and the check goes unjudged.
    /// </summary>
    /// <remarks>
    /// The other half of the same distinction, and the one a self-hosting operator cannot afford
    /// to have wrong: a timeout reported as a configuration failure sends them to change records
    /// that were already correct.
    /// </remarks>
    [Fact]
    public async Task A_lookup_that_did_not_answer_yields_null()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .WithNoAnswer("example.com", DnsDiagnosticRecordType.Txt)
            .WithNoAnswer("_dmarc.example.com", DnsDiagnosticRecordType.Txt)
            .WithNoAnswer("s._domainkey.example.com", DnsDiagnosticRecordType.Txt);

        AuthenticationFacts facts = await new AuthenticationProbe(dns)
            .GatherAsync(Domain, [Selector("s")], CancellationToken.None);

        facts.DomainTxtRecords.ShouldBeNull();
        facts.DmarcTxtRecords.ShouldBeNull();
        facts.Selectors[0].TxtRecords.ShouldBeNull();

        foreach (DeliverabilityCheck check in AuthenticationChecks.Evaluate(facts))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, check.Id);
        }
    }

    /// <summary>
    /// One failed lookup does not withhold the others.
    /// </summary>
    /// <remarks>
    /// A report that reduced itself to "unknown" because one of three names timed out would
    /// waste the two answers it did get. Each name stands on its own.
    /// </remarks>
    [Fact]
    public async Task One_unanswered_lookup_does_not_withhold_the_rest()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Txt, "v=spf1 mx -all")
            .WithNoAnswer("_dmarc.example.com", DnsDiagnosticRecordType.Txt);

        AuthenticationFacts facts = await new AuthenticationProbe(dns)
            .GatherAsync(Domain, [], CancellationToken.None);

        IReadOnlyList<DeliverabilityCheck> checks = AuthenticationChecks.Evaluate(facts);

        checks.Single(c => c.Id == AuthenticationChecks.SpfPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);

        checks.Single(c => c.Id == AuthenticationChecks.DmarcPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }
}
