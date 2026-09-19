using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

public sealed class AuthenticationCheckTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");

    /// <summary>A 2048-bit RSA public key, as DKIM publishes one.</summary>
    private const string Key2048 =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7JliQdtpMedIfKjNZkeGYPSt8GJmx6p3GBWx8G8la/" +
        "7ulpaZupAG4SCXhY/A5mm8X+/0b1H7XqHOUWEptsv/noJCmasr9P3JoL+/ge49UoL+NF32/SOjoHENSJ6pZSEf" +
        "OPoJH1hpCS/guGUl4RamyTbyUkjchHvfAu4hVLmwWrSOk2pCBkSZnfUKLSkxT2fugvkW98Iss1bUcS6hQVIKSQ" +
        "aHbYM5Qfu4CKsRneb/MXpzROwIneHGcZJuaDHEvu/kY6xwiYxgeiRoV9IhX4asHcMgUZGjK7vUDSTTOrgLCYR3" +
        "nVqew/3In9xeIy0PywREH67MOLA9V8bCCPhBwQpGNwIDAQAB";

    /// <summary>A 1024-bit key: RFC 8301's floor, below its recommendation.</summary>
    private const string Key1024 =
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbkt73lvz3Dfvv7vO8i9yBUnNjYD89wYSOmD0563bodxqdsQ" +
        "RHGNgan4Wr2ouYznZKLqpMH2fKouxm1zUz/gj+Qi45h5P4uaNCMgjmuRteVtw204sqNTk8HghJI/rvKQwbrCnQ" +
        "PtUDp33BFAzh510q6AXQVbmZT8Vaw7siFwy7zwIDAQAB";

    /// <summary>A 512-bit key, which RFC 8301 says verifiers must not accept at all.</summary>
    private const string Key512 =
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOZZpBuGlmWjahcslAj7jUfM9Zpi4AJb2jSZqNvAF1S5I4HoW/rBlh" +
        "2NdQ/w2SjwK2WQhCIsiGxKO5mlxY93AnECAwEAAQ==";

    private static string Dkim(string key) => $"v=DKIM1; k=rsa; p={key}";

    /// <summary>
    /// A correct configuration, with one aspect replaced.
    /// </summary>
    /// <remarks>
    /// As in <see cref="IdentityCheckTests"/>, a null argument here means "leave this correct",
    /// so a test that needs a lookup to have <i>not answered</i> builds the record directly.
    /// </remarks>
    private static AuthenticationFacts Facts(
        IReadOnlyList<string>? domainTxt = null,
        IReadOnlyList<string>? dmarcTxt = null,
        IReadOnlyList<DkimSelectorFacts>? selectors = null) =>
        new(
            Domain,
            domainTxt ?? ["v=spf1 mx -all"],
            dmarcTxt ?? ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            selectors ?? [new DkimSelectorFacts("mail2026", [Dkim(Key2048)])]);

    private static DeliverabilityCheck Check(AuthenticationFacts facts, string id) =>
        AuthenticationChecks.Evaluate(facts).Single(c => c.Id == id);

    // ---------------------------------------------------------------------------------------
    // Shape.
    // ---------------------------------------------------------------------------------------

    /// <summary>Every check belongs to the category it is weighted under.</summary>
    [Fact]
    public void Every_authentication_check_is_in_the_authentication_category()
    {
        foreach (DeliverabilityCheck check in AuthenticationChecks.Evaluate(Facts()))
        {
            check.Category.ShouldBe(DeliverabilityCategory.Authentication);
        }
    }

    /// <summary>
    /// The weights add up to the category's share.
    /// </summary>
    /// <remarks>
    /// Not arithmetic for its own sake: <see cref="DeliverabilityReport.From"/> normalises a
    /// category's checks against its weight, so a category whose parts drifted would still
    /// produce a plausible-looking score. The intended split is 3+2+1 for SPF, 3+1 for DKIM and
    /// 3+2+1 for DMARC.
    /// </remarks>
    [Fact]
    public void The_authentication_weights_sum_to_sixteen()
    {
        AuthenticationChecks.Evaluate(Facts()).Sum(c => c.Weight).ShouldBe(16);
    }

    /// <summary>A check id is a public name; no two may collide.</summary>
    [Fact]
    public void Authentication_check_ids_are_unique()
    {
        IReadOnlyList<DeliverabilityCheck> checks = AuthenticationChecks.Evaluate(Facts());

        checks.Select(c => c.Id).Distinct().Count().ShouldBe(checks.Count);
    }

    /// <summary>A correct configuration passes everything.</summary>
    [Fact]
    public void A_correctly_published_domain_passes_every_authentication_check()
    {
        foreach (DeliverabilityCheck check in AuthenticationChecks.Evaluate(Facts()))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Pass, check.Id);
        }
    }

    /// <summary>
    /// Anything that is not a pass says what to do about it.
    /// </summary>
    /// <remarks>
    /// A readiness report whose findings have no remedies is a list of complaints. The
    /// inconclusive outcome is exempt: nothing was measured, so there is nothing to remedy.
    /// </remarks>
    [Fact]
    public void Every_authentication_finding_carries_a_remedy()
    {
        AuthenticationFacts[] broken =
        [
            Facts(domainTxt: []),
            Facts(domainTxt: ["v=spf1 +all"]),
            Facts(domainTxt: ["v=spf1 mx"]),
            Facts(domainTxt: [Spf(11)]),
            Facts(dmarcTxt: []),
            Facts(dmarcTxt: ["v=DMARC1; p=none"]),
            Facts(dmarcTxt: ["v=DMARC1; p=reject"]),
            Facts(selectors: []),
            Facts(selectors: [new DkimSelectorFacts("s", [Dkim(Key512)])]),
            Facts(selectors: [new DkimSelectorFacts("s", [Dkim(Key1024)])]),
        ];

        foreach (AuthenticationFacts facts in broken)
        {
            foreach (DeliverabilityCheck check in AuthenticationChecks.Evaluate(facts))
            {
                if (check.Outcome is DeliverabilityOutcome.Warn or DeliverabilityOutcome.Fail)
                {
                    check.Remedy.ShouldNotBeNullOrWhiteSpace(check.Id);
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // SPF: publication.
    // ---------------------------------------------------------------------------------------

    /// <summary>No TXT answer is not the same as no SPF record.</summary>
    [Fact]
    public void An_unanswered_txt_lookup_leaves_spf_unjudged()
    {
        AuthenticationFacts facts = new(Domain, null, ["v=DMARC1; p=reject; rua=mailto:d@e.com"], []);

        Check(facts, AuthenticationChecks.SpfPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>An answer with no SPF record in it is a finding, not an unknown.</summary>
    [Fact]
    public void A_domain_with_no_spf_record_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(domainTxt: ["google-site-verification=abc"]),
            AuthenticationChecks.SpfPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence.ShouldNotBeNull().Found.ShouldBeNull();
    }

    /// <summary>
    /// Two records is a permanent error, which is worse than none.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §4.5: "If the resultant record set includes more than one record, check_host()
    /// produces the 'permerror' result." The most common way to arrive here is adding a second
    /// record for a new sending service, so the detail names the count.
    /// </remarks>
    [Fact]
    public void Two_spf_records_fail()
    {
        DeliverabilityCheck check = Check(
            Facts(domainTxt: ["v=spf1 mx -all", "v=spf1 include:_spf.example.net -all"]),
            AuthenticationChecks.SpfPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("2 SPF records");
        check.Remedy.ShouldNotBeNull().ShouldContain("single");
    }

    /// <summary>
    /// The version must be the whole first token.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §4.5 discards a record whose version section is "v=spf10", so a domain
    /// publishing one of those alongside a real record has one record, not two.
    /// </remarks>
    [Fact]
    public void A_v_equals_spf10_record_is_not_an_spf_record()
    {
        DeliverabilityCheck check = Check(
            Facts(domainTxt: ["v=spf10 something", "v=spf1 mx -all"]),
            AuthenticationChecks.SpfPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>The version tag is matched without regard to case.</summary>
    [Fact]
    public void An_uppercase_spf_version_is_still_an_spf_record()
    {
        Check(Facts(domainTxt: ["V=SPF1 mx -all"]), AuthenticationChecks.SpfPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>A record that does not parse is a finding, not a pass.</summary>
    [Fact]
    public void An_unparseable_spf_record_fails()
    {
        Check(Facts(domainTxt: ["v=spf1 ip4:not-an-address -all"]), AuthenticationChecks.SpfPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    // ---------------------------------------------------------------------------------------
    // SPF: policy.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("v=spf1 mx -all", DeliverabilityOutcome.Pass)]
    [InlineData("v=spf1 mx ~all", DeliverabilityOutcome.Warn)]
    [InlineData("v=spf1 mx ?all", DeliverabilityOutcome.Warn)]
    [InlineData("v=spf1 mx", DeliverabilityOutcome.Warn)]
    public void The_spf_closing_policy_is_judged_by_its_qualifier(string record, DeliverabilityOutcome expected)
    {
        Check(Facts(domainTxt: [record]), AuthenticationChecks.SpfPolicyId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>
    /// <c>+all</c> fails rather than warns.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §5.1 makes <c>all</c> a mechanism that always matches, so a leading <c>+</c>
    /// authorises the entire internet. It is not a weaker policy than <c>~all</c>; it is the
    /// absence of one, published in a form that looks like a policy — which is exactly why an
    /// operator will not notice it.
    /// </remarks>
    [Fact]
    public void A_plus_all_spf_record_fails_rather_than_warning()
    {
        DeliverabilityCheck check = Check(
            Facts(domainTxt: ["v=spf1 mx +all"]),
            AuthenticationChecks.SpfPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence.ShouldNotBeNull().Found.ShouldBe("+all");
    }

    /// <summary>A record that defers to another domain has a policy: that domain's.</summary>
    [Fact]
    public void A_redirect_counts_as_a_closing_policy()
    {
        DeliverabilityCheck check = Check(
            Facts(domainTxt: ["v=spf1 redirect=_spf.example.net"]),
            AuthenticationChecks.SpfPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Pass);
        check.Detail.ShouldContain("_spf.example.net");
    }

    /// <summary>
    /// A record with neither <c>all</c> nor <c>redirect</c> leaves a receiver where it started.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §4.7: "If none of the mechanisms match and there is no 'redirect' modifier, then
    /// the check_host() returns a result of 'neutral', just as if '?all' were specified as the
    /// last directive."
    /// </remarks>
    [Fact]
    public void A_record_with_no_all_and_no_redirect_says_nothing()
    {
        DeliverabilityCheck check = Check(
            Facts(domainTxt: ["v=spf1 ip4:203.0.113.0/24"]),
            AuthenticationChecks.SpfPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("no closing");
    }

    /// <summary>
    /// The <i>first</i> <c>all</c> decides, not the last.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §5.1: "Mechanisms after 'all' will never be tested. Mechanisms listed after 'all'
    /// MUST be ignored." A receiver evaluating this record returns fail and never reaches the
    /// <c>~all</c>, so reporting the last one would name a policy nobody applies — and would
    /// tell an operator their record is weaker than it is.
    /// </remarks>
    [Fact]
    public void The_first_all_mechanism_decides_the_policy()
    {
        DeliverabilityCheck check = Check(
            Facts(domainTxt: ["v=spf1 mx -all ~all"]),
            AuthenticationChecks.SpfPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Pass);
        check.Evidence.ShouldNotBeNull().Found.ShouldBe("-all");
    }

    /// <summary>
    /// A redirect beside an <c>all</c> is ignored, so the <c>all</c> is the policy.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §5.1: "Any 'redirect' modifier (Section 6.1) MUST be ignored when there is an
    /// 'all' mechanism in the record, regardless of the relative ordering of the terms." The
    /// ordering clause is the part that matters here: the redirect comes first in this record and
    /// is still the one discarded.
    /// </remarks>
    [Fact]
    public void A_redirect_is_ignored_when_the_record_also_has_an_all()
    {
        DeliverabilityCheck check = Check(
            Facts(domainTxt: ["v=spf1 redirect=_spf.example.net ~all"]),
            AuthenticationChecks.SpfPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Evidence.ShouldNotBeNull().Found.ShouldBe("~all");
    }

    /// <summary>With no SPF record there is no policy to judge, and no second charge for it.</summary>
    [Fact]
    public void Without_an_spf_record_the_policy_check_is_not_charged()
    {
        IReadOnlyList<DeliverabilityCheck> checks = AuthenticationChecks.Evaluate(Facts(domainTxt: []));

        checks.Single(c => c.Id == AuthenticationChecks.SpfPolicyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);

        checks.Single(c => c.Id == AuthenticationChecks.SpfLookupBudgetId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    // ---------------------------------------------------------------------------------------
    // SPF: the lookup budget.
    // ---------------------------------------------------------------------------------------

    /// <summary>An SPF record with <paramref name="includes"/> terms that cost a lookup.</summary>
    private static string Spf(int includes) =>
        "v=spf1 " + string.Join(" ", Enumerable.Range(0, includes).Select(i => $"include:s{i}.example.net")) + " -all";

    /// <summary>
    /// Eleven lookup terms is a permanent error.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §4.6.4: "SPF implementations MUST limit the total number of those terms to 10
    /// during SPF evaluation […] If this limit is exceeded, the implementation MUST return
    /// 'permerror'."
    /// </remarks>
    [Fact]
    public void An_spf_record_past_the_lookup_limit_fails()
    {
        DeliverabilityCheck check = Check(Facts(domainTxt: [Spf(11)]), AuthenticationChecks.SpfLookupBudgetId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("11 terms");
    }

    /// <summary>Exactly ten is inside the limit, since the RFC's word is "to 10".</summary>
    [Fact]
    public void An_spf_record_at_exactly_ten_lookups_does_not_fail()
    {
        Check(Facts(domainTxt: [Spf(10)]), AuthenticationChecks.SpfLookupBudgetId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>
    /// A record close to the limit warns, because the count is a floor.
    /// </summary>
    /// <remarks>
    /// Each <c>include</c> spends the budget again inside the record it fetches, so a domain at
    /// eight terms of its own may already exceed ten in a receiver's evaluation. Warning only at
    /// eleven would tell an operator they have headroom they do not have.
    /// </remarks>
    [Theory]
    [InlineData(8, DeliverabilityOutcome.Warn)]
    [InlineData(7, DeliverabilityOutcome.Pass)]
    public void The_lookup_budget_warns_as_the_limit_approaches(int includes, DeliverabilityOutcome expected)
    {
        Check(Facts(domainTxt: [Spf(includes)]), AuthenticationChecks.SpfLookupBudgetId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>
    /// Only the terms RFC 7208 §4.6.4 lists cost a lookup.
    /// </summary>
    /// <remarks>
    /// §4.6.4 names them exactly: "the 'include', 'a', 'mx', 'ptr', and 'exists' mechanisms, and
    /// the 'redirect' modifier". A record of twenty ip4 terms costs nothing, and counting them
    /// would send an operator to consolidate the one part of their record that is free.
    /// </remarks>
    [Fact]
    public void Ip4_terms_cost_no_dns_lookups()
    {
        string record = "v=spf1 " +
            string.Join(" ", Enumerable.Range(0, 20).Select(i => $"ip4:203.0.{i}.0/24")) + " -all";

        DeliverabilityCheck check = Check(Facts(domainTxt: [record]), AuthenticationChecks.SpfLookupBudgetId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Pass);
        check.Detail.ShouldContain("0 of");
    }

    /// <summary>The redirect modifier is one of the terms that costs a lookup.</summary>
    [Fact]
    public void A_redirect_modifier_counts_against_the_lookup_budget()
    {
        string record = "v=spf1 " +
            string.Join(" ", Enumerable.Range(0, 10).Select(i => $"include:s{i}.example.net")) +
            " redirect=_spf.example.net";

        Check(Facts(domainTxt: [record]), AuthenticationChecks.SpfLookupBudgetId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// An ignored redirect costs no lookup.
    /// </summary>
    /// <remarks>
    /// The same §5.1 sentence, on the budget rather than the policy: a modifier a receiver must
    /// ignore is never evaluated, so it cannot be one of §4.6.4's terms. This record has ten
    /// terms of its own and would breach the limit if the redirect were counted — sending an
    /// operator to shorten a record that is already inside it.
    /// </remarks>
    [Fact]
    public void A_redirect_beside_an_all_costs_no_lookup()
    {
        string record = "v=spf1 " +
            string.Join(" ", Enumerable.Range(0, 10).Select(i => $"include:s{i}.example.net")) +
            " redirect=_spf.example.net -all";

        DeliverabilityCheck check = Check(Facts(domainTxt: [record]), AuthenticationChecks.SpfLookupBudgetId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("10 of");
    }

    /// <summary>The detail says the count is only this record's, so nobody reads it as the total.</summary>
    [Fact]
    public void The_lookup_budget_detail_says_the_count_excludes_nested_records()
    {
        Check(Facts(domainTxt: [Spf(9)]), AuthenticationChecks.SpfLookupBudgetId)
            .Detail.ShouldContain("only the terms in your own record");
    }

    // ---------------------------------------------------------------------------------------
    // DKIM.
    // ---------------------------------------------------------------------------------------

    /// <summary>A server that signs nothing cannot be DKIM-aligned.</summary>
    [Fact]
    public void No_configured_selector_fails()
    {
        DeliverabilityCheck check = Check(Facts(selectors: []), AuthenticationChecks.DkimPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Remedy.ShouldNotBeNull().ShouldContain("_domainkey.example.com");
    }

    /// <summary>A selector whose name does not resolve is not a published key.</summary>
    [Fact]
    public void A_selector_with_no_record_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(selectors: [new DkimSelectorFacts("mail2026", [])]),
            AuthenticationChecks.DkimPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence.ShouldNotBeNull().Found.ShouldNotBeNull().ShouldContain("has no record");
    }

    /// <summary>
    /// A revoked key is worse than a missing one, and the check names it.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §3.6.1 gives an empty <c>p=</c> that meaning. A server signing with a revoked
    /// selector produces signatures every receiver rejects, and DMARC alignment then rests on
    /// SPF alone — which continues to pass, so nothing visibly breaks until an SPF change.
    /// </remarks>
    [Fact]
    public void A_revoked_key_is_not_a_published_key()
    {
        DeliverabilityCheck check = Check(
            Facts(selectors: [new DkimSelectorFacts("mail2026", ["v=DKIM1; k=rsa; p="])]),
            AuthenticationChecks.DkimPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence.ShouldNotBeNull().Found.ShouldNotBeNull().ShouldContain("revoked");
    }

    /// <summary>One good selector is enough, whatever else is configured.</summary>
    [Fact]
    public void One_usable_selector_passes_even_beside_a_broken_one()
    {
        AuthenticationFacts facts = Facts(selectors:
        [
            new DkimSelectorFacts("old", ["v=DKIM1; k=rsa; p="]),
            new DkimSelectorFacts("mail2026", [Dkim(Key2048)]),
        ]);

        Check(facts, AuthenticationChecks.DkimPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// A stale record beside a live one does not condemn the selector.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §6.1.2: "If the query for the public key returns multiple key records, the
    /// Verifier can choose one of the key records or may cycle through the key records[…] The
    /// order of the key records is unspecified." Judging only whichever record DNS happened to
    /// return first would report a working domain as broken, differently on different days.
    /// </remarks>
    [Fact]
    public void A_selector_is_judged_on_the_best_of_its_records()
    {
        AuthenticationFacts facts = Facts(selectors:
        [
            new DkimSelectorFacts("mail2026", ["v=DKIM1; k=rsa; p=", Dkim(Key2048)]),
        ]);

        Check(facts, AuthenticationChecks.DkimPublishedId).Outcome.ShouldBe(DeliverabilityOutcome.Pass);
        Check(facts, AuthenticationChecks.DkimKeyStrengthId).Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// An Ed25519 selector is not judged by RFC 8301's modulus sizes.
    /// </summary>
    /// <remarks>
    /// RFC 8463 added <c>k=ed25519</c>, whose strength is not a key size and is not the
    /// operator's to choose. Measuring it against "at least 2048 bits" would fail every domain
    /// that adopted the newer algorithm — for having adopted it.
    /// </remarks>
    [Fact]
    public void An_ed25519_selector_is_not_measured_against_rsa_sizes()
    {
        AuthenticationFacts facts = Facts(selectors:
        [
            new DkimSelectorFacts(
                "ed",
                ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="]),
        ]);

        Check(facts, AuthenticationChecks.DkimKeyStrengthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>An unanswered selector lookup is not a missing key.</summary>
    [Fact]
    public void An_unanswered_selector_lookup_leaves_dkim_unjudged()
    {
        AuthenticationFacts facts = Facts(selectors: [new DkimSelectorFacts("mail2026", null)]);

        Check(facts, AuthenticationChecks.DkimPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// An unanswered selector alongside a broken one is still a finding.
    /// </summary>
    /// <remarks>
    /// The evidence the operator can act on — a record that does not parse — is the one to
    /// report. Withholding the whole check because a second selector's lookup timed out would
    /// hide a fault that was measured.
    /// </remarks>
    [Fact]
    public void A_broken_selector_is_reported_even_when_another_did_not_answer()
    {
        AuthenticationFacts facts = Facts(selectors:
        [
            new DkimSelectorFacts("timeout", null),
            new DkimSelectorFacts("broken", ["not a dkim record"]),
        ]);

        Check(facts, AuthenticationChecks.DkimPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// RFC 8301 §3.2 makes 1024 a MUST and 2048 a SHOULD, so the two get different outcomes.
    /// </summary>
    [Theory]
    [InlineData(Key2048, DeliverabilityOutcome.Pass)]
    [InlineData(Key1024, DeliverabilityOutcome.Warn)]
    [InlineData(Key512, DeliverabilityOutcome.Fail)]
    public void The_key_strength_check_follows_rfc_8301(string key, DeliverabilityOutcome expected)
    {
        Check(Facts(selectors: [new DkimSelectorFacts("s", [Dkim(key)])]),
                AuthenticationChecks.DkimKeyStrengthId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>
    /// The weakest published key decides.
    /// </summary>
    /// <remarks>
    /// An attacker forging mail chooses which selector to claim, so a domain is only as strong as
    /// its weakest live key. Reporting the strongest — or the first — would let a forgotten
    /// 512-bit selector from a previous rotation pass unnoticed.
    /// </remarks>
    [Fact]
    public void The_weakest_key_decides_the_strength_check()
    {
        AuthenticationFacts facts = Facts(selectors:
        [
            new DkimSelectorFacts("new", [Dkim(Key2048)]),
            new DkimSelectorFacts("old", [Dkim(Key512)]),
        ]);

        DeliverabilityCheck check = Check(facts, AuthenticationChecks.DkimKeyStrengthId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("old._domainkey.example.com");
    }

    /// <summary>A revoked selector has no key to measure, so it does not decide the strength.</summary>
    [Fact]
    public void A_revoked_selector_is_not_measured_for_strength()
    {
        AuthenticationFacts facts = Facts(selectors:
        [
            new DkimSelectorFacts("old", ["v=DKIM1; k=rsa; p="]),
            new DkimSelectorFacts("new", [Dkim(Key2048)]),
        ]);

        Check(facts, AuthenticationChecks.DkimKeyStrengthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// The declared key type decides which rule applies, not what the value happens to parse as.
    /// </summary>
    /// <remarks>
    /// A selector that says <c>k=ed25519</c> and carries an RSA key is misconfigured, and a
    /// verifier following RFC 8463 will not use it. Measuring the value anyway would report a
    /// size for a key nobody verifies with, and pass a selector that signs nothing anyone
    /// accepts.
    /// </remarks>
    [Fact]
    public void A_key_declared_as_ed25519_is_not_measured_as_rsa()
    {
        AuthenticationFacts facts = Facts(selectors:
        [
            new DkimSelectorFacts("mixed", [$"v=DKIM1; k=ed25519; p={Key2048}"]),
        ]);

        Check(facts, AuthenticationChecks.DkimKeyStrengthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>Nothing measurable leaves the strength unjudged rather than passing it.</summary>
    [Fact]
    public void An_unmeasurable_key_leaves_the_strength_unjudged()
    {
        Check(Facts(selectors: [new DkimSelectorFacts("s", ["v=DKIM1; k=rsa; p=not-base64!!"])]),
                AuthenticationChecks.DkimKeyStrengthId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// A well-formed base64 string that is not a key is unmeasurable, not a crash.
    /// </summary>
    /// <remarks>
    /// The value comes from DNS, which anybody can publish. A malformed SubjectPublicKeyInfo must
    /// not take the whole readiness report down with it.
    /// </remarks>
    [Fact]
    public void Base64_that_is_not_a_key_is_unmeasurable()
    {
        AuthenticationChecks.RsaKeyBits("aGVsbG8gd29ybGQ=").ShouldBeNull();
        AuthenticationChecks.RsaKeyBits("!!!").ShouldBeNull();
        AuthenticationChecks.RsaKeyBits(string.Empty).ShouldBeNull();
        AuthenticationChecks.RsaKeyBits(Key2048).ShouldBe(2048);
    }

    // ---------------------------------------------------------------------------------------
    // DMARC.
    // ---------------------------------------------------------------------------------------

    /// <summary>The record is looked for at <c>_dmarc</c>, and the evidence says so.</summary>
    [Fact]
    public void A_domain_with_no_dmarc_record_fails()
    {
        DeliverabilityCheck check = Check(Facts(dmarcTxt: []), AuthenticationChecks.DmarcPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence.ShouldNotBeNull().Expected.ShouldContain("_dmarc.example.com");
    }

    /// <summary>An unanswered lookup at <c>_dmarc</c> is not a missing record.</summary>
    [Fact]
    public void An_unanswered_dmarc_lookup_leaves_dmarc_unjudged()
    {
        AuthenticationFacts facts = new(Domain, ["v=spf1 mx -all"], null, []);

        foreach (string id in new[]
                 {
                     AuthenticationChecks.DmarcPublishedId,
                     AuthenticationChecks.DmarcPolicyId,
                     AuthenticationChecks.DmarcReportingId,
                 })
        {
            Check(facts, id).Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, id);
        }
    }

    /// <summary>
    /// A DMARC record may have whitespace around its equals signs.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.4: <c>dmarc-version = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43 %x31</c>.
    /// The <c>*WSP</c> is not decoration: a record written this way is valid, every receiver
    /// applies it, and a prefix match on "v=DMARC1" would report the domain as publishing no
    /// DMARC record at all — sending the operator to add a second one beside the working one.
    /// </remarks>
    [Fact]
    public void A_dmarc_record_with_spaces_around_its_equals_is_found()
    {
        Check(Facts(dmarcTxt: ["v = DMARC1; p=reject; rua=mailto:d@example.com"]),
                AuthenticationChecks.DmarcPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// A TXT record at <c>_dmarc</c> that is not a DMARC record is not one.
    /// </summary>
    /// <remarks>
    /// Verification tokens and the like get parked at all sorts of names. Counting one as a
    /// second DMARC record would fail a correctly configured domain.
    /// </remarks>
    [Fact]
    public void An_unrelated_txt_record_beside_the_dmarc_record_is_ignored()
    {
        Check(Facts(dmarcTxt: ["verify=abc123", "v=DMARC1; p=reject; rua=mailto:d@example.com"]),
                AuthenticationChecks.DmarcPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// A mis-cased version is reported as an unparseable record, not as a missing one.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.3: "It MUST have the value of 'DMARC1'. The value of this tag MUST match
    /// precisely; if it does not or it is absent, the entire retrieved record MUST be ignored."
    /// Both readings end in a failure, so the only question is which one an operator can act on
    /// — and "you publish no DMARC record" is not actionable when they are looking at one.
    /// </remarks>
    [Fact]
    public void A_miscased_dmarc_version_fails_as_a_record_that_receivers_ignore()
    {
        DeliverabilityCheck check = Check(
            Facts(dmarcTxt: ["v=dmarc1; p=reject; rua=mailto:d@example.com"]),
            AuthenticationChecks.DmarcPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Evidence.ShouldNotBeNull().Found.ShouldNotBeNull().ShouldContain("v=dmarc1");
    }

    /// <summary>Two records leave a receiver with no policy to apply.</summary>
    [Fact]
    public void Two_dmarc_records_fail()
    {
        Check(Facts(dmarcTxt: ["v=DMARC1; p=none", "v=DMARC1; p=reject"]),
                AuthenticationChecks.DmarcPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// <c>p=none</c> warns.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.3: "none: The Domain Owner requests no specific action be taken regarding
    /// delivery of messages." It is the right setting while reports are being read and it
    /// protects nobody, so the remedy describes the path out rather than simply saying to
    /// tighten it.
    /// </remarks>
    [Fact]
    public void A_dmarc_policy_of_none_warns()
    {
        DeliverabilityCheck check = Check(
            Facts(dmarcTxt: ["v=DMARC1; p=none; rua=mailto:d@example.com"]),
            AuthenticationChecks.DmarcPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Remedy.ShouldNotBeNull().ShouldContain("quarantine");
    }

    [Theory]
    [InlineData("v=DMARC1; p=quarantine", DeliverabilityOutcome.Pass)]
    [InlineData("v=DMARC1; p=reject", DeliverabilityOutcome.Pass)]
    [InlineData("v=DMARC1; p=none", DeliverabilityOutcome.Warn)]
    public void The_dmarc_policy_is_judged_by_its_p_tag(string record, DeliverabilityOutcome expected)
    {
        Check(Facts(dmarcTxt: [record]), AuthenticationChecks.DmarcPolicyId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>
    /// A policy that applies to a fraction of the mail is a partial policy.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.3 makes <c>pct</c> default to 100. An operator who set it to 10 during a
    /// rollout and forgot has a record that reads <c>p=reject</c> and rejects almost nothing.
    /// </remarks>
    [Fact]
    public void A_partial_dmarc_percentage_warns()
    {
        DeliverabilityCheck check = Check(
            Facts(dmarcTxt: ["v=DMARC1; p=reject; pct=10; rua=mailto:d@example.com"]),
            AuthenticationChecks.DmarcPolicyId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Evidence.ShouldNotBeNull().Found.ShouldNotBeNull().ShouldContain("pct=10");
    }

    /// <summary>
    /// A record with no <c>rua</c> warns.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.3 defines <c>rua</c> as "Addresses to which aggregate feedback is to be sent".
    /// Without it the reports that would reveal a legitimate sender failing alignment are never
    /// sent, so every remedy that says "once the reports show your mail passing" is unfollowable.
    /// </remarks>
    [Fact]
    public void A_dmarc_record_without_rua_warns()
    {
        DeliverabilityCheck check = Check(
            Facts(dmarcTxt: ["v=DMARC1; p=reject"]),
            AuthenticationChecks.DmarcReportingId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Remedy.ShouldNotBeNull().ShouldContain("rua=mailto:");
    }

    /// <summary>The tag is found wherever it sits, and whatever its case.</summary>
    [Theory]
    [InlineData("v=DMARC1; p=reject; rua=mailto:d@example.com")]
    [InlineData("v=DMARC1; rua=mailto:d@example.com; p=reject")]
    [InlineData("v=DMARC1;RUA=mailto:d@example.com;p=reject")]
    public void The_rua_tag_is_found_wherever_it_sits(string record)
    {
        Check(Facts(dmarcTxt: [record]), AuthenticationChecks.DmarcReportingId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// The tag name is what precedes the <c>=</c>, whitespace and all.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.4's ABNF puts <c>*WSP</c> on both sides of the equals sign, so a record with
    /// a space before it is well-formed and a receiver reads its reports address. Matching the
    /// raw text against "rua=" would call such a record silent.
    /// </remarks>
    [Fact]
    public void A_rua_tag_with_space_around_its_equals_is_found()
    {
        Check(Facts(dmarcTxt: ["v=DMARC1; p=reject; rua = mailto:d@example.com"]),
                AuthenticationChecks.DmarcReportingId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// <c>ruf</c> is not <c>rua</c>.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.3 gives them different meanings — failure reports rather than aggregate ones —
    /// and a prefix match on "ru" would call a record complete that sends no aggregate reports at
    /// all.
    /// </remarks>
    [Fact]
    public void A_ruf_tag_is_not_an_rua_tag()
    {
        Check(Facts(dmarcTxt: ["v=DMARC1; p=reject; ruf=mailto:d@example.com"]),
                AuthenticationChecks.DmarcReportingId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    // ---------------------------------------------------------------------------------------
    // The category as a whole.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A domain that publishes nothing scores zero rather than going unjudged.
    /// </summary>
    /// <remarks>
    /// The distinction the whole report rests on: "you have not published this" is a measurement,
    /// and only a resolver that did not answer is an unknown.
    /// </remarks>
    [Fact]
    public void A_domain_publishing_nothing_scores_zero_for_authentication()
    {
        DeliverabilityReport report = DeliverabilityReport.From(
            AuthenticationChecks.Evaluate(new AuthenticationFacts(Domain, [], [], [])),
            new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));

        report.Score.ShouldBe(0d);
        report.Readiness.ShouldBe(DeliverabilityReadiness.NotReady);
    }

    /// <summary>And a correct one scores the whole category.</summary>
    [Fact]
    public void A_correctly_published_domain_scores_the_whole_category()
    {
        DeliverabilityReport report = DeliverabilityReport.From(
            AuthenticationChecks.Evaluate(Facts()),
            new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));

        report.Score.ShouldBe(100d);
        report.Readiness.ShouldBe(DeliverabilityReadiness.Ready);

        report.Categories
            .Single(c => c.Category == DeliverabilityCategory.Authentication)
            .Earned.ShouldBe(30d, 0.0001);
    }
}
