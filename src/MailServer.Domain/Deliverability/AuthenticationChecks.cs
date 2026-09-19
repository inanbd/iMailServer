using System.Globalization;
using System.Security.Cryptography;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>What was published at one DKIM selector.</summary>
/// <param name="Selector">The selector name, as it appears before <c>._domainkey</c>.</param>
/// <param name="TxtRecords">
/// The TXT records at <c>selector._domainkey.domain</c>, or null when the lookup did not answer.
/// </param>
public sealed record DkimSelectorFacts(string Selector, IReadOnlyList<string>? TxtRecords);

/// <summary>
/// What the authentication probe observed.
/// </summary>
/// <param name="Domain">The domain being judged.</param>
/// <param name="DomainTxtRecords">
/// Every TXT record at the domain itself, or null when the lookup did not answer. All of them,
/// not just the SPF one: RFC 7208 §4.5 makes "more than one <c>v=spf1</c> record" a
/// <c>permerror</c>, so the check has to see the others to notice.
/// </param>
/// <param name="DmarcTxtRecords">
/// Every TXT record at <c>_dmarc.domain</c>, or null when the lookup did not answer.
/// </param>
/// <param name="Selectors">The DKIM selectors this server is configured to sign with.</param>
public sealed record AuthenticationFacts(
    DomainName Domain,
    IReadOnlyList<string>? DomainTxtRecords,
    IReadOnlyList<string>? DmarcTxtRecords,
    IReadOnlyList<DkimSelectorFacts> Selectors);

/// <summary>
/// The Authentication category: SPF, DKIM and DMARC as a receiver would read them.
/// </summary>
/// <remarks>
/// <para>
/// Weighted highest of the six, and <c>docs/Deliverability.md</c> gives the argument: these "are
/// the checks a receiver can evaluate on the very first message from an unknown sender.
/// Everything else — volume patterns, complaint rates, engagement — takes time to accumulate.
/// Getting authentication right is the part that is entirely within your control and entirely
/// verifiable before you send anything."
/// </para>
/// <para>
/// <b>Every judgement here is about what is published, not about what this server does.</b> A
/// server that signs perfectly with a key nobody can fetch is a server whose mail fails DKIM,
/// and the only way to know is to look the record up the way a receiver would.
/// </para>
/// </remarks>
public static class AuthenticationChecks
{
    /// <summary>The SPF-published check's id.</summary>
    public const string SpfPublishedId = "auth.spf-published";

    /// <summary>The SPF-policy check's id.</summary>
    public const string SpfPolicyId = "auth.spf-policy";

    /// <summary>The SPF-lookup-budget check's id.</summary>
    public const string SpfLookupBudgetId = "auth.spf-lookup-budget";

    /// <summary>The DKIM-published check's id.</summary>
    public const string DkimPublishedId = "auth.dkim-published";

    /// <summary>The DKIM-key-strength check's id.</summary>
    public const string DkimKeyStrengthId = "auth.dkim-key-strength";

    /// <summary>The DMARC-published check's id.</summary>
    public const string DmarcPublishedId = "auth.dmarc-published";

    /// <summary>The DMARC-policy check's id.</summary>
    public const string DmarcPolicyId = "auth.dmarc-policy";

    /// <summary>The DMARC-reporting check's id.</summary>
    public const string DmarcReportingId = "auth.dmarc-reporting";

    /// <summary>
    /// RFC 7208 §4.6.4's budget: "SPF implementations MUST limit the total number of those terms
    /// to 10 during SPF evaluation, to avoid unreasonable load on the DNS. If this limit is
    /// exceeded, the implementation MUST return 'permerror'."
    /// </summary>
    public const int SpfLookupLimit = 10;

    /// <summary>
    /// RFC 8301 §3.2: "Signers MUST use RSA keys of at least 1024 bits for all keys."
    /// </summary>
    public const int MinimumDkimKeyBits = 1024;

    /// <summary>RFC 8301 §3.2: "Signers SHOULD use RSA keys of at least 2048 bits."</summary>
    public const int RecommendedDkimKeyBits = 2048;

    /// <summary>Judges a set of observations. Pure.</summary>
    public static IReadOnlyList<DeliverabilityCheck> Evaluate(AuthenticationFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        IReadOnlyList<string>? spfTexts =
            facts.DomainTxtRecords is { } domainTxt ? SelectSpf(domainTxt) : null;

        SpfRecord? spf = ParseSingleSpf(spfTexts);

        IReadOnlyList<string>? dmarcTexts =
            facts.DmarcTxtRecords is { } dmarcTxt ? SelectDmarc(dmarcTxt) : null;
        string? dmarcText = dmarcTexts is { Count: 1 } ? dmarcTexts[0] : null;

        DmarcRecord? dmarc = dmarcText is not null &&
                             DmarcRecord.TryParse(dmarcText, out DmarcRecord? parsed, out _)
            ? parsed
            : null;

        return
        [
            SpfPublished(facts, spfTexts, spf),
            SpfPolicy(spf),
            SpfLookupBudget(spf),
            DkimPublished(facts),
            DkimKeyStrength(facts),
            DmarcPublished(facts, dmarcTexts, dmarc),
            DmarcEnforcement(dmarc),
            DmarcReporting(dmarcText, dmarc),
        ];
    }

    // -------------------------------------------------------------------------------------------
    // SPF.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Exactly one <c>v=spf1</c> record is published, and it parses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 7208 §3.2: "A domain name MUST NOT have multiple records that would cause an
    /// authorization check to select more than one record", and §4.5 says what happens when it
    /// does: "If the resultant record set includes more than one record, check_host() produces
    /// the 'permerror' result."
    /// </para>
    /// <para>
    /// <b>Two records is worse than none, and the check says so.</b> A domain with no SPF gets
    /// <c>none</c> and is judged on DKIM alone; a domain with two gets <c>permerror</c> from
    /// every receiver, which several treat as a failure. An operator who has just added a
    /// second record for a new sending service has made things worse and will not guess why.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck SpfPublished(
        AuthenticationFacts facts,
        IReadOnlyList<string>? texts,
        SpfRecord? parsed)
    {
        const string Id = SpfPublishedId;
        const string Title = "An SPF record is published";
        const int Weight = 3;

        if (texts is null)
        {
            return Unmeasured(Id, Title, Weight, $"No TXT answer for {facts.Domain.Value}.");
        }

        DeliverabilityEvidence evidence = new(
            "Exactly one v=spf1 TXT record",
            texts.Count == 0 ? null : string.Join(" | ", texts));

        if (texts.Count == 0)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"{facts.Domain.Value} publishes no SPF record, so receivers cannot tell which " +
                "hosts may send for it.",
                evidence,
                $"Publish a TXT record at {facts.Domain.Value} such as " +
                "\"v=spf1 mx -all\", listing every host that sends your mail.");
        }

        if (texts.Count > 1)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"{facts.Domain.Value} publishes {texts.Count} SPF records. RFC 7208 §4.5 makes " +
                "that a permanent error at every receiver, which is worse than publishing none.",
                evidence,
                "Merge them into a single v=spf1 record and delete the others.");
        }

        return parsed is null
            ? Fail(
                Id,
                Title,
                Weight,
                "The SPF record does not parse, so receivers will treat it as a permanent error.",
                evidence,
                "Correct the record's syntax; every term must be a mechanism or a name=value " +
                "modifier.")
            : Pass(Id, Title, Weight, "One SPF record is published and parses.", evidence);
    }

    /// <summary>
    /// The record says what to do about hosts it does not list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A record with no <c>all</c> and no <c>redirect</c> ends in <c>neutral</c> for everything
    /// it did not match, which tells a receiver nothing it did not already know. <c>?all</c> is
    /// the same statement written explicitly.
    /// </para>
    /// <para>
    /// <b><c>+all</c> fails rather than warns.</b> RFC 7208 §5.1 makes <c>all</c> a mechanism
    /// that "always matches", so a leading <c>+</c> authorises the entire internet to send as
    /// the domain — it is not a weak policy but the absence of one, published in a form that
    /// looks like a policy.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck SpfPolicy(SpfRecord? spf)
    {
        const string Id = SpfPolicyId;
        const string Title = "The SPF record has a closing policy";
        const int Weight = 2;

        if (spf is null)
        {
            return Unmeasured(Id, Title, Weight, "There is no SPF record to read a policy from.");
        }

        // RFC 7208 SS5.1: "Mechanisms after 'all' will never be tested. Mechanisms listed after
        // 'all' MUST be ignored." So the *first* all is the effective one; reading the last would
        // report a policy no receiver applies - "v=spf1 -all ~all" is -all.
        SpfDirective? all = spf.Directives.FirstOrDefault(d => d.Mechanism == SpfMechanismType.All);

        if (all is null)
        {
            return spf.RedirectDomain is { } redirect
                ? Pass(
                    Id,
                    Title,
                    Weight,
                    $"The record defers to {redirect}, whose policy applies.",
                    new DeliverabilityEvidence("A closing -all, ~all or redirect=", $"redirect={redirect}"))
                // SS4.7: "If none of the mechanisms match and there is no 'redirect' modifier,
                // then the check_host() returns a result of 'neutral', just as if '?all' were
                // specified as the last directive."
                : Warn(
                    Id,
                    Title,
                    Weight,
                    "The record has no closing 'all' mechanism, so it says nothing about hosts " +
                    "it does not list: receivers treat every host it does not name as neutral, " +
                    "which is what they would have done without the record.",
                    new DeliverabilityEvidence("A closing -all or ~all", "no all mechanism"),
                    "Add '-all' to the end of the record once you are sure every sending host " +
                    "is listed, or '~all' while you are still checking.");
        }

        DeliverabilityEvidence evidence = new("-all", Render(all.Qualifier));

        return all.Qualifier switch
        {
            SpfQualifier.Fail => Pass(
                Id,
                Title,
                Weight,
                "The record ends in '-all', so receivers may reject mail from hosts it does not " +
                "list.",
                evidence),

            SpfQualifier.SoftFail => Warn(
                Id,
                Title,
                Weight,
                "The record ends in '~all', which asks receivers to accept mail from unlisted " +
                "hosts and mark it. That is the right setting while you are still confirming " +
                "the list, and a weaker statement than '-all' once you are.",
                evidence,
                "Change '~all' to '-all' once you are confident every sending host is listed."),

            SpfQualifier.Neutral => Warn(
                Id,
                Title,
                Weight,
                "The record ends in '?all', which explicitly declines to say anything about " +
                "unlisted hosts.",
                evidence,
                "Change '?all' to '-all', or to '~all' while you are still confirming the list."),

            _ => Fail(
                Id,
                Title,
                Weight,
                "The record ends in '+all', which authorises every host on the internet to send " +
                "as this domain. That is not a weak policy; it is the absence of one, published " +
                "in a form that looks like a policy.",
                evidence,
                "Replace '+all' with '-all'."),
        };
    }

    /// <summary>
    /// The record stays inside RFC 7208 §4.6.4's ten-lookup budget.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §4.6.4: "The following terms cause DNS queries: the 'include', 'a', 'mx', 'ptr', and
    /// 'exists' mechanisms, and the 'redirect' modifier. SPF implementations MUST limit the
    /// total number of those terms to 10 during SPF evaluation, to avoid unreasonable load on
    /// the DNS. If this limit is exceeded, the implementation MUST return 'permerror'."
    /// </para>
    /// <para>
    /// <b>This counts only the terms in the record itself, which is a floor rather than the
    /// total.</b> Every <c>include</c> costs one lookup and then spends the budget again inside
    /// the record it fetches, so a domain at nine terms of its own may still exceed ten. The
    /// check therefore warns as the count approaches the limit rather than only when the
    /// record alone breaches it — and the detail says which number it is reporting, because an
    /// operator who reads "9 of 10" as headroom they do not have will be surprised by a
    /// permerror.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck SpfLookupBudget(SpfRecord? spf)
    {
        const string Id = SpfLookupBudgetId;
        const string Title = "The SPF record stays inside the DNS lookup limit";
        const int Weight = 1;

        if (spf is null)
        {
            return Unmeasured(Id, Title, Weight, "There is no SPF record to count terms in.");
        }

        int terms = spf.Directives.Count(d => CausesLookup(d.Mechanism));

        // The redirect modifier is one of SS4.6.4's terms - but only when it is evaluated at all.
        // SS5.1: "Any 'redirect' modifier MUST be ignored when there is an 'all' mechanism in the
        // record, regardless of the relative ordering of the terms." Charging for an ignored
        // modifier would send an operator to shorten a record that is already inside the limit.
        bool redirectApplies = spf.RedirectDomain is not null &&
                               !spf.Directives.Any(d => d.Mechanism == SpfMechanismType.All);

        if (redirectApplies)
        {
            terms++;
        }

        DeliverabilityEvidence evidence = new(
            $"At most {SpfLookupLimit} terms that cause DNS lookups",
            string.Create(CultureInfo.InvariantCulture, $"{terms} in this record"));

        const string Note =
            "This counts only the terms in your own record. Each 'include' spends the budget " +
            "again inside the record it fetches, so the real total is higher.";

        if (terms > SpfLookupLimit)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"The record uses {terms} terms that cause DNS lookups, past RFC 7208's limit of " +
                $"{SpfLookupLimit}. Receivers must return a permanent error. {Note}",
                evidence,
                "Remove or consolidate 'include' terms, or replace them with the ip4/ip6 " +
                "addresses they resolve to, which cost no lookups.");
        }

        return terms >= SpfLookupLimit - 2
            ? Warn(
                Id,
                Title,
                Weight,
                $"The record uses {terms} of RFC 7208's {SpfLookupLimit} DNS lookups. {Note}",
                evidence,
                "Consider replacing an 'include' with the addresses it resolves to before you " +
                "add another sending service.")
            : Pass(
                Id,
                Title,
                Weight,
                $"The record uses {terms} of RFC 7208's {SpfLookupLimit} DNS lookups.",
                evidence);
    }

    /// <summary>§4.6.4's list, exactly: these terms cause DNS queries and nothing else does.</summary>
    private static bool CausesLookup(SpfMechanismType mechanism) => mechanism is
        SpfMechanismType.Include or
        SpfMechanismType.A or
        SpfMechanismType.Mx or
        SpfMechanismType.Ptr or
        SpfMechanismType.Exists;

    // -------------------------------------------------------------------------------------------
    // DKIM.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// At least one configured selector has a usable key published.
    /// </summary>
    /// <remarks>
    /// <b>A revoked key is not a published key.</b> RFC 6376 §3.6.1 gives <c>p=</c> with an
    /// empty value that meaning, and a selector in that state signs mail that every receiver
    /// rejects the signature of — which is worse than not signing, because DMARC alignment then
    /// rests on SPF alone without anyone noticing.
    /// </remarks>
    private static DeliverabilityCheck DkimPublished(AuthenticationFacts facts)
    {
        const string Id = DkimPublishedId;
        const string Title = "A DKIM public key is published";
        const int Weight = 3;

        if (facts.Selectors.Count == 0)
        {
            return Fail(
                Id,
                Title,
                Weight,
                "No DKIM selector is configured, so this server does not sign its outbound mail.",
                DeliverabilityEvidence.Missing("A configured DKIM selector"),
                "Generate a DKIM key for this domain and publish its public half at " +
                $"<selector>._domainkey.{facts.Domain.Value}.");
        }

        List<string> usable = [];
        List<string> problems = [];
        bool anyUnanswered = false;

        foreach (DkimSelectorFacts selector in facts.Selectors)
        {
            if (selector.TxtRecords is null)
            {
                anyUnanswered = true;
                continue;
            }

            string name = $"{selector.Selector}._domainkey.{facts.Domain.Value}";

            if (Key(selector) is not { } key)
            {
                problems.Add(selector.TxtRecords.Count == 0
                    ? $"{name} has no record"
                    : $"{name} does not parse");

                continue;
            }

            if (key.IsRevoked)
            {
                problems.Add($"{name} is revoked (p= is empty)");
                continue;
            }

            usable.Add(name);
        }

        DeliverabilityEvidence evidence = new(
            $"A key at <selector>._domainkey.{facts.Domain.Value}",
            usable.Count > 0 ? string.Join(", ", usable) : NullIfEmpty(string.Join("; ", problems)));

        if (usable.Count > 0)
        {
            return Pass(
                Id,
                Title,
                Weight,
                $"{usable.Count} selector(s) publish a usable key.",
                evidence);
        }

        return anyUnanswered && problems.Count == 0
            ? Unmeasured(Id, Title, Weight, "No answer for the configured selector(s).")
            : Fail(
                Id,
                Title,
                Weight,
                "No configured selector publishes a usable key, so every signature this server " +
                "makes will fail verification.",
                evidence,
                $"Publish the public key at {facts.Selectors[0].Selector}._domainkey." +
                $"{facts.Domain.Value}, and check it is not revoked (an empty p= value).");
    }

    /// <summary>
    /// The published keys are strong enough.
    /// </summary>
    /// <remarks>
    /// RFC 8301 §3.2: "Signers MUST use RSA keys of at least 1024 bits for all keys. Signers
    /// SHOULD use RSA keys of at least 2048 bits", and "Verifiers MUST NOT consider signatures
    /// using RSA keys of less than 1024 bits as valid signatures." A MUST and a SHOULD, so a
    /// short key fails and a merely-not-recommended one warns.
    /// </remarks>
    private static DeliverabilityCheck DkimKeyStrength(AuthenticationFacts facts)
    {
        const string Id = DkimKeyStrengthId;
        const string Title = "The DKIM keys are strong enough";
        const int Weight = 1;

        List<(string Name, int Bits)> sized = [];

        foreach (DkimSelectorFacts selector in facts.Selectors)
        {
            // RFC 8301 is about RSA and says nothing about the Ed25519 keys RFC 8463 added, whose
            // strength is not a modulus size and is not the operator's to choose. A non-RSA
            // selector is therefore not measured rather than judged by a rule that does not
            // apply to it.
            if (Key(selector) is { IsRevoked: false } key &&
                key.KeyType.Equals("rsa", StringComparison.OrdinalIgnoreCase) &&
                RsaKeyBits(key.PublicKeyBase64) is { } bits)
            {
                sized.Add(($"{selector.Selector}._domainkey.{facts.Domain.Value}", bits));
            }
        }

        if (sized.Count == 0)
        {
            return Unmeasured(
                Id,
                Title,
                Weight,
                "No published RSA key could be measured. RFC 8301's sizes do not apply to a " +
                "selector that publishes no key, a revoked one, or a key of another type.");
        }

        (string Name, int Bits) weakest = sized.MinBy(s => s.Bits);

        DeliverabilityEvidence evidence = new(
            $"An RSA key of at least {RecommendedDkimKeyBits} bits",
            string.Create(CultureInfo.InvariantCulture, $"{weakest.Name} is {weakest.Bits} bits"));

        if (weakest.Bits < MinimumDkimKeyBits)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"{weakest.Name} is {weakest.Bits} bits. RFC 8301 requires at least " +
                $"{MinimumDkimKeyBits}, and says verifiers must not treat a shorter key's " +
                "signatures as valid at all.",
                evidence,
                $"Generate a new key of at least {RecommendedDkimKeyBits} bits, publish it under " +
                "a new selector, and switch signing to it before removing the old one.");
        }

        return weakest.Bits < RecommendedDkimKeyBits
            ? Warn(
                Id,
                Title,
                Weight,
                $"{weakest.Name} is {weakest.Bits} bits. RFC 8301 requires 1024 and recommends " +
                $"{RecommendedDkimKeyBits}.",
                evidence,
                $"Rotate to a {RecommendedDkimKeyBits}-bit key under a new selector when " +
                "convenient.")
            : Pass(
                Id,
                Title,
                Weight,
                $"The weakest published key is {weakest.Bits} bits.",
                evidence);
    }

    // -------------------------------------------------------------------------------------------
    // DMARC.
    // -------------------------------------------------------------------------------------------

    /// <summary>A parseable <c>v=DMARC1</c> record exists at <c>_dmarc</c>.</summary>
    private static DeliverabilityCheck DmarcPublished(
        AuthenticationFacts facts,
        IReadOnlyList<string>? texts,
        DmarcRecord? parsed)
    {
        const string Id = DmarcPublishedId;
        const string Title = "A DMARC record is published";
        const int Weight = 3;

        string name = $"_dmarc.{facts.Domain.Value}";

        if (texts is null)
        {
            return Unmeasured(Id, Title, Weight, $"No TXT answer for {name}.");
        }

        DeliverabilityEvidence evidence = new(
            $"A v=DMARC1 TXT record at {name}",
            texts.Count == 0 ? null : string.Join(" | ", texts));

        if (texts.Count == 0)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"{name} publishes no DMARC record, so receivers have no instruction for mail " +
                "that fails SPF and DKIM, and you receive no reports about it.",
                evidence,
                $"Publish a TXT record at {name} such as " +
                $"\"v=DMARC1; p=none; rua=mailto:dmarc@{facts.Domain.Value}\", and tighten the " +
                "policy once the reports show your own mail passing.");
        }

        if (texts.Count > 1)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"{name} publishes {texts.Count} DMARC records. Receivers that find more than " +
                "one apply none of them.",
                evidence,
                "Delete all but one.");
        }

        return parsed is null
            ? Fail(
                Id,
                Title,
                Weight,
                "The DMARC record does not parse, so receivers will ignore it.",
                evidence,
                "Correct the record's syntax; it must begin with v=DMARC1 and carry a p= tag.")
            : Pass(Id, Title, Weight, "One DMARC record is published and parses.", evidence);
    }

    /// <summary>
    /// The policy asks receivers to do something.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.3 on <c>p=none</c>: "The Domain Owner requests no specific action be taken
    /// regarding delivery of messages." That is the correct setting while reports are being
    /// read, and it protects nothing — so it warns rather than passes, with a remedy that says
    /// what to do next rather than simply "tighten it".
    /// </remarks>
    private static DeliverabilityCheck DmarcEnforcement(DmarcRecord? dmarc)
    {
        const string Id = DmarcPolicyId;
        const string Title = "The DMARC policy asks for enforcement";
        const int Weight = 2;

        if (dmarc is null)
        {
            return Unmeasured(Id, Title, Weight, "There is no DMARC record to read a policy from.");
        }

        DeliverabilityEvidence evidence = new("p=quarantine or p=reject", $"p={Render(dmarc.Policy)}");

        if (dmarc.Policy == DmarcPolicy.None)
        {
            return Warn(
                Id,
                Title,
                Weight,
                "The policy is p=none, which asks receivers to take no action. That is the right " +
                "setting while you are reading reports, and it protects nobody from someone " +
                "sending as your domain.",
                evidence,
                "Once the aggregate reports show your own mail passing, move to p=quarantine " +
                "and then p=reject.");
        }

        // A policy that only applies to some of the mail is a partial policy, and pct= is the
        // tag that makes it so. RFC 7489 §6.3 makes 100 the default.
        return dmarc.Percentage < 100
            ? Warn(
                Id,
                Title,
                Weight,
                $"The policy is p={Render(dmarc.Policy)} but applies to only " +
                $"{dmarc.Percentage}% of messages.",
                evidence with { Found = $"p={Render(dmarc.Policy)}; pct={dmarc.Percentage}" },
                "Raise pct= to 100 once the reports show your own mail passing.")
            : Pass(
                Id,
                Title,
                Weight,
                $"The policy is p={Render(dmarc.Policy)}.",
                evidence);
    }

    /// <summary>
    /// The record asks for aggregate reports.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 7489 §6.3 defines <c>rua</c> as "Addresses to which aggregate feedback is to be sent".
    /// </para>
    /// <para>
    /// <b>Without it a DMARC record is advice nobody reads back.</b> The reports are the only
    /// way to discover that a legitimate sending service is failing alignment, and the only
    /// evidence on which tightening the policy is safe. A record with no <c>rua</c> makes the
    /// remedy for every other DMARC finding unverifiable.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck DmarcReporting(string? text, DmarcRecord? dmarc)
    {
        const string Id = DmarcReportingId;
        const string Title = "DMARC aggregate reports are requested";
        const int Weight = 1;

        if (dmarc is null || text is null)
        {
            return Unmeasured(Id, Title, Weight, "There is no DMARC record to read a rua= tag from.");
        }

        // RFC 7489 SS6.4's ABNF puts *WSP on both sides of the '=', so the tag name is what
        // precedes it once trimmed - not a prefix of the raw text. A prefix match would also
        // accept "ruf=", which SS6.3 gives an entirely different meaning: failure reports rather
        // than aggregate ones.
        bool hasRua = text
            .Split(';')
            .Select(TagName)
            .Any(name => string.Equals(name, "rua", StringComparison.OrdinalIgnoreCase));

        DeliverabilityEvidence evidence = new("A rua= tag", hasRua ? "present" : null);

        return hasRua
            ? Pass(Id, Title, Weight, "The record requests aggregate reports.", evidence)
            : Warn(
                Id,
                Title,
                Weight,
                "The record has no rua= tag, so no aggregate reports are sent to you. The " +
                "reports are the only way to find a legitimate sender that is failing " +
                "alignment, and the only evidence on which tightening the policy is safe.",
                evidence,
                "Add rua=mailto:<an address you read> to the record.");
    }

    // -------------------------------------------------------------------------------------------
    // Shared.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The records that are SPF records.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §4.5: "discard records that do not begin with a version section of exactly
    /// 'v=spf1'. Note that the version section is terminated by either an SP character or the
    /// end of the record. As an example, a record with a version section of 'v=spf10' does not
    /// match and is discarded." So the match is on the whole token rather than a prefix, and the
    /// terminator is a space — not a semicolon, which SPF does not use as a separator at all.
    /// The comparison ignores case because §4.5 spells the version as the ABNF string
    /// "v=spf1", and RFC 5234 §2.3 makes such a string case-insensitive.
    /// </remarks>
    private static IReadOnlyList<string> SelectSpf(IReadOnlyList<string> texts)
    {
        const string Version = "v=spf1";

        List<string> matching = [];

        foreach (string text in texts)
        {
            if (!text.StartsWith(Version, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string rest = text[Version.Length..];

            if (rest.Length == 0 || rest[0] == ' ')
            {
                matching.Add(text);
            }
        }

        return matching;
    }

    /// <summary>
    /// The records that are DMARC records.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A separate method from <see cref="SelectSpf"/> because the two RFCs disagree about the
    /// shape of the thing. RFC 7489 §6.4: <c>dmarc-version = "v" *WSP "=" *WSP %x44 %x4d
    /// %x41 %x52 %x43 %x31</c>. Two differences from SPF follow from that one line: whitespace
    /// is permitted on both sides of the equals sign, so <c>v = DMARC1</c> is a valid record
    /// that a prefix match would not find at all; and the value is written as hex literals
    /// rather than as an ABNF string, which is how a grammar spells case-sensitive.
    /// </para>
    /// <para>
    /// <b>That case rule is deliberately not enforced here.</b> §6.3 is emphatic — "It MUST
    /// have the value of 'DMARC1'. The value of this tag MUST match precisely; if it does not or
    /// it is absent, the entire retrieved record MUST be ignored" — but an operator looking at
    /// a <c>v=dmarc1</c> record on screen is better served by "this record does not parse, so
    /// receivers ignore it" than by "you publish no DMARC record". So a mis-cased record is
    /// selected here and fails at the parser, which is the finding that names the actual fault.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<string> SelectDmarc(IReadOnlyList<string> texts)
    {
        const string Version = "DMARC1";

        List<string> matching = [];

        foreach (string text in texts)
        {
            string trimmed = text.TrimStart();

            if (trimmed.Length == 0 || trimmed[0] is not ('v' or 'V'))
            {
                continue;
            }

            string afterName = trimmed[1..].TrimStart();

            if (afterName.Length == 0 || afterName[0] != '=')
            {
                continue;
            }

            string value = afterName[1..].TrimStart();

            if (!value.StartsWith(Version, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string rest = value[Version.Length..];

            if (rest.Length == 0 || rest[0] is ';' or ' ' or '\t')
            {
                matching.Add(text);
            }
        }

        return matching;
    }

    private static SpfRecord? ParseSingleSpf(IReadOnlyList<string>? texts) =>
        texts is { Count: 1 } && SpfRecord.TryParse(texts[0], out SpfRecord? record, out _)
            ? record
            : null;

    /// <summary>
    /// The key a verifier would use at this selector, or null when none parses.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §6.1.2: "If the query for the public key returns multiple key records, the
    /// Verifier can choose one of the key records or may cycle through the key records[…] The
    /// order of the key records is unspecified." Unspecified order is the operative part: a
    /// selector with several records is judged on the best of them, because taking whichever one
    /// DNS happened to return first would report a working domain as broken, differently on
    /// different days.
    /// </remarks>
    private static DkimPublicKeyRecord? Key(DkimSelectorFacts selector)
    {
        if (selector.TxtRecords is not { Count: > 0 } records)
        {
            return null;
        }

        DkimPublicKeyRecord? best = null;

        foreach (string text in records)
        {
            if (!DkimPublicKeyRecord.TryParse(text, out DkimPublicKeyRecord? key, out _))
            {
                continue;
            }

            if (!key.IsRevoked)
            {
                return key;
            }

            best ??= key;
        }

        return best;
    }

    /// <summary>The name of a tag-value pair, or an empty string when there is no '='.</summary>
    private static string TagName(string tag)
    {
        int equals = tag.IndexOf('=', StringComparison.Ordinal);

        return equals < 0 ? string.Empty : tag[..equals].Trim();
    }

    /// <summary>
    /// The modulus size of an RSA public key, or null when it cannot be read.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §3.6.1 publishes the key as base64 of a DER SubjectPublicKeyInfo, which the
    /// platform can import. Null rather than an exception for anything malformed: a key that
    /// does not parse is the published-key check's finding, and this one has nothing to add.
    /// </remarks>
    public static int? RsaKeyBits(string publicKeyBase64)
    {
        if (string.IsNullOrWhiteSpace(publicKeyBase64))
        {
            return null;
        }

        try
        {
            byte[] der = Convert.FromBase64String(publicKeyBase64);

            using RSA rsa = RSA.Create();

            rsa.ImportSubjectPublicKeyInfo(der, out _);

            return rsa.KeySize;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return null;
        }
    }

    private static string Render(SpfQualifier qualifier) => qualifier switch
    {
        SpfQualifier.Pass => "+all",
        SpfQualifier.Fail => "-all",
        SpfQualifier.SoftFail => "~all",
        _ => "?all",
    };

    private static string Render(DmarcPolicy policy) => policy switch
    {
        DmarcPolicy.None => "none",
        DmarcPolicy.Quarantine => "quarantine",
        _ => "reject",
    };

    private static string? NullIfEmpty(string value) => value.Length == 0 ? null : value;

    private static DeliverabilityCheck Pass(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence) =>
        new(id, DeliverabilityCategory.Authentication, title, weight, DeliverabilityOutcome.Pass, detail, evidence);

    private static DeliverabilityCheck Warn(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Authentication, title, weight, DeliverabilityOutcome.Warn, detail, evidence, remedy);

    private static DeliverabilityCheck Fail(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Authentication, title, weight, DeliverabilityOutcome.Fail, detail, evidence, remedy);

    private static DeliverabilityCheck Unmeasured(string id, string title, int weight, string detail) =>
        new(id, DeliverabilityCategory.Authentication, title, weight, DeliverabilityOutcome.Inconclusive, detail);
}
