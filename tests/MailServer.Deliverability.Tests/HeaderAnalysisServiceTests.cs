using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;
using MailServer.Infrastructure.Dmarc;
using MailServer.Infrastructure.Spf;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Deliverability.Tests;

/// <summary>TXT records, scripted by name.</summary>
internal sealed class ScriptedTxt : ITxtRecordResolver
{
    private readonly Dictionary<string, TxtLookupResult> _answers = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Asked { get; } = [];

    public ScriptedTxt With(string name, params string[] records)
    {
        _answers[name] = TxtLookupResult.Success(records);
        return this;
    }

    public ScriptedTxt WithNoAnswer(string name)
    {
        _answers[name] = TxtLookupResult.Temporary("scripted timeout");
        return this;
    }

    public Task<TxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken)
    {
        Asked.Add(domain);

        return Task.FromResult(_answers.TryGetValue(domain, out TxtLookupResult? answer)
            ? answer
            : TxtLookupResult.Success([]));
    }
}

/// <summary>An MX resolver that answers nothing, which SPF's a/mx mechanisms tolerate.</summary>
internal sealed class SilentDnsResolver : IDnsResolver
{
    public Task<MxLookupResult> ResolveMxAsync(DomainName domain, CancellationToken cancellationToken) =>
        Task.FromResult(MxLookupResult.Success([]));

    public Task<AddressLookupResult> ResolveAddressesAsync(string hostname, CancellationToken cancellationToken) =>
        Task.FromResult(AddressLookupResult.Success([]));
}

/// <summary>DKIM public keys, scripted by selector and domain.</summary>
internal sealed class ScriptedKeys : IDkimPublicKeyResolver
{
    private readonly Dictionary<string, DkimPublicKeyLookupResult> _answers = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Asked { get; } = [];

    public ScriptedKeys With(string selector, string domain, string record)
    {
        _answers[$"{selector}.{domain}"] = DkimPublicKeyRecord.TryParse(record, out DkimPublicKeyRecord? key, out string? error)
            ? DkimPublicKeyLookupResult.Success(key)
            : DkimPublicKeyLookupResult.Permanent(error);

        return this;
    }

    public ScriptedKeys WithNoAnswer(string selector, string domain)
    {
        _answers[$"{selector}.{domain}"] = DkimPublicKeyLookupResult.Temporary("scripted timeout");
        return this;
    }

    public Task<DkimPublicKeyLookupResult> ResolveAsync(
        DkimSelector selector,
        DomainName signingDomain,
        CancellationToken cancellationToken)
    {
        string key = $"{selector.Value}.{signingDomain.Value}";

        Asked.Add(key);

        return Task.FromResult(_answers.TryGetValue(key, out DkimPublicKeyLookupResult? answer)
            ? answer
            : DkimPublicKeyLookupResult.Permanent("no record"));
    }
}

internal sealed class FakePsl(string listText) : IPublicSuffixListProvider
{
    public PublicSuffixList List { get; } = PublicSuffixList.Parse(listText);
}

public sealed class HeaderAnalysisServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly IpAddressValue Sender = IpAddressValue.Parse("203.0.113.10");

    /// <summary>A 2048-bit RSA key, as a selector publishes one.</summary>
    private const string Key =
        "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7JliQdtpMedIfKjNZkeGYPSt8GJmx" +
        "6p3GBWx8G8la/7ulpaZupAG4SCXhY/A5mm8X+/0b1H7XqHOUWEptsv/noJCmasr9P3JoL+/ge49UoL+NF32/SOjoHEN" +
        "SJ6pZSEfOPoJH1hpCS/guGUl4RamyTbyUkjchHvfAu4hVLmwWrSOk2pCBkSZnfUKLSkxT2fugvkW98Iss1bUcS6hQVI" +
        "KSQaHbYM5Qfu4CKsRneb/MXpzROwIneHGcZJuaDHEvu/kY6xwiYxgeiRoV9IhX4asHcMgUZGjK7vUDSTTOrgLCYR3nV" +
        "qew/3In9xeIy0PywREH67MOLA9V8bCCPhBwQpGNwIDAQAB";

    private static HeaderAnalysisService Service(ScriptedTxt txt, ScriptedKeys? keys = null) =>
        new(
            new SpfEvaluator(txt, new SilentDnsResolver(), NullLogger<SpfEvaluator>.Instance),
            keys ?? new ScriptedKeys(),
            txt,
            // Just the two TLDs: listing example.com would make it a public SUFFIX, so
            // news.example.com's organisational domain would be itself and RFC 7489 §3.1.1's own
            // worked example would stop being an example of relaxed alignment.
            new FakePsl("com\nnet\n"),
            new ProbeClock(Now),
            NullLogger<HeaderAnalysisService>.Instance);

    private static string Block(params string[] lines) => string.Join("\r\n", lines) + "\r\n";

    private static bool Has(AnalysedHeaders analysis, string id) =>
        analysis.Observations.Any(o => o.Id == id);

    private const string Trace =
        "Received: from a.example.com ([203.0.113.10]) by mail.receiver.example; " +
        "Sat, 19 Sep 2026 11:00:00 +0000";

    // ---------------------------------------------------------------------------------------
    // SPF.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// SPF is checked for the Return-Path domain, not the From domain.
    /// </summary>
    /// <remarks>
    /// RFC 7208 §2.2: "Without explicit approval of the publishing ADMD, checking other
    /// identities against SPF version 1 records is NOT RECOMMENDED because there are cases that
    /// are known to give incorrect results. For example, almost all mailing lists rewrite the
    /// 'MAIL FROM' identity […] but some do not change any other identities in the message."
    /// Checking From is exactly that mistake, and it is the one that makes every forwarded
    /// message look forged.
    /// </remarks>
    [Fact]
    public async Task Spf_is_checked_for_the_return_path_domain()
    {
        ScriptedTxt txt = new ScriptedTxt()
            .With("bounces.example.net", "v=spf1 ip4:203.0.113.10 -all")
            .With("example.com", "v=spf1 -all");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block(Trace, "Return-Path: <b@bounces.example.net>", "From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.SpfDomain.ShouldNotBeNull().Value.ShouldBe("bounces.example.net");
        analysis.Authentication.Spf.ShouldBe(SpfResult.Pass);
    }

    /// <summary>With no Return-Path the From domain is used, and the result says so.</summary>
    [Fact]
    public async Task Without_a_return_path_the_from_domain_is_used_and_flagged()
    {
        ScriptedTxt txt = new ScriptedTxt().With("example.com", "v=spf1 ip4:203.0.113.10 -all");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block(Trace, "From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.SpfDomain.ShouldNotBeNull().Value.ShouldBe("example.com");
        Has(analysis, HeaderAnalysisService.NoReturnPathId).ShouldBeTrue();
    }

    /// <summary>
    /// With no supplied address, the topmost hop's observed address is used — and flagged.
    /// </summary>
    /// <remarks>
    /// An address out of the message's own trace was written by a host the operator may not
    /// control. Using it is better than refusing to evaluate, but presenting the result without
    /// saying where the address came from would let a forged trace header produce a confident
    /// SPF pass.
    /// </remarks>
    [Fact]
    public async Task An_address_from_the_trace_is_used_and_flagged()
    {
        ScriptedTxt txt = new ScriptedTxt().With("example.com", "v=spf1 ip4:203.0.113.10 -all");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block(Trace, "From: alice@example.com"),
            clientAddress: null,
            CancellationToken.None);

        analysis.Authentication.SpfAddress.ShouldNotBeNull().Value.ShouldBe("203.0.113.10");
        analysis.Authentication.SpfAddressFromTrace.ShouldBeTrue();
        Has(analysis, HeaderAnalysisService.SpfAddressFromTraceId).ShouldBeTrue();
    }

    /// <summary>A supplied address is used in preference, and is not flagged.</summary>
    [Fact]
    public async Task A_supplied_address_is_preferred_and_not_flagged()
    {
        ScriptedTxt txt = new ScriptedTxt().With("example.com", "v=spf1 ip4:198.51.100.7 -all");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block(Trace, "From: alice@example.com"),
            IpAddressValue.Parse("198.51.100.7"),
            CancellationToken.None);

        analysis.Authentication.SpfAddress.ShouldNotBeNull().Value.ShouldBe("198.51.100.7");
        analysis.Authentication.SpfAddressFromTrace.ShouldBeFalse();
        analysis.Authentication.Spf.ShouldBe(SpfResult.Pass);
        Has(analysis, HeaderAnalysisService.SpfAddressFromTraceId).ShouldBeFalse();
    }

    /// <summary>With no address anywhere, SPF is not evaluated rather than guessed.</summary>
    [Fact]
    public async Task With_no_address_spf_is_not_evaluated()
    {
        AnalysedHeaders analysis = await Service(new ScriptedTxt()).AnalyseAsync(
            Block("From: alice@example.com"),
            clientAddress: null,
            CancellationToken.None);

        analysis.Authentication.Spf.ShouldBeNull();
        Has(analysis, HeaderAnalysisService.NoSpfAddressId).ShouldBeTrue();
    }

    /// <summary>A real SPF failure is reported as one.</summary>
    [Fact]
    public async Task A_real_spf_failure_is_reported()
    {
        ScriptedTxt txt = new ScriptedTxt().With("example.com", "v=spf1 ip4:198.51.100.0/24 -all");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block(Trace, "From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.Spf.ShouldBe(SpfResult.Fail);
    }

    // ---------------------------------------------------------------------------------------
    // DKIM keys.
    // ---------------------------------------------------------------------------------------

    private static string Signature(string domain = "example.com", string selector = "mail2026") =>
        $"DKIM-Signature: v=1; a=rsa-sha256; d={domain}; s={selector}; h=from; " +
        "bh=YmFzZTY0; b=c2lnbmF0dXJl";

    /// <summary>A published key is reported with its size.</summary>
    [Fact]
    public async Task A_published_key_is_reported_with_its_size()
    {
        ScriptedKeys keys = new ScriptedKeys().With("mail2026", "example.com", Key);

        AnalysedHeaders analysis = await Service(new ScriptedTxt(), keys).AnalyseAsync(
            Block("From: alice@example.com", Signature()),
            Sender,
            CancellationToken.None);

        AnalysedKey found = analysis.Authentication.Keys.ShouldHaveSingleItem();

        found.State.ShouldBe(AnalysedKeyState.Published);
        found.KeyBits.ShouldBe(2048);
    }

    /// <summary>
    /// A selector that does not resolve is the most common DKIM fault there is.
    /// </summary>
    /// <remarks>
    /// A server signing with a key nobody can fetch produces signatures every receiver rejects,
    /// and nothing about it is visible from the sending side.
    /// </remarks>
    [Fact]
    public async Task A_missing_key_is_reported()
    {
        AnalysedHeaders analysis = await Service(new ScriptedTxt(), new ScriptedKeys()).AnalyseAsync(
            Block("From: alice@example.com", Signature()),
            Sender,
            CancellationToken.None);

        analysis.Authentication.Keys.ShouldHaveSingleItem()
            .State.ShouldBe(AnalysedKeyState.NotPublished);

        Has(analysis, HeaderAnalysisService.KeyNotPublishedId).ShouldBeTrue();
    }

    /// <summary>A revoked key is its own state, because the cause differs from a missing one.</summary>
    [Fact]
    public async Task A_revoked_key_is_reported_as_revoked()
    {
        ScriptedKeys keys = new ScriptedKeys().With("mail2026", "example.com", "v=DKIM1; k=rsa; p=");

        AnalysedHeaders analysis = await Service(new ScriptedTxt(), keys).AnalyseAsync(
            Block("From: alice@example.com", Signature()),
            Sender,
            CancellationToken.None);

        analysis.Authentication.Keys.ShouldHaveSingleItem()
            .State.ShouldBe(AnalysedKeyState.Revoked);
    }

    /// <summary>
    /// A resolver that did not answer is not a missing key.
    /// </summary>
    /// <remarks>
    /// The distinction the whole report rests on, here too: telling an operator to republish a
    /// record that is already there wastes their time and leaves the real fault unfound.
    /// </remarks>
    [Fact]
    public async Task An_unanswered_key_lookup_is_not_a_missing_key()
    {
        ScriptedKeys keys = new ScriptedKeys().WithNoAnswer("mail2026", "example.com");

        AnalysedHeaders analysis = await Service(new ScriptedTxt(), keys).AnalyseAsync(
            Block("From: alice@example.com", Signature()),
            Sender,
            CancellationToken.None);

        analysis.Authentication.Keys.ShouldHaveSingleItem()
            .State.ShouldBe(AnalysedKeyState.LookupFailed);

        Has(analysis, HeaderAnalysisService.KeyNotPublishedId).ShouldBeFalse();
    }

    /// <summary>
    /// DKIM is never reported as passing, whatever the key lookup found.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §3.7 hashes the body, and a paste has none. A signature over a modified body
    /// looks identical here, so the analyser says what it established — a published key and an
    /// aligned d= — and says plainly that this is not verification.
    /// </remarks>
    [Fact]
    public async Task Dkim_is_never_reported_as_passing()
    {
        ScriptedKeys keys = new ScriptedKeys().With("mail2026", "example.com", Key);

        AnalysedHeaders analysis = await Service(new ScriptedTxt(), keys).AnalyseAsync(
            Block("From: alice@example.com", Signature()),
            Sender,
            CancellationToken.None);

        analysis.Authentication.DkimCouldAlign.ShouldBeTrue();
        Has(analysis, HeaderAnalysisService.DkimUnverifiableId).ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // Alignment.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Relaxed alignment matches on the organisational domain.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §3.1.1: "In relaxed mode, the Organizational Domains of both the [DKIM]-
    /// authenticated signing domain […] and that of the RFC5322.From domain must be equal if the
    /// identifiers are to be considered aligned." Its own example is a <c>d=</c> of example.com
    /// against a From of alerts@news.example.com, which this mirrors.
    /// </remarks>
    [Fact]
    public async Task Relaxed_alignment_matches_on_the_organisational_domain()
    {
        ScriptedTxt txt = new ScriptedTxt()
            .With("_dmarc.news.example.com", "v=DMARC1; p=reject");

        ScriptedKeys keys = new ScriptedKeys().With("mail2026", "example.com", Key);

        AnalysedHeaders analysis = await Service(txt, keys).AnalyseAsync(
            Block("From: alerts@news.example.com", Signature(domain: "example.com")),
            Sender,
            CancellationToken.None);

        analysis.Authentication.DkimCouldAlign.ShouldBeTrue();
    }

    /// <summary>
    /// Strict alignment needs an exact match, so the same pair does not align.
    /// </summary>
    /// <remarks>
    /// §3.1.1: "In strict mode, only an exact match between both of the Fully Qualified Domain
    /// Names (FQDNs) is considered to produce Identifier Alignment."
    /// </remarks>
    [Fact]
    public async Task Strict_alignment_needs_an_exact_match()
    {
        ScriptedTxt txt = new ScriptedTxt()
            .With("_dmarc.news.example.com", "v=DMARC1; p=reject; adkim=s");

        ScriptedKeys keys = new ScriptedKeys().With("mail2026", "example.com", Key);

        AnalysedHeaders analysis = await Service(txt, keys).AnalyseAsync(
            Block("From: alerts@news.example.com", Signature(domain: "example.com")),
            Sender,
            CancellationToken.None);

        analysis.Authentication.DkimCouldAlign.ShouldBeFalse();
    }

    /// <summary>
    /// A signature whose key is not published cannot align, however well its d= matches.
    /// </summary>
    /// <remarks>
    /// Alignment is about which domain is authenticated, and a signature nobody can verify
    /// authenticates none. Counting it would tell an operator DMARC is satisfied by a signature
    /// every receiver discards.
    /// </remarks>
    [Fact]
    public async Task A_signature_with_no_published_key_cannot_align()
    {
        AnalysedHeaders analysis = await Service(new ScriptedTxt(), new ScriptedKeys()).AnalyseAsync(
            Block("From: alice@example.com", Signature()),
            Sender,
            CancellationToken.None);

        analysis.Authentication.DkimCouldAlign.ShouldBeFalse();
    }

    /// <summary>SPF alignment needs SPF to have passed, not merely to have been evaluated.</summary>
    [Fact]
    public async Task Spf_alignment_needs_spf_to_have_passed()
    {
        ScriptedTxt failing = new ScriptedTxt().With("example.com", "v=spf1 -all");

        AnalysedHeaders analysis = await Service(failing).AnalyseAsync(
            Block(Trace, "From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.Spf.ShouldBe(SpfResult.Fail);
        analysis.Authentication.SpfAligned.ShouldBeFalse();
    }

    /// <summary>
    /// When nothing can align, the analyser says DMARC cannot pass.
    /// </summary>
    /// <remarks>
    /// The single most useful sentence the tool can produce for "why was my mail refused": both
    /// legs are ruled out, so no amount of receiver-side variation changes the answer.
    /// </remarks>
    [Fact]
    public async Task When_nothing_aligns_the_analyser_says_so()
    {
        ScriptedTxt txt = new ScriptedTxt()
            .With("bounces.example.net", "v=spf1 ip4:203.0.113.10 -all")
            .With("_dmarc.example.com", "v=DMARC1; p=reject; aspf=s");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block(Trace, "Return-Path: <b@bounces.example.net>", "From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.Spf.ShouldBe(SpfResult.Pass);
        analysis.Authentication.SpfAligned.ShouldBeFalse();
        Has(analysis, HeaderAnalysisService.NothingAlignsId).ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // DMARC.
    // ---------------------------------------------------------------------------------------

    /// <summary>The DMARC record is read from the From domain's <c>_dmarc</c> name.</summary>
    [Fact]
    public async Task The_dmarc_record_is_read_from_the_from_domain()
    {
        ScriptedTxt txt = new ScriptedTxt()
            .With("_dmarc.example.com", "v=DMARC1; p=quarantine; rua=mailto:d@example.com");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block("From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.DmarcPolicy.ShouldBe(DmarcPolicy.Quarantine);
        txt.Asked.ShouldContain("_dmarc.example.com");
    }

    /// <summary>
    /// The policy is discovered at the From domain even when Return-Path is elsewhere.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §6.6.3: "Mail Receivers MUST query the DNS for a DMARC TXT record at the DNS
    /// domain matching the one found in the RFC5322.From domain in the message." Looking it up
    /// at the Return-Path instead would find nothing for most bulk mail — every sender using a
    /// separate bounce domain would read as having no DMARC policy, and the analyser would then
    /// apply relaxed alignment defaults to a domain that asked for strict.
    /// </remarks>
    [Fact]
    public async Task The_policy_is_discovered_at_the_from_domain_not_the_return_path()
    {
        ScriptedTxt txt = new ScriptedTxt()
            .With("bounces.example.net", "v=spf1 ip4:203.0.113.10 -all")
            .With("_dmarc.example.com", "v=DMARC1; p=reject")
            .With("_dmarc.bounces.example.net", "v=DMARC1; p=none");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block(Trace, "Return-Path: <b@bounces.example.net>", "From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.DmarcPolicy.ShouldBe(DmarcPolicy.Reject);
        txt.Asked.ShouldContain("_dmarc.example.com");
        txt.Asked.ShouldNotContain("_dmarc.bounces.example.net");
    }

    /// <summary>No DMARC record is a finding, since receivers then have no instruction.</summary>
    [Fact]
    public async Task No_dmarc_record_is_a_finding()
    {
        AnalysedHeaders analysis = await Service(new ScriptedTxt()).AnalyseAsync(
            Block("From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.DmarcPolicy.ShouldBeNull();
        Has(analysis, HeaderAnalysisService.NoDmarcId).ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // The discipline, end to end.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A forged authentication header changes nothing, even with DNS in play.
    /// </summary>
    /// <remarks>
    /// The pure half already asserts this; repeating it here is what proves the lookup half did
    /// not quietly reintroduce the trust. A message claiming dmarc=pass gets exactly the verdict
    /// its DNS supports, which here is none at all.
    /// </remarks>
    [Fact]
    public async Task A_forged_authentication_header_changes_no_verdict()
    {
        ScriptedTxt txt = new ScriptedTxt().With("example.com", "v=spf1 -all");

        AnalysedHeaders analysis = await Service(txt).AnalyseAsync(
            Block(
                "Authentication-Results: mx.example.com; dmarc=pass; spf=pass; dkim=pass",
                Trace,
                "From: alice@example.com"),
            Sender,
            CancellationToken.None);

        analysis.Authentication.Spf.ShouldBe(SpfResult.Fail);
        analysis.Authentication.SpfAligned.ShouldBeFalse();
        analysis.Authentication.DkimCouldAlign.ShouldBeFalse();
        Has(analysis, HeaderAnalysisService.NothingAlignsId).ShouldBeTrue();
    }

    /// <summary>The pure half's observations survive into the combined result.</summary>
    [Fact]
    public async Task The_pure_halfs_observations_are_carried_through()
    {
        AnalysedHeaders analysis = await Service(new ScriptedTxt()).AnalyseAsync(
            Block("From: alice@example.com"),
            Sender,
            CancellationToken.None);

        Has(analysis, HeaderAnalyser.NoTraceId).ShouldBeTrue();
        Has(analysis, HeaderAnalyser.NoDkimId).ShouldBeTrue();
    }
}
