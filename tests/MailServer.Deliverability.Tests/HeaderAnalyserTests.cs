using MailServer.Domain.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// Reading a pasted header block.
/// </summary>
/// <remarks>
/// Every case here is header text and nothing else — no resolver, no clock but the one passed in.
/// That is the point of keeping this half pure: it can be tested against header blocks no DNS
/// would ever answer for, which is exactly the mail an operator pastes in when something has
/// gone wrong.
/// </remarks>
public sealed class HeaderAnalyserTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);

    private static HeaderAnalysis Analyse(params string[] lines) =>
        HeaderAnalyser.Analyse(string.Join("\r\n", lines) + "\r\n", Now);

    private static bool Has(HeaderAnalysis analysis, string id) =>
        analysis.Observations.Any(o => o.Id == id);

    private const string GoodDkim =
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail2026; " +
        "h=from:to:subject; bh=YmFzZTY0; b=c2lnbmF0dXJl";

    // ---------------------------------------------------------------------------------------
    // Reading the fields.
    // ---------------------------------------------------------------------------------------

    /// <summary>The trace chain comes back in the order the headers were pasted.</summary>
    [Fact]
    public void The_trace_chain_is_read_in_order()
    {
        HeaderAnalysis analysis = Analyse(
            "Received: from b.example.net ([198.51.100.7]) by second.example.com; " +
            "Sat, 19 Sep 2026 11:00:30 +0000",
            "Received: from a.example.net ([203.0.113.10]) by first.example.com; " +
            "Sat, 19 Sep 2026 11:00:00 +0000",
            "From: alice@example.com");

        analysis.Chain.Hops.Count.ShouldBe(2);
        analysis.Chain.Hops[0].Hop.By.ShouldBe("second.example.com");
        analysis.Chain.Hops[0].Delay.ShouldBe(TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// The addr-spec is taken from the angle brackets, not from a display name that mimics one.
    /// </summary>
    /// <remarks>
    /// RFC 5322 §3.4: <c>name-addr = [display-name] angle-addr</c>, and a display name is a
    /// phrase that may be a quoted-string. A scan that took the first <c>&lt;</c> without
    /// skipping quoted text would read the attacker's text and report a domain the message never
    /// came from — which is the whole question the operator is asking.
    /// </remarks>
    [Fact]
    public void A_quoted_display_name_cannot_impersonate_the_address()
    {
        HeaderAnalysis analysis = Analyse(
            "From: \"<victim@bank.example>\" <attacker@evil.example>");

        analysis.From.ShouldNotBeNull().Mailbox.ShouldBe("attacker@evil.example");
        analysis.From.ShouldNotBeNull().Domain.ShouldBe("evil.example");
    }

    /// <summary>A bare addr-spec with no angle brackets is still an address.</summary>
    [Fact]
    public void A_bare_address_is_read()
    {
        HeaderAnalysis analysis = Analyse("From: alice@example.com");

        analysis.From.ShouldNotBeNull().Mailbox.ShouldBe("alice@example.com");
        analysis.From.ShouldNotBeNull().Domain.ShouldBe("example.com");
    }

    /// <summary>The domain is lowercased, so two spellings of one domain compare equal.</summary>
    [Fact]
    public void The_domain_is_lowercased()
    {
        Analyse("From: Alice <alice@EXAMPLE.COM>")
            .From.ShouldNotBeNull().Domain.ShouldBe("example.com");
    }

    /// <summary>A field that is not an address yields no mailbox rather than a wrong one.</summary>
    [Fact]
    public void A_field_that_is_not_an_address_yields_no_mailbox()
    {
        HeaderAnalysis analysis = Analyse("From: undisclosed recipients");

        analysis.From.ShouldNotBeNull().Mailbox.ShouldBeNull();
        analysis.From.ShouldNotBeNull().Raw.ShouldBe("undisclosed recipients");
    }

    /// <summary>A DKIM signature is read for what it claims to have signed.</summary>
    [Fact]
    public void A_dkim_signature_is_read_for_what_it_claims()
    {
        AnalysedSignature signature = Analyse("From: alice@example.com", GoodDkim)
            .Signatures.ShouldHaveSingleItem();

        signature.Domain.ShouldBe("example.com");
        signature.Selector.ShouldBe("mail2026");
        signature.SignedHeaders.ShouldBe(["from", "to", "subject"]);
        signature.ParseError.ShouldBeNull();
    }

    /// <summary>
    /// A signature that does not parse is reported, not dropped.
    /// </summary>
    /// <remarks>
    /// A malformed signature is the finding: a receiver treats it as a permanent error, so an
    /// analyser that silently omitted it would show an operator a message with no DKIM problem
    /// and no DKIM signature either.
    /// </remarks>
    [Fact]
    public void A_malformed_signature_is_reported_rather_than_dropped()
    {
        AnalysedSignature signature = Analyse(
                "From: alice@example.com",
                "DKIM-Signature: this is not a tag list")
            .Signatures.ShouldHaveSingleItem();

        signature.ParseError.ShouldNotBeNullOrWhiteSpace();
        signature.Domain.ShouldBeNull();
    }

    /// <summary>Folded headers are unfolded before anything is read from them.</summary>
    [Fact]
    public void Folded_headers_are_read_whole()
    {
        HeaderAnalysis analysis = HeaderAnalyser.Analyse(
            "From: alice@example.com\r\n" +
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail2026;\r\n" +
            "\th=from:to; bh=YmFzZTY0; b=c2ln\r\n",
            Now);

        analysis.Signatures.ShouldHaveSingleItem().Selector.ShouldBe("mail2026");
    }

    /// <summary>
    /// Bare LF line endings are accepted, because that is what a person pastes.
    /// </summary>
    /// <remarks>
    /// A header block copied out of a mail client, through a terminal, into a text box loses its
    /// CRLFs about half the time. A parser that required them would reject the input in the one
    /// situation the tool exists for.
    /// </remarks>
    [Fact]
    public void Bare_lf_line_endings_are_accepted()
    {
        HeaderAnalysis analysis = HeaderAnalyser.Analyse(
            "Received: from a.example.net ([203.0.113.10]) by mail.example.com; " +
            "Sat, 19 Sep 2026 11:00:00 +0000\n" +
            "From: alice@example.com\n",
            Now);

        analysis.Chain.Hops.ShouldHaveSingleItem();
        analysis.From.ShouldNotBeNull().Domain.ShouldBe("example.com");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void An_empty_paste_analyses_to_nothing(string? text)
    {
        HeaderAnalysis analysis = HeaderAnalyser.Analyse(text, Now);

        analysis.Chain.Hops.ShouldBeEmpty();
        analysis.From.ShouldBeNull();
        analysis.Observations.ShouldBeEmpty();
    }

    /// <summary>A paste larger than the bound is truncated rather than refused.</summary>
    [Fact]
    public void An_oversized_paste_is_bounded()
    {
        string huge = "From: alice@example.com\r\nX-Filler: " +
                      new string('a', HeaderAnalyser.MaxInputBytes * 2);

        HeaderAnalysis analysis = HeaderAnalyser.Analyse(huge, Now);

        analysis.From.ShouldNotBeNull().Domain.ShouldBe("example.com");
    }

    // ---------------------------------------------------------------------------------------
    // Observations.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A message with no trace header is worth pointing at.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §4.4 requires every SMTP server to add one, so a block with none either never
    /// travelled or has had its trace removed — and both are worth an operator knowing.
    /// </remarks>
    [Fact]
    public void No_trace_header_is_an_observation()
    {
        Has(Analyse("From: alice@example.com"), HeaderAnalyser.NoTraceId).ShouldBeTrue();
    }

    /// <summary>An ambiguous hop is surfaced from the chain into the observations.</summary>
    [Fact]
    public void An_ambiguous_hop_is_surfaced()
    {
        HeaderAnalysis analysis = Analyse(
            "Received: from evil.example by trusted.example.com with ESMTPS " +
            "([203.0.113.10]) by mail.example.com; Sat, 19 Sep 2026 11:00:00 +0000",
            "From: alice@example.com");

        Has(analysis, HeaderAnalyser.AmbiguousTraceId).ShouldBeTrue();
    }

    /// <summary>
    /// A negative delay is reported as a clock problem, which is what it is.
    /// </summary>
    /// <remarks>
    /// The chain reports the negative delay; this turns it into the sentence an operator can act
    /// on. Nothing else in a header block tells you a host's clock is wrong.
    /// </remarks>
    [Fact]
    public void A_negative_delay_is_reported_as_a_clock_problem()
    {
        HeaderAnalysis analysis = Analyse(
            "Received: from b.example.net ([198.51.100.7]) by second.example.com; " +
            "Sat, 19 Sep 2026 11:00:00 +0000",
            "Received: from a.example.net ([203.0.113.10]) by first.example.com; " +
            "Sat, 19 Sep 2026 11:00:30 +0000",
            "From: alice@example.com");

        Has(analysis, HeaderAnalyser.TraceClockSkewId).ShouldBeTrue();
    }

    /// <summary>A message with no signature is told it has none, and why that costs it.</summary>
    [Fact]
    public void No_dkim_signature_is_an_observation()
    {
        HeaderAnalysis analysis = Analyse("From: alice@example.com");

        Has(analysis, HeaderAnalyser.NoDkimId).ShouldBeTrue();

        analysis.Observations.Single(o => o.Id == HeaderAnalyser.NoDkimId)
            .Text.ShouldContain("forwarding");
    }

    /// <summary>
    /// An expired signature is reported against the instant passed in.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §3.5 makes a verifier treat an expired signature as a failure, so a signature
    /// whose <c>x=</c> has passed is a signature that is doing nothing.
    /// </remarks>
    [Fact]
    public void An_expired_signature_is_reported()
    {
        long expired = new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        HeaderAnalysis analysis = Analyse(
            "From: alice@example.com",
            $"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail2026; h=from; " +
            $"x={expired}; bh=YmFzZTY0; b=c2ln");

        Has(analysis, HeaderAnalyser.DkimExpiredId).ShouldBeTrue();
    }

    /// <summary>A signature still inside its window is not reported as expired.</summary>
    [Fact]
    public void A_signature_inside_its_window_is_not_expired()
    {
        long future = new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        HeaderAnalysis analysis = Analyse(
            "From: alice@example.com",
            $"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail2026; h=from; " +
            $"x={future}; bh=YmFzZTY0; b=c2ln");

        Has(analysis, HeaderAnalyser.DkimExpiredId).ShouldBeFalse();
    }

    /// <summary>
    /// A body-length limit is reported, because it bounds what the signature covers.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §8.2 warns that content appended past <c>l=</c> is unsigned and the signature
    /// still verifies — so a message can be modified after signing without breaking it.
    /// </remarks>
    [Fact]
    public void A_body_length_limit_is_reported()
    {
        HeaderAnalysis analysis = Analyse(
            "From: alice@example.com",
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail2026; h=from; l=100; " +
            "bh=YmFzZTY0; b=c2ln");

        Has(analysis, HeaderAnalyser.DkimBodyLengthId).ShouldBeTrue();
    }

    /// <summary>
    /// A signing domain that differs from From is reported without being called a failure.
    /// </summary>
    /// <remarks>
    /// Relaxed alignment matches on the organisational domain, which needs the public suffix
    /// list — not something a pure type has. So this half reports the difference and says so;
    /// calling it a DMARC failure is for the half that can look things up.
    /// </remarks>
    [Fact]
    public void A_differing_signing_domain_is_reported_but_not_judged()
    {
        HeaderAnalysis analysis = Analyse(
            "From: alice@example.com",
            "DKIM-Signature: v=1; a=rsa-sha256; d=mail.example.com; s=mail2026; h=from; " +
            "bh=YmFzZTY0; b=c2ln");

        Has(analysis, HeaderAnalyser.DkimDomainDiffersId).ShouldBeTrue();

        analysis.Observations.Single(o => o.Id == HeaderAnalyser.DkimDomainDiffersId)
            .Text.ShouldContain("may still align");
    }

    /// <summary>A signature from the From domain itself is not reported as differing.</summary>
    [Fact]
    public void A_matching_signing_domain_is_not_reported()
    {
        Has(Analyse("From: alice@example.com", GoodDkim), HeaderAnalyser.DkimDomainDiffersId)
            .ShouldBeFalse();
    }

    /// <summary>
    /// A Return-Path that differs from From is where SPF and DMARC part company.
    /// </summary>
    /// <remarks>
    /// SPF authorises the Return-Path domain; the recipient sees the From domain. A message
    /// whose two differ can pass SPF and still fail DMARC, which is the single most common
    /// surprise in a deliverability investigation.
    /// </remarks>
    [Fact]
    public void A_differing_return_path_is_reported()
    {
        HeaderAnalysis analysis = Analyse(
            "Return-Path: <bounces@sendgrid.example>",
            "From: alice@example.com");

        Has(analysis, HeaderAnalyser.ReturnPathDiffersId).ShouldBeTrue();
    }

    /// <summary>A matching Return-Path is not reported.</summary>
    [Fact]
    public void A_matching_return_path_is_not_reported()
    {
        HeaderAnalysis analysis = Analyse(
            "Return-Path: <alice@example.com>",
            "From: alice@example.com");

        Has(analysis, HeaderAnalyser.ReturnPathDiffersId).ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // One-click unsubscribe.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// One-click is signalled by the pair, with the exact value RFC 8058 §3.1 fixes.
    /// </summary>
    /// <remarks>
    /// §3.1: "The List-Unsubscribe-Post header MUST contain the single key/value pair
    /// 'List-Unsubscribe=One-Click'."
    /// </remarks>
    [Fact]
    public void One_click_needs_both_headers()
    {
        Analyse(
                "From: alice@example.com",
                "List-Unsubscribe: <https://example.com/u/abc>",
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click")
            .OneClickUnsubscribe.ShouldBeTrue();

        Analyse(
                "From: alice@example.com",
                "List-Unsubscribe: <https://example.com/u/abc>")
            .OneClickUnsubscribe.ShouldBeFalse();
    }

    /// <summary>
    /// The Post header's value is fixed, so anything else is not one-click.
    /// </summary>
    /// <remarks>
    /// RFC 8058 §3.1: "The List-Unsubscribe-Post header MUST contain the single key/value pair
    /// 'List-Unsubscribe=One-Click'." Accepting any value would make the analyser report a
    /// one-click button that no receiver will show, and then go on to complain that it is
    /// unsigned — two wrong findings from one loose comparison.
    /// </remarks>
    [Theory]
    [InlineData("List-Unsubscribe=One-Click", true)]
    [InlineData("list-unsubscribe=one-click", true)]
    [InlineData("List-Unsubscribe = One-Click", true)]
    [InlineData("List-Unsubscribe=Two-Click", false)]
    [InlineData("Something-Else=One-Click", false)]
    [InlineData("One-Click", false)]
    public void The_post_headers_value_is_fixed(string value, bool expected)
    {
        Analyse(
                "From: alice@example.com",
                "List-Unsubscribe: <https://example.com/u/abc>",
                $"List-Unsubscribe-Post: {value}")
            .OneClickUnsubscribe.ShouldBe(expected);
    }

    /// <summary>
    /// A signing domain differing only in case still matches.
    /// </summary>
    /// <remarks>
    /// DNS is case-insensitive and both halves of this comparison are normalised before it — the
    /// From domain here and <c>DomainName</c> for the <c>d=</c> tag. Asserting it end to end is
    /// what keeps a future change to either normalisation from quietly turning every
    /// mixed-case signature into a DMARC finding.
    /// </remarks>
    [Fact]
    public void A_signing_domain_differing_only_in_case_still_matches()
    {
        HeaderAnalysis analysis = Analyse(
            "From: Alice <alice@Example.COM>",
            "DKIM-Signature: v=1; a=rsa-sha256; d=EXAMPLE.com; s=mail2026; h=from; " +
            "bh=YmFzZTY0; b=c2ln");

        Has(analysis, HeaderAnalyser.DkimDomainDiffersId).ShouldBeFalse();
    }

    /// <summary>A Return-Path differing only in case is not a difference.</summary>
    [Fact]
    public void A_return_path_differing_only_in_case_still_matches()
    {
        HeaderAnalysis analysis = Analyse(
            "Return-Path: <bounce@EXAMPLE.com>",
            "From: alice@example.com");

        Has(analysis, HeaderAnalyser.ReturnPathDiffersId).ShouldBeFalse();
    }

    /// <summary>
    /// One-click without a signature covering both headers is the finding RFC 8058 §3.1 implies.
    /// </summary>
    /// <remarks>
    /// §3.1: "the message MUST have a valid DomainKeys Identified Mail (DKIM) signature that
    /// covers at least the List-Unsubscribe and List-Unsubscribe-Post headers." Whether it
    /// verifies needs the body; whether it claims to cover them is in the <c>h=</c> list, and a
    /// receiver enforcing the requirement will simply not show the button.
    /// </remarks>
    [Fact]
    public void One_click_unsigned_is_reported()
    {
        HeaderAnalysis analysis = Analyse(
            "From: alice@example.com",
            "List-Unsubscribe: <https://example.com/u/abc>",
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
            GoodDkim);

        Has(analysis, HeaderAnalyser.UnsignedOneClickId).ShouldBeTrue();
    }

    /// <summary>A signature covering both headers satisfies it.</summary>
    [Fact]
    public void One_click_covered_by_the_signature_is_not_reported()
    {
        HeaderAnalysis analysis = Analyse(
            "From: alice@example.com",
            "List-Unsubscribe: <https://example.com/u/abc>",
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail2026; " +
            "h=from:list-unsubscribe:list-unsubscribe-post; bh=YmFzZTY0; b=c2ln");

        Has(analysis, HeaderAnalyser.UnsignedOneClickId).ShouldBeFalse();
    }

    /// <summary>
    /// Covering only one of the two headers is not covering both.
    /// </summary>
    /// <remarks>
    /// The half-measure is the realistic mistake: a sender adds List-Unsubscribe to h= and
    /// forgets the -Post header, and the button silently never appears.
    /// </remarks>
    [Fact]
    public void Covering_only_one_unsubscribe_header_is_not_enough()
    {
        HeaderAnalysis analysis = Analyse(
            "From: alice@example.com",
            "List-Unsubscribe: <https://example.com/u/abc>",
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail2026; " +
            "h=from:list-unsubscribe; bh=YmFzZTY0; b=c2ln");

        Has(analysis, HeaderAnalyser.UnsignedOneClickId).ShouldBeTrue();
    }

    /// <summary>Without one-click offered at all, there is nothing to sign and nothing to say.</summary>
    [Fact]
    public void No_one_click_means_no_finding_about_it()
    {
        Has(Analyse("From: alice@example.com", GoodDkim), HeaderAnalyser.UnsignedOneClickId)
            .ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // The discipline.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A forged authentication header changes nothing the analyser reports.
    /// </summary>
    /// <remarks>
    /// The property the whole design exists for. A message asserting that some earlier hop
    /// authenticated it is a message making a claim, and an analyser that read it back would be
    /// presenting the forgery as its own finding. Here the same block analyses identically with
    /// and without it.
    /// </remarks>
    [Fact]
    public void A_forged_authentication_header_changes_nothing()
    {
        string[] honest =
        [
            "Received: from a.example.net ([203.0.113.10]) by mail.example.com; " +
            "Sat, 19 Sep 2026 11:00:00 +0000",
            "From: alice@example.com",
        ];

        HeaderAnalysis without = Analyse(honest);

        HeaderAnalysis with = Analyse(
        [
            "Authentication-Results: mx.example.com; dmarc=pass; spf=pass; dkim=pass",
            .. honest,
        ]);

        with.Observations.Select(o => o.Id).ShouldBe(without.Observations.Select(o => o.Id));
        with.Signatures.Count.ShouldBe(without.Signatures.Count);
        with.From.ShouldNotBeNull().Domain.ShouldBe(without.From.ShouldNotBeNull().Domain);

        // And the claim is nowhere in what the analyser says.
        with.Observations.ShouldNotContain(o => o.Text.Contains("dmarc=pass", StringComparison.Ordinal));
    }
}
