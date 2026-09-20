using System.Text;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="ArcChain"/>'s structural parsing and grouping - RFC 8617 groundwork only, with no
/// cryptographic chain validation (see the type's own remarks).
/// </summary>
public class ArcChainTests
{
    private static RawMessageHeaders Headers(params string[] headerLines)
    {
        string text = string.Join("", headerLines.Select(l => l + "\r\n")) + "\r\n" + "Body.";
        byte[] buffer = Encoding.ASCII.GetBytes(text);
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error).ShouldBeTrue(error);
        return headers!;
    }

    private const string Seal1 = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=selector1; b=YWJjZA==";
    private const string Sig1 =
        "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to:subject; bh=YmFzZTY0; b=c2lnbmF0dXJl";
    private const string AuthRes1 = "ARC-Authentication-Results: i=1; mx.example.com; spf=pass smtp.mailfrom=example.com";

    private const string Seal2 = "ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=forwarder.example; s=selector2; b=ZWZnaA==";
    private const string Sig2 =
        "ARC-Message-Signature: i=2; a=rsa-sha256; d=forwarder.example; s=selector2; h=from:to; bh=Ym9keWhhc2g=; b=c2lnMg==";
    private const string AuthRes2 = "ARC-Authentication-Results: i=2; mx.forwarder.example; arc=pass";

    [Fact]
    public void No_arc_headers_at_all_is_well_formed_and_empty()
    {
        ArcChainParseResult result = ArcChain.Parse(Headers("From: alice@example.com", "To: bob@example.com"));

        result.IsWellFormed.ShouldBeTrue();
        result.Sets.ShouldBeEmpty();
    }

    [Fact]
    public void A_single_complete_instance_parses_into_one_well_formed_set()
    {
        ArcChainParseResult result = ArcChain.Parse(Headers(Seal1, Sig1, AuthRes1));

        result.IsWellFormed.ShouldBeTrue(result.Diagnostic);
        result.Sets.Count.ShouldBe(1);

        ArcSet set = result.Sets[0];
        set.Instance.ShouldBe(1);
        set.IsComplete.ShouldBeTrue();
        set.Seal!.ChainValidation.ShouldBe(ArcChainValidation.None);
        set.Seal.SigningDomain.Value.ShouldBe("example.com");
        set.MessageSignature!.SignedHeaderNames.ShouldBe(["from", "to", "subject"]);
        set.AuthenticationResults!.ResultsText.ShouldBe("mx.example.com; spf=pass smtp.mailfrom=example.com");
    }

    [Fact]
    public void Two_complete_instances_parse_in_order_and_are_well_formed()
    {
        ArcChainParseResult result = ArcChain.Parse(Headers(Seal1, Sig1, AuthRes1, Seal2, Sig2, AuthRes2));

        result.IsWellFormed.ShouldBeTrue(result.Diagnostic);
        result.Sets.Count.ShouldBe(2);
        result.Sets[0].Instance.ShouldBe(1);
        result.Sets[1].Instance.ShouldBe(2);
        result.Sets[1].Seal!.ChainValidation.ShouldBe(ArcChainValidation.Pass);
    }

    [Fact]
    public void A_gap_in_instance_numbers_is_not_well_formed()
    {
        // Instance 1 is entirely missing; only instance 2's headers are present.
        ArcChainParseResult result = ArcChain.Parse(Headers(Seal2, Sig2, AuthRes2));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull();
    }

    [Fact]
    public void An_instance_missing_one_of_its_three_headers_is_not_well_formed()
    {
        ArcChainParseResult result = ArcChain.Parse(Headers(Seal1, Sig1));

        result.IsWellFormed.ShouldBeFalse();
        result.Sets.Single().IsComplete.ShouldBeFalse();
    }

    [Fact]
    public void Instance_1_declaring_cv_other_than_none_is_not_well_formed()
    {
        const string badSeal1 = "ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=example.com; s=selector1; b=YWJjZA==";

        ArcChainParseResult result = ArcChain.Parse(Headers(badSeal1, Sig1, AuthRes1));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull();
        result.Diagnostic.ShouldContain("cv=none");
    }

    [Fact]
    public void An_instance_above_1_declaring_cv_none_is_not_well_formed()
    {
        const string badSeal2 = "ARC-Seal: i=2; a=rsa-sha256; cv=none; d=forwarder.example; s=selector2; b=ZWZnaA==";

        ArcChainParseResult result = ArcChain.Parse(Headers(Seal1, Sig1, AuthRes1, badSeal2, Sig2, AuthRes2));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull();
        result.Diagnostic.ShouldContain("only instance 1 may");
    }

    [Fact]
    public void Two_arc_seal_headers_for_the_same_instance_is_not_well_formed()
    {
        ArcChainParseResult result = ArcChain.Parse(Headers(Seal1, Seal1, Sig1, AuthRes1));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull();
        result.Diagnostic.ShouldContain("more than one");
    }

    [Fact]
    public void An_instance_number_above_50_is_rejected()
    {
        const string badSeal = "ARC-Seal: i=51; a=rsa-sha256; cv=none; d=example.com; s=selector1; b=YWJjZA==";

        ArcChainParseResult result = ArcChain.Parse(Headers(badSeal));

        result.IsWellFormed.ShouldBeFalse();
    }

    [Fact]
    public void A_seal_missing_a_required_tag_is_rejected()
    {
        const string incompleteSeal = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; b=YWJjZA==";

        ArcChainParseResult result = ArcChain.Parse(Headers(incompleteSeal, Sig1, AuthRes1));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull();
        result.Diagnostic.ShouldContain("malformed ARC-Seal");
    }

    [Fact]
    public void An_arc_authentication_results_header_without_a_leading_i_tag_is_rejected()
    {
        const string badAuthRes = "ARC-Authentication-Results: mx.example.com; spf=pass";

        ArcChainParseResult result = ArcChain.Parse(Headers(Seal1, Sig1, badAuthRes));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull();
        result.Diagnostic.ShouldContain("malformed ARC-Authentication-Results");
    }
    // ---------------------------------------------------------------------------------------
    // RFC 8617 §5.2 step 3C and §4.1.3 — structural rules that need no cryptography.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A seal declaring <c>cv=fail</c> is not a well-formed chain, at any instance.
    /// </summary>
    /// <remarks>
    /// RFC 8617 §5.2 step 3C: "The 'cv' value for all ARC-Seal header fields MUST NOT be 'fail'.
    /// For ARC Sets with instance values &gt; 1, the values MUST be 'pass'. For the ARC Set with
    /// instance value = 1, the value MUST be 'none'." §5.1.3 makes it terminal rather than
    /// advisory — "Once broken, the chain cannot be continued" — so a set declaring cv=fail
    /// describes a chain that is already over, and no structure below it changes that.
    /// </remarks>
    [Fact]
    public void A_seal_declaring_cv_fail_is_not_well_formed()
    {
        const string FailedSeal2 =
            "ARC-Seal: i=2; a=rsa-sha256; cv=fail; d=forwarder.example; s=selector2; b=ZWZnaA==";

        ArcChainParseResult result = ArcChain.Parse(
            Headers(Seal1, Sig1, AuthRes1, FailedSeal2, Sig2, AuthRes2));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull().ShouldContain("cv=fail");
    }

    /// <summary>
    /// The chain is over even when the failure is at the newest set.
    /// </summary>
    /// <remarks>
    /// The case that matters in practice: a forwarder that found the chain already broken seals
    /// with cv=fail to say so. Reporting the chain as well-formed because everything below it
    /// looks tidy would invert the one thing that seal was written to communicate.
    /// </remarks>
    [Fact]
    public void A_failure_at_the_newest_set_still_breaks_the_chain()
    {
        const string FailedSeal3 =
            "ARC-Seal: i=3; a=rsa-sha256; cv=fail; d=last.example; s=selector3; b=aGVsbG8=";
        const string Sig3 =
            "ARC-Message-Signature: i=3; a=rsa-sha256; d=last.example; s=selector3; h=from; bh=Ym9keQ==; b=c2lnMw==";
        const string AuthRes3 = "ARC-Authentication-Results: i=3; mx.last.example; arc=fail";

        ArcChainParseResult result = ArcChain.Parse(
            Headers(Seal1, Sig1, AuthRes1, Seal2, Sig2, AuthRes2, FailedSeal3, Sig3, AuthRes3));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull().ShouldContain("cv=fail");
    }

    /// <summary>
    /// An <c>ARC-Seal</c> carrying an <c>h=</c> tag is rejected.
    /// </summary>
    /// <remarks>
    /// RFC 8617 §4.1.3, listing the tags a seal may carry: "Note especially that the DKIM 'h' tag
    /// is NOT allowed and, if found, MUST result in a cv status of 'fail'". A seal is computed
    /// over the ARC headers themselves rather than over a chosen set of message headers, so an
    /// <c>h=</c> tag is not a stray extra — it is a claim about what was sealed that the seal
    /// cannot support.
    /// </remarks>
    [Fact]
    public void A_seal_carrying_an_h_tag_is_rejected()
    {
        const string SealWithH =
            "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=selector1; h=from:to; b=YWJjZA==";

        ArcChainParseResult result = ArcChain.Parse(Headers(SealWithH, Sig1, AuthRes1));

        result.IsWellFormed.ShouldBeFalse();
        result.Diagnostic.ShouldNotBeNull().ShouldContain("h=");
    }

    /// <summary>
    /// An <c>h=</c> tag is still required on an <c>ARC-Message-Signature</c>.
    /// </summary>
    /// <remarks>
    /// §4.1.2 gives the AMS "the same tag grammar as a DKIM-Signature", where <c>h=</c> is what
    /// names the signed headers. Rejecting it on both would make every real chain unparseable.
    /// </remarks>
    [Fact]
    public void An_h_tag_on_a_message_signature_is_still_required()
    {
        ArcChain.Parse(Headers(Seal1, Sig1, AuthRes1)).IsWellFormed.ShouldBeTrue();
    }

    /// <summary>A chain whose seals follow §5.2 step 3C exactly is well-formed.</summary>
    [Fact]
    public void A_chain_following_step_3c_is_well_formed()
    {
        ArcChain.Parse(Headers(Seal1, Sig1, AuthRes1, Seal2, Sig2, AuthRes2))
            .IsWellFormed.ShouldBeTrue();
    }

}
