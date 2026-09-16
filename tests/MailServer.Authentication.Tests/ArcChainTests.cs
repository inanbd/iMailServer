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
}
