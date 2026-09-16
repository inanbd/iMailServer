using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Authentication.Tests;

public class DkimSignatureTagsTests
{
    private static readonly DateTimeOffset SignedAt = new(2026, 9, 16, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CreateForSigning_always_uses_rsa_sha256_and_relaxed_relaxed()
    {
        DkimSignatureTags tags = DkimSignatureTags.CreateForSigning(
            DomainName.Parse("example.com"),
            DkimSelector.Parse("mail202609"),
            ["from", "from", "to", "subject", "date"],
            bodyHashBase64: "47DEQpj8HBSa+/TImW+5JCeuQeR",
            SignedAt);

        tags.Algorithm.ShouldBe(DkimKeyAlgorithm.RsaSha256);
        tags.HeaderCanonicalization.ShouldBe(DkimCanonicalizationMode.Relaxed);
        tags.BodyCanonicalization.ShouldBe(DkimCanonicalizationMode.Relaxed);
        tags.SignatureValueBase64.ShouldBe(string.Empty);
    }

    [Fact]
    public void Compose_then_TryParse_round_trips_every_tag()
    {
        DkimSignatureTags original = DkimSignatureTags
            .CreateForSigning(
                DomainName.Parse("example.com"),
                DkimSelector.Parse("mail202609"),
                ["from", "from", "to", "subject", "date"],
                bodyHashBase64: "47DEQpj8HBSa+/TImW+5JCeuQeR",
                SignedAt)
            .WithSignatureValue("cGxhY2Vob2xkZXItc2lnbmF0dXJl");

        DkimSignatureTags.TryParse(original.Compose(), out DkimSignatureTags? parsed, out string? error)
            .ShouldBeTrue(error);

        parsed!.Algorithm.ShouldBe(original.Algorithm);
        parsed.HeaderCanonicalization.ShouldBe(original.HeaderCanonicalization);
        parsed.BodyCanonicalization.ShouldBe(original.BodyCanonicalization);
        parsed.SigningDomain.ShouldBe(original.SigningDomain);
        parsed.Selector.ShouldBe(original.Selector);
        parsed.SignedHeaderNames.ShouldBe(original.SignedHeaderNames);
        parsed.BodyHashBase64.ShouldBe(original.BodyHashBase64);
        parsed.SignatureValueBase64.ShouldBe(original.SignatureValueBase64);
        parsed.SignedAtUtc.ShouldBe(original.SignedAtUtc);
    }

    [Fact]
    public void Oversigned_From_is_preserved_as_two_entries_not_deduplicated()
    {
        DkimSignatureTags tags = DkimSignatureTags.CreateForSigning(
            DomainName.Parse("example.com"),
            DkimSelector.Parse("mail202609"),
            ["from", "from", "subject"],
            bodyHashBase64: "abc",
            SignedAt).WithSignatureValue("c2ln");

        bool ok = DkimSignatureTags.TryParse(tags.Compose(), out DkimSignatureTags? parsed, out string? error);

        ok.ShouldBeTrue(error);
        parsed!.SignedHeaderNames.ShouldBe(["from", "from", "subject"]);
    }

    [Fact]
    public void TryParse_tolerates_folding_whitespace_inside_the_tag_list()
    {
        string folded = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail;\r\n" +
            " h=from:to; bh=YWJj; b=c2ln";

        bool ok = DkimSignatureTags.TryParse(folded, out DkimSignatureTags? parsed, out string? error);

        ok.ShouldBeTrue(error);
        parsed!.BodyHashBase64.ShouldBe("YWJj");
        parsed.SignatureValueBase64.ShouldBe("c2ln");
    }

    [Fact]
    public void TryParse_accepts_a_signature_this_product_cannot_yet_verify()
    {
        // simple/simple canonicalization and ed25519-sha256 are both real, RFC-legal values
        // this product does not implement - TryParse must still succeed so a message's other
        // signatures remain parseable, leaving the "unsupported" decision to the caller.
        string value = "v=1; a=ed25519-sha256; c=simple/simple; d=example.com; s=mail; " +
            "h=from; bh=YWJj; b=c2ln";

        bool ok = DkimSignatureTags.TryParse(value, out DkimSignatureTags? parsed, out string? error);

        ok.ShouldBeTrue(error);
        parsed!.Algorithm.ShouldBe(DkimKeyAlgorithm.Ed25519Sha256);
        parsed.HeaderCanonicalization.ShouldBe(DkimCanonicalizationMode.Simple);
        parsed.BodyCanonicalization.ShouldBe(DkimCanonicalizationMode.Simple);
    }

    [Fact]
    public void TryParse_defaults_missing_c_to_simple_simple_per_rfc()
    {
        string value = "v=1; a=rsa-sha256; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln";

        DkimSignatureTags.TryParse(value, out DkimSignatureTags? parsed, out string? error).ShouldBeTrue(error);

        parsed!.HeaderCanonicalization.ShouldBe(DkimCanonicalizationMode.Simple);
        parsed.BodyCanonicalization.ShouldBe(DkimCanonicalizationMode.Simple);
    }

    [Theory]
    [InlineData("a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln")] // missing v=
    [InlineData("v=1; c=relaxed/relaxed; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln")] // missing a=
    [InlineData("v=1; a=rsa-sha256; c=relaxed/relaxed; s=mail; h=from; bh=YWJj; b=c2ln")] // missing d=
    [InlineData("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; h=from; bh=YWJj; b=c2ln")] // missing s=
    [InlineData("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; bh=YWJj; b=c2ln")] // missing h=
    [InlineData("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; h=from; b=c2ln")] // missing bh=
    [InlineData("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; h=from; bh=YWJj")] // missing b=
    [InlineData("v=1; a=made-up; c=relaxed/relaxed; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln")] // unknown algorithm
    [InlineData("v=1; a=rsa-sha256; c=made-up/relaxed; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln")] // unknown canon
    [InlineData("")]
    public void TryParse_rejects_a_malformed_or_incomplete_tag_list(string value)
    {
        bool ok = DkimSignatureTags.TryParse(value, out DkimSignatureTags? parsed, out string? error);

        ok.ShouldBeFalse();
        parsed.ShouldBeNull();
        error.ShouldNotBeNull();
    }

    /// <summary>
    /// A crafted <c>t=</c>/<c>x=</c> so large it names no real <see cref="DateTimeOffset"/> must
    /// not throw out of <see cref="DkimSignatureTags.TryParse"/> - a single malformed signature
    /// on an inbound message must fail only that signature, never crash verification of the
    /// whole message.
    /// </summary>
    [Theory]
    [InlineData("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln; t=99999999999999")]
    [InlineData("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln; x=99999999999999")]
    [InlineData("v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln; t=-99999999999999")]
    public void TryParse_tolerates_an_out_of_range_timestamp_instead_of_throwing(string value)
    {
        bool ok = DkimSignatureTags.TryParse(value, out DkimSignatureTags? parsed, out string? error);

        ok.ShouldBeTrue(error);
        parsed!.SignedAtUtc.ShouldBeNull();
        parsed.ExpiresUtc.ShouldBeNull();
    }
}
