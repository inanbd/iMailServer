using System.Text;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;

namespace MailServer.Authentication.Tests;

public class DkimSignatureTagsBlankingTests
{
    private static RawHeaderField ParseDkimSignatureField(string wireValue)
    {
        byte[] buffer = Encoding.ASCII.GetBytes($"DKIM-Signature: {wireValue}\r\n\r\n");
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error).ShouldBeTrue(error);
        return headers!.Fields[0];
    }

    private static string BlankAndRead(string wireValue) =>
        Encoding.ASCII.GetString(DkimSignatureTags.BlankSignatureValue(ParseDkimSignatureField(wireValue)).RawBytes.Span);

    [Fact]
    public void Blanks_only_the_b_tags_value()
    {
        string result = BlankAndRead("v=1; a=rsa-sha256; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln");

        result.ShouldBe("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail; h=from; bh=YWJj; b=\r\n");
    }

    [Fact]
    public void Does_not_confuse_the_bh_tag_with_the_b_tag()
    {
        string result = BlankAndRead("bh=YWJj; b=c2ln");

        result.ShouldBe("DKIM-Signature: bh=YWJj; b=\r\n");
    }

    [Fact]
    public void Preserves_tag_order_when_b_appears_first()
    {
        string result = BlankAndRead("b=c2ln; bh=YWJj; d=example.com");

        result.ShouldBe("DKIM-Signature: b=; bh=YWJj; d=example.com\r\n");
    }

    [Fact]
    public void Preserves_whitespace_and_folding_around_other_tags()
    {
        byte[] buffer = Encoding.ASCII.GetBytes(
            "DKIM-Signature: v=1; d=example.com;\r\n s=mail; b=c2lnbmF0dXJl\r\n\r\n");
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out _).ShouldBeTrue();

        RawHeaderField blanked = DkimSignatureTags.BlankSignatureValue(headers!.Fields[0]);
        string result = Encoding.ASCII.GetString(blanked.RawBytes.Span);

        result.ShouldBe("DKIM-Signature: v=1; d=example.com;\r\n s=mail; b=\r\n");
    }

    [Fact]
    public void Tolerates_whitespace_around_the_b_tags_own_equals_sign()
    {
        string result = BlankAndRead("d=example.com; b = c2ln");

        result.ShouldBe("DKIM-Signature: d=example.com; b =\r\n");
    }

    [Fact]
    public void Result_still_parses_back_via_TryParse_style_scanning()
    {
        // Not literally re-run through TryParse (which requires a non-empty b=), but confirms
        // the blanked field remains well-formed: exactly one '=' after "b" and nothing after it
        // but the tag separator or end of value.
        string result = BlankAndRead("v=1; a=rsa-sha256; d=example.com; s=mail; h=from; bh=YWJj; b=c2ln; t=123");

        result.ShouldBe(
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail; h=from; bh=YWJj; b=; t=123\r\n");
    }
}
