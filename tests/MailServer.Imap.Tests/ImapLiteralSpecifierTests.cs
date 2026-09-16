using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapLiteralSpecifierTests
{
    [Fact]
    public void Parses_a_synchronizing_literal()
    {
        ImapLiteralSpecifier.TryParse("{5}", out ImapLiteralSpecifier result).ShouldBeTrue();

        result.ByteCount.ShouldBe(5L);
        result.IsSynchronizing.ShouldBeTrue();
    }

    [Fact]
    public void Parses_a_non_synchronizing_literal_plus_literal()
    {
        ImapLiteralSpecifier.TryParse("{5+}", out ImapLiteralSpecifier result).ShouldBeTrue();

        result.ByteCount.ShouldBe(5L);
        result.IsSynchronizing.ShouldBeFalse();
    }

    [Fact]
    public void An_empty_literal_is_legal()
    {
        // RFC 3501's "number" is 1*DIGIT with no minimum value - {0} is a legal, meaningful
        // literal (an empty password, say), not a malformed one.
        ImapLiteralSpecifier.TryParse("{0}", out ImapLiteralSpecifier result).ShouldBeTrue();
        result.ByteCount.ShouldBe(0L);
    }

    [Fact]
    public void A_leading_zero_is_tolerated()
    {
        // Unlike seq-number's nz-number, RFC 3501's literal "number" has no leading-zero rule.
        ImapLiteralSpecifier.TryParse("{007}", out ImapLiteralSpecifier result).ShouldBeTrue();
        result.ByteCount.ShouldBe(7L);
    }

    [Fact]
    public void A_huge_byte_count_still_parses_the_specifier_itself()
    {
        // Parsing the specifier succeeds; whether this many bytes is ACCEPTABLE is a policy
        // decision for whatever configured limit reads them, not for this type - see the class
        // remarks. A value that does not even fit in a long is the one shape that must fail here.
        ImapLiteralSpecifier.TryParse("{4000000000+}", out ImapLiteralSpecifier result).ShouldBeTrue();
        result.ByteCount.ShouldBe(4_000_000_000L);
        result.IsSynchronizing.ShouldBeFalse();
    }

    [Theory]
    [InlineData("")]
    [InlineData("{}")]
    [InlineData("{+}")]
    [InlineData("5")]
    [InlineData("{5")]
    [InlineData("5}")]
    [InlineData("{-5}")]
    [InlineData("{+5}")]
    [InlineData("{5 }")]
    [InlineData("{ 5}")]
    [InlineData("{5++}")]
    [InlineData("{5.0}")]
    [InlineData("{99999999999999999999999999}")] // does not fit in a long.
    public void Rejects_malformed_input(string text)
    {
        ImapLiteralSpecifier.TryParse(text, out ImapLiteralSpecifier result).ShouldBeFalse();
        result.ShouldBe(default);
    }
}
