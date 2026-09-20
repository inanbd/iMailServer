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

    // ---- TryParseTrailing -------------------------------------------------------------------

    /// <summary>
    /// The specifier that makes a line "a command so far" rather than a whole command.
    /// </summary>
    [Theory]
    [InlineData("a1 SELECT {5}", 5, true, 10)]
    [InlineData("a1 SELECT {5+}", 5, false, 10)]
    [InlineData("a1 LOGIN {17} {7}", 7, true, 14)]
    [InlineData("a1 APPEND INBOX (\\Seen) {310}", 310, true, 24)]
    public void Finds_a_trailing_specifier(string line, long bytes, bool synchronizing, int start)
    {
        ImapLiteralSpecifier.TryParseTrailing(line, out ImapLiteralSpecifier result, out int at)
            .ShouldBeTrue();

        result.ByteCount.ShouldBe(bytes);
        result.IsSynchronizing.ShouldBe(synchronizing);
        at.ShouldBe(start);
        line[at].ShouldBe('{');
    }

    /// <summary>
    /// A line that does not end in a specifier is a whole command, and reading one out of it
    /// would make the connection wait for octets the client is not going to send.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("a1 NOOP")]
    [InlineData("a1 SELECT INBOX")]
    [InlineData("a1 SELECT {5} ")]              // trailing space: the specifier is not last.
    [InlineData("a1 SELECT \"{5}\"")]            // quoted, so the braces are content.
    [InlineData("a1 SELECT weird}")]            // an atom may end in a closing brace.
    [InlineData("a1 SELECT {}")]
    [InlineData("a1 SELECT {-1}")]
    [InlineData("a1 SELECT {5x}")]
    public void Finds_no_trailing_specifier(string line)
    {
        ImapLiteralSpecifier.TryParseTrailing(line, out ImapLiteralSpecifier result, out int at)
            .ShouldBeFalse();

        result.ShouldBe(default);
        at.ShouldBe(-1);
    }

    /// <summary>
    /// The scan takes the <i>last</i> opening brace, so a quoted argument containing one does
    /// not capture the specifier that follows it.
    /// </summary>
    [Fact]
    public void Takes_the_last_opening_brace()
    {
        ImapLiteralSpecifier.TryParseTrailing(
            "a1 APPEND \"my{folder\" {42}",
            out ImapLiteralSpecifier result,
            out int at).ShouldBeTrue();

        result.ByteCount.ShouldBe(42L);
        at.ShouldBe(22);
    }
}
