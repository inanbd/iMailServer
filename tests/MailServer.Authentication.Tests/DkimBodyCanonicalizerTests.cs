using System.Security.Cryptography;
using System.Text;
using MailServer.Domain.Mail;

namespace MailServer.Authentication.Tests;

public class DkimBodyCanonicalizerTests
{
    /// <summary>
    /// Runs the canonicalizer over <paramref name="input"/>, split into single-byte
    /// <see cref="DkimBodyCanonicalizer.Append"/> calls, so every test also exercises state
    /// carried across chunk boundaries (a split CRLF, a split whitespace run, a blank line that
    /// spans two calls).
    /// </summary>
    private static byte[] CanonicalHash(string input)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var canonicalizer = new DkimBodyCanonicalizer(hash);

        foreach (byte b in Encoding.ASCII.GetBytes(input))
        {
            canonicalizer.Append([b]);
        }

        canonicalizer.Finish();
        return hash.GetHashAndReset();
    }

    private static byte[] ExpectedHash(string canonicalForm) =>
        SHA256.HashData(Encoding.ASCII.GetBytes(canonicalForm));

    private static void AssertCanonicalizesTo(string input, string expectedCanonicalForm)
    {
        CanonicalHash(input).ShouldBe(ExpectedHash(expectedCanonicalForm));
    }

    [Fact]
    public void A_completely_empty_body_canonicalizes_to_a_single_crlf()
    {
        AssertCanonicalizesTo("", "\r\n");
    }

    [Fact]
    public void A_body_of_only_blank_lines_canonicalizes_to_a_single_crlf()
    {
        AssertCanonicalizesTo("\r\n\r\n\r\n", "\r\n");
    }

    [Fact]
    public void Trailing_blank_lines_are_removed()
    {
        AssertCanonicalizesTo("Hello\r\n\r\n\r\n", "Hello\r\n");
    }

    [Fact]
    public void A_non_empty_body_missing_its_final_crlf_gets_one_added()
    {
        AssertCanonicalizesTo("Hello", "Hello\r\n");
    }

    [Fact]
    public void Internal_whitespace_runs_collapse_and_trailing_line_whitespace_is_dropped()
    {
        AssertCanonicalizesTo("Hello   World  \r\n", "Hello World\r\n");
    }

    [Fact]
    public void A_blank_line_in_the_middle_is_preserved_because_it_is_not_trailing()
    {
        AssertCanonicalizesTo("A\r\n\r\nB\r\n", "A\r\n\r\nB\r\n");
    }

    [Fact]
    public void Tabs_collapse_the_same_as_spaces()
    {
        AssertCanonicalizesTo("A\t\tB\r\n", "A B\r\n");
    }

    [Fact]
    public void A_large_run_of_trailing_blank_lines_is_still_removed()
    {
        string manyBlankLines = string.Concat(Enumerable.Repeat("\r\n", 10_000));
        AssertCanonicalizesTo("Content\r\n" + manyBlankLines, "Content\r\n");
    }

    [Fact]
    public void Feeding_the_whole_input_in_one_call_matches_feeding_it_byte_by_byte()
    {
        const string input = "A  \r\n\r\nB\t\r\n\r\n\r\n";

        using IncrementalHash wholeHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var wholeCanonicalizer = new DkimBodyCanonicalizer(wholeHash);
        wholeCanonicalizer.Append(Encoding.ASCII.GetBytes(input));
        wholeCanonicalizer.Finish();

        wholeHash.GetHashAndReset().ShouldBe(CanonicalHash(input));
    }
}
