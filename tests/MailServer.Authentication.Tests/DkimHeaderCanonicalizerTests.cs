using System.Text;
using MailServer.Domain.Mail;

namespace MailServer.Authentication.Tests;

public class DkimHeaderCanonicalizerTests
{
    private static RawHeaderField ParseOneField(string wireText)
    {
        byte[] buffer = Encoding.ASCII.GetBytes(wireText + "\r\n\r\n");
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error).ShouldBeTrue(error);
        return headers!.Fields[0];
    }

    private static string Canonicalize(string wireText) =>
        Encoding.ASCII.GetString(DkimHeaderCanonicalizer.Canonicalize(ParseOneField(wireText)));

    [Fact]
    public void Lowercases_the_field_name_but_not_the_value()
    {
        Canonicalize("Subject: Hello").ShouldBe("subject:Hello\r\n");
    }

    [Fact]
    public void Collapses_internal_whitespace_runs_to_a_single_space()
    {
        Canonicalize("Subject:   Hello   World  ").ShouldBe("subject:Hello World\r\n");
    }

    [Fact]
    public void Trims_whitespace_immediately_after_the_colon()
    {
        Canonicalize("Subject:    Hello").ShouldBe("subject:Hello\r\n");
    }

    [Fact]
    public void Trims_whitespace_immediately_before_the_colon()
    {
        Canonicalize("Subject   : Hello").ShouldBe("subject:Hello\r\n");
    }

    [Fact]
    public void Unfolds_a_continuation_line_and_collapses_the_fold_whitespace()
    {
        byte[] buffer = Encoding.ASCII.GetBytes("To: alice@example.com,\r\n bob@example.com\r\n\r\n");
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out _).ShouldBeTrue();

        string canonical = Encoding.ASCII.GetString(DkimHeaderCanonicalizer.Canonicalize(headers!.Fields[0]));

        canonical.ShouldBe("to:alice@example.com, bob@example.com\r\n");
    }

    [Fact]
    public void Tabs_count_as_whitespace_alongside_spaces()
    {
        Canonicalize("Subject:\tHello\tWorld\t").ShouldBe("subject:Hello World\r\n");
    }

    [Fact]
    public void An_empty_value_canonicalizes_to_just_the_colon()
    {
        Canonicalize("X-Empty:").ShouldBe("x-empty:\r\n");
    }
}
