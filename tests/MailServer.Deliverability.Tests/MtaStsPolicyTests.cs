using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// The policy resource parser. RFC 8461 §3.2.
/// </summary>
/// <remarks>
/// Lives beside the deliverability checks rather than with the other value objects because it
/// exists only for them: nothing in the mail path reads another domain's MTA-STS policy yet.
/// </remarks>
public sealed class MtaStsPolicyTests
{
    private static MtaStsPolicy Parse(string text)
    {
        MtaStsPolicy.TryParse(text, out MtaStsPolicy? policy, out string? error)
            .ShouldBeTrue(error);

        return policy.ShouldNotBeNull();
    }

    private static string Reject(string text)
    {
        MtaStsPolicy.TryParse(text, out MtaStsPolicy? policy, out string? error).ShouldBeFalse();
        policy.ShouldBeNull();

        return error.ShouldNotBeNull();
    }

    /// <summary>RFC 8461 §3.2's own example policy parses to what it says.</summary>
    [Fact]
    public void The_rfcs_example_policy_parses()
    {
        MtaStsPolicy policy = Parse(
            "version: STSv1\r\n" +
            "mode: enforce\r\n" +
            "mx: mail.example.com\r\n" +
            "mx: *.example.net\r\n" +
            "mx: backupmx.example.com\r\n" +
            "max_age: 604800\r\n");

        policy.Mode.ShouldBe(MtaStsMode.Enforce);
        policy.MxPatterns.ShouldBe(["mail.example.com", "*.example.net", "backupmx.example.com"]);
        policy.MaxAgeSeconds.ShouldBe(604800);
    }

    [Theory]
    [InlineData("enforce", MtaStsMode.Enforce)]
    [InlineData("testing", MtaStsMode.Testing)]
    [InlineData("none", MtaStsMode.None)]
    [InlineData("ENFORCE", MtaStsMode.Enforce)]
    public void The_mode_is_read_without_regard_to_case(string text, MtaStsMode expected)
    {
        Parse($"version: STSv1\nmode: {text}\nmx: a.example.com\nmax_age: 604800")
            .Mode.ShouldBe(expected);
    }

    /// <summary>
    /// A policy with no <c>mx</c> is rejected, unless its mode is none.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.2's ABNF requires at least one <c>mx</c>, and a policy with none tells senders
    /// no host is permitted — which in enforce mode means the domain refuses its own mail. Mode
    /// none is the exception because §5 makes it the file a domain publishes to withdraw a
    /// policy senders have cached, and there is nothing left to deliver to.
    /// </remarks>
    [Fact]
    public void A_policy_with_no_mx_is_rejected_unless_its_mode_is_none()
    {
        Reject("version: STSv1\nmode: enforce\nmax_age: 604800").ShouldContain("mx");
        Reject("version: STSv1\nmode: testing\nmax_age: 604800").ShouldContain("mx");

        Parse("version: STSv1\nmode: none\nmax_age: 604800").MxPatterns.ShouldBeEmpty();
    }

    /// <summary>Every required field is required, and the error names which is missing.</summary>
    [Theory]
    [InlineData("mode: enforce\nmx: a.example.com\nmax_age: 604800", "version")]
    [InlineData("version: STSv1\nmx: a.example.com\nmax_age: 604800", "mode")]
    [InlineData("version: STSv1\nmode: enforce\nmx: a.example.com", "max_age")]
    public void A_missing_required_field_is_rejected_by_name(string text, string expected)
    {
        Reject(text).ShouldContain(expected);
    }

    /// <summary>
    /// The version must be exactly STSv1.
    /// </summary>
    /// <remarks>
    /// §3.2: "Currently, only 'STSv1' is supported." A parser that accepted another version would
    /// be reading a format it does not know by rules that may no longer apply.
    /// </remarks>
    [Theory]
    [InlineData("STSv2")]
    [InlineData("stsv1")]
    [InlineData("STSv10")]
    public void An_unsupported_version_is_rejected(string version)
    {
        Reject($"version: {version}\nmode: enforce\nmx: a.example.com\nmax_age: 604800");
    }

    /// <summary>
    /// LF-only line endings are accepted although §3.2 says CRLF.
    /// </summary>
    /// <remarks>
    /// A policy file edited on a Unix host is LF-separated about half the time, and the senders
    /// that matter accept it. Rejecting those would report a working domain's policy as
    /// malformed — a finding that is both wrong and unfixable, since the operator would look at
    /// a file that reads correctly.
    /// </remarks>
    [Fact]
    public void Lf_only_line_endings_are_accepted()
    {
        Parse("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800")
            .MxPatterns.ShouldBe(["mail.example.com"]);
    }

    /// <summary>
    /// An unknown key is ignored rather than fatal.
    /// </summary>
    /// <remarks>
    /// §3.2's ABNF carries an <c>sts-policy-extension</c> production precisely so a later
    /// revision can add a field. A parser that rejected unknown keys would break on the first
    /// domain to adopt one.
    /// </remarks>
    [Fact]
    public void An_unknown_key_is_ignored()
    {
        Parse("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 604800\nfuture: yes")
            .Mode.ShouldBe(MtaStsMode.Enforce);
    }

    /// <summary>A line that is not a key/value pair is fatal, since the file is a list of them.</summary>
    [Fact]
    public void A_line_that_is_not_a_pair_is_rejected()
    {
        Reject("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 604800\nnonsense");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void An_empty_policy_is_rejected(string text) => Reject(text);

    [Fact]
    public void A_null_policy_is_rejected()
    {
        MtaStsPolicy.TryParse(null, out MtaStsPolicy? policy, out string? error).ShouldBeFalse();
        policy.ShouldBeNull();
        error.ShouldNotBeNull();
    }

    /// <summary>A non-numeric or negative max_age is rejected; §3.2 makes it a non-negative integer.</summary>
    [Theory]
    [InlineData("soon")]
    [InlineData("-1")]
    [InlineData("1.5")]
    public void A_max_age_that_is_not_a_non_negative_integer_is_rejected(string value)
    {
        Reject($"version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: {value}");
    }

    // ---------------------------------------------------------------------------------------
    // Coverage.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The wildcard replaces exactly the left-most label.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §4.1: "the wildcard character '*' may only be used to match the entire left-most
    /// label in the presented identifier. Thus, the mx pattern '*.example.com' matches
    /// 'mail.example.com' but not 'example.com' or 'foo.bar.example.com'." Each of the three is
    /// asserted here, because the RFC bothered to name all three.
    /// </remarks>
    [Theory]
    [InlineData("mail.example.com", true)]
    [InlineData("example.com", false)]
    [InlineData("foo.bar.example.com", false)]
    [InlineData("MAIL.EXAMPLE.COM", true)]
    [InlineData("mail.example.com.", true)]
    [InlineData("notexample.com", false)]
    public void A_wildcard_pattern_matches_one_label(string host, bool expected)
    {
        Parse("version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800")
            .Covers(host).ShouldBe(expected);
    }

    /// <summary>A fully specified pattern matches that name and nothing under it.</summary>
    [Theory]
    [InlineData("mail.example.com", true)]
    [InlineData("Mail.Example.Com", true)]
    [InlineData("sub.mail.example.com", false)]
    [InlineData("example.com", false)]
    public void A_literal_pattern_matches_that_name(string host, bool expected)
    {
        Parse("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800")
            .Covers(host).ShouldBe(expected);
    }

    /// <summary>Any one pattern matching is enough.</summary>
    [Fact]
    public void Any_one_pattern_matching_is_enough()
    {
        MtaStsPolicy policy = Parse(
            "version: STSv1\nmode: enforce\nmx: a.example.com\nmx: b.example.com\nmax_age: 604800");

        policy.Covers("b.example.com").ShouldBeTrue();
        policy.Covers("c.example.com").ShouldBeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Nothing_is_not_covered(string? host)
    {
        Parse("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 604800")
            .Covers(host).ShouldBeFalse();
    }
}
