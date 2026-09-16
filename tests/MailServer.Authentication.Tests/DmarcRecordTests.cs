using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Authentication.Tests;

public class DmarcRecordTests
{
    [Fact]
    public void Rejects_a_record_not_starting_with_v_equals_DMARC1()
    {
        DmarcRecord.TryParse("p=reject", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Rejects_a_lowercase_dmarc1_version_value()
    {
        // RFC 7489's ABNF spells the literal in uppercase; a lowercase "dmarc1" is a different,
        // unrecognised version.
        DmarcRecord.TryParse("v=dmarc1; p=reject", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Requires_a_p_tag()
    {
        DmarcRecord.TryParse("v=DMARC1; pct=50", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Theory]
    [InlineData("none", DmarcPolicy.None)]
    [InlineData("quarantine", DmarcPolicy.Quarantine)]
    [InlineData("reject", DmarcPolicy.Reject)]
    [InlineData("REJECT", DmarcPolicy.Reject)]
    public void Parses_every_policy_value(string value, DmarcPolicy expected)
    {
        DmarcRecord.TryParse($"v=DMARC1; p={value}", out DmarcRecord? record, out string? error).ShouldBeTrue(error);
        record!.Policy.ShouldBe(expected);
    }

    [Fact]
    public void Rejects_an_unrecognized_policy_value()
    {
        DmarcRecord.TryParse("v=DMARC1; p=drop", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Subdomain_policy_falls_back_to_the_domain_policy_when_absent()
    {
        DmarcRecord.TryParse("v=DMARC1; p=reject", out DmarcRecord? record, out string? error).ShouldBeTrue(error);
        record!.SubdomainPolicy.ShouldBe(DmarcPolicy.Reject);
    }

    [Fact]
    public void Subdomain_policy_uses_its_own_tag_when_present()
    {
        DmarcRecord.TryParse("v=DMARC1; p=reject; sp=none", out DmarcRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.Policy.ShouldBe(DmarcPolicy.Reject);
        record.SubdomainPolicy.ShouldBe(DmarcPolicy.None);
    }

    [Fact]
    public void Percentage_defaults_to_100()
    {
        DmarcRecord.TryParse("v=DMARC1; p=reject", out DmarcRecord? record, out string? error).ShouldBeTrue(error);
        record!.Percentage.ShouldBe(100);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("50")]
    [InlineData("100")]
    public void Parses_a_valid_percentage(string value)
    {
        DmarcRecord.TryParse($"v=DMARC1; p=reject; pct={value}", out DmarcRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.Percentage.ShouldBe(int.Parse(value));
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("101")]
    [InlineData("abc")]
    public void Rejects_an_out_of_range_or_non_numeric_percentage(string value)
    {
        DmarcRecord.TryParse($"v=DMARC1; p=reject; pct={value}", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Alignment_modes_default_to_relaxed()
    {
        DmarcRecord.TryParse("v=DMARC1; p=reject", out DmarcRecord? record, out string? error).ShouldBeTrue(error);
        record!.DkimAlignment.ShouldBe(AlignmentMode.Relaxed);
        record.SpfAlignment.ShouldBe(AlignmentMode.Relaxed);
    }

    [Theory]
    [InlineData("r", AlignmentMode.Relaxed)]
    [InlineData("s", AlignmentMode.Strict)]
    public void Parses_adkim_and_aspf(string value, AlignmentMode expected)
    {
        DmarcRecord.TryParse($"v=DMARC1; p=reject; adkim={value}; aspf={value}", out DmarcRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.DkimAlignment.ShouldBe(expected);
        record.SpfAlignment.ShouldBe(expected);
    }

    [Fact]
    public void Rejects_an_invalid_alignment_mode()
    {
        DmarcRecord.TryParse("v=DMARC1; p=reject; adkim=relaxed", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Ignores_unrecognized_tags_such_as_rua_and_ruf()
    {
        DmarcRecord.TryParse(
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; fo=1",
            out DmarcRecord? record, out string? error).ShouldBeTrue(error);

        record!.Policy.ShouldBe(DmarcPolicy.Quarantine);
    }

    [Fact]
    public void Tolerates_whitespace_around_tags_and_a_trailing_semicolon()
    {
        DmarcRecord.TryParse(
            "v=DMARC1;  p = reject ; pct = 50 ;",
            out DmarcRecord? record, out string? error).ShouldBeTrue(error);

        record!.Policy.ShouldBe(DmarcPolicy.Reject);
        record.Percentage.ShouldBe(50);
    }

    [Fact]
    public void Rejects_an_empty_record()
    {
        DmarcRecord.TryParse("", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Rejects_a_malformed_tag_spec()
    {
        DmarcRecord.TryParse("v=DMARC1; p=reject; =nope", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Parses_the_full_example_record_from_the_dmarc_documentation()
    {
        DmarcRecord.TryParse(
            "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
            out DmarcRecord? record, out string? error).ShouldBeTrue(error);

        record!.Policy.ShouldBe(DmarcPolicy.None);
        record.SubdomainPolicy.ShouldBe(DmarcPolicy.None);
        record.Percentage.ShouldBe(100);
    }
}
