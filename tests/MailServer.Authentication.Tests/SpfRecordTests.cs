using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Authentication.Tests;

public class SpfRecordTests
{
    [Fact]
    public void Rejects_a_record_not_starting_with_v_equals_spf1()
    {
        SpfRecord.TryParse("spf1 -all", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Theory]
    [InlineData("V=SPF1 -all")]
    [InlineData("v=SPF1 -all")]
    [InlineData("V=spf1 -all")]
    public void Accepts_the_version_literal_case_insensitively(string record)
    {
        // RFC 7208 section 4.5's ABNF spells "v=spf1" as a plain quoted string, which RFC 5234
        // section 2.3 makes case-insensitive absent an explicit %s prefix.
        SpfRecord.TryParse(record, out SpfRecord? parsed, out string? error).ShouldBeTrue(error);
        parsed!.Directives.Count.ShouldBe(1);
    }

    [Fact]
    public void Parses_a_bare_all_mechanism_with_default_pass_qualifier()
    {
        SpfRecord.TryParse("v=spf1 all", out SpfRecord? record, out string? error).ShouldBeTrue(error);

        record!.Directives.Count.ShouldBe(1);
        record.Directives[0].Mechanism.ShouldBe(SpfMechanismType.All);
        record.Directives[0].Qualifier.ShouldBe(SpfQualifier.Pass);
    }

    [Theory]
    [InlineData("+all", SpfQualifier.Pass)]
    [InlineData("-all", SpfQualifier.Fail)]
    [InlineData("~all", SpfQualifier.SoftFail)]
    [InlineData("?all", SpfQualifier.Neutral)]
    public void Parses_every_qualifier(string term, SpfQualifier expected)
    {
        SpfRecord.TryParse($"v=spf1 {term}", out SpfRecord? record, out string? error).ShouldBeTrue(error);
        record!.Directives[0].Qualifier.ShouldBe(expected);
    }

    [Fact]
    public void Rejects_all_with_a_value()
    {
        SpfRecord.TryParse("v=spf1 all:example.com", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Parses_mx_with_no_domain_spec_and_no_cidr()
    {
        SpfRecord.TryParse("v=spf1 mx -all", out SpfRecord? record, out string? error).ShouldBeTrue(error);

        SpfDirective mx = record!.Directives[0];
        mx.Mechanism.ShouldBe(SpfMechanismType.Mx);
        mx.DomainSpec.ShouldBeNull();
        mx.Ip4PrefixLength.ShouldBeNull();
        mx.Ip6PrefixLength.ShouldBeNull();
    }

    [Fact]
    public void Parses_a_with_domain_spec_and_ipv4_cidr()
    {
        SpfRecord.TryParse("v=spf1 a:mail.example.com/24 -all", out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        SpfDirective a = record!.Directives[0];
        a.Mechanism.ShouldBe(SpfMechanismType.A);
        a.DomainSpec.ShouldBe("mail.example.com");
        a.Ip4PrefixLength.ShouldBe(24);
        a.Ip6PrefixLength.ShouldBeNull();
    }

    [Fact]
    public void Parses_mx_with_dual_cidr_both_families()
    {
        SpfRecord.TryParse("v=spf1 mx/24/64 -all", out SpfRecord? record, out string? error).ShouldBeTrue(error);

        SpfDirective mx = record!.Directives[0];
        mx.Ip4PrefixLength.ShouldBe(24);
        mx.Ip6PrefixLength.ShouldBe(64);
    }

    [Fact]
    public void Parses_mx_with_ipv6_only_dual_cidr()
    {
        SpfRecord.TryParse("v=spf1 mx//64 -all", out SpfRecord? record, out string? error).ShouldBeTrue(error);

        SpfDirective mx = record!.Directives[0];
        mx.Ip4PrefixLength.ShouldBeNull();
        mx.Ip6PrefixLength.ShouldBe(64);
    }

    [Fact]
    public void Parses_ip4_with_explicit_cidr()
    {
        SpfRecord.TryParse("v=spf1 ip4:203.0.113.0/24 -all", out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        SpfDirective ip4 = record!.Directives[0];
        ip4.Mechanism.ShouldBe(SpfMechanismType.Ip4);
        ip4.IpNetwork!.Value.ShouldBe("203.0.113.0");
        ip4.Ip4PrefixLength.ShouldBe(24);
    }

    [Fact]
    public void Ip4_without_a_cidr_defaults_to_slash_32()
    {
        SpfRecord.TryParse("v=spf1 ip4:203.0.113.10 -all", out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.Directives[0].Ip4PrefixLength.ShouldBe(32);
    }

    [Fact]
    public void Ip6_without_a_cidr_defaults_to_slash_128()
    {
        SpfRecord.TryParse("v=spf1 ip6:2001:db8::1 -all", out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.Directives[0].Ip6PrefixLength.ShouldBe(128);
    }

    [Fact]
    public void Rejects_ip4_value_that_is_actually_an_ipv6_address()
    {
        SpfRecord.TryParse("v=spf1 ip4:2001:db8::1 -all", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Parses_include_and_exists_domain_specs()
    {
        SpfRecord.TryParse("v=spf1 include:_spf.provider.example exists:%{i}.example.com -all",
                out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.Directives[0].Mechanism.ShouldBe(SpfMechanismType.Include);
        record.Directives[0].DomainSpec.ShouldBe("_spf.provider.example");
        record.Directives[0].UsesMacros.ShouldBeFalse();

        record.Directives[1].Mechanism.ShouldBe(SpfMechanismType.Exists);
        record.Directives[1].DomainSpec.ShouldBe("%{i}.example.com");
        record.Directives[1].UsesMacros.ShouldBeTrue();
    }

    [Fact]
    public void Rejects_include_with_no_domain_spec()
    {
        SpfRecord.TryParse("v=spf1 include -all", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void Parses_bare_ptr_and_ptr_with_domain_spec()
    {
        SpfRecord.TryParse("v=spf1 ptr ptr:example.com -all", out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.Directives[0].DomainSpec.ShouldBeNull();
        record.Directives[1].DomainSpec.ShouldBe("example.com");
    }

    [Fact]
    public void Parses_redirect_modifier()
    {
        SpfRecord.TryParse("v=spf1 redirect=_spf.example.com", out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.RedirectDomain.ShouldBe("_spf.example.com");
        record.RedirectUsesMacros.ShouldBeFalse();
    }

    [Fact]
    public void Rejects_a_second_redirect_modifier()
    {
        SpfRecord.TryParse("v=spf1 redirect=a.example redirect=b.example", out _, out string? error)
            .ShouldBeFalse();

        error.ShouldNotBeNull();
    }

    [Fact]
    public void Ignores_exp_and_other_unrecognised_modifiers()
    {
        SpfRecord.TryParse("v=spf1 exp=explain.example.com unknown-modifier=value -all",
                out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.Directives.Count.ShouldBe(1);
        record.Directives[0].Mechanism.ShouldBe(SpfMechanismType.All);
    }

    [Fact]
    public void Rejects_an_unrecognised_mechanism_keyword()
    {
        SpfRecord.TryParse("v=spf1 bogus -all", out _, out string? error).ShouldBeFalse();
        error.ShouldNotBeNull();
    }

    [Fact]
    public void A_realistic_multi_mechanism_record_parses_completely()
    {
        SpfRecord.TryParse(
                "v=spf1 mx a:mail.example.com ip4:203.0.113.0/24 include:_spf.provider.example ~all",
                out SpfRecord? record, out string? error)
            .ShouldBeTrue(error);

        record!.Directives.Count.ShouldBe(5);
        record.Directives.Select(d => d.Mechanism).ShouldBe(
        [
            SpfMechanismType.Mx,
            SpfMechanismType.A,
            SpfMechanismType.Ip4,
            SpfMechanismType.Include,
            SpfMechanismType.All,
        ]);
    }
}
