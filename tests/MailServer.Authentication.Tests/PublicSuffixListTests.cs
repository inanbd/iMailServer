using MailServer.Domain.ValueObjects;

namespace MailServer.Authentication.Tests;

public class PublicSuffixListTests
{
    private const string SampleList = """
        // VERSION: 2026-09-15_10-18-26_UTC
        // COMMIT: 3955e3ec29b94c3cca7bd4509c5f14a7c0959e26

        // ===BEGIN ICANN DOMAINS===

        // com
        com

        // uk
        uk
        *.uk
        *.sch.uk
        !bl.uk
        !british-library.uk

        // ck
        *.ck
        !www.ck

        // Google, Inc.
        github.io

        // Adobe : https://www.adobe.com
        *.dev.adobeaemcloud.com

        // China
        cn
        公司.cn
        网络.cn

        // ===END ICANN DOMAINS===
        """;

    private static readonly PublicSuffixList List = PublicSuffixList.Parse(SampleList);

    [Fact]
    public void Parses_the_snapshot_date_from_the_version_comment()
    {
        List.SnapshotDateUtc.ShouldBe(new DateTimeOffset(2026, 9, 15, 10, 18, 26, TimeSpan.Zero));
    }

    [Fact]
    public void Returns_null_snapshot_date_when_no_version_comment_is_present()
    {
        PublicSuffixList.Parse("com\nuk\n").SnapshotDateUtc.ShouldBeNull();
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("mail.example.com", "example.com")]
    [InlineData("a.b.c.example.com", "example.com")]
    public void Plain_rule_organizational_domain_is_the_registrable_label_plus_the_suffix(
        string input, string expected)
    {
        List.GetOrganizationalDomain(DomainName.Parse(input)).Value.ShouldBe(expected);
    }

    [Theory]
    [InlineData("example.co.uk", "example.co.uk")]
    [InlineData("www.example.co.uk", "example.co.uk")]
    public void Multi_label_wildcard_rule_extends_the_public_suffix(string input, string expected)
    {
        // *.uk means every direct child of uk is itself a public suffix (co.uk, org.uk, ...),
        // so the organizational domain needs one label beyond that, not beyond "uk" itself.
        List.GetOrganizationalDomain(DomainName.Parse(input)).Value.ShouldBe(expected);
    }

    [Fact]
    public void Exception_rule_shortens_the_public_suffix_by_one_label()
    {
        // *.uk would otherwise make "bl.uk" itself a public suffix; the exception says it isn't -
        // bl.uk is a registrable domain in its own right.
        List.GetOrganizationalDomain(DomainName.Parse("bl.uk")).Value.ShouldBe("bl.uk");
        List.GetOrganizationalDomain(DomainName.Parse("www.bl.uk")).Value.ShouldBe("bl.uk");
    }

    [Fact]
    public void Exception_rule_under_a_single_label_wildcard_shortens_by_one_label()
    {
        // *.ck implies every direct child of ck is a public suffix; !www.ck says www.ck is not.
        List.GetOrganizationalDomain(DomainName.Parse("www.ck")).Value.ShouldBe("www.ck");
        List.GetOrganizationalDomain(DomainName.Parse("a.www.ck")).Value.ShouldBe("www.ck");
    }

    [Fact]
    public void Single_label_wildcard_rule_makes_every_direct_child_a_public_suffix()
    {
        // *.ck with no matching exception: mycompany.ck is itself a public suffix, so the
        // organizational domain needs one more label.
        List.GetOrganizationalDomain(DomainName.Parse("example.mycompany.ck")).Value.ShouldBe("example.mycompany.ck");
    }

    [Theory]
    [InlineData("foo.github.io", "foo.github.io")]
    [InlineData("bar.foo.github.io", "foo.github.io")]
    public void Plain_rule_with_two_labels_is_a_whole_public_suffix(string input, string expected)
    {
        List.GetOrganizationalDomain(DomainName.Parse(input)).Value.ShouldBe(expected);
    }

    [Theory]
    [InlineData("tenant.dev.adobeaemcloud.com", "tenant.dev.adobeaemcloud.com")]
    [InlineData("www.tenant.dev.adobeaemcloud.com", "www.tenant.dev.adobeaemcloud.com")]
    [InlineData("a.www.tenant.dev.adobeaemcloud.com", "www.tenant.dev.adobeaemcloud.com")]
    public void Wildcard_rule_whose_concrete_part_spans_multiple_labels_matches_as_a_whole(
        string input, string expected)
    {
        // *.dev.adobeaemcloud.com makes "tenant" (any single label) a public suffix together
        // with the three labels after it, so the registrable label sits one further to the left
        // than a naive single-label wildcard reading would place it.
        List.GetOrganizationalDomain(DomainName.Parse(input)).Value.ShouldBe(expected);
    }

    [Fact]
    public void Unrecognized_tld_falls_back_to_the_implicit_star_rule()
    {
        // No rule at all matches "example.invalidtld" -> the single rightmost label is the
        // public suffix (the implicit "*" rule), so the organizational domain is one more label.
        List.GetOrganizationalDomain(DomainName.Parse("www.example.invalidtld")).Value.ShouldBe("example.invalidtld");
    }

    [Fact]
    public void Unicode_rule_lines_are_normalized_to_ascii_and_match_the_ascii_domain_form()
    {
        // "公司.cn" is itself a plain (2-label) public-suffix rule - like "github.io", the whole
        // thing is the suffix, so one label above it is the organizational domain.
        DomainName oneLabelUp = DomainName.Parse("www.公司.cn");
        List.GetOrganizationalDomain(oneLabelUp).Value.ShouldBe(oneLabelUp.Value);

        DomainName twoLabelsUp = DomainName.Parse("a.www.公司.cn");
        List.GetOrganizationalDomain(twoLabelsUp).Value.ShouldBe(oneLabelUp.Value);
    }

    [Fact]
    public void A_bare_public_suffix_is_returned_unchanged_for_lack_of_a_label_to_add()
    {
        // "co.uk" alone (both labels consumed by *.uk) has no label left for an organizational
        // domain to add - DomainName's own "at least 2 labels" rule keeps a single bare TLD like
        // "com" from ever reaching here at all.
        List.GetOrganizationalDomain(DomainName.Parse("co.uk")).Value.ShouldBe("co.uk");
    }
}
