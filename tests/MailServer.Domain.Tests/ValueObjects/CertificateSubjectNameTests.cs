using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.ValueObjects;

/// <summary>
/// subjectAltName entries and the RFC 6125 §6.4.3 matching rules.
/// </summary>
/// <remarks>
/// Every permissive mistake here is a security-relevant one: it makes the server claim a
/// hostname is covered when connecting clients will reject it. The tests are therefore
/// weighted towards what must NOT match.
/// </remarks>
public sealed class CertificateSubjectNameTests
{
    [Theory]
    [InlineData("mail.example.com")]
    [InlineData("example.com")]
    [InlineData("a.b.c.example.com")]
    public void An_exact_hostname_parses(string input)
    {
        CertificateSubjectName name = CertificateSubjectName.Parse(input);

        name.IsWildcard.ShouldBeFalse();
        name.Value.ShouldBe(input);
    }

    [Fact]
    public void A_wildcard_parses_and_records_its_parent()
    {
        CertificateSubjectName name = CertificateSubjectName.Parse("*.example.com");

        name.IsWildcard.ShouldBeTrue();
        name.Value.ShouldBe("*.example.com");
        name.BaseName.Value.ShouldBe("example.com");
    }

    [Fact]
    public void An_internationalized_name_is_stored_in_ascii_form()
    {
        CertificateSubjectName name = CertificateSubjectName.Parse("*.bücher.example");

        name.Value.ShouldBe("*.xn--bcher-kva.example");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a hostname")]
    [InlineData("m*.example.com")]      // partial-label wildcard
    [InlineData("*mail.example.com")]   // no separating dot
    [InlineData("*.*.example.com")]     // two wildcards
    [InlineData("*.com")]               // a whole TLD
    [InlineData("*")]
    public void An_unusable_entry_is_refused(string input)
    {
        CertificateSubjectName.TryParse(input, out _).ShouldBeFalse();
        Should.Throw<InvalidValueObjectException>(() => CertificateSubjectName.Parse(input));
    }

    [Fact]
    public void An_exact_entry_matches_only_itself()
    {
        CertificateSubjectName name = CertificateSubjectName.Parse("mail.example.com");

        name.Matches(DomainName.Parse("mail.example.com")).ShouldBeTrue();
        name.Matches(DomainName.Parse("imap.example.com")).ShouldBeFalse();
        name.Matches(DomainName.Parse("example.com")).ShouldBeFalse();
        name.Matches(DomainName.Parse("a.mail.example.com")).ShouldBeFalse();
    }

    [Theory]
    [InlineData("mail.example.com", true)]
    [InlineData("imap.example.com", true)]
    [InlineData("example.com", false)]        // a wildcard does not match the bare parent
    [InlineData("a.b.example.com", false)]    // it replaces exactly one label
    [InlineData("mail.example.org", false)]
    [InlineData("mail.notexample.com", false)]
    [InlineData("mail.example.com.evil.test", false)]
    public void A_wildcard_replaces_exactly_one_label(string candidate, bool expected)
    {
        CertificateSubjectName name = CertificateSubjectName.Parse("*.example.com");

        name.Matches(DomainName.Parse(candidate)).ShouldBe(expected);
    }

    /// <summary>
    /// A suffix comparison would accept this; label-wise comparison does not. The candidate
    /// ends with the parent's text but its labels do not line up.
    /// </summary>
    [Fact]
    public void A_suffix_that_is_not_a_label_boundary_does_not_match()
    {
        CertificateSubjectName name = CertificateSubjectName.Parse("*.example.com");

        name.Matches(DomainName.Parse("evilexample.com")).ShouldBeFalse();
    }

    [Fact]
    public void Entries_compare_by_value()
    {
        CertificateSubjectName.Parse("*.example.com")
            .ShouldBe(CertificateSubjectName.Parse("*.EXAMPLE.com"));

        CertificateSubjectName.Parse("mail.example.com")
            .ShouldNotBe(CertificateSubjectName.Parse("*.example.com"));
    }

    [Fact]
    public void A_hostname_converts_to_an_exact_entry()
    {
        CertificateSubjectName name =
            CertificateSubjectName.FromHostname(DomainName.Parse("mail.example.com"));

        name.IsWildcard.ShouldBeFalse();
        name.Matches(DomainName.Parse("mail.example.com")).ShouldBeTrue();
    }
}
