using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.ValueObjects;

public sealed class DomainNameTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("EXAMPLE.COM", "example.com")]
    [InlineData("  Example.Com  ", "example.com")]
    [InlineData("example.com.", "example.com")]
    [InlineData("mail.example.co.uk", "mail.example.co.uk")]
    [InlineData("a-b.example.com", "a-b.example.com")]
    [InlineData("xn--bcher-kva.example", "xn--bcher-kva.example")]
    public void Parse_normalises_valid_names(string input, string expected) =>
        DomainName.Parse(input).Value.ShouldBe(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("localhost")]                       // single label: not a mail domain
    [InlineData("example..com")]                    // consecutive dots
    [InlineData("-example.com")]                    // label starts with a hyphen
    [InlineData("example-.com")]                    // label ends with a hyphen
    [InlineData("exa mple.com")]                    // space
    [InlineData("example.com/path")]                // not a name at all
    [InlineData("[203.0.113.10]")]                  // SMTP address literal
    [InlineData("203.0.113.10")]                    // numeric TLD: an IP, not a domain
    public void Parse_rejects_invalid_names(string? input) =>
        Should.Throw<InvalidValueObjectException>(() => DomainName.Parse(input));

    [Fact]
    public void Parse_rejects_a_label_longer_than_63_characters()
    {
        string tooLong = new('a', 64);
        Should.Throw<InvalidValueObjectException>(() => DomainName.Parse($"{tooLong}.com"));
    }

    [Fact]
    public void Parse_accepts_a_label_of_exactly_63_characters()
    {
        string atLimit = new('a', 63);
        DomainName.Parse($"{atLimit}.com").Labels[0].Length.ShouldBe(63);
    }

    [Fact]
    public void Parse_rejects_a_name_longer_than_253_characters()
    {
        // Four 63-character labels plus separators exceeds the 253-octet limit.
        string label = new('a', 63);
        string tooLong = string.Join('.', label, label, label, label);

        Should.Throw<InvalidValueObjectException>(() => DomainName.Parse(tooLong));
    }

    [Fact]
    public void Unicode_names_round_trip_through_punycode_without_corruption()
    {
        DomainName domain = DomainName.Parse("bücher.example");

        // The ASCII form goes on the wire and into DNS; the Unicode form is for display and
        // SMTPUTF8. Keeping both is how "never silently corrupt addresses" is honoured.
        domain.Value.ShouldBe("xn--bcher-kva.example");
        domain.UnicodeValue.ShouldBe("bücher.example");
        domain.IsInternationalized.ShouldBeTrue();
    }

    [Fact]
    public void An_ascii_name_and_its_unicode_form_compare_equal()
    {
        DomainName fromUnicode = DomainName.Parse("bücher.example");
        DomainName fromAscii = DomainName.Parse("xn--bcher-kva.example");

        fromUnicode.ShouldBe(fromAscii);
        fromUnicode.GetHashCode().ShouldBe(fromAscii.GetHashCode());
    }

    [Fact]
    public void A_plain_ascii_name_is_not_internationalized() =>
        DomainName.Parse("example.com").IsInternationalized.ShouldBeFalse();

    [Theory]
    [InlineData("mail.example.com", "example.com", true)]
    [InlineData("example.com", "example.com", true)]
    [InlineData("a.b.example.com", "example.com", true)]
    [InlineData("example.com", "mail.example.com", false)]
    [InlineData("other.com", "example.com", false)]
    public void IsSameOrSubdomainOf_matches_the_dns_hierarchy(string child, string parent, bool expected) =>
        DomainName.Parse(child).IsSameOrSubdomainOf(DomainName.Parse(parent)).ShouldBe(expected);

    [Fact]
    public void IsSameOrSubdomainOf_does_not_match_on_a_bare_suffix()
    {
        // The classic bug: "notexample.com".EndsWith("example.com") is true, and treating
        // that as a subdomain relationship would make DMARC relaxed alignment pass for an
        // attacker-registered lookalike domain.
        DomainName impostor = DomainName.Parse("notexample.com");
        DomainName legitimate = DomainName.Parse("example.com");

        impostor.IsSameOrSubdomainOf(legitimate).ShouldBeFalse();
    }

    [Fact]
    public void TryParse_reports_a_reason_rather_than_throwing()
    {
        bool parsed = DomainName.TryParse("localhost", out DomainName? result, out string? error);

        parsed.ShouldBeFalse();
        result.ShouldBeNull();
        error.ShouldNotBeNullOrWhiteSpace();
        error.ShouldContain("fully qualified");
    }

    [Fact]
    public void Comparison_is_ordinal_on_the_ascii_form()
    {
        DomainName a = DomainName.Parse("alpha.example");
        DomainName b = DomainName.Parse("beta.example");

        a.CompareTo(b).ShouldBeLessThan(0);
        b.CompareTo(a).ShouldBeGreaterThan(0);
        a.CompareTo(DomainName.Parse("ALPHA.EXAMPLE")).ShouldBe(0);
    }
}
