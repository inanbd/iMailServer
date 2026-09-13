using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.ValueObjects;

public sealed class EmailAddressTests
{
    [Theory]
    [InlineData("user@example.com", "user", "example.com")]
    [InlineData("<user@example.com>", "user", "example.com")]
    [InlineData("  user@example.com  ", "user", "example.com")]
    [InlineData("first.last@example.com", "first.last", "example.com")]
    [InlineData("user+tag@example.com", "user+tag", "example.com")]
    [InlineData("user_name@example.com", "user_name", "example.com")]
    public void Parse_accepts_valid_addresses(string input, string localPart, string domain)
    {
        EmailAddress address = EmailAddress.Parse(input);

        address.LocalPart.ShouldBe(localPart);
        address.Domain.Value.ShouldBe(domain);
    }

    [Fact]
    public void Parse_accepts_the_full_atext_character_set()
    {
        // RFC 5322 "atext". These are legal unquoted and do appear in real addresses,
        // particularly the plus and hyphen forms used for tagging.
        EmailAddress address = EmailAddress.Parse("a!#$%&'*+-/=?^_`{|}~b@example.com");

        address.LocalPart.ShouldBe("a!#$%&'*+-/=?^_`{|}~b");
        address.IsQuoted.ShouldBeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("no-at-sign")]
    [InlineData("@example.com")]                 // empty local-part
    [InlineData("user@")]                        // empty domain
    [InlineData(".user@example.com")]            // leading dot
    [InlineData("user.@example.com")]            // trailing dot
    [InlineData("us..er@example.com")]           // consecutive dots
    [InlineData("user name@example.com")]        // unquoted space
    [InlineData("user@localhost")]               // domain is not fully qualified
    [InlineData("user@exa mple.com")]
    public void Parse_rejects_invalid_addresses(string? input) =>
        Should.Throw<InvalidValueObjectException>(() => EmailAddress.Parse(input));

    [Fact]
    public void The_local_part_case_is_preserved_for_display()
    {
        EmailAddress address = EmailAddress.Parse("Sales@Example.COM");

        address.LocalPart.ShouldBe("Sales");
        address.Value.ShouldBe("Sales@example.com");
    }

    [Fact]
    public void Matching_is_case_insensitive_on_the_local_part()
    {
        // RFC 5321 makes the local-part case-sensitive, but every significant mail system
        // treats it case-insensitively and users expect Sales@ and sales@ to be one mailbox.
        // The normalised form is what the unique index and every lookup use.
        EmailAddress upper = EmailAddress.Parse("Sales@example.com");
        EmailAddress lower = EmailAddress.Parse("sales@example.com");

        upper.ShouldBe(lower);
        upper.NormalizedValue.ShouldBe("sales@example.com");
        upper.GetHashCode().ShouldBe(lower.GetHashCode());
    }

    [Fact]
    public void A_quoted_local_part_is_accepted_and_re_quoted_on_output()
    {
        EmailAddress address = EmailAddress.Parse("\"odd name\"@example.com");

        address.IsQuoted.ShouldBeTrue();
        address.LocalPart.ShouldBe("odd name");
        address.Value.ShouldBe("\"odd name\"@example.com");
    }

    [Fact]
    public void A_quoted_local_part_may_contain_an_at_sign()
    {
        // Splitting on the FIRST at-sign would mis-parse this. The parser splits on the last.
        EmailAddress address = EmailAddress.Parse("\"a@b\"@example.com");

        address.LocalPart.ShouldBe("a@b");
        address.Domain.Value.ShouldBe("example.com");
    }

    [Fact]
    public void An_unterminated_quoted_local_part_is_rejected() =>
        Should.Throw<InvalidValueObjectException>(() => EmailAddress.Parse("\"unterminated@example.com"));

    [Fact]
    public void A_local_part_over_64_octets_is_rejected()
    {
        string tooLong = new('a', 65);
        Should.Throw<InvalidValueObjectException>(() => EmailAddress.Parse($"{tooLong}@example.com"));
    }

    [Fact]
    public void A_local_part_of_exactly_64_octets_is_accepted()
    {
        string atLimit = new('a', 64);
        EmailAddress.Parse($"{atLimit}@example.com").LocalPart.Length.ShouldBe(64);
    }

    [Fact]
    public void A_non_ascii_local_part_is_flagged_as_requiring_smtputf8()
    {
        EmailAddress address = EmailAddress.Parse("bücher@example.com");

        // Accepted, but flagged. The delivery path refuses to send it to a peer that has not
        // advertised SMTPUTF8 rather than corrupting the address.
        address.RequiresSmtpUtf8.ShouldBeTrue();
        address.LocalPart.ShouldBe("bücher");
    }

    [Fact]
    public void An_ascii_local_part_does_not_require_smtputf8() =>
        EmailAddress.Parse("user@example.com").RequiresSmtpUtf8.ShouldBeFalse();

    [Fact]
    public void An_international_domain_is_punycoded_on_the_wire_and_readable_for_display()
    {
        EmailAddress address = EmailAddress.Parse("user@bücher.example");

        address.Value.ShouldBe("user@xn--bcher-kva.example");
        address.UnicodeValue.ShouldBe("user@bücher.example");
    }

    [Fact]
    public void A_control_character_in_a_local_part_is_rejected()
    {
        // Built from a char code rather than written literally, so the test source itself
        // stays free of control characters.
        string withControlCharacter = "user" + (char)0x01 + "name@example.com";

        Should.Throw<InvalidValueObjectException>(() => EmailAddress.Parse(withControlCharacter));
    }

    [Fact]
    public void A_crlf_in_a_local_part_is_rejected()
    {
        // A CR or LF reaching a generated header splits it, which is the classic header
        // injection vector: an attacker who can insert one can forge any header they like.
        string injected = "user" + (char)0x0D + (char)0x0A + "X-Injected: yes@example.com";

        Should.Throw<InvalidValueObjectException>(() => EmailAddress.Parse(injected));
    }

    [Fact]
    public void TryParse_reports_a_reason_rather_than_throwing()
    {
        EmailAddress.TryParse("not-an-address", out EmailAddress? result, out string? error)
            .ShouldBeFalse();

        result.ShouldBeNull();
        error.ShouldNotBeNullOrWhiteSpace();
    }
}
