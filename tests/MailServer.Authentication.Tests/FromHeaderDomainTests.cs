using System.Text;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dkim;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="FromHeaderDomain"/>'s domain extraction, including the multi-mailbox refusal that
/// closes the DMARC alignment bypass RFC 7489 section 6.6.1 warns about: a crafted
/// <c>From:</c> field naming more than one mailbox must never silently resolve to one of them.
/// </summary>
public class FromHeaderDomainTests
{
    private static RawMessageHeaders Headers(params string[] fromLines)
    {
        string text = string.Concat(fromLines.Select(l => l + "\r\n")) + "\r\nBody.";
        byte[] buffer = Encoding.ASCII.GetBytes(text);
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error).ShouldBeTrue(error);
        return headers!;
    }

    [Fact]
    public void Extracts_the_domain_from_a_simple_addr_spec()
    {
        FromHeaderDomain.TryExtract(Headers("From: alice@example.com"), out DomainName? domain).ShouldBeTrue();
        domain!.Value.ShouldBe("example.com");
    }

    [Fact]
    public void Extracts_the_domain_from_a_display_name_and_angle_bracket_address()
    {
        FromHeaderDomain.TryExtract(Headers("From: Alice <alice@example.com>"), out DomainName? domain).ShouldBeTrue();
        domain!.Value.ShouldBe("example.com");
    }

    [Fact]
    public void Refuses_a_from_field_naming_two_bracketed_mailboxes()
    {
        // The exploit shape: a legitimate-looking first mailbox, then the attacker's own domain
        // (which the earlier last-<...>-pair heuristic would have picked) as a second.
        bool ok = FromHeaderDomain.TryExtract(
            Headers("From: \"CEO\" <ceo@bigcorp.example>, <attacker@evil.example>"),
            out DomainName? domain);

        ok.ShouldBeFalse();
        domain.ShouldBeNull();
    }

    [Fact]
    public void Refuses_a_from_field_with_a_bracketed_and_a_bare_mailbox()
    {
        bool ok = FromHeaderDomain.TryExtract(
            Headers("From: <ceo@bigcorp.example>, attacker@evil.example"),
            out DomainName? domain);

        ok.ShouldBeFalse();
        domain.ShouldBeNull();
    }

    [Fact]
    public void Refuses_more_than_one_from_header_field()
    {
        bool ok = FromHeaderDomain.TryExtract(
            Headers("From: ceo@bigcorp.example", "From: attacker@evil.example"),
            out DomainName? domain);

        ok.ShouldBeFalse();
        domain.ShouldBeNull();
    }

    [Fact]
    public void No_from_field_at_all_is_refused()
    {
        FromHeaderDomain.TryExtract(Headers("To: bob@example.com"), out DomainName? domain).ShouldBeFalse();
        domain.ShouldBeNull();
    }
}
