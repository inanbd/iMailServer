using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dkim;
using MailServer.Infrastructure.Dmarc;

namespace MailServer.Authentication.Tests;

public class AuthenticationResultsComposerTests
{
    private static DmarcEvaluationOutcome DmarcOutcome(
        DmarcResult? result, string? fromDomain = "example.com") =>
        new(
            result,
            DmarcPolicy.None,
            DmarcAlignedMechanism.None,
            fromDomain is null ? null : DomainName.Parse(fromDomain),
            fromDomain is null ? null : DomainName.Parse(fromDomain),
            null);

    [Fact]
    public void Leads_with_the_authserv_id()
    {
        string value = AuthenticationResultsComposer.Compose(
            "mail.example.com", null, [], DmarcOutcome(DmarcResult.Pass));

        value.ShouldStartWith("mail.example.com;");
    }

    [Fact]
    public void Composes_a_dkim_pass_with_its_signing_domain()
    {
        string value = AuthenticationResultsComposer.Compose(
            "mail.example.com",
            null,
            [new DkimVerifiedSignature(DkimVerificationResult.Pass, DomainName.Parse("example.com"), null)],
            DmarcOutcome(DmarcResult.Pass));

        value.ShouldContain("dkim=pass header.d=example.com");
    }

    [Fact]
    public void A_dkim_none_result_carries_no_signing_domain()
    {
        string value = AuthenticationResultsComposer.Compose(
            "mail.example.com",
            null,
            [new DkimVerifiedSignature(DkimVerificationResult.None, null, null)],
            DmarcOutcome(DmarcResult.Fail));

        value.ShouldContain("dkim=none");
        value.ShouldNotContain("dkim=none header.d=");
    }

    [Fact]
    public void Composes_one_dkim_entry_per_signature()
    {
        string value = AuthenticationResultsComposer.Compose(
            "mail.example.com",
            null,
            [
                new DkimVerifiedSignature(DkimVerificationResult.Pass, DomainName.Parse("example.com"), null),
                new DkimVerifiedSignature(DkimVerificationResult.Fail, DomainName.Parse("relay.example.net"), null),
            ],
            DmarcOutcome(DmarcResult.Pass));

        value.ShouldContain("dkim=pass header.d=example.com");
        value.ShouldContain("dkim=fail header.d=relay.example.net");
    }

    [Fact]
    public void Composes_spf_with_the_checked_domain_when_spf_was_evaluated()
    {
        string value = AuthenticationResultsComposer.Compose(
            "mail.example.com",
            new SpfEvaluationOutcome(SpfResult.Pass, DomainName.Parse("example.com"), null),
            [],
            DmarcOutcome(DmarcResult.Pass));

        value.ShouldContain("spf=pass smtp.mailfrom=example.com");
    }

    [Fact]
    public void Omits_spf_entirely_when_it_was_never_evaluated()
    {
        string value = AuthenticationResultsComposer.Compose(
            "mail.example.com", null, [], DmarcOutcome(DmarcResult.Pass));

        value.ShouldNotContain("spf=");
    }

    [Theory]
    [InlineData(DmarcResult.Pass, "dmarc=pass header.from=example.com")]
    [InlineData(DmarcResult.Fail, "dmarc=fail header.from=example.com")]
    public void Composes_dmarc_with_its_from_domain(DmarcResult result, string expected)
    {
        string value = AuthenticationResultsComposer.Compose("mail.example.com", null, [], DmarcOutcome(result));

        value.ShouldContain(expected);
    }

    [Fact]
    public void A_null_dmarc_result_composes_as_none()
    {
        string value = AuthenticationResultsComposer.Compose("mail.example.com", null, [], DmarcOutcome(null));

        value.ShouldContain("dmarc=none header.from=example.com");
    }

    [Fact]
    public void A_dmarc_outcome_with_no_from_domain_carries_no_header_from_annotation()
    {
        string value = AuthenticationResultsComposer.Compose(
            "mail.example.com", null, [], DmarcOutcome(null, fromDomain: null));

        value.ShouldContain("dmarc=none");
        value.ShouldNotContain("header.from=");
    }

    [Fact]
    public void Every_resinfo_entry_is_semicolon_separated_and_folded_onto_its_own_indented_line()
    {
        string value = AuthenticationResultsComposer.Compose(
            "mail.example.com",
            new SpfEvaluationOutcome(SpfResult.Pass, DomainName.Parse("example.com"), null),
            [new DkimVerifiedSignature(DkimVerificationResult.Pass, DomainName.Parse("example.com"), null)],
            DmarcOutcome(DmarcResult.Pass));

        value.ShouldBe(
            "mail.example.com;\r\n" +
            "    dkim=pass header.d=example.com;\r\n" +
            "    spf=pass smtp.mailfrom=example.com;\r\n" +
            "    dmarc=pass header.from=example.com");
    }
}
