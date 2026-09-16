using System.Text;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dkim;
using MailServer.Infrastructure.Dmarc;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="DmarcEvaluator"/> against fake DNS - the record parser
/// (<see cref="DmarcRecordTests"/>) and the organizational-domain algorithm
/// (<see cref="PublicSuffixListTests"/>) are both tested separately; this exercises policy
/// discovery (the exact-domain-then-organizational-domain fallback), alignment, and pct=
/// sampling.
/// </summary>
public sealed class DmarcEvaluatorTests
{
    private const string SamplePsl = """
        // VERSION: 2026-09-15_10-18-26_UTC
        com
        co.uk
        """;

    private static RawMessageHeaders HeadersWithFrom(string fromAddress)
    {
        byte[] buffer = Encoding.ASCII.GetBytes($"From: {fromAddress}\r\nTo: someone@elsewhere.example\r\n\r\nBody.");
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out _).ShouldBeTrue();
        return headers!;
    }

    private static RawMessageHeaders HeadersWithNoFrom()
    {
        byte[] buffer = Encoding.ASCII.GetBytes("To: someone@elsewhere.example\r\n\r\nBody.");
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out _).ShouldBeTrue();
        return headers!;
    }

    private static DmarcEvaluator CreateEvaluator(FakeTxtRecordResolver txt) =>
        new(txt, new FakePublicSuffixListProvider(SamplePsl), NullLogger<DmarcEvaluator>.Instance);

    private static SpfEvaluationOutcome SpfPass(string checkedDomain) =>
        new(SpfResult.Pass, DomainName.Parse(checkedDomain), null);

    private static SpfEvaluationOutcome SpfFail(string checkedDomain) =>
        new(SpfResult.Fail, DomainName.Parse(checkedDomain), null);

    private static DkimVerifiedSignature DkimPass(string signingDomain) =>
        new(DkimVerificationResult.Pass, DomainName.Parse(signingDomain), null);

    private static DkimVerifiedSignature DkimFail(string signingDomain) =>
        new(DkimVerificationResult.Fail, DomainName.Parse(signingDomain), null);

    [Fact]
    public async Task No_from_header_means_dmarc_does_not_apply()
    {
        var txt = new FakeTxtRecordResolver();

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithNoFrom(), null, [], CancellationToken.None);

        outcome.Result.ShouldBeNull();
        outcome.Disposition.ShouldBe(DmarcPolicy.None);
        outcome.PolicyDomain.ShouldBeNull();
    }

    [Fact]
    public async Task No_dmarc_record_anywhere_in_the_fallback_chain_means_dmarc_does_not_apply()
    {
        var txt = new FakeTxtRecordResolver();

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), null, [], CancellationToken.None);

        outcome.Result.ShouldBeNull();
        outcome.PolicyDomain.ShouldBeNull();
        outcome.FromDomain!.Value.ShouldBe("example.com");
    }

    [Fact]
    public async Task Spf_pass_aligned_with_the_from_domain_is_an_overall_pass()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), SpfPass("example.com"), [], CancellationToken.None);

        outcome.Result.ShouldBe(DmarcResult.Pass);
        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.Spf);
        outcome.Disposition.ShouldBe(DmarcPolicy.None);
        outcome.PolicyDomain!.Value.ShouldBe("example.com");
    }

    [Fact]
    public async Task Dkim_pass_aligned_with_the_from_domain_is_an_overall_pass()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), null, [DkimPass("example.com")], CancellationToken.None);

        outcome.Result.ShouldBe(DmarcResult.Pass);
        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.Dkim);
    }

    [Fact]
    public async Task Relaxed_alignment_matches_a_subdomain_against_the_organizational_domain()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        // The SPF-checked domain is a different subdomain of the same organizational domain -
        // relaxed alignment (the default) accepts this; strict would not.
        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), SpfPass("bounce.example.com"), [], CancellationToken.None);

        outcome.Result.ShouldBe(DmarcResult.Pass);
    }

    [Fact]
    public async Task Strict_alignment_rejects_a_subdomain_match()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject; aspf=s");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), SpfPass("bounce.example.com"), [], CancellationToken.None);

        outcome.Result.ShouldBe(DmarcResult.Fail);
        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.None);
    }

    [Fact]
    public async Task Unaligned_spf_and_dkim_results_produce_an_overall_fail_and_the_requested_disposition()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"),
            SpfFail("example.com"),
            [DkimFail("attacker.example.net")],
            CancellationToken.None);

        outcome.Result.ShouldBe(DmarcResult.Fail);
        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.None);
        outcome.Disposition.ShouldBe(DmarcPolicy.Reject);
    }

    [Fact]
    public async Task No_record_at_the_exact_domain_falls_back_to_the_organizational_domain()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject; sp=quarantine");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@mail.example.com"), null, [], CancellationToken.None);

        outcome.Result.ShouldBe(DmarcResult.Fail);
        outcome.PolicyDomain!.Value.ShouldBe("example.com");

        // The record was found only at the organizational domain, a fallback from the exact
        // "mail.example.com" From: domain, so "sp" governs rather than "p".
        outcome.Disposition.ShouldBe(DmarcPolicy.Quarantine);
    }

    [Fact]
    public async Task A_record_at_the_exact_from_domain_is_preferred_over_the_organizational_fallback()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.mail.example.com", "v=DMARC1; p=none");
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@mail.example.com"), null, [], CancellationToken.None);

        outcome.PolicyDomain!.Value.ShouldBe("mail.example.com");
        outcome.Disposition.ShouldBe(DmarcPolicy.None);
    }

    [Fact]
    public async Task A_policy_of_none_never_produces_a_disposition_even_on_fail()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=none");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), null, [], CancellationToken.None);

        outcome.Result.ShouldBe(DmarcResult.Fail);
        outcome.Disposition.ShouldBe(DmarcPolicy.None);
    }

    [Fact]
    public async Task A_zero_percent_sampling_excludes_every_message_from_enforcement()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject; pct=0");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), null, [], CancellationToken.None,
            randomSource: () => 0.0);

        outcome.Result.ShouldBe(DmarcResult.Fail);
        outcome.Disposition.ShouldBe(DmarcPolicy.None);
    }

    [Theory]
    [InlineData(0.10, true)]
    [InlineData(0.60, false)]
    public async Task Sampling_compares_the_random_draw_against_pct(double draw, bool expectEnforced)
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject; pct=50");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), null, [], CancellationToken.None,
            randomSource: () => draw);

        outcome.Disposition.ShouldBe(expectEnforced ? DmarcPolicy.Reject : DmarcPolicy.None);
    }

    [Fact]
    public async Task More_than_one_dmarc_record_at_the_same_name_is_discarded()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRawRecords("_dmarc.example.com", ["v=DMARC1; p=reject", "v=DMARC1; p=none"]);

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), null, [], CancellationToken.None);

        outcome.Result.ShouldBeNull();
        outcome.PolicyDomain.ShouldBeNull();
    }

    [Fact]
    public async Task A_malformed_record_at_the_exact_domain_falls_back_to_the_organizational_domain()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("_dmarc.mail.example.com", "v=DMARC1; p=bogus");
        txt.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@mail.example.com"), null, [], CancellationToken.None);

        outcome.PolicyDomain!.Value.ShouldBe("example.com");
        outcome.Result.ShouldBe(DmarcResult.Fail);
    }

    [Fact]
    public async Task A_temporary_dns_failure_means_dmarc_does_not_apply_and_is_not_enforced()
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetTemporaryFailure("_dmarc.example.com");

        DmarcEvaluationOutcome outcome = await CreateEvaluator(txt).EvaluateAsync(
            HeadersWithFrom("alice@example.com"), null, [], CancellationToken.None);

        outcome.Result.ShouldBeNull();
        outcome.Disposition.ShouldBe(DmarcPolicy.None);
        outcome.Diagnostic.ShouldNotBeNull();
    }

    private sealed class FakeTxtRecordResolver : ITxtRecordResolver
    {
        private readonly Dictionary<string, TxtLookupResult> _results = new(StringComparer.OrdinalIgnoreCase);

        public void SetRecord(string name, string record) => SetRawRecords(name, [record]);

        public void SetRawRecords(string name, IReadOnlyList<string> records) =>
            _results[name] = TxtLookupResult.Success(records);

        public void SetTemporaryFailure(string name) =>
            _results[name] = TxtLookupResult.Temporary("simulated failure");

        public Task<TxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(_results.GetValueOrDefault(domain, TxtLookupResult.Success([])));
    }

    private sealed class FakePublicSuffixListProvider(string listText) : IPublicSuffixListProvider
    {
        public PublicSuffixList List { get; } = PublicSuffixList.Parse(listText);
    }
}
