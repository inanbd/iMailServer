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
/// <see cref="DmarcEvaluator"/>'s alignment computation against RFC 7489 Appendix B.1's
/// "Identifier Alignment Examples" - the official vectors, not just this suite's own
/// expectations. Uses the real embedded Public Suffix List (<see cref="PublicSuffixListLoader"/>),
/// since every domain here is an ordinary one under "com"/"net" with no wildcard or exception
/// rule involved - exactly what a real deployment would see.
/// </summary>
public sealed class DmarcRfc7489AlignmentVectorTests
{
    private static readonly IPublicSuffixListProvider RealPsl = new PublicSuffixListLoader(NullLogger<PublicSuffixListLoader>.Instance);

    private static RawMessageHeaders HeadersWithFrom(string fromAddress)
    {
        byte[] buffer = Encoding.ASCII.GetBytes($"From: {fromAddress}\r\nTo: receiver@example.org\r\n\r\nBody.");
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out _).ShouldBeTrue();
        return headers!;
    }

    private static async Task<DmarcEvaluationOutcome> EvaluateAsync(
        string dmarcRecord, string fromAddress, SpfEvaluationOutcome? spfOutcome = null,
        IReadOnlyList<DkimVerifiedSignature>? dkimResults = null)
    {
        FakeTxtRecordResolver txt = new();
        txt.SetRecord("_dmarc.example.com", dmarcRecord);

        DmarcEvaluator evaluator = new(txt, RealPsl, NullLogger<DmarcEvaluator>.Instance);

        return await evaluator.EvaluateAsync(
            HeadersWithFrom(fromAddress), spfOutcome, dkimResults ?? [], CancellationToken.None);
    }

    // ---- B.1.1: SPF -------------------------------------------------------------------------

    [Fact]
    public async Task Spf_example_1_identical_domains_align_under_relaxed_mode()
    {
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject",
            "sender@example.com",
            new SpfEvaluationOutcome(SpfResult.Pass, DomainName.Parse("example.com"), null));

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.Spf);
        outcome.Result.ShouldBe(DmarcResult.Pass);
    }

    [Fact]
    public async Task Spf_example_1_identical_domains_align_under_strict_mode_too()
    {
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject; aspf=s",
            "sender@example.com",
            new SpfEvaluationOutcome(SpfResult.Pass, DomainName.Parse("example.com"), null));

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.Spf);
    }

    [Fact]
    public async Task Spf_example_2_parent_domain_aligns_under_relaxed_mode()
    {
        // MAIL FROM: sender@child.example.com ; From: sender@example.com
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject",
            "sender@example.com",
            new SpfEvaluationOutcome(SpfResult.Pass, DomainName.Parse("child.example.com"), null));

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.Spf);
        outcome.Result.ShouldBe(DmarcResult.Pass);
    }

    [Fact]
    public async Task Spf_example_2_parent_domain_does_not_align_under_strict_mode()
    {
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject; aspf=s",
            "sender@example.com",
            new SpfEvaluationOutcome(SpfResult.Pass, DomainName.Parse("child.example.com"), null));

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.None);
        outcome.Result.ShouldBe(DmarcResult.Fail);
    }

    [Fact]
    public async Task Spf_example_3_unrelated_domains_do_not_align_even_under_relaxed_mode()
    {
        // MAIL FROM: sender@example.net ; From: sender@child.example.com
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject",
            "sender@child.example.com",
            new SpfEvaluationOutcome(SpfResult.Pass, DomainName.Parse("example.net"), null));

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.None);
        outcome.Result.ShouldBe(DmarcResult.Fail);
    }

    // ---- B.1.2: DKIM -------------------------------------------------------------------------

    [Fact]
    public async Task Dkim_example_1_identical_domains_align_under_relaxed_mode()
    {
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject",
            "sender@example.com",
            dkimResults: [new DkimVerifiedSignature(DkimVerificationResult.Pass, DomainName.Parse("example.com"), null)]);

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.Dkim);
        outcome.Result.ShouldBe(DmarcResult.Pass);
    }

    [Fact]
    public async Task Dkim_example_2_parent_domain_aligns_under_relaxed_mode()
    {
        // d=example.com ; From: sender@child.example.com
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject",
            "sender@child.example.com",
            dkimResults: [new DkimVerifiedSignature(DkimVerificationResult.Pass, DomainName.Parse("example.com"), null)]);

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.Dkim);
        outcome.Result.ShouldBe(DmarcResult.Pass);
    }

    [Fact]
    public async Task Dkim_example_2_parent_domain_does_not_align_under_strict_mode()
    {
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject; adkim=s",
            "sender@child.example.com",
            dkimResults: [new DkimVerifiedSignature(DkimVerificationResult.Pass, DomainName.Parse("example.com"), null)]);

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.None);
        outcome.Result.ShouldBe(DmarcResult.Fail);
    }

    [Fact]
    public async Task Dkim_example_3_unrelated_domains_do_not_align_even_under_relaxed_mode()
    {
        // d=sample.net ; From: sender@child.example.com
        DmarcEvaluationOutcome outcome = await EvaluateAsync(
            "v=DMARC1; p=reject",
            "sender@child.example.com",
            dkimResults: [new DkimVerifiedSignature(DkimVerificationResult.Pass, DomainName.Parse("sample.net"), null)]);

        outcome.AlignedMechanisms.ShouldBe(DmarcAlignedMechanism.None);
        outcome.Result.ShouldBe(DmarcResult.Fail);
    }

    private sealed class FakeTxtRecordResolver : ITxtRecordResolver
    {
        private readonly Dictionary<string, TxtLookupResult> _results = new(StringComparer.OrdinalIgnoreCase);

        public void SetRecord(string name, string record) => _results[name] = TxtLookupResult.Success([record]);

        public Task<TxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(_results.GetValueOrDefault(domain, TxtLookupResult.Success([])));
    }
}
