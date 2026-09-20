using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Deliverability.Queries;
using MailServer.Application.Exceptions;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Tests;

internal sealed class ScriptedReportService(DeliverabilityReport report) : IDeliverabilityReportService
{
    public DeliverabilityRunOptions? Options { get; private set; }

    public DomainName? Domain { get; private set; }

    public Task<DeliverabilityReport> RunAsync(
        DomainName domain,
        DeliverabilityRunOptions options,
        CancellationToken cancellationToken)
    {
        Domain = domain;
        Options = options;

        return Task.FromResult(report);
    }
}

internal sealed class ScriptedAnalysisService(AnalysedHeaders analysis) : IHeaderAnalysisService
{
    public IpAddressValue? Address { get; private set; }

    public Task<AnalysedHeaders> AnalyseAsync(
        string? text,
        IpAddressValue? clientAddress,
        CancellationToken cancellationToken)
    {
        Address = clientAddress;

        return Task.FromResult(analysis);
    }
}

public sealed class DeliverabilityQueryTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);

    // ---------------------------------------------------------------------------------------
    // The report.
    // ---------------------------------------------------------------------------------------

    private static DeliverabilityReport Report(params DeliverabilityCheck[] checks) =>
        DeliverabilityReport.From(checks, Now);

    private static IRequestHandler<GetDeliverabilityReportQuery, DeliverabilityReportDto> Handler(
        ScriptedReportService service) =>
        new GetDeliverabilityReportQueryHandler(service);

    /// <summary>A check's evidence reaches the wire, which is what the report promises.</summary>
    /// <remarks>
    /// <c>docs/Deliverability.md</c>: "Every check returns Pass / Warn / Fail / Inconclusive
    /// <b>with evidence</b>: the record actually found, the value expected, the resolver used,
    /// the TTL observed." A DTO that dropped the evidence would leave the UI showing verdicts
    /// with nothing behind them.
    /// </remarks>
    [Fact]
    public async Task A_checks_evidence_reaches_the_dto()
    {
        DeliverabilityCheck check = new(
            "dns.ttl-sanity",
            DeliverabilityCategory.Dns,
            "The MX TTL is a sensible length",
            1,
            DeliverabilityOutcome.Warn,
            "The MX TTL is 30 seconds.",
            new DeliverabilityEvidence("Between 300 and 86400 seconds", "30 seconds", "ns1.example.com", TimeSpan.FromSeconds(30)),
            "Raise it.");

        ScriptedReportService service = new(Report(check));

        DeliverabilityReportDto dto = await Handler(service).Handle(
            new GetDeliverabilityReportQuery { Domain = "example.com" },
            CancellationToken.None);

        DeliverabilityCheckDto mapped = dto.Checks.ShouldHaveSingleItem();

        mapped.Id.ShouldBe("dns.ttl-sanity");
        mapped.Outcome.ShouldBe("Warn");
        mapped.Expected.ShouldBe("Between 300 and 86400 seconds");
        mapped.Found.ShouldBe("30 seconds");
        mapped.Source.ShouldBe("ns1.example.com");
        mapped.TtlSeconds.ShouldBe(30);
        mapped.Remedy.ShouldBe("Raise it.");
    }

    /// <summary>
    /// The readiness verdict and the summary both cross, not just the number.
    /// </summary>
    /// <remarks>
    /// The verdict is the worst outcome present and never the arithmetic, and the summary always
    /// states the real denominator. A DTO carrying only the score would let a UI lead with a
    /// comfortable number beside a failing check — the exact report that gets skimmed.
    /// </remarks>
    [Fact]
    public async Task The_verdict_and_summary_cross_with_the_score()
    {
        DeliverabilityCheck failing = new(
            "identity.ptr",
            DeliverabilityCategory.Identity,
            "A PTR record exists",
            3,
            DeliverabilityOutcome.Fail,
            "No PTR.",
            null,
            "Ask your provider.");

        ScriptedReportService service = new(Report(failing));

        DeliverabilityReportDto dto = await Handler(service).Handle(
            new GetDeliverabilityReportQuery { Domain = "example.com" },
            CancellationToken.None);

        dto.Readiness.ShouldBe(nameof(DeliverabilityReadiness.NotReady));
        dto.Summary.ShouldNotBeNullOrWhiteSpace();
        dto.ProducedAt.ShouldBe(Now);
    }

    /// <summary>A score of null survives: nothing judged is not a score of zero.</summary>
    [Fact]
    public async Task An_unjudged_report_has_a_null_score()
    {
        DeliverabilityCheck unmeasured = new(
            "identity.ptr",
            DeliverabilityCategory.Identity,
            "A PTR record exists",
            3,
            DeliverabilityOutcome.Inconclusive,
            "Not tested.");

        ScriptedReportService service = new(Report(unmeasured));

        DeliverabilityReportDto dto = await Handler(service).Handle(
            new GetDeliverabilityReportQuery { Domain = "example.com" },
            CancellationToken.None);

        dto.Score.ShouldBeNull();
        dto.Readiness.ShouldBe(nameof(DeliverabilityReadiness.Unknown));
    }

    /// <summary>
    /// The run options reach the service, because they decide what this server does to others.
    /// </summary>
    /// <remarks>
    /// They control whether an SMTP connection is opened, whether a policy host named by the
    /// domain under test is contacted, and whether third-party blocklists are queried. Dropping
    /// them on the way through would make an operator's "look at DNS only" mean nothing.
    /// </remarks>
    [Fact]
    public async Task The_run_options_reach_the_service()
    {
        ScriptedReportService service = new(Report());

        await Handler(service).Handle(
            new GetDeliverabilityReportQuery
            {
                Domain = "example.com",
                RunRelayTest = false,
                QueryReputationLists = false,
                FetchMtaStsPolicy = false,
            },
            CancellationToken.None);

        DeliverabilityRunOptions options = service.Options.ShouldNotBeNull();

        options.RunRelayTest.ShouldBeFalse();
        options.QueryReputationLists.ShouldBeFalse();
        options.FetchMtaStsPolicy.ShouldBeFalse();
    }

    /// <summary>Everything on is the default, matching the abstraction's own.</summary>
    [Fact]
    public async Task The_default_run_does_everything()
    {
        ScriptedReportService service = new(Report());

        await Handler(service).Handle(
            new GetDeliverabilityReportQuery { Domain = "example.com" },
            CancellationToken.None);

        DeliverabilityRunOptions options = service.Options.ShouldNotBeNull();

        options.RunRelayTest.ShouldBeTrue();
        options.QueryReputationLists.ShouldBeTrue();
        options.FetchMtaStsPolicy.ShouldBeTrue();
    }

    /// <summary>A domain that is not a domain is rejected before anything is looked up.</summary>
    [Fact]
    public async Task An_invalid_domain_is_rejected()
    {
        ScriptedReportService service = new(Report());

        await Should.ThrowAsync<ValidationFailedException>(() => Handler(service).Handle(
            new GetDeliverabilityReportQuery { Domain = "not a domain" },
            CancellationToken.None));

        service.Domain.ShouldBeNull();
    }

    /// <summary>Both queries need only ViewServerState, since neither reads message content.</summary>
    [Fact]
    public void Neither_query_needs_permission_to_read_message_content()
    {
        new GetDeliverabilityReportQuery { Domain = "example.com" }
            .RequiredPermission.ShouldBe(AdminPermission.ViewServerState);

        new AnalyseHeadersQuery { Headers = "From: a@b.example" }
            .RequiredPermission.ShouldBe(AdminPermission.ViewServerState);
    }

    // ---------------------------------------------------------------------------------------
    // The header analysis.
    // ---------------------------------------------------------------------------------------

    private static AnalysedSignature Signature(string? selector, string? domain, string? error = null) =>
        new(selector, domain, "RsaSha256", ["from"], null, null, null, error);

    private static AnalysedHeaders Analysis(
        IReadOnlyList<AnalysedSignature> signatures,
        IReadOnlyList<AnalysedKey> keys) =>
        new(
            new HeaderAnalysis(
                new ReceivedChain([], null),
                null, null, null, [], false,
                signatures,
                []),
            new HeaderAuthentication(null, null, null, false, null, keys, null, null, false, false),
            []);

    /// <summary>
    /// A signature is paired with its own selector's lookup, by name rather than by position.
    /// </summary>
    /// <remarks>
    /// A signature that fails to parse is never looked up, so the two lists are different
    /// lengths the moment one does. A positional join would attribute the second signature's key
    /// state to the first — reporting a published key for a selector that has none, which is the
    /// single most consequential thing this tool says.
    /// </remarks>
    [Fact]
    public async Task Signatures_are_paired_with_their_own_key_lookup()
    {
        AnalysedHeaders analysis = Analysis(
            [
                Signature(null, null, "malformed"),
                Signature("live", "example.com"),
            ],
            [new AnalysedKey("live", "example.com", AnalysedKeyState.Published, 2048, null)]);

        HeaderAnalysisDto dto = await new AnalyseHeadersQueryHandler(new ScriptedAnalysisService(analysis))
            .Handle(new AnalyseHeadersQuery { Headers = "x" }, CancellationToken.None);

        dto.Signatures.Count.ShouldBe(2);

        // The malformed one gets no key state and keeps its own parse error.
        dto.Signatures[0].KeyState.ShouldBe(nameof(AnalysedKeyState.Unknown));
        dto.Signatures[0].Diagnostic.ShouldBe("malformed");

        // The real one gets its own lookup, not the other's.
        dto.Signatures[1].KeyState.ShouldBe(nameof(AnalysedKeyState.Published));
        dto.Signatures[1].KeyBits.ShouldBe(2048);
    }

    /// <summary>Two signatures from different domains keep their own key states.</summary>
    [Fact]
    public async Task Two_signatures_keep_their_own_key_states()
    {
        AnalysedHeaders analysis = Analysis(
            [Signature("s1", "first.example"), Signature("s1", "second.example")],
            [
                new AnalysedKey("s1", "first.example", AnalysedKeyState.NotPublished, null, "gone"),
                new AnalysedKey("s1", "second.example", AnalysedKeyState.Published, 2048, null),
            ]);

        HeaderAnalysisDto dto = await new AnalyseHeadersQueryHandler(new ScriptedAnalysisService(analysis))
            .Handle(new AnalyseHeadersQuery { Headers = "x" }, CancellationToken.None);

        dto.Signatures[0].KeyState.ShouldBe(nameof(AnalysedKeyState.NotPublished));
        dto.Signatures[1].KeyState.ShouldBe(nameof(AnalysedKeyState.Published));
    }

    /// <summary>
    /// The DTO carries no DKIM verdict, only whether a signature could align.
    /// </summary>
    /// <remarks>
    /// Asserted on the shape rather than a value: a property called anything like "DkimPass"
    /// would be a promise a header block cannot keep, and the name is the safeguard.
    /// </remarks>
    [Fact]
    public void The_dto_has_no_dkim_verdict()
    {
        string[] names = [.. typeof(HeaderAnalysisDto).GetProperties().Select(p => p.Name)];

        names.ShouldContain(nameof(HeaderAnalysisDto.DkimCouldAlign));
        names.ShouldNotContain(n => n.Contains("DkimPass", StringComparison.OrdinalIgnoreCase));
        names.ShouldNotContain(n => n.Equals("Dkim", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>A supplied client address is parsed and passed through.</summary>
    [Fact]
    public async Task A_supplied_client_address_is_passed_through()
    {
        ScriptedAnalysisService service = new(Analysis([], []));

        await new AnalyseHeadersQueryHandler(service).Handle(
            new AnalyseHeadersQuery { Headers = "x", ClientAddress = "203.0.113.10" },
            CancellationToken.None);

        service.Address.ShouldNotBeNull().Value.ShouldBe("203.0.113.10");
    }

    /// <summary>An address that is not one is rejected rather than silently ignored.</summary>
    /// <remarks>
    /// Ignoring it would fall back to the message's own trace and produce an SPF result the
    /// operator would read as being about the address they typed.
    /// </remarks>
    [Fact]
    public async Task An_invalid_client_address_is_rejected()
    {
        ScriptedAnalysisService service = new(Analysis([], []));

        await Should.ThrowAsync<ValidationFailedException>(() =>
            new AnalyseHeadersQueryHandler(service).Handle(
                new AnalyseHeadersQuery { Headers = "x", ClientAddress = "not-an-address" },
                CancellationToken.None));

        service.Address.ShouldBeNull();
    }

    /// <summary>No address supplied is not an error; it is the common case.</summary>
    [Fact]
    public async Task No_client_address_is_not_an_error()
    {
        ScriptedAnalysisService service = new(Analysis([], []));

        await new AnalyseHeadersQueryHandler(service).Handle(
            new AnalyseHeadersQuery { Headers = "x" },
            CancellationToken.None);

        service.Address.ShouldBeNull();
    }
}
