using MailServer.Application.Abstractions.Deliverability;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Deliverability;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// What the planner is handed. Everything it decides is tested in
/// <see cref="DnsRecordPlanTests"/>; this is about whether the facts reaching it are this
/// server's own.
/// </summary>
public sealed class DnsPlanServiceTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);

    private static readonly MailDomain Record = MailDomain.Create(DomainId.New(), Domain, Now);

    private static MailServerOptions Settings(string? address = "203.0.113.10")
    {
        MailServerOptions settings = new();

        settings.Server.Hostname = "mail.example.com";
        settings.Server.PublicIpAddress = address;

        return settings;
    }

    private static DkimKey Key(DkimKeyStatus status, string selector = "mail2026")
    {
        DkimKey key = DkimKey.Generate(
            Record.Id,
            DkimSelector.Parse(selector),
            DkimKeyAlgorithm.RsaSha256,
            "MIIBIjANBgkqBASE64",
            2048,
            Now);

        if (status is DkimKeyStatus.Published or DkimKeyStatus.Active or DkimKeyStatus.Retired)
        {
            key.Publish(Now);
        }

        if (status is DkimKeyStatus.Active or DkimKeyStatus.Retired)
        {
            key.Activate(Now);
        }

        if (status == DkimKeyStatus.Retired)
        {
            key.Retire(TimeSpan.FromDays(7), Now);
        }

        return key;
    }

    private static DnsPlanService Service(
        MailServerOptions? settings = null,
        bool hosted = true,
        IReadOnlyList<DkimKey>? keys = null,
        string suffixes = "com\nnet\n") =>
        new(
            new FakeDomains(hosted ? Record : null),
            new FakeDkimKeys(keys),
            new FakePsl(suffixes),
            Options.Create(settings ?? Settings()),
            NullLogger<DnsPlanService>.Instance);

    private static async Task<DnsZonePlan> PlanAsync(
        DnsPlanService service,
        DnsPlanOptions? options = null) =>
        await service.CreateAsync(
            Domain,
            options ?? new DnsPlanOptions(),
            CancellationToken.None);

    private static DnsRecordAdvice? Named(DnsZonePlan plan, string name) =>
        plan.Records.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.Ordinal));

    // ---------------------------------------------------------------------------------------
    // What the server knows about itself.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_plan_names_the_configured_hostname_and_address()
    {
        DnsZonePlan plan = await PlanAsync(Service());

        Named(plan, "mail.example.com")!.Values.ShouldBe(["203.0.113.10"]);
        Named(plan, "example.com")!.Values.ShouldBe(["10 mail.example.com."]);
    }

    /// <summary>
    /// Configuration rather than the host's interfaces. A server behind NAT sees a private
    /// address on every interface and sends from a public one; enumerating them would authorise
    /// addresses that cannot send and omit the one that does.
    /// </summary>
    [Fact]
    public async Task An_unset_public_address_produces_a_plan_that_says_so()
    {
        DnsZonePlan plan = await PlanAsync(Service(Settings(address: null)));

        plan.Records.ShouldNotContain(r => r.Kind == DnsRecordKind.A);
        plan.Records.ShouldNotContain(r => r.Kind == DnsRecordKind.Ptr);
        plan.Caveats.ShouldContain(c =>
            c.Text.Contains("does not know a public address", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // Which key gets published.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_active_key_is_the_one_published()
    {
        DnsZonePlan plan = await PlanAsync(Service(keys: [Key(DkimKeyStatus.Active)]));

        string.Concat(Named(plan, "mail2026._domainkey.example.com")!.Values)
            .ShouldBe("v=DKIM1; k=rsa; p=MIIBIjANBgkqBASE64");
    }

    /// <summary>
    /// A key that has been generated but not yet published is not a record to publish — it is a
    /// key whose own workflow has a publish step, and proposing it here would have an operator
    /// paste a record the server does not yet believe is live.
    /// </summary>
    [Theory]
    [InlineData(DkimKeyStatus.Generated)]
    [InlineData(DkimKeyStatus.Published)]
    [InlineData(DkimKeyStatus.Retired)]
    public async Task A_key_that_is_not_active_is_not_proposed(DkimKeyStatus status)
    {
        DnsZonePlan plan = await PlanAsync(Service(keys: [Key(status)]));

        plan.Records.ShouldNotContain(r => r.Name.Contains("_domainkey", StringComparison.Ordinal));
        plan.Caveats.ShouldContain(c =>
            c.Text.Contains("No DKIM key has been generated", StringComparison.Ordinal));
    }

    /// <summary>
    /// <b>Exactly one key, even mid-rotation.</b> A retired key is legitimately still in DNS so
    /// that signatures already in flight verify, but it is on its way out — proposing it would
    /// have an operator re-publish a record they are in the middle of removing.
    /// </summary>
    [Fact]
    public async Task A_rotation_proposes_only_the_incoming_key()
    {
        DnsZonePlan plan = await PlanAsync(Service(keys:
        [
            Key(DkimKeyStatus.Retired, "mail2025"),
            Key(DkimKeyStatus.Active, "mail2026"),
        ]));

        plan.Records.Count(r => r.Name.Contains("_domainkey", StringComparison.Ordinal)).ShouldBe(1);
        Named(plan, "mail2026._domainkey.example.com").ShouldNotBeNull();
    }

    /// <summary>
    /// A domain this server does not host still gets a plan. Asking for one before adding the
    /// domain is the ordinary order of work, and refusing would make the wizard useless exactly
    /// when an operator is deciding whether to add it.
    /// </summary>
    [Fact]
    public async Task A_domain_this_server_does_not_host_still_gets_a_plan()
    {
        DnsZonePlan plan = await PlanAsync(Service(hosted: false, keys: [Key(DkimKeyStatus.Active)]));

        Named(plan, "example.com").ShouldNotBeNull();
        plan.Records.ShouldNotContain(r => r.Name.Contains("_domainkey", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // The operator's own choices.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_reporting_addresses_reach_the_records_that_carry_them()
    {
        DnsZonePlan plan = await PlanAsync(Service(), new DnsPlanOptions(
            EmailAddress.Parse("dmarc@example.com"),
            EmailAddress.Parse("tlsrpt@example.com"),
            "20260919T120000"));

        string.Concat(Named(plan, "_dmarc.example.com")!.Values)
            .ShouldBe("v=DMARC1; p=none; rua=mailto:dmarc@example.com");

        string.Concat(Named(plan, "_smtp._tls.example.com")!.Values)
            .ShouldBe("v=TLSRPTv1; rua=mailto:tlsrpt@example.com");

        string.Concat(Named(plan, "_mta-sts.example.com")!.Values)
            .ShouldBe("v=STSv1; id=20260919T120000;");
    }

    /// <summary>
    /// The suffix list reaches the planner, which is what stops a reporting address elsewhere in
    /// the same organization being flagged as external — RFC 7489 §7.1 compares organizational
    /// domains, not names.
    /// </summary>
    [Fact]
    public async Task The_suffix_list_reaches_the_external_reporting_rule()
    {
        DnsZonePlan plan = await PlanAsync(
            Service(),
            new DnsPlanOptions(EmailAddress.Parse("dmarc@reports.example.com")));

        plan.Caveats.ShouldNotContain(c =>
            c.Text.Contains("_report._dmarc", StringComparison.Ordinal));
    }

    /// <summary>
    /// The same address, the same code path, a different list — and a different answer. Paired
    /// with the test above, this is what pins that the <i>configured</i> list is consulted
    /// rather than some list: with <c>example.com</c> itself a public suffix,
    /// <c>reports.example.com</c> and <c>example.com</c> stop being one organization and RFC
    /// 7489 §7.1's authorisation becomes due.
    /// </summary>
    [Fact]
    public async Task A_different_suffix_list_gives_a_different_answer()
    {
        DnsZonePlan plan = await PlanAsync(
            Service(suffixes: "example.com\n"),
            new DnsPlanOptions(EmailAddress.Parse("dmarc@reports.example.com")));

        plan.Caveats.ShouldContain(c =>
            c.Text.Contains("_report._dmarc", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_service_refuses_null_arguments()
    {
        DnsPlanService service = Service();

        await Should.ThrowAsync<ArgumentNullException>(
            () => service.CreateAsync(null!, new DnsPlanOptions(), CancellationToken.None));

        await Should.ThrowAsync<ArgumentNullException>(
            () => service.CreateAsync(Domain, null!, CancellationToken.None));
    }
}
