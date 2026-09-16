using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Spf;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="SpfEvaluator"/> against fake DNS - the parser (<see cref="SpfRecordTests"/>) is
/// tested separately; this exercises the evaluation algorithm itself: mechanism matching,
/// include/redirect recursion and result translation, and the lookup/void-lookup budgets.
/// </summary>
public sealed class SpfEvaluatorTests
{
    private static DomainName Domain(string name) => DomainName.Parse(name);

    private static IpAddressValue Ip(string address) => IpAddressValue.Parse(address);

    private static SpfEvaluator CreateEvaluator(FakeSpfTxtResolver txt, FakeDnsResolver dns) =>
        new(txt, dns, NullLogger<SpfEvaluator>.Instance);

    [Fact]
    public async Task No_spf_record_at_all_is_None()
    {
        var txt = new FakeSpfTxtResolver();
        var dns = new FakeDnsResolver();

        SpfEvaluationResult result = await CreateEvaluator(txt, dns)
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.None);
    }

    [Fact]
    public async Task An_ip4_mechanism_matching_the_client_passes()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 ip4:203.0.113.0/24 -all");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task An_ip4_mechanism_not_matching_falls_through_to_the_default_qualifier()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 ip4:203.0.113.0/24 -all");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("198.51.100.5"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Fail);
    }

    [Theory]
    [InlineData("~all", SpfResult.SoftFail)]
    [InlineData("?all", SpfResult.Neutral)]
    [InlineData("+all", SpfResult.Pass)]
    public async Task All_qualifier_determines_the_default_result(string allTerm, SpfResult expected)
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", $"v=spf1 {allTerm}");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("198.51.100.5"), CancellationToken.None);

        result.Result.ShouldBe(expected);
    }

    [Fact]
    public async Task No_all_and_no_redirect_defaults_to_Neutral()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 ip4:203.0.113.0/24");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("198.51.100.5"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Neutral);
    }

    [Fact]
    public async Task An_a_mechanism_resolves_and_matches_the_domains_own_address()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 a -all");

        var dns = new FakeDnsResolver();
        dns.SetAddresses("example.com", "203.0.113.10");

        SpfEvaluationResult result = await CreateEvaluator(txt, dns)
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task An_mx_mechanism_matches_a_resolved_mx_hosts_address()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 mx -all");

        var dns = new FakeDnsResolver();
        dns.SetMx("example.com", "mail.example.com");
        dns.SetAddresses("mail.example.com", "203.0.113.20");

        SpfEvaluationResult result = await CreateEvaluator(txt, dns)
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.20"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task An_exists_mechanism_matches_when_the_constructed_name_resolves()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 exists:sentinel.example.com -all");

        var dns = new FakeDnsResolver();
        dns.SetAddresses("sentinel.example.com", "10.0.0.1");

        SpfEvaluationResult result = await CreateEvaluator(txt, dns)
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task An_include_whose_target_passes_makes_the_include_match()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 include:_spf.provider.example -all");
        txt.SetRecord("_spf.provider.example", "v=spf1 ip4:203.0.113.0/24 -all");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task An_include_whose_target_fails_falls_through_to_the_next_directive()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 include:_spf.provider.example ip4:198.51.100.0/24 -all");
        txt.SetRecord("_spf.provider.example", "v=spf1 -all");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("198.51.100.5"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task An_include_target_with_no_spf_record_is_a_PermError()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 include:missing.example -all");
        // missing.example has no SPF record at all.

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.PermError);
    }

    [Fact]
    public async Task A_redirect_evaluates_the_target_domains_record_as_the_overall_result()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 redirect=_spf.example.net");
        txt.SetRecord("_spf.example.net", "v=spf1 ip4:203.0.113.0/24 -all");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task A_redirect_target_with_no_record_is_a_PermError_not_a_None()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 redirect=missing.example");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.PermError);
    }

    [Fact]
    public async Task More_than_ten_include_mechanisms_is_a_PermError()
    {
        var txt = new FakeSpfTxtResolver();

        string includes = string.Join(' ', Enumerable.Range(1, 11).Select(i => $"include:p{i}.example"));
        txt.SetRecord("example.com", $"v=spf1 {includes} -all");

        for (int i = 1; i <= 11; i++)
        {
            txt.SetRecord($"p{i}.example", "v=spf1 -all");
        }

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.PermError);
        result.Diagnostic.ShouldNotBeNull().ShouldContain("10");
    }

    [Fact]
    public async Task More_than_two_void_lookups_is_a_PermError()
    {
        var txt = new FakeSpfTxtResolver();

        // Three "a" mechanisms against domains with no A/AAAA records at all: three void lookups.
        txt.SetRecord(
            "example.com",
            "v=spf1 a:void1.example a:void2.example a:void3.example -all");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.PermError);
        result.Diagnostic.ShouldNotBeNull().ShouldContain("void");
    }

    [Fact]
    public async Task A_temporary_dns_failure_on_the_top_level_record_is_TempError()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetTemporaryFailure("example.com");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.TempError);
    }

    [Fact]
    public async Task More_than_one_spf_record_at_a_domain_is_a_PermError()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRawRecords("example.com", ["v=spf1 -all", "v=spf1 +all"]);

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.PermError);
    }

    [Fact]
    public async Task A_malformed_record_is_a_PermError()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 bogus-mechanism -all");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.PermError);
    }

    [Fact]
    public async Task A_mechanism_using_a_macro_is_a_PermError()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRecord("example.com", "v=spf1 exists:%{i}.example.com -all");

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.PermError);
        result.Diagnostic.ShouldNotBeNull().ShouldContain("macro");
    }

    [Fact]
    public async Task An_unrelated_txt_record_alongside_the_spf_record_is_ignored()
    {
        var txt = new FakeSpfTxtResolver();
        txt.SetRawRecords("example.com", ["google-site-verification=abc123", "v=spf1 -all"]);

        SpfEvaluationResult result = await CreateEvaluator(txt, new FakeDnsResolver())
            .EvaluateAsync(Domain("example.com"), Ip("203.0.113.10"), CancellationToken.None);

        result.Result.ShouldBe(SpfResult.Fail);
    }

    // ---- Fakes ------------------------------------------------------------------------------

    private sealed class FakeSpfTxtResolver : ISpfTxtResolver
    {
        private readonly Dictionary<string, SpfTxtLookupResult> _results = new(StringComparer.OrdinalIgnoreCase);

        public void SetRecord(string domain, string record) => SetRawRecords(domain, [record]);

        public void SetRawRecords(string domain, IReadOnlyList<string> records) =>
            _results[domain] = SpfTxtLookupResult.Success(records);

        public void SetTemporaryFailure(string domain) =>
            _results[domain] = SpfTxtLookupResult.Temporary("simulated failure");

        public Task<SpfTxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(_results.GetValueOrDefault(domain, SpfTxtLookupResult.Success([])));
    }

    private sealed class FakeDnsResolver : IDnsResolver
    {
        private readonly Dictionary<string, IReadOnlyList<MxHost>> _mx = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, IReadOnlyList<IpAddressValue>> _addresses =
            new(StringComparer.OrdinalIgnoreCase);

        public void SetMx(string domain, params string[] hosts) =>
            _mx[domain] = [.. hosts.Select(h => new MxHost(h, 10))];

        public void SetAddresses(string hostname, params string[] addresses) =>
            _addresses[hostname] = [.. addresses.Select(IpAddressValue.Parse)];

        public Task<MxLookupResult> ResolveMxAsync(DomainName domain, CancellationToken cancellationToken) =>
            Task.FromResult(_mx.TryGetValue(domain.Value, out IReadOnlyList<MxHost>? hosts)
                ? MxLookupResult.Success(hosts)
                : MxLookupResult.Permanent("no MX record"));

        public Task<AddressLookupResult> ResolveAddressesAsync(string hostname, CancellationToken cancellationToken) =>
            Task.FromResult(_addresses.TryGetValue(hostname, out IReadOnlyList<IpAddressValue>? addresses)
                ? AddressLookupResult.Success(addresses)
                : AddressLookupResult.Permanent("no address record"));
    }
}
