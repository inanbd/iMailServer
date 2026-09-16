using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Spf;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="SpfEvaluator"/> against the exact DNS zone and pass/fail expectations of RFC 7208
/// Appendix A ("Extended Examples") - the official vector, not just this suite's own
/// expectations. <see cref="SpfEvaluatorTests"/> covers the evaluator's own mechanics
/// (recursion, budgets, error translation) more broadly with ad hoc records.
/// </summary>
/// <remarks>
/// One example from Appendix A.1 is deliberately not reproduced here: <c>v=spf1 ptr -all</c>.
/// <see cref="SpfEvaluator"/> recognises the <c>ptr</c> mechanism so a record naming it does not
/// PermError, but never queries reverse DNS and never matches — see
/// <c>SpfMechanismType.Ptr</c>'s own remarks on why. <see cref="Ptr_never_matches_by_design"/>
/// documents that divergence from the RFC's example as a deliberate assertion instead of a
/// silently skipped vector.
/// </remarks>
public sealed class SpfRfc7208VectorTests
{
    // The DNS zone from RFC 7208 Appendix A: "these examples are based on the following DNS
    // setup". Reproduced exactly - MX/A records for example.com and example.org, and PTR records
    // (unused by this evaluator's ptr mechanism, but named here for the class remarks' benefit).
    private static SpfEvaluator CreateEvaluator(string spfRecord)
    {
        var txt = new FakeTxtRecordResolver();
        txt.SetRecord("example.com", spfRecord);

        var dns = new FakeDnsResolver();
        dns.SetMx("example.com", ("mail-a.example.com", 10), ("mail-b.example.com", 20));
        dns.SetAddresses("example.com", "192.0.2.10", "192.0.2.11");
        dns.SetAddresses("mail-a.example.com", "192.0.2.129");
        dns.SetAddresses("mail-b.example.com", "192.0.2.130");
        dns.SetAddresses("amy.example.com", "192.0.2.65");
        dns.SetAddresses("bob.example.com", "192.0.2.66");

        dns.SetMx("example.org", ("mail-c.example.org", 10));
        dns.SetAddresses("mail-c.example.org", "192.0.2.140");
        // example.org deliberately has no A records of its own - RFC 7208 Appendix A.1's
        // "a:example.org" example: "no sending hosts pass since example.org has no A records".

        return new SpfEvaluator(txt, dns, NullLogger<SpfEvaluator>.Instance);
    }

    private static async Task<SpfResult> EvaluateAsync(string spfRecord, string clientIp) =>
        (await CreateEvaluator(spfRecord).EvaluateAsync(
            DomainName.Parse("example.com"), IpAddressValue.Parse(clientIp), CancellationToken.None)).Result;

    [Fact]
    public async Task Plus_all_passes_any_ip()
    {
        (await EvaluateAsync("v=spf1 +all", "203.0.113.99")).ShouldBe(SpfResult.Pass);
    }

    [Theory]
    [InlineData("192.0.2.10")]
    [InlineData("192.0.2.11")]
    public async Task A_mechanism_passes_the_domains_own_addresses(string clientIp)
    {
        (await EvaluateAsync("v=spf1 a -all", clientIp)).ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task A_mechanism_fails_an_address_the_domain_does_not_publish()
    {
        (await EvaluateAsync("v=spf1 a -all", "192.0.2.65")).ShouldBe(SpfResult.Fail);
    }

    [Fact]
    public async Task A_colon_example_org_passes_nothing_because_example_org_has_no_a_records()
    {
        (await EvaluateAsync("v=spf1 a:example.org -all", "192.0.2.140")).ShouldBe(SpfResult.Fail);
    }

    [Theory]
    [InlineData("192.0.2.129")]
    [InlineData("192.0.2.130")]
    public async Task Mx_mechanism_passes_the_domains_mail_exchangers(string clientIp)
    {
        (await EvaluateAsync("v=spf1 mx -all", clientIp)).ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task Mx_colon_example_org_passes_its_mail_exchanger()
    {
        (await EvaluateAsync("v=spf1 mx:example.org -all", "192.0.2.140")).ShouldBe(SpfResult.Pass);
    }

    [Theory]
    [InlineData("192.0.2.129")]
    [InlineData("192.0.2.130")]
    [InlineData("192.0.2.140")]
    public async Task Combined_mx_mechanisms_pass_every_listed_exchanger(string clientIp)
    {
        (await EvaluateAsync("v=spf1 mx mx:example.org -all", clientIp)).ShouldBe(SpfResult.Pass);
    }

    [Theory]
    [InlineData("192.0.2.128")]
    [InlineData("192.0.2.131")]
    [InlineData("192.0.2.140")]
    [InlineData("192.0.2.143")]
    public async Task Mx_with_cidr_length_passes_the_whole_containing_subnet(string clientIp)
    {
        (await EvaluateAsync("v=spf1 mx/30 mx:example.org/30 -all", clientIp)).ShouldBe(SpfResult.Pass);
    }

    [Fact]
    public async Task Ip4_mechanism_fails_an_address_outside_its_declared_range()
    {
        (await EvaluateAsync("v=spf1 ip4:192.0.2.128/28 -all", "192.0.2.65")).ShouldBe(SpfResult.Fail);
    }

    [Fact]
    public async Task Ip4_mechanism_passes_an_address_inside_its_declared_range()
    {
        (await EvaluateAsync("v=spf1 ip4:192.0.2.128/28 -all", "192.0.2.129")).ShouldBe(SpfResult.Pass);
    }

    /// <summary>
    /// RFC 7208 Appendix A.1's <c>ptr</c> example expects host 192.0.2.65 (amy.example.com, whose
    /// forward and reverse DNS agree) to pass. This evaluator's <c>ptr</c> mechanism never
    /// queries reverse DNS at all - see this class's own remarks - so it never matches, and the
    /// record falls through to <c>-all</c> regardless of how clean the client's reverse DNS is.
    /// </summary>
    [Fact]
    public async Task Ptr_never_matches_by_design()
    {
        (await EvaluateAsync("v=spf1 ptr -all", "192.0.2.65")).ShouldBe(SpfResult.Fail);
    }

    private sealed class FakeTxtRecordResolver : ITxtRecordResolver
    {
        private readonly Dictionary<string, TxtLookupResult> _results = new(StringComparer.OrdinalIgnoreCase);

        public void SetRecord(string domain, string record) => _results[domain] = TxtLookupResult.Success([record]);

        public Task<TxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(_results.GetValueOrDefault(domain, TxtLookupResult.Success([])));
    }

    private sealed class FakeDnsResolver : IDnsResolver
    {
        private readonly Dictionary<string, IReadOnlyList<MxHost>> _mx = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, IReadOnlyList<IpAddressValue>> _addresses =
            new(StringComparer.OrdinalIgnoreCase);

        public void SetMx(string domain, params (string Hostname, int Preference)[] hosts) =>
            _mx[domain] = [.. hosts.Select(h => new MxHost(h.Hostname, h.Preference))];

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
