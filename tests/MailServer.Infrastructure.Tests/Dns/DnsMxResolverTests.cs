using DnsClient;
using DnsClient.Protocol;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dns;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Infrastructure.Tests.Dns;

/// <summary>
/// MX resolution and classification, against a fake <see cref="IMxDnsClient"/> - the one method
/// this resolver actually calls, per <see cref="IMxDnsClient"/>'s own remarks on why it exists
/// separately from the much larger <c>DnsClient.IDnsQuery</c>.
/// </summary>
public sealed class DnsMxResolverTests
{
    private static DomainName Domain(string name) => DomainName.Parse(name);

    [Fact]
    public async Task Mx_records_are_returned_in_priority_order_as_published()
    {
        FakeDnsClient client = new();
        client.SetMx(
            "example.com",
            new FakeMxAnswer("mx2.example.com", 20),
            new FakeMxAnswer("mx1.example.com", 10));

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Success);
        result.Hosts.Select(h => (h.Hostname, h.Preference)).ShouldBe(
        [
            ("mx2.example.com", 20),
            ("mx1.example.com", 10),
        ]);
    }

    [Fact]
    public async Task A_trailing_dot_is_trimmed_from_the_exchange_hostname()
    {
        FakeDnsClient client = new();
        client.SetMx("example.com", new FakeMxAnswer("mail.example.com.", 10));

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Hosts[0].Hostname.ShouldBe("mail.example.com");
    }

    [Fact]
    public async Task Nxdomain_is_classified_as_permanent()
    {
        FakeDnsClient client = new();
        client.SetError("example.com", QueryType.MX, DnsHeaderResponseCode.NotExistentDomain);

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
        result.Hosts.ShouldBeEmpty();
    }

    [Fact]
    public async Task Servfail_is_classified_as_temporary()
    {
        FakeDnsClient client = new();
        client.SetError("example.com", QueryType.MX, DnsHeaderResponseCode.ServerFailure);

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Temporary);
    }

    [Fact]
    public async Task A_thrown_dns_response_exception_is_classified_the_same_as_the_equivalent_response_code()
    {
        FakeDnsClient client = new();
        client.SetException("example.com", QueryType.MX, new DnsResponseException(DnsResponseCode.NotExistentDomain, "nope"));

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
    }

    [Fact]
    public async Task A_transport_level_failure_is_classified_as_temporary_not_thrown()
    {
        FakeDnsClient client = new();
        client.SetException("example.com", QueryType.MX, new InvalidOperationException("socket closed"));

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Temporary);
    }

    [Fact]
    public async Task A_null_mx_is_an_immediate_permanent_failure()
    {
        FakeDnsClient client = new();
        client.SetMx("example.com", new FakeMxAnswer(".", 0));

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
        result.Diagnostic.ShouldNotBeNull().ShouldContain("null MX");
    }

    [Fact]
    public async Task No_mx_record_falls_back_to_the_domains_own_address_record()
    {
        FakeDnsClient client = new();
        client.SetMx("example.com"); // NOERROR, no records
        client.SetAddresses("example.com", "203.0.113.10");

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Success);
        result.Hosts.ShouldBe([new MxHost("example.com", 0)]);
    }

    [Fact]
    public async Task No_mx_and_no_address_record_is_a_permanent_failure()
    {
        FakeDnsClient client = new();
        client.SetMx("example.com");
        client.SetAddresses("example.com");

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        MxLookupResult result = await resolver.ResolveMxAsync(Domain("example.com"), CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
    }

    [Fact]
    public async Task Address_resolution_combines_a_and_aaaa_records()
    {
        FakeDnsClient client = new();
        client.SetAddresses("mail.example.com", "203.0.113.10", "2001:db8::1");

        DnsMxResolver resolver = new(client, NullLogger<DnsMxResolver>.Instance);

        AddressLookupResult result = await resolver.ResolveAddressesAsync("mail.example.com", CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Success);
        result.Addresses.Select(a => a.Value).ShouldBe(["203.0.113.10", "2001:db8::1"], ignoreOrder: true);
    }

    // ---- Fakes --------------------------------------------------------------------------------

    private sealed record FakeMxAnswer(string Exchange, int Preference);

    private sealed class FakeDnsClient : IMxDnsClient
    {
        private readonly Dictionary<(string Name, QueryType Type), FakeResponse> _responses = new();

        public void SetMx(string name, params FakeMxAnswer[] records) =>
            _responses[(name, QueryType.MX)] = FakeResponse.Success(
                [.. records.Select(r => (DnsResourceRecord)BuildMxRecord(name, r.Exchange, r.Preference))]);

        public void SetAddresses(string name, params string[] addresses)
        {
            List<DnsResourceRecord> aRecords = [];
            List<DnsResourceRecord> aaaaRecords = [];

            foreach (string address in addresses)
            {
                System.Net.IPAddress ip = System.Net.IPAddress.Parse(address);

                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    aRecords.Add(BuildARecord(name, ip));
                }
                else
                {
                    aaaaRecords.Add(BuildAaaaRecord(name, ip));
                }
            }

            _responses[(name, QueryType.A)] = FakeResponse.Success(aRecords);
            _responses[(name, QueryType.AAAA)] = FakeResponse.Success(aaaaRecords);
        }

        public void SetError(string name, QueryType type, DnsHeaderResponseCode code) =>
            _responses[(name, type)] = FakeResponse.Error(code);

        public void SetException(string name, QueryType type, Exception exception) =>
            _responses[(name, type)] = FakeResponse.Throws(exception);

        public Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken)
        {
            if (!_responses.TryGetValue((query, queryType), out FakeResponse? response))
            {
                response = FakeResponse.Success([]);
            }

            if (response.Exception is not null)
            {
                throw response.Exception;
            }

            return Task.FromResult<IDnsQueryResponse>(response!);
        }

        private static MxRecord BuildMxRecord(string domain, string exchange, int preference) =>
            new(
                new ResourceRecordInfo(domain, ResourceRecordType.MX, QueryClass.IN, 300, 0),
                (ushort)preference,
                DnsString.Parse(exchange));

        private static ARecord BuildARecord(string domain, System.Net.IPAddress address) =>
            new(new ResourceRecordInfo(domain, ResourceRecordType.A, QueryClass.IN, 300, 0), address);

        private static AaaaRecord BuildAaaaRecord(string domain, System.Net.IPAddress address) =>
            new(new ResourceRecordInfo(domain, ResourceRecordType.AAAA, QueryClass.IN, 300, 0), address);
    }

    private sealed class FakeResponse : IDnsQueryResponse
    {
        private FakeResponse() { }

        public Exception? Exception { get; private init; }

        public IReadOnlyList<DnsQuestion> Questions => [];

        public IReadOnlyList<DnsResourceRecord> Additionals => [];

        public IEnumerable<DnsResourceRecord> AllRecords => Answers;

        public IReadOnlyList<DnsResourceRecord> Answers { get; private init; } = [];

        public IReadOnlyList<DnsResourceRecord> Authorities => [];

        public string AuditTrail => string.Empty;

        public string ErrorMessage => HasError ? $"{Header.ResponseCode}" : string.Empty;

        public bool HasError => Header.ResponseCode != DnsHeaderResponseCode.NoError;

        public DnsResponseHeader Header { get; private init; } = new(0, 0, 0, 0, 0, 0);

        public int MessageSize => 0;

        public NameServer? NameServer => null;

        // DnsQuerySettings and DnsQueryOptions expose no public constructor; nothing this
        // resolver does reads this property, so a null (suppressed) is a correct fake, not a
        // corner cut - there is no real value this test could construct instead.
        public DnsQuerySettings Settings => null!;

        public static FakeResponse Success(IReadOnlyList<DnsResourceRecord> answers) =>
            new() { Answers = answers, Header = new DnsResponseHeader(1, 0x8180, 1, answers.Count, 0, 0) };

        public static FakeResponse Error(DnsHeaderResponseCode code) =>
            new() { Header = new DnsResponseHeader(1, (ushort)(0x8180 | (int)code), 1, 0, 0, 0) };

        public static FakeResponse Throws(Exception exception) => new() { Exception = exception };
    }
}
