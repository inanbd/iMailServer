using DnsClient;
using DnsClient.Protocol;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dns;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Authentication.Tests;

/// <summary>
/// DKIM public key TXT lookup and classification, against a fake <see cref="IDkimDnsClient"/> -
/// the one method this resolver actually calls.
/// </summary>
public sealed class DnsDkimPublicKeyResolverTests
{
    private static DkimSelector Selector => DkimSelector.Parse("mail202609");
    private static DomainName Domain => DomainName.Parse("example.com");
    private const string ExpectedName = "mail202609._domainkey.example.com";

    [Fact]
    public async Task A_well_formed_record_resolves_successfully()
    {
        FakeDnsClient client = new();
        client.SetTxt(ExpectedName, "v=DKIM1; k=rsa; p=AAAAB3NzaC1yc2E=");

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Success);
        result.Record.ShouldNotBeNull();
        result.Record.PublicKeyBase64.ShouldBe("AAAAB3NzaC1yc2E=");
    }

    [Fact]
    public async Task Multiple_character_strings_in_one_record_are_concatenated_in_order()
    {
        FakeDnsClient client = new();
        client.SetTxtMultiString(ExpectedName, "v=DKIM1; k=rsa; p=AAAA", "B3NzaC1yc2E=");

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Success);
        result.Record!.PublicKeyBase64.ShouldBe("AAAAB3NzaC1yc2E=");
    }

    [Fact]
    public async Task Nxdomain_is_classified_as_permanent()
    {
        FakeDnsClient client = new();
        client.SetError(ExpectedName, DnsHeaderResponseCode.NotExistentDomain);

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
    }

    [Fact]
    public async Task No_txt_record_at_all_is_classified_as_permanent()
    {
        FakeDnsClient client = new();

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
    }

    [Fact]
    public async Task Servfail_is_classified_as_temporary()
    {
        FakeDnsClient client = new();
        client.SetError(ExpectedName, DnsHeaderResponseCode.ServerFailure);

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Temporary);
    }

    [Fact]
    public async Task A_thrown_dns_response_exception_is_classified_the_same_as_the_equivalent_response_code()
    {
        FakeDnsClient client = new();
        client.SetException(ExpectedName, new DnsResponseException(DnsResponseCode.NotExistentDomain, "nope"));

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
    }

    [Fact]
    public async Task A_transport_level_failure_is_classified_as_temporary_not_thrown()
    {
        FakeDnsClient client = new();
        client.SetException(ExpectedName, new InvalidOperationException("socket closed"));

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Temporary);
    }

    [Fact]
    public async Task More_than_one_txt_record_at_the_name_is_classified_as_permanent()
    {
        FakeDnsClient client = new();
        client.SetTxtRecords(
            ExpectedName,
            "v=DKIM1; k=rsa; p=AAAA",
            "v=DKIM1; k=rsa; p=BBBB");

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
        result.Diagnostic.ShouldNotBeNull().ShouldContain("2 TXT records");
    }

    [Fact]
    public async Task A_malformed_record_is_classified_as_permanent()
    {
        FakeDnsClient client = new();
        client.SetTxt(ExpectedName, "this is not a tag list");

        DnsDkimPublicKeyResolver resolver = new(client, NullLogger<DnsDkimPublicKeyResolver>.Instance);

        DkimPublicKeyLookupResult result = await resolver.ResolveAsync(Selector, Domain, CancellationToken.None);

        result.Status.ShouldBe(DnsLookupStatus.Permanent);
    }

    // ---- Fake -----------------------------------------------------------------------------

    private sealed class FakeDnsClient : IDkimDnsClient
    {
        private readonly Dictionary<string, FakeResponse> _responses = new();

        public void SetTxt(string name, string text) => SetTxtMultiString(name, text);

        public void SetTxtMultiString(string name, params string[] characterStrings) =>
            _responses[name] = FakeResponse.Success([BuildTxtRecord(name, characterStrings)]);

        public void SetTxtRecords(string name, params string[] oneStringPerRecord) =>
            _responses[name] = FakeResponse.Success(
                [.. oneStringPerRecord.Select(s => BuildTxtRecord(name, [s]))]);

        public void SetError(string name, DnsHeaderResponseCode code) =>
            _responses[name] = FakeResponse.Error(code);

        public void SetException(string name, Exception exception) =>
            _responses[name] = FakeResponse.Throws(exception);

        public Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken)
        {
            if (!_responses.TryGetValue(query, out FakeResponse? response))
            {
                response = FakeResponse.Success([]);
            }

            if (response.Exception is not null)
            {
                throw response.Exception;
            }

            return Task.FromResult<IDnsQueryResponse>(response!);
        }

        private static DnsResourceRecord BuildTxtRecord(string domain, IReadOnlyList<string> characterStrings) =>
            new TxtRecord(
                new ResourceRecordInfo(domain, ResourceRecordType.TXT, QueryClass.IN, 300, 0),
                [.. characterStrings],
                [.. characterStrings]);
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

        public DnsQuerySettings Settings => null!;

        public static FakeResponse Success(IReadOnlyList<DnsResourceRecord> answers) =>
            new() { Answers = answers, Header = new DnsResponseHeader(1, 0x8180, 1, answers.Count, 0, 0) };

        public static FakeResponse Error(DnsHeaderResponseCode code) =>
            new() { Header = new DnsResponseHeader(1, (ushort)(0x8180 | (int)code), 1, 0, 0, 0) };

        public static FakeResponse Throws(Exception exception) => new() { Exception = exception };
    }
}
