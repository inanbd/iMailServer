using System.Text;
using MailServer.Application;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="ILocalDeliveryService"/>'s DMARC wiring: real DI, real SQLite, only the DMARC TXT
/// lookup replaced with a fake, so alignment and the reject-enforcement path can be exercised
/// without a network. <see cref="DmarcEvaluatorTests"/> covers the evaluation algorithm itself in
/// isolation.
/// </summary>
public sealed class LocalDeliveryDmarcVerificationTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-local-delivery-dmarc-tests",
        Guid.NewGuid().ToString("N"));

    private ServiceProvider _services = null!;

    private sealed class FakeDmarcTxtResolver : ITxtRecordResolver
    {
        private readonly Dictionary<string, TxtLookupResult> _results = new(StringComparer.OrdinalIgnoreCase);

        public void SetRecord(string name, string record) =>
            _results[name] = TxtLookupResult.Success([record]);

        public Task<TxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(_results.GetValueOrDefault(domain, TxtLookupResult.Success([])));
    }

    private readonly FakeDmarcTxtResolver _txtResolver = new();

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["MailServer:Server:Hostname"] = "mail.test.example",
                ["MailServer:Storage:DataRoot"] = _directory,
                ["MailServer:Database:Provider"] = "Sqlite",
                ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "delivery.db"),
                ["MailServer:Security:SecretProtection"] = "Development",
            })
            .Build();

        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddApplication();

        // Registered before AddInfrastructure so its TryAddSingleton<ITxtRecordResolver, ...>
        // finds one already present and leaves this fake in place - both SPF and DMARC's own
        // policy lookup share this same resolver, but no test here exercises SPF's own DNS path.
        services.TryAddSingleton<ITxtRecordResolver>(_txtResolver);

        // No DKIM signature is ever presented in these tests, so what the DKIM key resolver
        // would return never matters - only its absence from AddInfrastructure's own real
        // DNS-backed default would (which would attempt a real lookup this test cannot make).
        services.TryAddSingleton<IDkimPublicKeyResolver>(new NoOpPublicKeyResolver());

        services.AddInfrastructure(configuration, isProductionEnvironment: false);
        services.AddSqlitePersistence();

        _services = services.BuildServiceProvider();

        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        await scope.ServiceProvider
            .GetRequiredService<IDatabaseMigrator>()
            .MigrateAsync(CancellationToken.None);
    }

    public async Task DisposeAsync()
    {
        await _services.DisposeAsync();

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        try
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
    }

    private sealed class NoOpPublicKeyResolver : IDkimPublicKeyResolver
    {
        public Task<DkimPublicKeyLookupResult> ResolveAsync(
            DkimSelector selector, DomainName signingDomain, CancellationToken cancellationToken) =>
            Task.FromResult(DkimPublicKeyLookupResult.Permanent("no DKIM signature is ever presented in this test"));
    }

    private async Task<StoredMessageId> StoreAsync(byte[] content)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IMessageStore store = scope.ServiceProvider.GetRequiredService<IMessageStore>();

        await using IMessageWriter writer = await store.BeginWriteAsync(content.LongLength, CancellationToken.None);
        await writer.WriteAsync(content, CancellationToken.None);
        StoredMessage stored = await writer.CommitAsync(CancellationToken.None);
        return stored.Id;
    }

    private async Task<DeliveryResult> DeliverAsync(
        StoredMessageId messageId, byte[] content, SpfEvaluationOutcome? spfOutcome)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        ILocalDeliveryService delivery = scope.ServiceProvider.GetRequiredService<ILocalDeliveryService>();

        StoredMessage stored = new(
            messageId, content.LongLength,
            Sha256Hash.FromBytes(System.Security.Cryptography.SHA256.HashData(content)),
            DateTimeOffset.UtcNow);

        return await delivery.DeliverAsync(
            new DeliveryRequest(
                stored,
                EmailAddress.Parse("alice@example.com"),
                Recipients: [],
                IpAddressValue.Parse("203.0.113.10"),
                GreetedName: "mx.sender.example",
                SmtpListenerRole.InboundMta,
                TlsActive: true,
                AuthenticatedAs: null,
                spfOutcome),
            CancellationToken.None);
    }

    private async Task<(int? Result, int Disposition, string? PolicyDomain)?> QueryDmarcResultAsync(StoredMessageId messageId)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDbConnectionFactory connectionFactory = scope.ServiceProvider.GetRequiredService<IDbConnectionFactory>();

        await using System.Data.Common.DbConnection connection =
            await connectionFactory.OpenConnectionAsync(CancellationToken.None);

        return await Dapper.SqlMapper.QuerySingleOrDefaultAsync<(int?, int, string?)?>(
            connection,
            "SELECT Result, Disposition, PolicyDomain FROM DmarcVerificationResults WHERE MessageId = @Id",
            new { Id = messageId.Value });
    }

    private static byte[] Message(string fromAddress) => Encoding.ASCII.GetBytes(
        $"From: {fromAddress}\r\nTo: bob@destination.example\r\nSubject: Hi\r\n\r\nHello.\r\n");

    private async Task<DateTimeOffset?> QueryContentRemovedUtcAsync(StoredMessageId messageId)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDbConnectionFactory connectionFactory = scope.ServiceProvider.GetRequiredService<IDbConnectionFactory>();

        await using System.Data.Common.DbConnection connection =
            await connectionFactory.OpenConnectionAsync(CancellationToken.None);

        return await Dapper.SqlMapper.QuerySingleAsync<DateTimeOffset?>(
            connection, "SELECT ContentRemovedUtc FROM Messages WHERE Id = @Id", new { Id = messageId.Value });
    }

    private async Task<bool> ContentExistsAsync(StoredMessageId messageId)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IMessageStore store = scope.ServiceProvider.GetRequiredService<IMessageStore>();
        return await store.ExistsAsync(messageId, CancellationToken.None);
    }

    [Fact]
    public async Task A_message_failing_alignment_under_p_reject_is_rejected_and_delivers_to_nobody()
    {
        _txtResolver.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        byte[] content = Message("alice@example.com");
        StoredMessageId messageId = await StoreAsync(content);

        DeliveryResult result = await DeliverAsync(
            messageId, content, new SpfEvaluationOutcome(SpfResult.Fail, DomainName.Parse("example.com"), null));

        result.Rejection.ShouldNotBeNull();
        result.Rejection.PolicyDomain.Value.ShouldBe("example.com");
        result.Outcomes.ShouldBeEmpty();

        (int? dbResult, int disposition, string? policyDomain) = (await QueryDmarcResultAsync(messageId))!.Value;
        dbResult.ShouldBe((int)DmarcResult.Fail);
        disposition.ShouldBe((int)DmarcPolicy.Reject);
        policyDomain.ShouldBe("example.com");

        // A rejected message is never delivered anywhere, so its content is removed rather than
        // retained forever - see IDeliveryRepository.MarkContentRemovedAsync's own remarks.
        (await ContentExistsAsync(messageId)).ShouldBeFalse();
        (await QueryContentRemovedUtcAsync(messageId)).ShouldNotBeNull();
    }

    [Fact]
    public async Task A_message_passing_spf_alignment_is_accepted_and_records_a_pass()
    {
        _txtResolver.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        byte[] content = Message("alice@example.com");
        StoredMessageId messageId = await StoreAsync(content);

        DeliveryResult result = await DeliverAsync(
            messageId, content, new SpfEvaluationOutcome(SpfResult.Pass, DomainName.Parse("example.com"), null));

        result.Rejection.ShouldBeNull();

        (int? dbResult, int disposition, string? policyDomain) = (await QueryDmarcResultAsync(messageId))!.Value;
        dbResult.ShouldBe((int)DmarcResult.Pass);
        disposition.ShouldBe((int)DmarcPolicy.None);
        policyDomain.ShouldBe("example.com");
    }

    [Fact]
    public async Task A_message_failing_alignment_under_p_quarantine_is_accepted_and_records_the_disposition()
    {
        _txtResolver.SetRecord("_dmarc.example.com", "v=DMARC1; p=quarantine");

        byte[] content = Message("alice@example.com");
        StoredMessageId messageId = await StoreAsync(content);

        DeliveryResult result = await DeliverAsync(
            messageId, content, new SpfEvaluationOutcome(SpfResult.Fail, DomainName.Parse("example.com"), null));

        // Only p=reject blocks delivery at the SMTP level; p=quarantine is recorded but this
        // milestone does not itself move the message into a spam folder.
        result.Rejection.ShouldBeNull();

        (int? dbResult, int disposition, string? policyDomain) = (await QueryDmarcResultAsync(messageId))!.Value;
        dbResult.ShouldBe((int)DmarcResult.Fail);
        disposition.ShouldBe((int)DmarcPolicy.Quarantine);
    }

    [Fact]
    public async Task No_dmarc_record_published_delivers_normally_and_records_no_verdict()
    {
        byte[] content = Message("alice@example.com");
        StoredMessageId messageId = await StoreAsync(content);

        DeliveryResult result = await DeliverAsync(messageId, content, spfOutcome: null);

        result.Rejection.ShouldBeNull();

        (int? dbResult, int disposition, string? policyDomain) = (await QueryDmarcResultAsync(messageId))!.Value;
        dbResult.ShouldBeNull();
        disposition.ShouldBe((int)DmarcPolicy.None);
        policyDomain.ShouldBeNull();
    }

    [Fact]
    public async Task A_submission_message_is_never_evaluated_for_dmarc()
    {
        _txtResolver.SetRecord("_dmarc.example.com", "v=DMARC1; p=reject");

        byte[] content = Message("alice@example.com");
        StoredMessageId messageId = await StoreAsync(content);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        ILocalDeliveryService delivery = scope.ServiceProvider.GetRequiredService<ILocalDeliveryService>();

        StoredMessage stored = new(
            messageId, content.LongLength,
            Sha256Hash.FromBytes(System.Security.Cryptography.SHA256.HashData(content)),
            DateTimeOffset.UtcNow);

        DeliveryResult result = await delivery.DeliverAsync(
            new DeliveryRequest(
                stored,
                EmailAddress.Parse("alice@example.com"),
                Recipients: [],
                IpAddressValue.Parse("203.0.113.10"),
                GreetedName: "mx.sender.example",
                SmtpListenerRole.Submission,
                TlsActive: true,
                AuthenticatedAs: EmailAddress.Parse("alice@example.com")),
            CancellationToken.None);

        result.Rejection.ShouldBeNull();
        (await QueryDmarcResultAsync(messageId)).ShouldBeNull();
    }
}
