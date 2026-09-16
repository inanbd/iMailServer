using System.Security.Cryptography;
using System.Text;
using MailServer.Application;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure;
using MailServer.Infrastructure.Dkim;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="ILocalDeliveryService"/>'s DKIM verification wiring: real DI, real SQLite, only
/// the DNS public-key lookup replaced with a fake, so a message signed with a known key pair can
/// be checked against it without a network.
/// </summary>
public sealed class LocalDeliveryDkimVerificationTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-local-delivery-dkim-tests",
        Guid.NewGuid().ToString("N"));

    private ServiceProvider _services = null!;

    /// <summary>Swapped in before <c>AddInfrastructure</c> so its own <c>TryAddSingleton</c> leaves this in place.</summary>
    private sealed class FakePublicKeyResolver : IDkimPublicKeyResolver
    {
        public string? PublicKeyBase64 { get; set; }

        public Task<DkimPublicKeyLookupResult> ResolveAsync(
            DkimSelector selector, DomainName signingDomain, CancellationToken cancellationToken)
        {
            if (PublicKeyBase64 is null)
            {
                return Task.FromResult(DkimPublicKeyLookupResult.Permanent("no key configured for this test"));
            }

            DkimPublicKeyRecord.TryParse(
                $"v=DKIM1; k=rsa; p={PublicKeyBase64}", out DkimPublicKeyRecord? record, out _);

            return Task.FromResult(DkimPublicKeyLookupResult.Success(record!));
        }
    }

    private readonly FakePublicKeyResolver _resolver = new();

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

        // Registered before AddInfrastructure so its TryAddSingleton<IDkimPublicKeyResolver, ...>
        // finds one already present and leaves this fake in place.
        services.TryAddSingleton<IDkimPublicKeyResolver>(_resolver);

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

    private static (byte[] Pkcs8PrivateKey, string PublicKeyBase64) GenerateKeyPair()
    {
        using RSA rsa = RSA.Create(2048);
        return (rsa.ExportPkcs8PrivateKey(), Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()));
    }

    private static async Task<byte[]> SignAsync(string message, byte[] pkcs8PrivateKey)
    {
        byte[] buffer = Encoding.ASCII.GetBytes(message);
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out _);

        var signer = new DkimMessageSigner();
        using var bodyStream = new MemoryStream(buffer[headers!.HeaderBlockLength..]);

        DkimSignatureTags tags = await signer.SignAsync(
            headers, bodyStream, DomainName.Parse("example.com"), DkimSelector.Parse("mail202609"),
            pkcs8PrivateKey, new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero),
            cancellationToken: CancellationToken.None);

        return Encoding.ASCII.GetBytes($"DKIM-Signature: {tags.Compose()}\r\n" + message);
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

    private async Task DeliverAsync(StoredMessageId messageId, byte[] content, SmtpListenerRole role)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        ILocalDeliveryService delivery = scope.ServiceProvider.GetRequiredService<ILocalDeliveryService>();

        StoredMessage stored = new(
            messageId, content.LongLength,
            Sha256Hash.FromBytes(SHA256.HashData(content)),
            DateTimeOffset.UtcNow);

        await delivery.DeliverAsync(
            new DeliveryRequest(
                stored,
                EmailAddress.Parse("alice@example.com"),
                Recipients: [],
                IpAddressValue.Parse("203.0.113.10"),
                GreetedName: "mx.sender.example",
                role,
                TlsActive: true,
                AuthenticatedAs: null),
            CancellationToken.None);
    }

    private async Task<List<(int Result, string? SigningDomain)>> QueryDkimResultsAsync(StoredMessageId messageId)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDbConnectionFactory connectionFactory = scope.ServiceProvider.GetRequiredService<IDbConnectionFactory>();

        await using System.Data.Common.DbConnection connection =
            await connectionFactory.OpenConnectionAsync(CancellationToken.None);

        IEnumerable<(int Result, string? SigningDomain)> rows = await Dapper.SqlMapper.QueryAsync<(int, string?)>(
            connection,
            "SELECT Result, SigningDomain FROM DkimVerificationResults WHERE MessageId = @Id ORDER BY SignatureIndex",
            new { Id = messageId.Value });

        return [.. rows];
    }

    [Fact]
    public async Task A_validly_signed_inbound_message_records_a_Pass_result()
    {
        (byte[] privateKey, string publicKeyBase64) = GenerateKeyPair();
        _resolver.PublicKeyBase64 = publicKeyBase64;

        const string message =
            "From: Alice <alice@example.com>\r\n" +
            "To: bob@destination.example\r\n" +
            "Subject: Hi\r\n" +
            "Date: Wed, 16 Sep 2026 12:00:00 +0000\r\n" +
            "Message-ID: <abc@example.com>\r\n" +
            "\r\n" +
            "Hello, Bob!\r\n";

        byte[] signed = await SignAsync(message, privateKey);
        StoredMessageId messageId = await StoreAsync(signed);

        await DeliverAsync(messageId, signed, SmtpListenerRole.InboundMta);

        List<(int Result, string? SigningDomain)> results = await QueryDkimResultsAsync(messageId);

        results.Count.ShouldBe(1);
        results[0].Result.ShouldBe((int)DkimVerificationResult.Pass);
        results[0].SigningDomain.ShouldBe("example.com");
    }

    [Fact]
    public async Task An_unsigned_inbound_message_records_a_None_result()
    {
        const string message = "From: alice@example.com\r\nTo: bob@destination.example\r\n\r\nHello.\r\n";
        byte[] content = Encoding.ASCII.GetBytes(message);
        StoredMessageId messageId = await StoreAsync(content);

        await DeliverAsync(messageId, content, SmtpListenerRole.InboundMta);

        List<(int Result, string? SigningDomain)> results = await QueryDkimResultsAsync(messageId);

        results.Count.ShouldBe(1);
        results[0].Result.ShouldBe((int)DkimVerificationResult.None);
    }

    [Fact]
    public async Task A_submission_message_is_never_verified()
    {
        (byte[] privateKey, string publicKeyBase64) = GenerateKeyPair();
        _resolver.PublicKeyBase64 = publicKeyBase64;

        const string message = "From: alice@example.com\r\nTo: bob@destination.example\r\n\r\nHello.\r\n";
        byte[] signed = await SignAsync(message, privateKey);
        StoredMessageId messageId = await StoreAsync(signed);

        await DeliverAsync(messageId, signed, SmtpListenerRole.Submission);

        List<(int Result, string? SigningDomain)> results = await QueryDkimResultsAsync(messageId);

        results.ShouldBeEmpty();
    }
}
