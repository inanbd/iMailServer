using MailServer.Application;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="DkimKeyRepository"/> against a real SQLite database: real migrations, real
/// encryption via the development <c>ISecretProtector</c>, real foreign key to a real
/// <see cref="MailDomain"/> row.
/// </summary>
public sealed class DkimKeyRepositoryTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-dkim-repository-tests",
        Guid.NewGuid().ToString("N"));

    private ServiceProvider _services = null!;
    private DomainId _domainId;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["MailServer:Server:Hostname"] = "mail.test.example",
                ["MailServer:Storage:DataRoot"] = _directory,
                ["MailServer:Database:Provider"] = "Sqlite",
                ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "dkim.db"),
                ["MailServer:Security:SecretProtection"] = "Development",
            })
            .Build();

        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddApplication();
        services.AddInfrastructure(configuration, isProductionEnvironment: false);
        services.AddSqlitePersistence();

        _services = services.BuildServiceProvider();

        await using AsyncServiceScope migrateScope = _services.CreateAsyncScope();
        await migrateScope.ServiceProvider
            .GetRequiredService<IDatabaseMigrator>()
            .MigrateAsync(CancellationToken.None);

        await using AsyncServiceScope setupScope = _services.CreateAsyncScope();
        IClock clock = setupScope.ServiceProvider.GetRequiredService<IClock>();

        MailDomain domain = MailDomain.Create(
            DomainId.New(), DomainName.Parse("example.com"), clock.UtcNow);
        _domainId = domain.Id;

        await setupScope.ServiceProvider
            .GetRequiredService<IDomainRepository>()
            .AddAsync(domain, CancellationToken.None);
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

    private static DkimKey NewKey(DomainId domainId, string selector, DateTimeOffset now) =>
        DkimKey.Generate(
            domainId,
            DkimSelector.Parse(selector),
            DkimKeyAlgorithm.RsaSha256,
            publicKeyBase64: "AAAAB3NzaC1yc2EAAAADAQAB",
            keyLengthBits: 2048,
            now);

    [Fact]
    public async Task A_key_and_its_private_key_round_trip_through_a_real_database()
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDkimKeyRepository repository = scope.ServiceProvider.GetRequiredService<IDkimKeyRepository>();
        IClock clock = scope.ServiceProvider.GetRequiredService<IClock>();

        DkimKey key = NewKey(_domainId, "mail202609", clock.UtcNow);
        byte[] privateKey = [1, 2, 3, 4, 5, 6, 7, 8];

        await repository.AddAsync(key, privateKey, CancellationToken.None);

        DkimKey? reloaded = await repository.GetAsync(key.Id, CancellationToken.None);

        reloaded.ShouldNotBeNull();
        reloaded.DomainId.ShouldBe(_domainId);
        reloaded.Selector.ShouldBe(DkimSelector.Parse("mail202609"));
        reloaded.Algorithm.ShouldBe(DkimKeyAlgorithm.RsaSha256);
        reloaded.PublicKeyBase64.ShouldBe(key.PublicKeyBase64);
        reloaded.KeyLengthBits.ShouldBe(2048);
        reloaded.Status.ShouldBe(DkimKeyStatus.Generated);

        byte[]? reloadedPrivateKey = await repository.GetPrivateKeyAsync(key.Id, CancellationToken.None);
        reloadedPrivateKey.ShouldBe(privateKey);
    }

    [Fact]
    public async Task The_stored_private_key_is_encrypted_at_rest_not_stored_as_plaintext()
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDkimKeyRepository repository = scope.ServiceProvider.GetRequiredService<IDkimKeyRepository>();
        IClock clock = scope.ServiceProvider.GetRequiredService<IClock>();
        IDbConnectionFactory connectionFactory = scope.ServiceProvider.GetRequiredService<IDbConnectionFactory>();

        DkimKey key = NewKey(_domainId, "mail202609", clock.UtcNow);
        byte[] privateKey = "-----BEGIN PRIVATE KEY-----plaintextmarker"u8.ToArray();

        await repository.AddAsync(key, privateKey, CancellationToken.None);

        await using System.Data.Common.DbConnection connection =
            await connectionFactory.OpenConnectionAsync(CancellationToken.None);

        object? stored = await Dapper.SqlMapper.ExecuteScalarAsync(
            connection,
            "SELECT ProtectedPrivateKey FROM DkimPrivateKeys WHERE DkimKeyId = @Id",
            new { Id = key.Id.Value });

        stored.ShouldBeOfType<byte[]>();
        ((byte[])stored!).ShouldNotBe(privateKey);
    }

    [Fact]
    public async Task GetActiveForDomain_returns_only_the_active_key()
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDkimKeyRepository repository = scope.ServiceProvider.GetRequiredService<IDkimKeyRepository>();
        IClock clock = scope.ServiceProvider.GetRequiredService<IClock>();
        DateTimeOffset now = clock.UtcNow;

        DkimKey generated = NewKey(_domainId, "mail202608", now);
        await repository.AddAsync(generated, [1], CancellationToken.None);

        DkimKey active = NewKey(_domainId, "mail202609", now);
        active.Publish(now);
        active.Activate(now);
        await repository.AddAsync(active, [2], CancellationToken.None);

        DkimKey? result = await repository.GetActiveForDomainAsync(_domainId, CancellationToken.None);

        result.ShouldNotBeNull();
        result.Id.ShouldBe(active.Id);
    }

    [Fact]
    public async Task GetActiveForDomain_returns_null_when_no_key_is_active()
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDkimKeyRepository repository = scope.ServiceProvider.GetRequiredService<IDkimKeyRepository>();

        DkimKey? result = await repository.GetActiveForDomainAsync(_domainId, CancellationToken.None);

        result.ShouldBeNull();
    }

    [Fact]
    public async Task Update_persists_a_status_transition()
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDkimKeyRepository repository = scope.ServiceProvider.GetRequiredService<IDkimKeyRepository>();
        IClock clock = scope.ServiceProvider.GetRequiredService<IClock>();
        DateTimeOffset now = clock.UtcNow;

        DkimKey key = NewKey(_domainId, "mail202609", now);
        await repository.AddAsync(key, [1], CancellationToken.None);

        key.Publish(now);
        await repository.UpdateAsync(key, CancellationToken.None);

        DkimKey? reloaded = await repository.GetAsync(key.Id, CancellationToken.None);

        reloaded.ShouldNotBeNull();
        reloaded.Status.ShouldBe(DkimKeyStatus.Published);
        reloaded.PublishedUtc.ShouldBe(now);
    }

    [Fact]
    public async Task Remove_deletes_both_the_metadata_and_the_private_key()
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDkimKeyRepository repository = scope.ServiceProvider.GetRequiredService<IDkimKeyRepository>();
        IClock clock = scope.ServiceProvider.GetRequiredService<IClock>();

        DkimKey key = NewKey(_domainId, "mail202609", clock.UtcNow);
        await repository.AddAsync(key, [1], CancellationToken.None);

        await repository.RemoveAsync(key.Id, CancellationToken.None);

        (await repository.GetAsync(key.Id, CancellationToken.None)).ShouldBeNull();
        (await repository.GetPrivateKeyAsync(key.Id, CancellationToken.None)).ShouldBeNull();
    }

    [Fact]
    public async Task GetForDomain_returns_every_key_for_that_domain_in_creation_order()
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        IDkimKeyRepository repository = scope.ServiceProvider.GetRequiredService<IDkimKeyRepository>();
        IClock clock = scope.ServiceProvider.GetRequiredService<IClock>();
        DateTimeOffset now = clock.UtcNow;

        DkimKey first = NewKey(_domainId, "mail202608", now);
        await repository.AddAsync(first, [1], CancellationToken.None);

        DkimKey second = NewKey(_domainId, "mail202609", now.AddDays(1));
        await repository.AddAsync(second, [2], CancellationToken.None);

        IReadOnlyList<DkimKey> keys = await repository.GetForDomainAsync(_domainId, CancellationToken.None);

        keys.Count.ShouldBe(2);
        keys[0].Id.ShouldBe(first.Id);
        keys[1].Id.ShouldBe(second.Id);
    }
}
