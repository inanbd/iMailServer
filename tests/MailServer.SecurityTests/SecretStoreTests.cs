using MailServer.Application;
using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Security;
using MailServer.Infrastructure;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.SecurityTests;

/// <summary>
/// The secret store, against a real database and a real protector.
/// </summary>
/// <remarks>
/// <para>
/// The property that matters is not that a value can be written and read back — any dictionary
/// does that. It is that <b>what reaches the database is not the value</b>. A test that only
/// round-trips through the store's own API would pass just as happily if the protector were
/// removed, so these tests read the stored column directly.
/// </para>
/// <para>
/// The protector here is <c>DevelopmentSecretProtector</c>, because DPAPI is Windows-only and
/// this suite must run on the build agent. That protector refuses to start in Production and
/// logs at Critical, and the DPAPI path is exercised by the Windows CI leg. What these tests
/// pin down is the storage contract both protectors sit behind.
/// </para>
/// </remarks>
public sealed class SecretStoreTests : IAsyncLifetime
{
    private const string SecretName = "Test.Secret";
    private const string SecretValue = "correct-horse-battery-staple";

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-secret-tests",
        Guid.NewGuid().ToString("N"));

    private ServiceProvider _services = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["MailServer:Server:Hostname"] = "mail.test.example",
                ["MailServer:Storage:DataRoot"] = _directory,
                ["MailServer:Database:Provider"] = "Sqlite",
                ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "secrets.db"),
                ["MailServer:Security:SecretProtection"] = "Development",
            })
            .Build();

        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddApplication();
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

    private ISecretStore Store => _services.GetRequiredService<ISecretStore>();

    private async Task<string?> ReadStoredColumnAsync()
    {
        await using System.Data.Common.DbConnection connection = await _services
            .GetRequiredService<IDbConnectionFactory>()
            .OpenConnectionAsync(CancellationToken.None);

        return await connection.ExecuteScalarAsync<string?>(
            "SELECT ProtectedValue FROM ProtectedSecrets WHERE SecretName = @Name",
            new { Name = SecretName });
    }

    [Fact]
    public async Task A_secret_round_trips()
    {
        await Store.SetAsync(SecretName, SecretValue, "a test secret", CancellationToken.None);

        string? read = await Store.GetAsync(SecretName, CancellationToken.None);

        read.ShouldBe(SecretValue);
    }

    [Fact]
    public async Task The_plaintext_never_reaches_the_database()
    {
        await Store.SetAsync(SecretName, SecretValue, null, CancellationToken.None);

        string? stored = await ReadStoredColumnAsync();

        stored.ShouldNotBeNull();
        stored.ShouldNotBe(SecretValue);
        stored.ShouldNotContain(SecretValue);
    }

    [Fact]
    public async Task A_missing_secret_reads_as_null_rather_than_throwing()
    {
        (await Store.GetAsync("Nothing.Stored.Here", CancellationToken.None)).ShouldBeNull();
    }

    [Fact]
    public async Task Setting_the_same_name_twice_replaces_the_value()
    {
        await Store.SetAsync(SecretName, "first", null, CancellationToken.None);
        await Store.SetAsync(SecretName, "second", null, CancellationToken.None);

        (await Store.GetAsync(SecretName, CancellationToken.None)).ShouldBe("second");

        IReadOnlyList<SecretDescriptor> all = await Store.ListAsync(CancellationToken.None);

        all.Count(d => d.Name == SecretName).ShouldBe(1);
    }

    [Fact]
    public async Task Existence_can_be_checked_without_decrypting()
    {
        (await Store.ExistsAsync(SecretName, CancellationToken.None)).ShouldBeFalse();

        await Store.SetAsync(SecretName, SecretValue, null, CancellationToken.None);

        (await Store.ExistsAsync(SecretName, CancellationToken.None)).ShouldBeTrue();
    }

    [Fact]
    public async Task Removing_a_secret_reports_whether_it_was_there()
    {
        (await Store.RemoveAsync(SecretName, CancellationToken.None)).ShouldBeFalse();

        await Store.SetAsync(SecretName, SecretValue, null, CancellationToken.None);

        (await Store.RemoveAsync(SecretName, CancellationToken.None)).ShouldBeTrue();
        (await Store.GetAsync(SecretName, CancellationToken.None)).ShouldBeNull();
    }

    /// <summary>
    /// The listing is the one path a UI is likely to call, so it must be metadata only. If a
    /// secret value ever appears here, it will be rendered somewhere.
    /// </summary>
    [Fact]
    public async Task Listing_returns_metadata_and_no_values()
    {
        await Store.SetAsync(SecretName, SecretValue, "a test secret", CancellationToken.None);

        IReadOnlyList<SecretDescriptor> all = await Store.ListAsync(CancellationToken.None);

        SecretDescriptor descriptor = all.ShouldHaveSingleItem();

        descriptor.Name.ShouldBe(SecretName);
        descriptor.Description.ShouldBe("a test secret");
        descriptor.ProtectionScheme.ShouldNotBeNullOrWhiteSpace();

        // SecretDescriptor has no value member at all; this asserts the type, not the instance,
        // so adding one later fails here rather than leaking quietly.
        typeof(SecretDescriptor)
            .GetProperties()
            .Select(p => p.Name)
            .ShouldNotContain("Value");
    }

    [Fact]
    public async Task An_oversized_value_is_refused()
    {
        string oversized = new('x', Infrastructure.Security.DatabaseSecretStore.MaxValueLength + 1);

        await Should.ThrowAsync<ArgumentException>(
            () => Store.SetAsync(SecretName, oversized, null, CancellationToken.None));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task A_blank_name_is_refused(string name)
    {
        await Should.ThrowAsync<ArgumentException>(
            () => Store.GetAsync(name, CancellationToken.None));
    }
}
