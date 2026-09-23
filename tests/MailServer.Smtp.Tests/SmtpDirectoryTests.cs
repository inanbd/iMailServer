using System.Data.Common;
using Dapper;
using MailServer.Application;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

/// <summary>
/// The directory, against a real database.
/// </summary>
/// <remarks>
/// It answers one question per RCPT TO and every answer becomes a reply code a sender acts on,
/// so each case here is one where a wrong answer either bounces mail that should have been
/// delivered or accepts mail that cannot be.
/// </remarks>
public sealed class SmtpDirectoryTests : IAsyncLifetime
{
    private const long ServerMaxMessageBytes = 36_700_160;

    private static readonly DateTimeOffset Now = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-directory",
        Guid.NewGuid().ToString("N"));

    private ServiceProvider _services = null!;
    private Guid _domainId;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["MailServer:Server:Hostname"] = "mail.example.com",
                ["MailServer:Storage:DataRoot"] = _directory,
                ["MailServer:Storage:MaxMessageSizeBytes"] = ServerMaxMessageBytes.ToString(),
                ["MailServer:Database:Provider"] = "Sqlite",
                ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "mail.db"),
                ["MailServer:Security:SecretProtection"] = "Development",
                ["MailServer:Smtp:AuthorizedRelayAddresses:0"] = "192.0.2.50",
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

        _domainId = Guid.NewGuid();

        await using DbConnection connection = await OpenAsync();

        // A domain quota well BELOW the server-wide message size limit, which is the ordinary
        // case and the one that used to break: a mailbox is not full merely because the largest
        // message the server would ever accept might not fit in it.
        await connection.ExecuteAsync(
            """
            INSERT INTO Domains (Id, Name, UnicodeName, Status, DefaultMailboxQuotaBytes, CreatedUtc)
            VALUES (@Id, 'example.com', 'example.com', 1, 1000000, @Now)
            """,
            new { Id = _domainId, Now });
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

    private Task<DbConnection> OpenAsync() =>
        _services.GetRequiredService<IDbConnectionFactory>().OpenConnectionAsync(CancellationToken.None);

    private async Task AddMailboxAsync(
        string localPart,
        int status = 1,
        long quotaBytes = 0,
        long usedBytes = 0)
    {
        await using DbConnection connection = await OpenAsync();

        await connection.ExecuteAsync(
            """
            INSERT INTO Mailboxes
                (Id, DomainId, LocalPart, Address, Status, QuotaBytes, StorageUsedBytes, CreatedUtc)
            VALUES (@Id, @DomainId, @LocalPart, @Address, @Status, @Quota, @Used, @Now)
            """,
            new
            {
                Id = Guid.NewGuid(),
                DomainId = _domainId,
                LocalPart = localPart,
                Address = $"{localPart}@example.com",
                Status = status,
                Quota = quotaBytes,
                Used = usedBytes,
                Now,
            });
    }

    private async Task AddAliasAsync(string localPart, bool enabled = true, params string[] targets)
    {
        await using DbConnection connection = await OpenAsync();

        await connection.ExecuteAsync(
            """
            INSERT INTO Aliases (Id, DomainId, LocalPart, Address, Targets, IsEnabled, CreatedUtc)
            VALUES (@Id, @DomainId, @LocalPart, @Address, @Targets, @Enabled, @Now)
            """,
            new
            {
                Id = Guid.NewGuid(),
                DomainId = _domainId,
                LocalPart = localPart,
                Address = $"{localPart}@example.com",
                Targets = string.Join('\n', targets),
                Enabled = enabled,
                Now,
            });
    }

    private async Task<T> WithDirectoryAsync<T>(Func<ISmtpDirectory, Task<T>> action)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        return await action(scope.ServiceProvider.GetRequiredService<ISmtpDirectory>());
    }

    private Task<bool> IsLocalAsync(string domain) =>
        WithDirectoryAsync(async d =>
            await d.IsLocalDomainAsync(DomainName.Parse(domain), default));

    private Task<LocalRecipientStatus> InspectAsync(string address) =>
        WithDirectoryAsync(async d =>
            await d.InspectLocalRecipientAsync(EmailAddress.Parse(address), default));

    // ---------------------------------------------------------------------------------------
    // Local domains.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_hosted_domain_is_local()
    {
        (await IsLocalAsync("example.com")).ShouldBeTrue();
    }

    [Fact]
    public async Task A_domain_we_do_not_host_is_not_local()
    {
        (await IsLocalAsync("elsewhere.example")).ShouldBeFalse();
    }

    [Fact]
    public async Task A_subdomain_of_a_hosted_domain_is_not_local()
    {
        // A different domain. Treating it as local would accept mail for names the operator
        // never configured, and there are a great many of them.
        (await IsLocalAsync("mail.example.com")).ShouldBeFalse();
        (await IsLocalAsync("sub.example.com")).ShouldBeFalse();
    }

    [Fact]
    public async Task A_disabled_domain_is_not_local()
    {
        // The relay policy then refuses it, which is the correct answer to "we no longer take
        // mail for that domain". Reporting it local would accept mail this server was told to
        // stop handling.
        await using (DbConnection connection = await OpenAsync())
        {
            await connection.ExecuteAsync(
                "UPDATE Domains SET Status = 0 WHERE Id = @Id",
                new { Id = _domainId });
        }

        (await IsLocalAsync("example.com")).ShouldBeFalse();
    }

    [Theory]
    [InlineData(0, DomainStatus.Pending)]
    [InlineData(1, DomainStatus.Active)]
    [InlineData(2, DomainStatus.Disabled)]
    [InlineData(3, DomainStatus.PendingDeletion)]
    public async Task A_configured_domain_reports_its_status_from_the_database(int stored, DomainStatus expected)
    {
        await using (DbConnection connection = await OpenAsync())
        {
            await connection.ExecuteAsync(
                "UPDATE Domains SET Status = @Status WHERE Id = @Id",
                new { Status = stored, Id = _domainId });
        }

        (await WithDirectoryAsync(async d =>
            await d.GetConfiguredDomainStatusAsync(DomainName.Parse("Example.COM"), default)))
            .ShouldBe(expected);
    }

    [Fact]
    public async Task A_domain_that_is_not_configured_has_no_status()
    {
        // Null, not Pending: "not ours" is the ordinary relay refusal, and mistaking a stranger's
        // domain for one being set up here would defer mail this server should refuse outright.
        (await WithDirectoryAsync(async d =>
            await d.GetConfiguredDomainStatusAsync(DomainName.Parse("elsewhere.example"), default)))
            .ShouldBeNull();
    }

    [Fact]
    public async Task Domain_matching_is_case_insensitive()
    {
        (await IsLocalAsync("EXAMPLE.COM")).ShouldBeTrue();
        (await IsLocalAsync("Example.Com")).ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // Mailboxes.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_empty_mailbox_whose_quota_is_smaller_than_the_message_limit_is_deliverable()
    {
        // The ordinary case, and the one that used to be reported as full. The server-wide size
        // limit is tens of megabytes and a typical quota is smaller, so a check of "would the
        // largest allowed message fit?" reports every mailbox full - including empty ones - and
        // the server refuses all mail with a 452 nobody can explain.
        await AddMailboxAsync("alice", quotaBytes: 1_000_000);

        ServerMaxMessageBytes.ShouldBeGreaterThan(1_000_000);

        (await InspectAsync("alice@example.com")).ShouldBe(LocalRecipientStatus.Deliverable);
    }

    [Fact]
    public async Task A_mailbox_inheriting_a_domain_quota_below_the_message_limit_is_deliverable()
    {
        // Same shape, reached through inheritance: quota 0 means "use the domain default", which
        // here is well below the server-wide message limit.
        await AddMailboxAsync("bob", quotaBytes: 0);

        (await InspectAsync("bob@example.com")).ShouldBe(LocalRecipientStatus.Deliverable);
    }

    [Fact]
    public async Task An_unknown_address_is_no_such_mailbox()
    {
        (await InspectAsync("nobody@example.com")).ShouldBe(LocalRecipientStatus.NoSuchMailbox);
    }

    [Fact]
    public async Task A_disabled_mailbox_reports_disabled()
    {
        await AddMailboxAsync("dormant", status: 0);

        (await InspectAsync("dormant@example.com")).ShouldBe(LocalRecipientStatus.Disabled);
    }

    [Fact]
    public async Task A_suspended_mailbox_still_accepts_mail()
    {
        // Suspension stops the owner logging in; it does not stop mail arriving. Refusing would
        // bounce a customer's mail over a billing state they can fix.
        await AddMailboxAsync("suspended", status: 2);

        (await InspectAsync("suspended@example.com")).ShouldBe(LocalRecipientStatus.Deliverable);
    }

    [Fact]
    public async Task A_mailbox_at_its_quota_is_full()
    {
        await AddMailboxAsync("full", quotaBytes: 1000, usedBytes: 1000);

        (await InspectAsync("full@example.com")).ShouldBe(LocalRecipientStatus.OverQuota);
    }

    [Fact]
    public async Task A_mailbox_just_below_its_quota_is_deliverable()
    {
        // The boundary in the accepting direction. A message that tips a mailbox past its quota
        // is accepted; the next one is not, which is how a quota works in practice.
        await AddMailboxAsync("nearly", quotaBytes: 1000, usedBytes: 999);

        (await InspectAsync("nearly@example.com")).ShouldBe(LocalRecipientStatus.Deliverable);
    }

    [Fact]
    public async Task A_mailbox_with_an_unlimited_quota_is_never_full()
    {
        await using (DbConnection connection = await OpenAsync())
        {
            await connection.ExecuteAsync(
                "UPDATE Domains SET DefaultMailboxQuotaBytes = 0 WHERE Id = @Id",
                new { Id = _domainId });
        }

        await AddMailboxAsync("boundless", quotaBytes: 0, usedBytes: 500_000_000);

        (await InspectAsync("boundless@example.com")).ShouldBe(LocalRecipientStatus.Deliverable);
    }

    // ---------------------------------------------------------------------------------------
    // Aliases.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_alias_for_a_deliverable_mailbox_is_deliverable()
    {
        // The sender addressed support@; whether that is one mailbox or five is none of its
        // business, and refusing would bounce mail to a perfectly good distribution list.
        await AddMailboxAsync("alice");
        await AddAliasAsync("support", true, "alice@example.com");

        (await InspectAsync("support@example.com")).ShouldBe(LocalRecipientStatus.Deliverable);
    }

    [Fact]
    public async Task An_alias_is_deliverable_if_any_target_is()
    {
        // Refusing because one member of a list is over quota would bounce the message for
        // everyone else on it, and the sender cannot do anything about somebody else's mailbox.
        await AddMailboxAsync("alice");
        await AddMailboxAsync("full", quotaBytes: 100, usedBytes: 100);
        await AddAliasAsync("team", true, "full@example.com", "alice@example.com");

        (await InspectAsync("team@example.com")).ShouldBe(LocalRecipientStatus.Deliverable);
    }

    [Fact]
    public async Task An_alias_whose_every_target_is_full_reports_a_transient_refusal()
    {
        // 452, not 550: the condition is fixable and the sender should keep the message.
        await AddMailboxAsync("full", quotaBytes: 100, usedBytes: 100);
        await AddAliasAsync("team", true, "full@example.com");

        (await InspectAsync("team@example.com")).ShouldBe(LocalRecipientStatus.OverQuota);
    }

    [Fact]
    public async Task A_disabled_alias_is_no_such_mailbox()
    {
        await AddMailboxAsync("alice");
        await AddAliasAsync("retired", false, "alice@example.com");

        (await InspectAsync("retired@example.com")).ShouldBe(LocalRecipientStatus.NoSuchMailbox);
    }

    [Fact]
    public async Task An_alias_chain_resolves()
    {
        await AddMailboxAsync("alice");
        await AddAliasAsync("staff", true, "alice@example.com");
        await AddAliasAsync("everyone", true, "staff@example.com");

        (await InspectAsync("everyone@example.com")).ShouldBe(LocalRecipientStatus.Deliverable);
    }

    [Fact]
    public async Task An_alias_cycle_terminates_rather_than_hanging()
    {
        await AddAliasAsync("loop-a", true, "loop-b@example.com");
        await AddAliasAsync("loop-b", true, "loop-a@example.com");

        (await InspectAsync("loop-a@example.com")).ShouldBe(LocalRecipientStatus.NoSuchMailbox);
    }

    [Fact]
    public async Task An_alias_pointing_only_at_nothing_is_no_such_mailbox()
    {
        await AddAliasAsync("ghost", true, "missing@example.com");

        (await InspectAsync("ghost@example.com")).ShouldBe(LocalRecipientStatus.NoSuchMailbox);
    }

    // ---------------------------------------------------------------------------------------
    // The relay allow-list.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_configured_address_is_on_the_relay_allow_list()
    {
        (await WithDirectoryAsync(async d =>
            await d.IsAuthorizedRelayAddressAsync(IpAddressValue.Parse("192.0.2.50"), default)))
            .ShouldBeTrue();
    }

    [Fact]
    public async Task An_address_not_configured_is_not_on_the_list()
    {
        // Including the neighbour one octet away. The list is addresses, not subnets: "the local
        // network" is exactly how an open relay gets configured by accident.
        (await WithDirectoryAsync(async d =>
            await d.IsAuthorizedRelayAddressAsync(IpAddressValue.Parse("192.0.2.51"), default)))
            .ShouldBeFalse();

        (await WithDirectoryAsync(async d =>
            await d.IsAuthorizedRelayAddressAsync(IpAddressValue.Parse("127.0.0.1"), default)))
            .ShouldBeFalse();
    }

    [Fact]
    public async Task An_ipv4_mapped_form_of_a_listed_address_is_recognised()
    {
        // Same host, different spelling. A string comparison would authorise one and refuse the
        // other depending on how the connection happened to arrive.
        (await WithDirectoryAsync(async d =>
            await d.IsAuthorizedRelayAddressAsync(IpAddressValue.Parse("::ffff:192.0.2.50"), default)))
            .ShouldBeTrue();
    }
}
