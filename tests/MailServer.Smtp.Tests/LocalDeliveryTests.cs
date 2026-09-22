using System.Data.Common;
using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Application;
using MailServer.Infrastructure;
using MailServer.Infrastructure.Smtp;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

/// <summary>
/// Local delivery against a real SQLite database with the real migrations, so migration 0006's
/// constraints participate in every assertion rather than being taken on trust.
/// </summary>
public sealed class LocalDeliveryTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-delivery",
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
                ["MailServer:Database:Provider"] = "Sqlite",
                ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "mail.db"),
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

        _domainId = Guid.NewGuid();

        await using DbConnection connection = await OpenAsync();

        await connection.ExecuteAsync(
            """
            INSERT INTO Domains (Id, Name, UnicodeName, Status, DefaultMailboxQuotaBytes, CreatedUtc)
            VALUES (@Id, 'example.com', 'example.com', 1, 10000000, @Now)
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

    /// <summary>Creates a mailbox with an INBOX, the way mailbox administration does.</summary>
    private async Task<MailboxId> CreateMailboxAsync(string localPart, long quotaBytes = 0)
    {
        MailboxId mailboxId = MailboxId.New();

        await using DbConnection connection = await OpenAsync();

        await connection.ExecuteAsync(
            """
            INSERT INTO Mailboxes (Id, DomainId, LocalPart, Address, Status, QuotaBytes, CreatedUtc)
            VALUES (@Id, @DomainId, @LocalPart, @Address, 1, @Quota, @Now)
            """,
            new
            {
                Id = mailboxId.Value,
                DomainId = _domainId,
                LocalPart = localPart,
                Address = $"{localPart}@example.com",
                Quota = quotaBytes,
                Now,
            });

        await connection.ExecuteAsync(
            """
            INSERT INTO MailboxFolders (Id, MailboxId, Path, SpecialUse, UidValidity, NextUid, CreatedUtc)
            VALUES (@Id, @MailboxId, 'INBOX', 1, 1, 1, @Now)
            """,
            new
            {
                Id = Guid.NewGuid(),
                MailboxId = mailboxId.Value,
                Now,
            });

        return mailboxId;
    }

    private async Task CreateAliasAsync(string localPart, params string[] targets)
    {
        await using DbConnection connection = await OpenAsync();

        await connection.ExecuteAsync(
            """
            INSERT INTO Aliases (Id, DomainId, LocalPart, Address, Targets, IsEnabled, CreatedUtc)
            VALUES (@Id, @DomainId, @LocalPart, @Address, @Targets, 1, @Now)
            """,
            new
            {
                Id = Guid.NewGuid(),
                DomainId = _domainId,
                LocalPart = localPart,
                Address = $"{localPart}@example.com",
                Targets = string.Join('\n', targets),
                Now,
            });
    }

    /// <summary>Stores a message and delivers it, the way the session loop will.</summary>
    private async Task<DeliveryResult> DeliverAsync(
        string body,
        params (string Address, RelayDecision Decision)[] recipients)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        IMessageStore store = scope.ServiceProvider.GetRequiredService<IMessageStore>();

        StoredMessage stored;

        await using (IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default))
        {
            await writer.WriteAsync(System.Text.Encoding.UTF8.GetBytes(body), default);
            stored = await writer.CommitAsync(default);
        }

        DeliveryRequest request = new(
            stored,
            EmailAddress.Parse("sender@example.net"),
            [.. recipients.Select(r => new AcceptedRecipient(EmailAddress.Parse(r.Address), r.Decision))],
            IpAddressValue.Parse("198.51.100.20"),
            "relay.example.net",
            SmtpListenerRole.InboundMta,
            TlsActive: true,
            AuthenticatedAs: null);

        return await scope.ServiceProvider
            .GetRequiredService<ILocalDeliveryService>()
            .DeliverAsync(request, default);
    }

    private async Task<T> ScalarAsync<T>(string sql, object? parameters = null)
    {
        await using DbConnection connection = await OpenAsync();

        return (await connection.ExecuteScalarAsync<T>(sql, parameters))!;
    }

    // ---------------------------------------------------------------------------------------
    // The ordinary path.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_message_is_delivered_to_a_local_mailbox()
    {
        await CreateMailboxAsync("alice");

        DeliveryResult result = await DeliverAsync(
            "Subject: hi\r\n\r\nBody.\r\n",
            ("alice@example.com", RelayDecision.AcceptLocal));

        result.TotalDeliveries.ShouldBe(1);
        result.EverythingPlaced.ShouldBeTrue();

        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(1);
        (await ScalarAsync<int>("SELECT COUNT(*) FROM Messages")).ShouldBe(1);
        (await ScalarAsync<int>("SELECT COUNT(*) FROM MessageRecipients")).ShouldBe(1);
    }

    [Fact]
    public async Task The_envelope_is_recorded_not_the_headers()
    {
        // From: and To: are content the sender wrote and may have made up. Every later decision
        // - bounces, DMARC alignment, abuse investigation - needs the envelope, and by then the
        // headers are no substitute.
        await CreateMailboxAsync("alice");

        await DeliverAsync(
            "From: someone-else@lies.example\r\nTo: nobody@nowhere.example\r\n\r\nBody.\r\n",
            ("alice@example.com", RelayDecision.AcceptLocal));

        (await ScalarAsync<string>("SELECT ReversePath FROM Messages")).ShouldBe("sender@example.net");
        (await ScalarAsync<string>("SELECT Address FROM MessageRecipients")).ShouldBe("alice@example.com");
        (await ScalarAsync<string>("SELECT RemoteAddress FROM Messages")).ShouldBe("198.51.100.20");
        (await ScalarAsync<string>("SELECT GreetedName FROM Messages")).ShouldBe("relay.example.net");
    }

    [Fact]
    public async Task One_message_to_several_mailboxes_is_one_file_and_several_rows()
    {
        // Copying the content per recipient would triple the disk a distribution list costs and
        // make deduplication a background job that has to prove two files are identical.
        await CreateMailboxAsync("alice");
        await CreateMailboxAsync("bob");
        await CreateMailboxAsync("carol");

        DeliveryResult result = await DeliverAsync(
            "Subject: all hands\r\n\r\nBody.\r\n",
            ("alice@example.com", RelayDecision.AcceptLocal),
            ("bob@example.com", RelayDecision.AcceptLocal),
            ("carol@example.com", RelayDecision.AcceptLocal));

        result.TotalDeliveries.ShouldBe(3);

        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(3);
        (await ScalarAsync<int>("SELECT COUNT(DISTINCT MessageId) FROM Deliveries")).ShouldBe(1);

        Directory.EnumerateFiles(_directory, "*.eml", SearchOption.AllDirectories).Count().ShouldBe(1);
    }

    [Fact]
    public async Task Every_delivery_gets_its_own_uid_within_its_folder()
    {
        // The IMAP promise. A reused UID makes a client's cache serve the wrong message, with no
        // error anyone could report.
        await CreateMailboxAsync("alice");

        await DeliverAsync("one\r\n", ("alice@example.com", RelayDecision.AcceptLocal));
        await DeliverAsync("two\r\n", ("alice@example.com", RelayDecision.AcceptLocal));
        await DeliverAsync("three\r\n", ("alice@example.com", RelayDecision.AcceptLocal));

        await using DbConnection connection = await OpenAsync();

        long[] uids =
        [
            .. await connection.QueryAsync<long>("SELECT Uid FROM Deliveries ORDER BY Uid")
        ];

        uids.ShouldBe([1L, 2L, 3L]);
        (await ScalarAsync<long>("SELECT NextUid FROM MailboxFolders")).ShouldBe(4L);
    }

    [Fact]
    public async Task Quota_usage_is_charged_once_per_mailbox()
    {
        // The recipient's quota is about how much mail they are holding, not how many bytes are
        // on this server's disk. Two mailboxes sharing one file are each charged for it.
        MailboxId alice = await CreateMailboxAsync("alice");
        MailboxId bob = await CreateMailboxAsync("bob");

        const string Body = "Subject: shared\r\n\r\nBody.\r\n";

        await DeliverAsync(
            Body,
            ("alice@example.com", RelayDecision.AcceptLocal),
            ("bob@example.com", RelayDecision.AcceptLocal));

        long size = System.Text.Encoding.UTF8.GetByteCount(Body);

        (await ScalarAsync<long>(
            "SELECT StorageUsedBytes FROM Mailboxes WHERE Id = @Id",
            new { Id = alice.Value })).ShouldBe(size);

        (await ScalarAsync<long>(
            "SELECT StorageUsedBytes FROM Mailboxes WHERE Id = @Id",
            new { Id = bob.Value })).ShouldBe(size);
    }

    // ---------------------------------------------------------------------------------------
    // Aliases.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_alias_expands_to_its_targets()
    {
        await CreateMailboxAsync("alice");
        await CreateMailboxAsync("bob");
        await CreateAliasAsync("support", "alice@example.com", "bob@example.com");

        DeliveryResult result = await DeliverAsync(
            "Subject: help\r\n\r\nBody.\r\n",
            ("support@example.com", RelayDecision.AcceptLocal));

        result.TotalDeliveries.ShouldBe(2);
        result.Outcomes.Single().Address.Value.ShouldBe("support@example.com");
    }

    [Fact]
    public async Task The_recipient_row_names_the_address_the_sender_wrote_not_the_mailbox_behind_it()
    {
        // A bounce has to name the address the sender used. Naming the mailbox it resolved to
        // leaks an internal name and tells the sender nothing they can act on.
        await CreateMailboxAsync("alice");
        await CreateAliasAsync("support", "alice@example.com");

        await DeliverAsync("body\r\n", ("support@example.com", RelayDecision.AcceptLocal));

        (await ScalarAsync<string>("SELECT Address FROM MessageRecipients"))
            .ShouldBe("support@example.com");
    }

    [Fact]
    public async Task An_alias_chain_is_followed_to_its_mailboxes()
    {
        await CreateMailboxAsync("alice");
        await CreateAliasAsync("everyone", "staff@example.com");
        await CreateAliasAsync("staff", "alice@example.com");

        DeliveryResult result = await DeliverAsync(
            "body\r\n",
            ("everyone@example.com", RelayDecision.AcceptLocal));

        result.TotalDeliveries.ShouldBe(1);
    }

    [Fact]
    public async Task An_alias_cycle_does_not_hang_or_duplicate()
    {
        // An operator builds all@ from staff@ from everyone@ and creates a cycle without
        // noticing. Without the visited set this recurses until the process gives out, on the
        // delivery path, for every message.
        await CreateMailboxAsync("alice");
        await CreateAliasAsync("loop-a", "loop-b@example.com", "alice@example.com");
        await CreateAliasAsync("loop-b", "loop-a@example.com");

        DeliveryResult result = await DeliverAsync(
            "body\r\n",
            ("loop-a@example.com", RelayDecision.AcceptLocal));

        result.TotalDeliveries.ShouldBe(1);
        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(1);
    }

    [Fact]
    public async Task The_same_mailbox_reached_by_two_alias_paths_is_delivered_to_once()
    {
        // Two overlapping distribution lists are ordinary. A recipient on both must get one copy,
        // not two, and the expansion's distinctness is what guarantees it.
        await CreateMailboxAsync("alice");
        await CreateAliasAsync("team-a", "alice@example.com");
        await CreateAliasAsync("team-b", "alice@example.com");
        await CreateAliasAsync("everyone", "team-a@example.com", "team-b@example.com");

        DeliveryResult result = await DeliverAsync(
            "body\r\n",
            ("everyone@example.com", RelayDecision.AcceptLocal));

        result.TotalDeliveries.ShouldBe(1);
    }

    // ---------------------------------------------------------------------------------------
    // What does not get delivered.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_relay_recipient_is_recorded_but_not_delivered_locally()
    {
        // The outbound queue is Milestone 8. The recipient row exists either way, so the gap is
        // visible in the database rather than only in a comment.
        DeliveryResult result = await DeliverAsync(
            "body\r\n",
            ("partner@elsewhere.example", RelayDecision.AcceptRelay));

        result.TotalDeliveries.ShouldBe(0);
        result.Outcomes.Single().QueuedForRelay.ShouldBeTrue();
        result.EverythingPlaced.ShouldBeTrue();

        (await ScalarAsync<int>("SELECT COUNT(*) FROM MessageRecipients")).ShouldBe(1);
        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(0);
    }

    [Fact]
    public async Task A_disabled_mailbox_is_not_delivered_to_and_does_not_stop_the_others()
    {
        // One bad recipient must not cost the message its other deliveries: the sender was told
        // 250 for all of them.
        await CreateMailboxAsync("alice");
        MailboxId dormant = await CreateMailboxAsync("dormant");

        await using (DbConnection connection = await OpenAsync())
        {
            await connection.ExecuteAsync(
                "UPDATE Mailboxes SET Status = 0 WHERE Id = @Id",
                new { Id = dormant.Value });
        }

        DeliveryResult result = await DeliverAsync(
            "body\r\n",
            ("dormant@example.com", RelayDecision.AcceptLocal),
            ("alice@example.com", RelayDecision.AcceptLocal));

        result.TotalDeliveries.ShouldBe(1);
        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(1);
    }

    [Fact]
    public async Task A_suspended_mailbox_still_accepts_mail()
    {
        // Suspended stops the owner logging in; it does not stop mail arriving. Refusing
        // delivery would bounce a customer's mail over a billing state they can fix.
        MailboxId alice = await CreateMailboxAsync("alice");

        await using (DbConnection connection = await OpenAsync())
        {
            await connection.ExecuteAsync(
                "UPDATE Mailboxes SET Status = 2 WHERE Id = @Id",
                new { Id = alice.Value });
        }

        (await DeliverAsync("body\r\n", ("alice@example.com", RelayDecision.AcceptLocal)))
            .TotalDeliveries.ShouldBe(1);
    }

    [Fact]
    public async Task An_alias_pointing_at_nothing_records_the_recipient_and_delivers_nowhere()
    {
        await CreateAliasAsync("ghost", "missing@example.com");

        DeliveryResult result = await DeliverAsync(
            "body\r\n",
            ("ghost@example.com", RelayDecision.AcceptLocal));

        result.TotalDeliveries.ShouldBe(0);
        result.EverythingPlaced.ShouldBeFalse();

        (await ScalarAsync<int>("SELECT COUNT(*) FROM MessageRecipients")).ShouldBe(1);
    }

    [Fact]
    public async Task A_denied_recipient_cannot_be_delivered_at_all()
    {
        // Refused at RCPT TO, so it never reaches here. Asserted anyway: the domain type refuses
        // to construct one, which makes the schema's CHECK a second line of defence rather than
        // the only one.
        Should.Throw<ArgumentException>(() => MessageRecipient.Create(
            new StoredMessageId(Guid.NewGuid()),
            EmailAddress.Parse("victim@elsewhere.example"),
            RelayDecision.Deny));

        await Task.CompletedTask;
    }

    // ---------------------------------------------------------------------------------------
    // Ordering.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_content_file_exists_before_any_row_names_it()
    {
        // The recovery story. A crash between the two leaves an orphaned file, which a sweep
        // removes. The other ordering leaves a row naming a file that is not there, which is a
        // mailbox its owner cannot open and nothing can repair.
        await CreateMailboxAsync("alice");

        await DeliverAsync("body\r\n", ("alice@example.com", RelayDecision.AcceptLocal));

        Guid storedId = await ScalarAsync<Guid>("SELECT Id FROM Messages");

        string[] files =
        [
            .. Directory.EnumerateFiles(_directory, "*.eml", SearchOption.AllDirectories)
        ];

        files.Length.ShouldBe(1);
        files[0].ShouldContain(storedId.ToString("N"));
    }

    [Fact]
    public async Task The_recorded_size_and_hash_describe_the_file_on_disk()
    {
        await CreateMailboxAsync("alice");

        const string Body = "Subject: integrity\r\n\r\nBody.\r\n";

        await DeliverAsync(Body, ("alice@example.com", RelayDecision.AcceptLocal));

        string path = Directory.EnumerateFiles(_directory, "*.eml", SearchOption.AllDirectories).Single();

        (await ScalarAsync<long>("SELECT SizeBytes FROM Messages"))
            .ShouldBe(new FileInfo(path).Length);

        (await ScalarAsync<string>("SELECT ContentSha256 FROM Messages"))
            .ShouldBe(Convert.ToHexStringLower(
                System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(path))));
    }

    // ---------------------------------------------------------------------------------------
    // Releasing a held message. Milestone 12's exit criterion is a quarantine round trip, and
    // this is the half of it that has to actually put mail in a mailbox.
    // ---------------------------------------------------------------------------------------

    /// <summary>Stores a message and records its recipients without delivering it, as a hold does.</summary>
    private async Task<StoredMessage> HoldAsync(
        string body,
        params (string Address, RelayDecision Decision)[] recipients)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        IMessageStore store = scope.ServiceProvider.GetRequiredService<IMessageStore>();
        IDeliveryRepository deliveries = scope.ServiceProvider.GetRequiredService<IDeliveryRepository>();

        StoredMessage stored;

        await using (IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default))
        {
            await writer.WriteAsync(System.Text.Encoding.UTF8.GetBytes(body), default);
            stored = await writer.CommitAsync(default);
        }

        await deliveries.AddMessageAsync(
            MessageRecord.Create(
                stored.Id,
                stored.SizeBytes,
                stored.ContentHash,
                EmailAddress.Parse("sender@example.net"),
                IpAddressValue.Parse("198.51.100.20"),
                "relay.example.net",
                SmtpListenerRole.InboundMta,
                tlsActive: true,
                authenticatedAs: null,
                Now),
            default);

        foreach ((string address, RelayDecision decision) in recipients)
        {
            await deliveries.AddRecipientAsync(
                MessageRecipient.Create(stored.Id, EmailAddress.Parse(address), decision),
                default);
        }

        return stored;
    }

    private async Task<DeliveryResult> ReleaseAsync(StoredMessage stored)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        return await scope.ServiceProvider
            .GetRequiredService<ILocalDeliveryService>()
            .DeliverReleasedAsync(
                new ReleaseRequest(stored, EmailAddress.Parse("sender@example.net")), default);
    }

    [Fact]
    public async Task A_released_message_reaches_the_mailbox_it_was_held_for()
    {
        await CreateMailboxAsync("alice");

        StoredMessage stored = await HoldAsync(
            "Subject: held\r\n\r\nBody.\r\n",
            ("alice@example.com", RelayDecision.AcceptLocal));

        // Held means held: nothing is in any mailbox yet.
        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(0);

        DeliveryResult result = await ReleaseAsync(stored);

        result.TotalDeliveries.ShouldBe(1);
        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(1);
    }

    /// <summary>
    /// The recipients come from the rows the original delivery wrote, never from the message's
    /// own headers — a released message must not be able to name its own audience.
    /// </summary>
    [Fact]
    public async Task A_release_ignores_the_addresses_in_the_message_body()
    {
        await CreateMailboxAsync("alice");
        await CreateMailboxAsync("victim");

        StoredMessage stored = await HoldAsync(
            "From: x@lies.example\r\nTo: victim@example.com\r\n\r\nBody.\r\n",
            ("alice@example.com", RelayDecision.AcceptLocal));

        await ReleaseAsync(stored);

        MailboxId victim = new(await ScalarAsync<Guid>(
            "SELECT Id FROM Mailboxes WHERE LocalPart = 'victim'"));

        (await ScalarAsync<int>(
            "SELECT COUNT(*) FROM Deliveries WHERE MailboxId = @Id", new { Id = victim.Value }))
            .ShouldBe(0);
    }

    /// <summary>A release must not write the recipient rows again, or every release doubles them.</summary>
    [Fact]
    public async Task A_release_does_not_duplicate_the_recipient_rows()
    {
        await CreateMailboxAsync("alice");

        StoredMessage stored = await HoldAsync(
            "Subject: held\r\n\r\nBody.\r\n",
            ("alice@example.com", RelayDecision.AcceptLocal));

        await ReleaseAsync(stored);

        (await ScalarAsync<int>("SELECT COUNT(*) FROM MessageRecipients")).ShouldBe(1);
    }

    /// <summary>A release takes the same alias expansion an ordinary delivery does.</summary>
    [Fact]
    public async Task A_released_message_expands_an_alias()
    {
        await CreateMailboxAsync("alice");
        await CreateMailboxAsync("bob");
        await CreateAliasAsync("team", "alice@example.com", "bob@example.com");

        StoredMessage stored = await HoldAsync(
            "Subject: held\r\n\r\nBody.\r\n",
            ("team@example.com", RelayDecision.AcceptLocal));

        DeliveryResult result = await ReleaseAsync(stored);

        result.TotalDeliveries.ShouldBe(2);
        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(2);
    }

    /// <summary>And charges the quota the same way, per mailbox.</summary>
    [Fact]
    public async Task A_released_message_is_charged_against_the_quota()
    {
        await CreateMailboxAsync("alice", quotaBytes: 1_000_000);

        StoredMessage stored = await HoldAsync(
            "Subject: held\r\n\r\nBody.\r\n",
            ("alice@example.com", RelayDecision.AcceptLocal));

        (await ScalarAsync<long>("SELECT StorageUsedBytes FROM Mailboxes WHERE LocalPart = 'alice'"))
            .ShouldBe(0);

        await ReleaseAsync(stored);

        (await ScalarAsync<long>("SELECT StorageUsedBytes FROM Mailboxes WHERE LocalPart = 'alice'"))
            .ShouldBe(stored.SizeBytes);
    }

    /// <summary>
    /// A release whose recipients no longer exist reaches nobody, and says so rather than
    /// reporting a success the operator would believe.
    /// </summary>
    [Fact]
    public async Task A_release_to_a_mailbox_that_is_gone_delivers_nothing()
    {
        StoredMessage stored = await HoldAsync(
            "Subject: held\r\n\r\nBody.\r\n",
            ("nobody@example.com", RelayDecision.AcceptLocal));

        DeliveryResult result = await ReleaseAsync(stored);

        result.TotalDeliveries.ShouldBe(0);
        result.Outcomes.ShouldHaveSingleItem().MailboxesDelivered.ShouldBe(0);
    }

    /// <summary>A message held with no recipient rows at all is a repair problem, not a crash.</summary>
    [Fact]
    public async Task A_release_with_no_recipient_rows_delivers_nothing()
    {
        await CreateMailboxAsync("alice");

        StoredMessage stored = await HoldAsync("Subject: held\r\n\r\nBody.\r\n");

        DeliveryResult result = await ReleaseAsync(stored);

        result.Outcomes.ShouldBeEmpty();
        (await ScalarAsync<int>("SELECT COUNT(*) FROM Deliveries")).ShouldBe(0);
    }
}
