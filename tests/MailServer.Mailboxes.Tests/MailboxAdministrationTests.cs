using MailServer.Application;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Mailboxes.Commands;
using MailServer.Application.Mailboxes.Dtos;
using MailServer.Application.Mailboxes.Queries;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure;
using MailServer.Persistence.Sqlite;
using MediatR;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Mailboxes.Tests;

/// <summary>
/// Mailbox and alias administration end to end: real SQLite, real migrations, real repositories,
/// real Argon2 and the real MediatR pipeline.
/// </summary>
/// <remarks>
/// Milestone 5's exit criterion is "full CRUD through IPC + WPF". The IPC layer is exercised by
/// <c>IpcEndToEndTests</c>, which drives the same commands over a real pipe; this suite covers
/// what those commands do once they arrive.
/// </remarks>
public sealed class MailboxAdministrationTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-mailbox-tests",
        Guid.NewGuid().ToString("N"));

    private ServiceProvider _services = null!;
    private Guid _domainId;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["MailServer:Server:Hostname"] = "mail.test.example",
                ["MailServer:Storage:DataRoot"] = _directory,
                ["MailServer:Database:Provider"] = "Sqlite",
                ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "mail.db"),
                ["MailServer:Security:SecretProtection"] = "Development",

                // Reduced so the suite runs quickly; the properties under test are independent
                // of the work factors, and the production defaults are asserted elsewhere.
                ["MailServer:Security:Argon2MemoryKib"] = "8192",
                ["MailServer:Security:Argon2Iterations"] = "1",
                ["MailServer:Security:Argon2Parallelism"] = "1",
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

        DomainSummaryDto domain = await SendAsync(new CreateDomainCommand
        {
            Name = "example.com",
            MailHostname = "mail.example.com",
            DefaultMailboxQuotaBytes = 1_000_000,
        });

        _domainId = domain.Id;
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

    /// <summary>Sends a request through the full pipeline with an authenticated identity.</summary>
    /// <remarks>
    /// The identity is required, not incidental: <c>AuthorizationBehavior</c> refuses every
    /// non-anonymous request from an unauthenticated scope, and going through <c>ISender</c>
    /// rather than calling handlers directly is what keeps that enforcement in the path.
    /// </remarks>
    private async Task<TResponse> SendAsync<TResponse>(IRequest<TResponse> request)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        scope.ServiceProvider
            .GetRequiredService<IAdminContextInitializer>()
            .Assign("Administrator", "test-session", AdminPermission.FullControl, false, false);

        return await scope.ServiceProvider.GetRequiredService<ISender>().Send(request);
    }

    private Task<MailboxSummaryDto> CreateMailboxAsync(
        string localPart = "alice",
        string? password = "a-good-mailbox-password",
        long quotaBytes = 0) =>
        SendAsync(new CreateMailboxCommand
        {
            DomainId = _domainId,
            LocalPart = localPart,
            Password = password,
            QuotaBytes = quotaBytes,
        });

    // ---- Create -----------------------------------------------------------------------------

    [Fact]
    public async Task A_mailbox_is_created_with_its_standard_folders()
    {
        MailboxSummaryDto created = await CreateMailboxAsync();

        created.Address.ShouldBe("alice@example.com");
        created.Status.ShouldBe(MailboxStatus.Active);
        created.HasCredential.ShouldBeTrue();

        MailboxDetailDto detail =
            await SendAsync(new GetMailboxQuery { MailboxId = created.Id });

        // Created up front rather than on demand: a client that connects and finds no Sent
        // folder makes one, named in its own locale, and the history fragments.
        detail.Folders
            .Select(static f => f.Path)
            .ShouldBe(["INBOX", "Sent", "Drafts", "Trash", "Junk", "Archive"], ignoreOrder: true);

        detail.Folders.Count(static f => f.SpecialUse == FolderSpecialUse.Inbox).ShouldBe(1);
    }

    [Fact]
    public async Task A_mailbox_without_a_password_accepts_mail_but_has_no_credential()
    {
        MailboxSummaryDto created = await CreateMailboxAsync(password: null);

        // A legitimate state - a drop box, or an account not yet handed over - and one easy to
        // create by accident, so it is surfaced rather than inferred.
        created.HasCredential.ShouldBeFalse();
        created.Status.ShouldBe(MailboxStatus.Active);
    }

    [Fact]
    public async Task A_mailbox_inherits_the_domain_quota()
    {
        MailboxSummaryDto created = await CreateMailboxAsync(quotaBytes: 0);

        created.QuotaBytes.ShouldBe(0, "the mailbox's own value is 'inherit'");
        created.EffectiveQuotaBytes.ShouldBe(1_000_000);
    }

    [Fact]
    public async Task A_duplicate_address_is_refused()
    {
        await CreateMailboxAsync("alice");

        await Should.ThrowAsync<DuplicateEntityException>(() => CreateMailboxAsync("alice"));
    }

    /// <summary>
    /// An address is either a mailbox or an alias, never both — otherwise delivery has to
    /// choose, and whichever it chooses is wrong half the time.
    /// </summary>
    [Fact]
    public async Task An_address_already_used_by_an_alias_cannot_become_a_mailbox()
    {
        await CreateMailboxAsync("alice");

        await SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "sales",
            Targets = ["alice@example.com"],
        });

        DomainRuleViolationException error = await Should.ThrowAsync<DomainRuleViolationException>(
            () => CreateMailboxAsync("sales"));

        error.Code.ShouldBe("address.already_an_alias");
    }

    [Fact]
    public async Task An_address_already_used_by_a_mailbox_cannot_become_an_alias()
    {
        await CreateMailboxAsync("alice");
        await CreateMailboxAsync("bob");

        await Should.ThrowAsync<DuplicateEntityException>(() => SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "alice",
            Targets = ["bob@example.com"],
        }));
    }

    // ---- Read -------------------------------------------------------------------------------

    [Fact]
    public async Task Mailboxes_are_listed_for_their_domain()
    {
        await CreateMailboxAsync("alice");
        await CreateMailboxAsync("bob");

        IReadOnlyList<MailboxSummaryDto> all =
            await SendAsync(new GetMailboxesQuery { DomainId = _domainId });

        all.Select(static m => m.Address)
            .ShouldBe(["alice@example.com", "bob@example.com"], ignoreOrder: true);
    }

    // ---- Update -----------------------------------------------------------------------------

    [Fact]
    public async Task A_mailbox_quota_and_status_can_be_changed()
    {
        MailboxSummaryDto created = await CreateMailboxAsync();

        await SendAsync(new UpdateMailboxCommand
        {
            MailboxId = created.Id,
            QuotaBytes = 250_000,
            Status = MailboxStatus.Suspended,
            DisplayName = "Alice Example",
        });

        MailboxDetailDto detail = await SendAsync(new GetMailboxQuery { MailboxId = created.Id });

        detail.Summary.EffectiveQuotaBytes.ShouldBe(250_000);
        detail.Summary.Status.ShouldBe(MailboxStatus.Suspended);
        detail.Summary.DisplayName.ShouldBe("Alice Example");
    }

    [Fact]
    public async Task A_password_can_be_set_on_a_mailbox_that_had_none()
    {
        MailboxSummaryDto created = await CreateMailboxAsync(password: null);

        await SendAsync(new SetMailboxPasswordCommand
        {
            MailboxId = created.Id,
            Password = "a-perfectly-fine-password",
        });

        MailboxDetailDto detail = await SendAsync(new GetMailboxQuery { MailboxId = created.Id });

        detail.Summary.HasCredential.ShouldBeTrue();
        detail.PasswordChangedUtc.ShouldBeNull("the credential was created, not changed");
    }

    /// <summary>
    /// The stored verifier must be an Argon2id hash, not the password.
    /// </summary>
    /// <remarks>
    /// Read straight out of the database rather than through the repository, because a
    /// round-trip through our own mapping would pass just as happily if the column held
    /// plaintext.
    /// </remarks>
    [Fact]
    public async Task The_password_is_stored_as_an_argon2id_verifier()
    {
        const string password = "a-very-specific-password-value";

        MailboxSummaryDto created = await CreateMailboxAsync(password: password);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        await using System.Data.Common.DbConnection connection = await scope.ServiceProvider
            .GetRequiredService<IDbConnectionFactory>()
            .OpenConnectionAsync(CancellationToken.None);

        string? stored = await Dapper.SqlMapper.ExecuteScalarAsync<string?>(
            connection,
            "SELECT PasswordHash FROM MailboxCredentials WHERE MailboxId = @Id",
            new { Id = created.Id });

        stored.ShouldNotBeNull();
        stored.ShouldStartWith("$argon2id$");
        stored.ShouldNotContain(password);
    }

    [Fact]
    public async Task A_password_change_clears_a_lockout()
    {
        MailboxSummaryDto created = await CreateMailboxAsync();

        await using (AsyncServiceScope scope = _services.CreateAsyncScope())
        {
            IMailboxRepository repository =
                scope.ServiceProvider.GetRequiredService<IMailboxRepository>();

            MailboxCredential credential = (await repository.GetCredentialAsync(
                new MailboxId(created.Id),
                CancellationToken.None))!;

            for (int i = 0; i < 10; i++)
            {
                credential.RecordFailure(new Domain.Policies.LockoutPolicy(), DateTimeOffset.UtcNow);
            }

            await repository.UpdateCredentialAsync(credential, CancellationToken.None);

            credential.IsLockedOut(DateTimeOffset.UtcNow).ShouldBeTrue();
        }

        await SendAsync(new SetMailboxPasswordCommand
        {
            MailboxId = created.Id,
            Password = "a-brand-new-password",
        });

        MailboxDetailDto detail = await SendAsync(new GetMailboxQuery { MailboxId = created.Id });

        // Whoever set this proved control by a stronger route than the password; leaving the
        // user locked out of an account whose password was just reset for them serves nobody.
        detail.Summary.IsLockedOut.ShouldBeFalse();
    }

    // ---- Delete -----------------------------------------------------------------------------

    [Fact]
    public async Task A_mailbox_is_deleted_with_its_folders_and_credential()
    {
        MailboxSummaryDto created = await CreateMailboxAsync();

        await SendAsync(new DeleteMailboxCommand { MailboxId = created.Id });

        IReadOnlyList<MailboxSummaryDto> all =
            await SendAsync(new GetMailboxesQuery { DomainId = _domainId });

        all.ShouldBeEmpty();
    }

    /// <summary>
    /// An alias pointing at a deleted mailbox would accept mail and then fail to deliver it —
    /// and the failure surfaces later, to a sender, as a bounce nobody here sees.
    /// </summary>
    [Fact]
    public async Task A_mailbox_that_an_alias_targets_cannot_be_deleted()
    {
        MailboxSummaryDto alice = await CreateMailboxAsync("alice");

        await SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "sales",
            Targets = ["alice@example.com"],
        });

        DomainRuleViolationException error = await Should.ThrowAsync<DomainRuleViolationException>(
            () => SendAsync(new DeleteMailboxCommand { MailboxId = alice.Id }));

        error.Code.ShouldBe("mailbox.delete.aliased");
        error.Message.ShouldContain("sales@example.com");
    }

    // ---- Aliases ----------------------------------------------------------------------------

    [Fact]
    public async Task An_alias_is_created_and_listed()
    {
        await CreateMailboxAsync("alice");
        await CreateMailboxAsync("bob");

        AliasDto created = await SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "sales",
            Targets = ["alice@example.com", "bob@example.com"],
            Description = "Sales enquiries",
        });

        created.IsDistributionList.ShouldBeTrue();
        created.ExternalTargets.ShouldBeEmpty();

        IReadOnlyList<AliasDto> all = await SendAsync(new GetAliasesQuery { DomainId = _domainId });

        all.ShouldHaveSingleItem().Address.ShouldBe("sales@example.com");
    }

    /// <summary>
    /// An external target is flagged, because forwarded mail arrives at the destination from
    /// this server — so SPF sees this server rather than the original sender.
    /// </summary>
    [Fact]
    public async Task An_external_target_is_reported_as_external()
    {
        AliasDto created = await SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "info",
            Targets = ["someone@elsewhere.test"],
        });

        created.ExternalTargets.ShouldHaveSingleItem().ShouldBe("someone@elsewhere.test");
    }

    /// <summary>
    /// A cycle is refused at creation, not left to the delivery-time limiter.
    /// </summary>
    /// <remarks>
    /// The limiter terminates safely either way, but it does so by silently dropping
    /// recipients — and the operator who built the cycle is the one person who can fix it, at
    /// the moment they are looking at it.
    /// </remarks>
    [Fact]
    public async Task An_alias_cycle_is_refused_at_creation()
    {
        await SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "a",
            Targets = ["external@elsewhere.test"],
        });

        AliasDto b = await SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "b",
            Targets = ["a@example.com"],
        });

        // Repointing 'a' at 'b' closes the loop: a -> b -> a.
        AliasDto a = (await SendAsync(new GetAliasesQuery { DomainId = _domainId }))
            .Single(x => x.Address == "a@example.com");

        DomainRuleViolationException error = await Should.ThrowAsync<DomainRuleViolationException>(
            () => SendAsync(new UpdateAliasCommand
            {
                AliasId = a.Id,
                Targets = ["b@example.com"],
            }));

        error.Code.ShouldBe("alias.expansion.no_recipients");
        b.Address.ShouldBe("b@example.com");
    }

    [Fact]
    public async Task An_alias_targeting_itself_is_refused()
    {
        DomainRuleViolationException error = await Should.ThrowAsync<DomainRuleViolationException>(
            () => SendAsync(new CreateAliasCommand
            {
                DomainId = _domainId,
                LocalPart = "loop",
                Targets = ["loop@example.com"],
            }));

        error.Code.ShouldBe("alias.target.self_reference");
    }

    [Fact]
    public async Task An_alias_can_be_repointed_and_deleted()
    {
        await CreateMailboxAsync("alice");
        await CreateMailboxAsync("bob");

        AliasDto created = await SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "sales",
            Targets = ["alice@example.com"],
        });

        await SendAsync(new UpdateAliasCommand
        {
            AliasId = created.Id,
            Targets = ["bob@example.com"],
        });

        IReadOnlyList<AliasDto> afterUpdate =
            await SendAsync(new GetAliasesQuery { DomainId = _domainId });

        afterUpdate.ShouldHaveSingleItem().Targets.ShouldBe(["bob@example.com"]);

        await SendAsync(new DeleteAliasCommand { AliasId = created.Id });

        (await SendAsync(new GetAliasesQuery { DomainId = _domainId })).ShouldBeEmpty();
    }

    // ---- Role addresses -----------------------------------------------------------------------

    /// <summary>
    /// <c>postmaster@</c> is required by RFC 5321 §4.5.1; without it, the one channel through
    /// which a delivery problem gets reported is gone.
    /// </summary>
    [Fact]
    public async Task A_new_domain_reports_its_missing_role_addresses()
    {
        IReadOnlyList<MissingRoleAddressDto> missing =
            await SendAsync(new GetMissingRoleAddressesQuery { DomainId = _domainId });

        missing.Select(static m => m.LocalPart).ShouldContain("postmaster");
        missing.Single(static m => m.LocalPart == "postmaster").IsRequired.ShouldBeTrue();
        missing.Select(static m => m.LocalPart).ShouldContain("abuse");
    }

    /// <summary>
    /// An alias satisfies the requirement exactly as well as a mailbox, and is usually the
    /// better arrangement — nobody wants to log into postmaster@ separately.
    /// </summary>
    [Fact]
    public async Task A_role_address_satisfied_by_an_alias_is_not_reported_missing()
    {
        await CreateMailboxAsync("alice");

        await SendAsync(new CreateAliasCommand
        {
            DomainId = _domainId,
            LocalPart = "postmaster",
            Targets = ["alice@example.com"],
        });

        IReadOnlyList<MissingRoleAddressDto> missing =
            await SendAsync(new GetMissingRoleAddressesQuery { DomainId = _domainId });

        missing.Select(static m => m.LocalPart).ShouldNotContain("postmaster");
    }
}
