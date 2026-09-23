using MailServer.Application;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

/// <summary>
/// One database of mailboxes, shared by every authenticator test.
/// </summary>
/// <remarks>
/// Shared because the setup is the expensive part — a migration and five Argon2id hashes, which
/// are slow on purpose — and nothing any test does changes the mailboxes. Failure counters do
/// change, but no test fails a single mailbox often enough to reach a lockout.
/// </remarks>
public sealed class AuthenticatorDatabase : IAsyncLifetime
{
    public const string Password = "correct-horse-battery-staple";

    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), "aethermail-auth", Guid.NewGuid().ToString("N"));

    internal CountingSecurityEventRecorder Events { get; } = new();

    public ServiceProvider Services { get; private set; } = null!;

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
        services.AddSingleton<ISecurityEventRecorder>(Events);

        Services = services.BuildServiceProvider();

        await using AsyncServiceScope scope = Services.CreateAsyncScope();

        await scope.ServiceProvider
            .GetRequiredService<IDatabaseMigrator>()
            .MigrateAsync(CancellationToken.None);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        IPasswordHasher hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        IMailboxRepository mailboxes = scope.ServiceProvider.GetRequiredService<IMailboxRepository>();

        MailDomain domain = MailDomain.Create(
            DomainId.New(), DomainName.Parse("example.com"), now, DomainName.Parse("mail.example.com"));

        await scope.ServiceProvider.GetRequiredService<IDomainRepository>().AddAsync(domain, CancellationToken.None);

        foreach ((string localPart, MailboxAccess access) in new[]
        {
            ("everything", MailboxAccess.All),
            ("default", MailboxAccess.Imap | MailboxAccess.Submission),
            ("imaponly", MailboxAccess.Imap),
            ("sendonly", MailboxAccess.Submission),
            ("poponly", MailboxAccess.Pop3),
        })
        {
            Mailbox mailbox = Mailbox.Create(
                domain.Id, EmailAddress.Parse($"{localPart}@example.com"), domain, null, QuotaBytes.Unlimited, access, now);

            await mailboxes.AddAsync(mailbox, CancellationToken.None);
            await mailboxes.AddCredentialAsync(
                MailboxCredential.Create(mailbox.Id, hasher.Hash(Password), mustChangePassword: false, now),
                CancellationToken.None);
        }
    }

    public async Task DisposeAsync()
    {
        await Services.DisposeAsync();

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
    }
}

/// <summary>
/// The real <c>MailboxAuthenticator</c>, over real SQLite and real Argon2id verifiers.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are the first tests of the real class, and their absence is how a bug lived for
/// three milestones.</b> Submission, IMAP and POP3 were each tested against a scripted
/// authenticator that never looks at access flags, and the real one — written for submission —
/// checked the submission flag for every protocol. An IMAP-only mailbox could not read its mail,
/// a send-only service account could read and delete mail over IMAP and POP3, and the POP3 flag
/// was never consulted at all. It was found by running the server with real clients.
/// </para>
/// <para>
/// Each mailbox is given one combination of flags and asked for by each protocol, so the whole
/// grid is pinned rather than the one cell that happened to be noticed.
/// </para>
/// </remarks>
public sealed class MailboxAuthenticatorTests(AuthenticatorDatabase database) : IClassFixture<AuthenticatorDatabase>
{
    private const string Password = AuthenticatorDatabase.Password;

    private static readonly IpAddressValue Peer = IpAddressValue.Parse("198.51.100.20");

    /// <summary>Local part, and the access that mailbox was given.</summary>
    public static TheoryData<string, MailboxAccess, bool> Grid => new()
    {
        // Every combination of mailbox and protocol, with whether sign-in must succeed.
        { "everything", MailboxAccess.Imap, true },
        { "everything", MailboxAccess.Pop3, true },
        { "everything", MailboxAccess.Submission, true },

        // The console's default for a new mailbox: IMAP and submission, and deliberately not POP3.
        { "default", MailboxAccess.Imap, true },
        { "default", MailboxAccess.Pop3, false },
        { "default", MailboxAccess.Submission, true },

        { "imaponly", MailboxAccess.Imap, true },
        { "imaponly", MailboxAccess.Pop3, false },
        { "imaponly", MailboxAccess.Submission, false },

        // A send-only service account — a printer, an application's noreply — must never be a
        // way to read, let alone delete, the mailbox's mail.
        { "sendonly", MailboxAccess.Imap, false },
        { "sendonly", MailboxAccess.Pop3, false },
        { "sendonly", MailboxAccess.Submission, true },

        { "poponly", MailboxAccess.Imap, false },
        { "poponly", MailboxAccess.Pop3, true },
        { "poponly", MailboxAccess.Submission, false },
    };

    private async Task<MailboxAuthenticationResult> SignInAsync(
        string localPart,
        MailboxAccess protocol,
        string password = Password)
    {
        await using AsyncServiceScope scope = database.Services.CreateAsyncScope();

        using SaslCredential credential = new($"{localPart}@example.com", string.Empty, password.ToCharArray());

        return await scope.ServiceProvider
            .GetRequiredService<IMailboxAuthenticator>()
            .AuthenticateAsync(credential, protocol, Peer, CancellationToken.None);
    }

    /// <summary>Starts an events assertion from nothing: the recorder is shared by the class.</summary>
    private async Task Isolate()
    {
        await database.Events.FlushAsync(CancellationToken.None);
        database.Events.Written.Clear();
    }

    [Theory]
    [MemberData(nameof(Grid))]
    public async Task Grants_exactly_the_access_the_mailbox_was_given(
        string localPart,
        MailboxAccess protocol,
        bool allowed)
    {
        MailboxAuthenticationResult result = await SignInAsync(localPart, protocol);

        result.IsSuccess.ShouldBe(allowed, $"{localPart} asking for {protocol}: {result.Diagnostic}");
    }

    /// <summary>
    /// A refusal for access looks exactly like a wrong password from outside.
    /// </summary>
    /// <remarks>
    /// Anything else tells whoever holds the password that the mailbox exists and what it may
    /// do, which is information about the account worth denying even to someone who knows it.
    /// </remarks>
    [Fact]
    public async Task A_refusal_for_access_is_an_ordinary_failure()
    {
        MailboxAuthenticationResult refused = await SignInAsync("sendonly", MailboxAccess.Imap);
        MailboxAuthenticationResult wrong = await SignInAsync("sendonly", MailboxAccess.Imap, "not-the-password");

        refused.Outcome.ShouldBe(MailboxAuthenticationOutcome.Failed);
        wrong.Outcome.ShouldBe(MailboxAuthenticationOutcome.Failed);
        refused.Mailbox.ShouldBeNull();
    }

    /// <summary>The audit trail names the protocol that signed in, not the one this was written for.</summary>
    [Fact]
    public async Task The_security_event_names_the_protocol()
    {
        await Isolate();

        await SignInAsync("everything", MailboxAccess.Imap);
        await SignInAsync("everything", MailboxAccess.Pop3);
        await database.Events.FlushAsync(CancellationToken.None);

        string[] successes =
        [
            .. database.Events.Written
                .Where(e => e.Type == SecurityEventType.MailboxAuthenticationSucceeded)
                .Select(e => e.Description),
        ];

        successes.ShouldBe(["Authenticated for IMAP.", "Authenticated for POP3."]);
    }

    [Fact]
    public async Task The_refusal_is_recorded_against_the_protocol_that_asked()
    {
        await Isolate();

        await SignInAsync("sendonly", MailboxAccess.Pop3);
        await database.Events.FlushAsync(CancellationToken.None);

        database.Events.Written.ShouldContain(e =>
            e.Type == SecurityEventType.MailboxAuthenticationFailed &&
            e.Description.Contains("not permitted to use POP3", StringComparison.Ordinal));
    }

    /// <summary>
    /// A caller must name exactly one protocol.
    /// </summary>
    /// <remarks>
    /// A combination would demand every flag at once; <c>None</c> would demand nothing and so be
    /// satisfied by every mailbox — the second is the dangerous one.
    /// </remarks>
    [Theory]
    [InlineData(MailboxAccess.None)]
    [InlineData(MailboxAccess.All)]
    [InlineData(MailboxAccess.Imap | MailboxAccess.Pop3)]
    public async Task Refuses_to_judge_anything_but_a_single_protocol(MailboxAccess protocol) =>
        await Should.ThrowAsync<ArgumentOutOfRangeException>(() => SignInAsync("everything", protocol));
}
