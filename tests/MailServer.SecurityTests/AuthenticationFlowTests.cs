using MailServer.Application;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Exceptions;
using MailServer.Application.Security.Commands;
using MailServer.Application.Security.Dtos;
using MailServer.Application.Security.Queries;
using MailServer.Domain.Policies;
using MailServer.Infrastructure;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Security;
using MailServer.Persistence.Sqlite;
using MediatR;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.SecurityTests;

/// <summary>
/// The authentication flow, end to end against a real SQLite database.
/// </summary>
/// <remarks>
/// <para>
/// Real Argon2 (at reduced work factors), real repositories, real session manager, real
/// migrations, the real MediatR pipeline. Only the clock is substituted, so lockout expiry can
/// be tested without sleeping.
/// </para>
/// <para>
/// Testing this against fakes would prove nothing: the properties that matter — that a wrong
/// password is indistinguishable from a missing account, that lockout survives a restart, that
/// a password change kills every session — all live in the interaction between the handler,
/// the aggregate and storage.
/// </para>
/// </remarks>
public sealed class AuthenticationFlowTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-security-tests",
        Guid.NewGuid().ToString("N"));

    private ServiceProvider _services = null!;
    private MutableClock _clock = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);

        _clock = new MutableClock();

        Dictionary<string, string?> settings = new(StringComparer.Ordinal)
        {
            ["MailServer:Server:Hostname"] = "mail.test.example",
            ["MailServer:Storage:DataRoot"] = _directory,
            ["MailServer:Database:Provider"] = "Sqlite",
            ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "security.db"),
            ["MailServer:Security:SecretProtection"] = "Development",

            // Reduced so the suite runs quickly. The properties under test are independent of
            // the factors; the production defaults are asserted in PasswordHashingTests.
            ["MailServer:Security:Argon2MemoryKib"] = "8192",
            ["MailServer:Security:Argon2Iterations"] = "1",
            ["MailServer:Security:Argon2Parallelism"] = "1",

            ["MailServer:Security:AdminLockoutThreshold"] = "3",
            ["MailServer:Security:AdminLockoutMinutes"] = "15",
            ["MailServer:Security:AutoLockMinutes"] = "10",
            ["MailServer:Security:SessionMaximumHours"] = "12",
        };

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddApplication();
        services.AddInfrastructure(configuration, isProductionEnvironment: false);
        services.AddSqlitePersistence();

        // The only substitution: a clock the test can move, so lockout expiry and session
        // timeouts are testable without sleeping.
        services.AddSingleton<IClock>(_clock);

        _services = services.BuildServiceProvider();

        // Real migrations, so the schema under test is the schema that ships.
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

    /// <summary>Sends a request through the full pipeline, as the dispatcher would.</summary>
    private async Task<TResponse> SendAsync<TResponse>(
        IRequest<TResponse> request,
        string? asAdministrator = null,
        Domain.Enums.AdminPermission permissions = Domain.Enums.AdminPermission.FullControl,
        bool mustChangePassword = false)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        if (asAdministrator is not null)
        {
            scope.ServiceProvider
                .GetRequiredService<IAdminContextInitializer>()
                .Assign(asAdministrator, "test-session", permissions, false, mustChangePassword);
        }

        return await scope.ServiceProvider.GetRequiredService<ISender>().Send(request);
    }

    private Task<SetupResultDto> CompleteSetupAsync(string password = "a-good-long-passphrase") =>
        SendAsync(new CompleteSetupCommand
        {
            Password = password,
            ConfirmPassword = password,
            Origin = "test",
        });

    // ---- Setup ---------------------------------------------------------------------------

    [Fact]
    public async Task A_fresh_server_reports_that_setup_is_required()
    {
        SetupStatusDto status = await SendAsync(new GetSetupStatusQuery());

        status.RequiresSetup.ShouldBeTrue();
        status.IsLockedOut.ShouldBeFalse();
        status.MinimumPasswordLength.ShouldBe(12);
    }

    [Fact]
    public async Task Setup_creates_the_account_and_returns_a_session_and_a_recovery_key()
    {
        SetupResultDto result = await CompleteSetupAsync();

        result.Authentication.SessionToken.ShouldNotBeNullOrWhiteSpace();
        result.Authentication.Administrator.ShouldBe("Administrator");
        result.RecoveryKey.RecoveryKey.ShouldNotBeNullOrWhiteSpace();

        // Formatted in groups for accurate transcription.
        result.RecoveryKey.RecoveryKey.ShouldContain("-");

        (await SendAsync(new GetSetupStatusQuery())).RequiresSetup.ShouldBeFalse();
    }

    [Fact]
    public async Task Setup_cannot_be_run_twice()
    {
        // The gate that makes an anonymous command safe: without it, anyone reaching the pipe
        // could re-run setup and take ownership of a configured server.
        await CompleteSetupAsync();

        Domain.Exceptions.DomainRuleViolationException ex =
            await Should.ThrowAsync<Domain.Exceptions.DomainRuleViolationException>(
                () => CompleteSetupAsync("another-good-passphrase"));

        ex.Code.ShouldBe("security.setup.already_completed");
    }

    [Fact]
    public async Task Setup_refuses_a_weak_password()
    {
        await Should.ThrowAsync<Domain.Exceptions.DomainRuleViolationException>(
            () => CompleteSetupAsync("short"));

        // Nothing was created, so setup is still required.
        (await SendAsync(new GetSetupStatusQuery())).RequiresSetup.ShouldBeTrue();
    }

    [Fact]
    public async Task Setup_refuses_a_password_containing_a_dictionary_word()
    {
        await Should.ThrowAsync<Domain.Exceptions.DomainRuleViolationException>(
            () => CompleteSetupAsync("mypassword12345678"));
    }

    // ---- Sign-in -------------------------------------------------------------------------

    [Fact]
    public async Task The_correct_password_signs_in()
    {
        await CompleteSetupAsync("a-good-long-passphrase");

        AuthenticationResultDto result = await SendAsync(new AuthenticateCommand
        {
            Password = "a-good-long-passphrase",
            Origin = "test",
        });

        result.SessionToken.ShouldNotBeNullOrWhiteSpace();
        result.Administrator.ShouldBe("Administrator");
        result.MustChangePassword.ShouldBeFalse();
    }

    [Fact]
    public async Task Each_sign_in_issues_a_distinct_token()
    {
        await CompleteSetupAsync("a-good-long-passphrase");

        AuthenticationResultDto first = await SendAsync(new AuthenticateCommand
        {
            Password = "a-good-long-passphrase",
        });

        AuthenticationResultDto second = await SendAsync(new AuthenticateCommand
        {
            Password = "a-good-long-passphrase",
        });

        first.SessionToken.ShouldNotBe(second.SessionToken);
        first.SessionId.ShouldNotBe(second.SessionId);
    }

    [Fact]
    public async Task A_wrong_password_is_refused()
    {
        await CompleteSetupAsync("a-good-long-passphrase");

        await Should.ThrowAsync<AuthenticationFailedException>(
            () => SendAsync(new AuthenticateCommand { Password = "not-the-password" }));
    }

    [Fact]
    public async Task A_wrong_password_and_a_missing_account_give_the_identical_message()
    {
        // The enumeration defence. "That account exists but the password is wrong" is exactly
        // the fact an attacker is trying to establish.
        AuthenticationFailedException beforeSetup =
            await Should.ThrowAsync<AuthenticationFailedException>(
                () => SendAsync(new AuthenticateCommand { Password = "anything" }));

        await CompleteSetupAsync("a-good-long-passphrase");

        AuthenticationFailedException afterSetup =
            await Should.ThrowAsync<AuthenticationFailedException>(
                () => SendAsync(new AuthenticateCommand { Password = "wrong-password-entirely" }));

        afterSetup.Message.ShouldBe(beforeSetup.Message);
        afterSetup.Code.ShouldBe(beforeSetup.Code);
    }

    // ---- Lockout -------------------------------------------------------------------------

    [Fact]
    public async Task Repeated_failures_lock_the_account()
    {
        await CompleteSetupAsync("a-good-long-passphrase");

        // Threshold is 3 in this fixture.
        for (int i = 0; i < 2; i++)
        {
            await Should.ThrowAsync<AuthenticationFailedException>(
                () => SendAsync(new AuthenticateCommand { Password = "wrong" }));
        }

        await Should.ThrowAsync<AccountLockedOutException>(
            () => SendAsync(new AuthenticateCommand { Password = "wrong" }));

        // And the correct password is refused too, for the duration.
        await Should.ThrowAsync<AccountLockedOutException>(
            () => SendAsync(new AuthenticateCommand { Password = "a-good-long-passphrase" }));
    }

    [Fact]
    public async Task Lockout_is_reported_to_an_unauthenticated_caller()
    {
        // Lockout state is not a secret: a legitimate administrator who has mistyped needs to
        // be told to wait rather than left guessing at a password that is currently irrelevant.
        await CompleteSetupAsync("a-good-long-passphrase");

        for (int i = 0; i < 3; i++)
        {
            await Should.ThrowAsync<ApplicationLayerException>(
                () => SendAsync(new AuthenticateCommand { Password = "wrong" }));
        }

        SetupStatusDto status = await SendAsync(new GetSetupStatusQuery());

        status.IsLockedOut.ShouldBeTrue();
        status.LockoutSecondsRemaining.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task A_lockout_expires_and_the_correct_password_works_again()
    {
        await CompleteSetupAsync("a-good-long-passphrase");

        for (int i = 0; i < 3; i++)
        {
            await Should.ThrowAsync<ApplicationLayerException>(
                () => SendAsync(new AuthenticateCommand { Password = "wrong" }));
        }

        // Past the 15-minute window.
        _clock.Advance(TimeSpan.FromMinutes(16));

        AuthenticationResultDto result = await SendAsync(new AuthenticateCommand
        {
            Password = "a-good-long-passphrase",
        });

        result.SessionToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task A_successful_sign_in_resets_the_failure_counter()
    {
        await CompleteSetupAsync("a-good-long-passphrase");

        // Two failures, below the threshold of three.
        for (int i = 0; i < 2; i++)
        {
            await Should.ThrowAsync<AuthenticationFailedException>(
                () => SendAsync(new AuthenticateCommand { Password = "wrong" }));
        }

        await SendAsync(new AuthenticateCommand { Password = "a-good-long-passphrase" });

        // Two more failures must not now lock, because the counter restarted.
        for (int i = 0; i < 2; i++)
        {
            await Should.ThrowAsync<AuthenticationFailedException>(
                () => SendAsync(new AuthenticateCommand { Password = "wrong" }));
        }

        (await SendAsync(new GetSetupStatusQuery())).IsLockedOut.ShouldBeFalse();
    }

    // ---- Recovery ------------------------------------------------------------------------

    [Fact]
    public async Task The_recovery_key_resets_the_password_and_issues_a_replacement()
    {
        SetupResultDto setup = await CompleteSetupAsync("original-long-passphrase");

        RecoveryKeyDto replacement = await SendAsync(new ResetPasswordWithRecoveryKeyCommand
        {
            RecoveryKey = setup.RecoveryKey.RecoveryKey,
            NewPassword = "brand-new-long-passphrase",
            ConfirmNewPassword = "brand-new-long-passphrase",
        });

        replacement.RecoveryKey.ShouldNotBeNullOrWhiteSpace();
        replacement.RecoveryKey.ShouldNotBe(setup.RecoveryKey.RecoveryKey);

        // The new password works and carries the mandatory-change flag.
        AuthenticationResultDto signIn = await SendAsync(new AuthenticateCommand
        {
            Password = "brand-new-long-passphrase",
        });

        signIn.MustChangePassword.ShouldBeTrue();
    }

    [Fact]
    public async Task A_recovery_key_works_only_once()
    {
        SetupResultDto setup = await CompleteSetupAsync("original-long-passphrase");

        await SendAsync(new ResetPasswordWithRecoveryKeyCommand
        {
            RecoveryKey = setup.RecoveryKey.RecoveryKey,
            NewPassword = "first-new-long-passphrase",
            ConfirmNewPassword = "first-new-long-passphrase",
        });

        // The original key is consumed. A key that still worked would be a permanent second
        // password, written on paper, with no expiry.
        await Should.ThrowAsync<AuthenticationFailedException>(
            () => SendAsync(new ResetPasswordWithRecoveryKeyCommand
            {
                RecoveryKey = setup.RecoveryKey.RecoveryKey,
                NewPassword = "second-new-long-passphrase",
                ConfirmNewPassword = "second-new-long-passphrase",
            }));
    }

    [Fact]
    public async Task A_recovery_key_is_accepted_with_or_without_its_display_hyphens()
    {
        SetupResultDto setup = await CompleteSetupAsync("original-long-passphrase");

        string unhyphenated = setup.RecoveryKey.RecoveryKey
            .Replace("-", string.Empty, StringComparison.Ordinal);

        await SendAsync(new ResetPasswordWithRecoveryKeyCommand
        {
            RecoveryKey = unhyphenated.ToLowerInvariant(),
            NewPassword = "brand-new-long-passphrase",
            ConfirmNewPassword = "brand-new-long-passphrase",
        });

        await SendAsync(new AuthenticateCommand { Password = "brand-new-long-passphrase" });
    }

    [Fact]
    public async Task A_wrong_recovery_key_is_refused()
    {
        await CompleteSetupAsync("original-long-passphrase");

        await Should.ThrowAsync<AuthenticationFailedException>(
            () => SendAsync(new ResetPasswordWithRecoveryKeyCommand
            {
                RecoveryKey = "ABCDE-FGHIJ-KLMNO-PQRST-VWXYZ",
                NewPassword = "brand-new-long-passphrase",
                ConfirmNewPassword = "brand-new-long-passphrase",
            }));
    }

    [Fact]
    public async Task The_recovery_key_bypasses_lockout()
    {
        // An attacker who has locked the account out must not thereby also deny the legitimate
        // administrator their recovery route. The key is 125 bits of entropy, so guessing it is
        // not a realistic threat.
        SetupResultDto setup = await CompleteSetupAsync("original-long-passphrase");

        for (int i = 0; i < 3; i++)
        {
            await Should.ThrowAsync<ApplicationLayerException>(
                () => SendAsync(new AuthenticateCommand { Password = "wrong" }));
        }

        (await SendAsync(new GetSetupStatusQuery())).IsLockedOut.ShouldBeTrue();

        await SendAsync(new ResetPasswordWithRecoveryKeyCommand
        {
            RecoveryKey = setup.RecoveryKey.RecoveryKey,
            NewPassword = "recovered-long-passphrase",
            ConfirmNewPassword = "recovered-long-passphrase",
        });

        (await SendAsync(new GetSetupStatusQuery())).IsLockedOut.ShouldBeFalse();
    }

    // ---- Password change ------------------------------------------------------------------

    [Fact]
    public async Task Changing_the_password_requires_the_current_one()
    {
        await CompleteSetupAsync("original-long-passphrase");

        // Re-proving the current password matters even with a valid session: it is what stops
        // an unattended, unlocked console from being used to lock the real administrator out.
        await Should.ThrowAsync<AuthenticationFailedException>(
            () => SendAsync(
                new ChangeMasterPasswordCommand
                {
                    CurrentPassword = "not-the-current-one",
                    NewPassword = "brand-new-long-passphrase",
                    ConfirmNewPassword = "brand-new-long-passphrase",
                },
                asAdministrator: "Administrator"));
    }

    [Fact]
    public async Task Changing_the_password_revokes_every_session()
    {
        await CompleteSetupAsync("original-long-passphrase");

        AuthenticationResultDto session = await SendAsync(new AuthenticateCommand
        {
            Password = "original-long-passphrase",
        });

        IAdminSessionManager sessions = _services.GetRequiredService<IAdminSessionManager>();

        (await sessions.ValidateAsync(session.SessionToken, CancellationToken.None))
            .IsValid.ShouldBeTrue();

        await SendAsync(
            new ChangeMasterPasswordCommand
            {
                CurrentPassword = "original-long-passphrase",
                NewPassword = "brand-new-long-passphrase",
                ConfirmNewPassword = "brand-new-long-passphrase",
            },
            asAdministrator: "Administrator");

        // A password change intended to lock out an intruder achieves nothing if the
        // intruder's existing session keeps working.
        (await sessions.ValidateAsync(session.SessionToken, CancellationToken.None))
            .IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task Other_sessions_can_be_kept_deliberately()
    {
        await CompleteSetupAsync("original-long-passphrase");

        AuthenticationResultDto session = await SendAsync(new AuthenticateCommand
        {
            Password = "original-long-passphrase",
        });

        await SendAsync(
            new ChangeMasterPasswordCommand
            {
                CurrentPassword = "original-long-passphrase",
                NewPassword = "brand-new-long-passphrase",
                ConfirmNewPassword = "brand-new-long-passphrase",
                KeepOtherSessions = true,
            },
            asAdministrator: "Administrator");

        IAdminSessionManager sessions = _services.GetRequiredService<IAdminSessionManager>();

        (await sessions.ValidateAsync(session.SessionToken, CancellationToken.None))
            .IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task The_old_password_stops_working_after_a_change()
    {
        await CompleteSetupAsync("original-long-passphrase");

        await SendAsync(
            new ChangeMasterPasswordCommand
            {
                CurrentPassword = "original-long-passphrase",
                NewPassword = "brand-new-long-passphrase",
                ConfirmNewPassword = "brand-new-long-passphrase",
            },
            asAdministrator: "Administrator");

        await Should.ThrowAsync<AuthenticationFailedException>(
            () => SendAsync(new AuthenticateCommand { Password = "original-long-passphrase" }));

        await SendAsync(new AuthenticateCommand { Password = "brand-new-long-passphrase" });
    }

    [Fact]
    public async Task The_new_password_must_differ_from_the_current_one()
    {
        await CompleteSetupAsync("original-long-passphrase");

        await Should.ThrowAsync<Domain.Exceptions.DomainRuleViolationException>(
            () => SendAsync(
                new ChangeMasterPasswordCommand
                {
                    CurrentPassword = "original-long-passphrase",
                    NewPassword = "original-long-passphrase",
                    ConfirmNewPassword = "original-long-passphrase",
                },
                asAdministrator: "Administrator"));
    }

    // ---- Security events -------------------------------------------------------------------

    [Fact]
    public async Task Failed_sign_ins_are_recorded_even_though_the_transaction_rolled_back()
    {
        // Security events are written out of band precisely so that an attacker who can make an
        // operation fail cannot thereby erase the record of their attempt.
        await CompleteSetupAsync("original-long-passphrase");

        for (int i = 0; i < 2; i++)
        {
            await Should.ThrowAsync<AuthenticationFailedException>(
                () => SendAsync(new AuthenticateCommand { Password = "wrong", Origin = "attacker" }));
        }

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        int failures = await scope.ServiceProvider
            .GetRequiredService<ISecurityEventQueries>()
            .CountFailedSignInsSinceAsync(_clock.UtcNow.AddHours(-1), CancellationToken.None);

        failures.ShouldBeGreaterThanOrEqualTo(2);
    }

    [Fact]
    public async Task The_security_status_reports_the_posture()
    {
        await CompleteSetupAsync("original-long-passphrase");
        await SendAsync(new AuthenticateCommand { Password = "original-long-passphrase" });

        SecurityStatusDto status = await SendAsync(
            new GetSecurityStatusQuery(),
            asAdministrator: "Administrator");

        status.Administrator.ShouldBe("Administrator");
        status.HasRecoveryKey.ShouldBeTrue();
        status.LastSignInUtc.ShouldNotBeNull();
        status.PasswordHashingDescription.ShouldStartWith("argon2id");

        // The development protector is in use in this fixture, and must say so.
        status.SecretProtectionIsProductionGrade.ShouldBeFalse();
    }

    /// <summary>
    /// A structural guard on the defect this suite caught: <c>AuthenticateCommand</c> must not
    /// be transactional.
    /// </summary>
    /// <remarks>
    /// A failed attempt increments the persisted failure counter and then throws, and
    /// <c>TransactionBehavior</c> rolls back on exception. Marking this command transactional
    /// therefore discards every failure it records, leaving lockout permanently inert while
    /// looking entirely correct in configuration and in the logs. The behavioural tests above
    /// would catch a regression, but they would not say why, so this asserts the cause.
    /// </remarks>
    [Fact]
    public void Authentication_is_not_wrapped_in_a_transaction()
    {
        typeof(Application.Abstractions.Messaging.ITransactionalRequest)
            .IsAssignableFrom(typeof(AuthenticateCommand))
            .ShouldBeFalse(
                "A transaction would roll back the failure counter that drives lockout.");
    }
}

/// <summary>A clock the test can move, so expiry is testable without sleeping.</summary>
internal sealed class MutableClock : IClock
{
    private long _timestamp;

    public DateTimeOffset UtcNow { get; private set; } =
        new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    public void Advance(TimeSpan by)
    {
        UtcNow = UtcNow.Add(by);
        _timestamp += by.Ticks;
    }

    public long GetTimestamp() => _timestamp;

    public TimeSpan GetElapsedTime(long startingTimestamp) =>
        TimeSpan.FromTicks(_timestamp - startingTimestamp);
}
