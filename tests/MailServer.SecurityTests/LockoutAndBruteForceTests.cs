using MailServer.Domain.Entities;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;

namespace MailServer.SecurityTests;

/// <summary>Brute-force resistance: lockout, escalation, and counter behaviour.</summary>
public sealed class LockoutAndBruteForceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static PasswordHash DummyHash(string marker = "a") =>
        PasswordHash.Create(
            PasswordHash.Argon2idAlgorithm,
            PasswordHash.Argon2Version,
            65_536,
            3,
            2,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            System.Text.Encoding.UTF8.GetBytes(marker.PadRight(32, 'x')));

    private static AdminAccount CreateAccount() =>
        AdminAccount.Create(
            AdminAccountId.New(),
            AdminAccount.BuiltInAdministratorName,
            DummyHash("password"),
            DummyHash("recovery"),
            Now);

    [Fact]
    public void Failures_below_the_threshold_do_not_lock()
    {
        LockoutPolicy policy = new(threshold: 5);
        AdminAccount account = CreateAccount();

        for (int i = 1; i <= 4; i++)
        {
            account.RecordFailedSignIn(policy, Now).ShouldBeFalse();
        }

        account.IsLockedOut(Now).ShouldBeFalse();
        account.ConsecutiveFailures.ShouldBe(4);
    }

    [Fact]
    public void Reaching_the_threshold_locks_the_account()
    {
        LockoutPolicy policy = new(threshold: 5);
        AdminAccount account = CreateAccount();

        for (int i = 1; i <= 4; i++)
        {
            account.RecordFailedSignIn(policy, Now);
        }

        account.RecordFailedSignIn(policy, Now).ShouldBeTrue();

        account.IsLockedOut(Now).ShouldBeTrue();
        account.LockedOutUntilUtc.ShouldNotBeNull();
    }

    [Fact]
    public void A_lockout_expires_on_its_own()
    {
        LockoutPolicy policy = new(threshold: 3, initialDuration: TimeSpan.FromMinutes(15));
        AdminAccount account = CreateAccount();

        for (int i = 0; i < 3; i++)
        {
            account.RecordFailedSignIn(policy, Now);
        }

        account.IsLockedOut(Now.AddMinutes(14)).ShouldBeTrue();
        account.IsLockedOut(Now.AddMinutes(16)).ShouldBeFalse();
    }

    [Fact]
    public void Successive_lockouts_escalate()
    {
        // A fixed window gives an attacker a steady budget: N guesses every M minutes,
        // forever. Doubling turns a sustained campaign into hours of waiting.
        LockoutPolicy policy = new(
            threshold: 5,
            initialDuration: TimeSpan.FromMinutes(15),
            maximumDuration: TimeSpan.FromHours(8));

        policy.GetLockoutDuration(5).ShouldBe(TimeSpan.FromMinutes(15));
        policy.GetLockoutDuration(10).ShouldBe(TimeSpan.FromMinutes(30));
        policy.GetLockoutDuration(15).ShouldBe(TimeSpan.FromHours(1));
        policy.GetLockoutDuration(20).ShouldBe(TimeSpan.FromHours(2));
    }

    [Fact]
    public void Escalation_is_capped()
    {
        LockoutPolicy policy = new(
            threshold: 5,
            initialDuration: TimeSpan.FromMinutes(15),
            maximumDuration: TimeSpan.FromHours(8));

        // A locked-out administrator must eventually get back in without a database edit, and
        // an unbounded exponent would also overflow.
        policy.GetLockoutDuration(500).ShouldBe(TimeSpan.FromHours(8));
        policy.GetLockoutDuration(int.MaxValue).ShouldBe(TimeSpan.FromHours(8));
    }

    [Fact]
    public void The_counter_resets_after_a_quiet_period()
    {
        // Otherwise three mistypes spread across a year would eventually lock an account under
        // no attack at all.
        LockoutPolicy policy = new(
            threshold: 5,
            counterResetWindow: TimeSpan.FromHours(1));

        AdminAccount account = CreateAccount();

        account.RecordFailedSignIn(policy, Now);
        account.RecordFailedSignIn(policy, Now.AddMinutes(1));
        account.ConsecutiveFailures.ShouldBe(2);

        // Two hours later, unrelated.
        account.RecordFailedSignIn(policy, Now.AddHours(2));
        account.ConsecutiveFailures.ShouldBe(1);
    }

    [Fact]
    public void Consecutive_failures_inside_the_window_accumulate()
    {
        LockoutPolicy policy = new(threshold: 5, counterResetWindow: TimeSpan.FromHours(1));
        AdminAccount account = CreateAccount();

        for (int i = 0; i < 4; i++)
        {
            account.RecordFailedSignIn(policy, Now.AddMinutes(i * 5));
        }

        account.ConsecutiveFailures.ShouldBe(4);
    }

    [Fact]
    public void A_successful_sign_in_clears_the_failure_state()
    {
        LockoutPolicy policy = new(threshold: 5);
        AdminAccount account = CreateAccount();

        account.RecordFailedSignIn(policy, Now);
        account.RecordFailedSignIn(policy, Now);

        account.RecordSuccessfulSignIn(Now);

        account.ConsecutiveFailures.ShouldBe(0);
        account.LastFailureUtc.ShouldBeNull();
        account.LockedOutUntilUtc.ShouldBeNull();
        account.LastSignInUtc.ShouldBe(Now);
    }

    [Fact]
    public void Lockout_state_survives_rehydration()
    {
        // Lockout is persisted precisely so a service restart does not clear an attacker's
        // failure counter. This asserts the aggregate carries it back from storage intact.
        LockoutPolicy policy = new(threshold: 3);
        AdminAccount account = CreateAccount();

        for (int i = 0; i < 3; i++)
        {
            account.RecordFailedSignIn(policy, Now);
        }

        AdminAccount reloaded = new(
            account.Id,
            account.Name,
            account.PasswordHash,
            account.RecoveryKeyHash,
            account.Permissions,
            account.ConsecutiveFailures,
            account.LastFailureUtc,
            account.LockedOutUntilUtc,
            account.LastSignInUtc,
            account.MustChangePassword,
            account.CreatedUtc,
            account.PasswordChangedUtc);

        reloaded.IsLockedOut(Now).ShouldBeTrue();
        reloaded.ConsecutiveFailures.ShouldBe(3);
    }

    [Fact]
    public void A_password_change_clears_the_lockout()
    {
        LockoutPolicy policy = new(threshold: 3);
        AdminAccount account = CreateAccount();

        for (int i = 0; i < 3; i++)
        {
            account.RecordFailedSignIn(policy, Now);
        }

        account.ChangePassword(DummyHash("new-password"), Now);

        account.IsLockedOut(Now).ShouldBeFalse();
        account.ConsecutiveFailures.ShouldBe(0);
    }

    [Fact]
    public void A_recovery_reset_clears_the_lockout()
    {
        // An attacker who has locked the account out must not thereby also deny the legitimate
        // administrator their recovery route.
        LockoutPolicy policy = new(threshold: 3);
        AdminAccount account = CreateAccount();

        for (int i = 0; i < 3; i++)
        {
            account.RecordFailedSignIn(policy, Now);
        }

        account.ResetPasswordWithRecoveryKey(DummyHash("reset-password"), Now);

        account.IsLockedOut(Now).ShouldBeFalse();
    }

    [Fact]
    public void An_invalid_lockout_configuration_is_rejected_at_construction()
    {
        // Caught at startup rather than at the first sign-in after a deployment.
        Should.Throw<Domain.Exceptions.DomainRuleViolationException>(
            () => new LockoutPolicy(threshold: 0));

        Should.Throw<Domain.Exceptions.DomainRuleViolationException>(
            () => new LockoutPolicy(initialDuration: TimeSpan.Zero));

        Should.Throw<Domain.Exceptions.DomainRuleViolationException>(
            () => new LockoutPolicy(
                initialDuration: TimeSpan.FromHours(2),
                maximumDuration: TimeSpan.FromMinutes(30)));
    }
}
