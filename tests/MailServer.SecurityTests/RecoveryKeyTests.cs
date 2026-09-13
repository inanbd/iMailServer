using MailServer.Domain.Entities;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Security;

namespace MailServer.SecurityTests;

/// <summary>Recovery key generation, single use, and replacement.</summary>
public sealed class RecoveryKeyTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static PasswordHash DummyHash(string marker) =>
        PasswordHash.Create(
            PasswordHash.Argon2idAlgorithm,
            PasswordHash.Argon2Version,
            65_536,
            3,
            2,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            System.Text.Encoding.UTF8.GetBytes(marker.PadRight(32, 'x')[..32]));

    private static AdminAccount CreateAccount() =>
        AdminAccount.Create(
            AdminAccountId.New(),
            AdminAccount.BuiltInAdministratorName,
            DummyHash("password"),
            DummyHash("recovery"),
            Now);

    [Fact]
    public void A_generated_key_has_the_expected_shape()
    {
        string key = new RecoveryKeyGenerator().Generate();

        key.Length.ShouldBe(RecoveryKeyGenerator.KeyLength);
        key.ShouldAllBe(c => char.IsAsciiLetterOrDigit(c) && !char.IsLower(c));
    }

    [Fact]
    public void The_alphabet_omits_visually_ambiguous_characters()
    {
        // I/L/O are indistinguishable from 1/0 in most fonts, and U is dropped so a random key
        // cannot spell something unfortunate. This key is transcribed by hand exactly once, and
        // a mis-copied one is discovered only in the emergency it was written for.
        string combined = string.Concat(
            Enumerable.Range(0, 200).Select(_ => new RecoveryKeyGenerator().Generate()));

        combined.ShouldNotContain("I");
        combined.ShouldNotContain("L");
        combined.ShouldNotContain("O");
        combined.ShouldNotContain("U");
    }

    [Fact]
    public void Generated_keys_do_not_repeat()
    {
        // A weak generator here is a permanent backdoor: the key bypasses lockout by design.
        RecoveryKeyGenerator generator = new();

        string[] keys = [.. Enumerable.Range(0, 500).Select(_ => generator.Generate())];

        keys.Distinct(StringComparer.Ordinal).Count().ShouldBe(keys.Length);
    }

    [Fact]
    public void Display_formatting_groups_the_key_for_transcription()
    {
        string formatted = PasswordPolicy.FormatRecoveryKey("ABCDEFGHIJKLMNOPQRSTUVWXY");

        formatted.ShouldBe("ABCDE-FGHIJ-KLMNO-PQRST-UVWXY");
    }

    [Theory]
    [InlineData("ABCDE-FGHIJ-KLMNO-PQRST-UVWXY")]
    [InlineData("abcde-fghij-klmno-pqrst-uvwxy")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXY")]
    [InlineData("  ABCDE FGHIJ KLMNO PQRST UVWXY  ")]
    public void Normalisation_accepts_every_reasonable_way_of_typing_it(string entered) =>
        PasswordPolicy.NormalizeRecoveryKey(entered).ShouldBe("ABCDEFGHIJKLMNOPQRSTUVWXY");

    [Fact]
    public void A_recovery_reset_consumes_the_key()
    {
        // Single use by design. A key that still worked afterwards would be a permanent second
        // password, written on paper, with no expiry.
        AdminAccount account = CreateAccount();
        account.HasRecoveryKey.ShouldBeTrue();

        account.ResetPasswordWithRecoveryKey(DummyHash("new"), Now);

        account.HasRecoveryKey.ShouldBeFalse();
    }

    [Fact]
    public void A_recovery_reset_forces_a_subsequent_password_change()
    {
        // The administrator proved possession of the recovery key, not knowledge of a password
        // they chose.
        AdminAccount account = CreateAccount();

        account.ResetPasswordWithRecoveryKey(DummyHash("new"), Now);

        account.MustChangePassword.ShouldBeTrue();
    }

    [Fact]
    public void A_replacement_key_can_be_issued_immediately()
    {
        AdminAccount account = CreateAccount();

        account.ResetPasswordWithRecoveryKey(DummyHash("new"), Now);
        account.IssueRecoveryKey(DummyHash("replacement"), Now);

        // The installation is never left without a recovery route.
        account.HasRecoveryKey.ShouldBeTrue();
    }

    [Fact]
    public void Resetting_without_a_recovery_key_is_refused()
    {
        AdminAccount account = CreateAccount();

        account.ResetPasswordWithRecoveryKey(DummyHash("first"), Now);

        Should.Throw<DomainRuleViolationException>(
                () => account.ResetPasswordWithRecoveryKey(DummyHash("second"), Now))
            .Code.ShouldBe("admin.recovery_key.absent");
    }

    [Fact]
    public void Completing_the_required_change_clears_the_flag()
    {
        AdminAccount account = CreateAccount();

        account.ResetPasswordWithRecoveryKey(DummyHash("reset"), Now);
        account.MustChangePassword.ShouldBeTrue();

        account.ChangePassword(DummyHash("chosen"), Now);

        account.MustChangePassword.ShouldBeFalse();
    }

    [Fact]
    public void Changing_to_the_identical_verifier_is_refused()
    {
        AdminAccount account = CreateAccount();

        Should.Throw<DomainRuleViolationException>(
                () => account.ChangePassword(account.PasswordHash, Now))
            .Code.ShouldBe("admin.password.unchanged");
    }
}
