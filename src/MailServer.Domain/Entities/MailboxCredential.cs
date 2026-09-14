using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// A password that authenticates access to one mailbox.
/// </summary>
/// <remarks>
/// <para>
/// <b>Stored as an Argon2id verifier, exactly like the master password.</b> The same
/// <c>PasswordHash</c> value object and the same hasher, so raising the work factors raises
/// them everywhere and an old hash is upgraded on the next successful sign-in.
/// </para>
/// <para>
/// <b>This is why CRAM-MD5 and DIGEST-MD5 are not offered.</b> Those mechanisms require the
/// server to hold something it can compute the challenge response from — in practice the
/// password itself, or a reversible transformation of it. A mail server that stores recoverable
/// mailbox passwords turns one database read into every user's password, and those users have
/// reused them elsewhere. The trade is stated plainly rather than quietly made: AUTH PLAIN and
/// AUTH LOGIN over TLS send the password to a server that immediately verifies and discards it,
/// which is strictly better than the alternative, and rule 105 already forbids offering AUTH
/// without TLS at all.
/// </para>
/// <para>
/// <b>A separate entity from <see cref="Mailbox"/>.</b> A mailbox outlives several passwords,
/// a password change must not need the whole aggregate rewritten, and per-credential lockout
/// state changes on every failed login — which would otherwise mean writing the mailbox row on
/// every brute-force attempt.
/// </para>
/// </remarks>
public sealed class MailboxCredential : Entity<MailboxCredentialId>
{
    /// <summary>Rehydration constructor for the persistence layer.</summary>
    public MailboxCredential(
        MailboxCredentialId id,
        MailboxId mailboxId,
        PasswordHash passwordHash,
        bool mustChangePassword,
        int consecutiveFailures,
        DateTimeOffset? lastFailureUtc,
        DateTimeOffset? lockedOutUntilUtc,
        DateTimeOffset? lastSuccessUtc,
        DateTimeOffset createdUtc,
        DateTimeOffset? passwordChangedUtc) : base(id)
    {
        MailboxId = mailboxId;
        PasswordHash = passwordHash;
        MustChangePassword = mustChangePassword;
        ConsecutiveFailures = consecutiveFailures;
        LastFailureUtc = lastFailureUtc;
        LockedOutUntilUtc = lockedOutUntilUtc;
        LastSuccessUtc = lastSuccessUtc;
        CreatedUtc = createdUtc;
        PasswordChangedUtc = passwordChangedUtc;
    }

    public MailboxId MailboxId { get; }

    /// <summary>The Argon2id verifier. Never the password.</summary>
    public PasswordHash PasswordHash { get; private set; }

    /// <summary>
    /// Set when an administrator assigns a password the user must replace.
    /// </summary>
    /// <remarks>
    /// Recorded but not yet enforced: enforcing it needs a protocol channel to tell a mail
    /// client "change your password", and neither IMAP nor SMTP has one. It exists so the
    /// admin UI can show which mailboxes are still on an administrator-set password, which is
    /// the actionable half.
    /// </remarks>
    public bool MustChangePassword { get; private set; }

    /// <summary>Consecutive failed logins. Persisted, so a restart does not clear a lockout.</summary>
    public int ConsecutiveFailures { get; private set; }

    public DateTimeOffset? LastFailureUtc { get; private set; }

    public DateTimeOffset? LockedOutUntilUtc { get; private set; }

    public DateTimeOffset? LastSuccessUtc { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? PasswordChangedUtc { get; private set; }

    /// <summary>True when this credential is locked out at <paramref name="now"/>.</summary>
    public bool IsLockedOut(DateTimeOffset now) =>
        LockedOutUntilUtc is { } until && now < until;

    /// <summary>How much of the lockout is left.</summary>
    public TimeSpan GetRemainingLockout(DateTimeOffset now) =>
        LockedOutUntilUtc is { } until && now < until ? until - now : TimeSpan.Zero;

    /// <summary>Creates a credential from an already-hashed password.</summary>
    /// <remarks>
    /// Takes a <see cref="PasswordHash"/>, never a plaintext. The aggregate has no business
    /// hashing anything: that needs the configured work factors, which live in the
    /// Infrastructure layer, and a domain type that could hash would be a domain type that
    /// could be handed a password.
    /// </remarks>
    public static MailboxCredential Create(
        MailboxId mailboxId,
        PasswordHash passwordHash,
        bool mustChangePassword,
        DateTimeOffset now)
    {
        if (mailboxId.IsEmpty)
        {
            throw new DomainRuleViolationException(
                "mailbox_credential.no_mailbox",
                "A credential must belong to a mailbox.");
        }

        return new MailboxCredential(
            MailboxCredentialId.New(),
            mailboxId,
            passwordHash,
            mustChangePassword,
            consecutiveFailures: 0,
            lastFailureUtc: null,
            lockedOutUntilUtc: null,
            lastSuccessUtc: null,
            createdUtc: now,
            passwordChangedUtc: null);
    }

    /// <summary>Replaces the password and clears any lockout.</summary>
    /// <remarks>
    /// The lockout is cleared deliberately: whoever set the password has proved control by a
    /// stronger route than the password itself, and leaving a user locked out of an account
    /// whose password was just reset for them serves nobody.
    /// </remarks>
    public void SetPassword(PasswordHash passwordHash, bool mustChange, DateTimeOffset now)
    {
        PasswordHash = passwordHash;
        MustChangePassword = mustChange;
        PasswordChangedUtc = now;
        ClearLockout();
    }

    /// <summary>Replaces the verifier with one at current work factors, same password.</summary>
    /// <remarks>
    /// Called after a successful login when the stored hash was produced with weaker
    /// parameters — the only moment the plaintext is legitimately available to rehash with.
    /// Does not touch <see cref="PasswordChangedUtc"/>, because the password did not change.
    /// </remarks>
    public void UpgradePasswordHash(PasswordHash passwordHash) => PasswordHash = passwordHash;

    /// <summary>Records a successful login.</summary>
    public void RecordSuccess(DateTimeOffset now)
    {
        LastSuccessUtc = now;
        ClearLockout();
    }

    /// <summary>
    /// Records a failed login and applies the lockout policy.
    /// </summary>
    /// <returns>True when this failure caused a lockout.</returns>
    /// <remarks>
    /// <para>
    /// The same escalating policy as the administrator account, and for the same reason: a
    /// counter that resets when the service restarts is no lockout at all.
    /// </para>
    /// <para>
    /// A locked-out mailbox credential is a real denial-of-service vector in a way the
    /// administrator's is not — anyone who knows an email address can lock its owner out by
    /// guessing wrongly. The mitigation is that lockouts are short and escalate slowly, and
    /// that Milestone 12's per-IP rate limiting stops the attempt long before the account
    /// locks. Not locking at all would be worse: the address is public and the password is
    /// whatever the user chose.
    /// </para>
    /// </remarks>
    public bool RecordFailure(LockoutPolicy policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(policy);

        // A gap longer than the reset window means the previous failures were unrelated - a
        // user who mistypes twice a month should never accumulate a lockout.
        if (LastFailureUtc is { } last && now - last > policy.CounterResetWindow)
        {
            ConsecutiveFailures = 0;
        }

        ConsecutiveFailures++;
        LastFailureUtc = now;

        if (ConsecutiveFailures < policy.Threshold)
        {
            return false;
        }

        LockedOutUntilUtc = now + policy.GetLockoutDuration(ConsecutiveFailures);

        return true;
    }

    /// <summary>Clears a lockout and the failure counter.</summary>
    public void ClearLockout()
    {
        ConsecutiveFailures = 0;
        LastFailureUtc = null;
        LockedOutUntilUtc = null;
    }
}
