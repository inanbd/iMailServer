using MailServer.Domain.Enums;
using MailServer.Domain.Events;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// The administrator identity that guards the administration console.
/// </summary>
/// <remarks>
/// <para>
/// A <b>singleton aggregate</b> in Milestone 2: one master password for the server, matching
/// the brief's model. The aggregate is nonetheless shaped so that multiple named
/// administrators can be introduced later without the concept of "the account" being baked
/// into every caller — which is why it has an id and a name rather than being a settings row.
/// </para>
/// <para>
/// <b>This aggregate never sees a plaintext password.</b> Hashing happens in the Infrastructure
/// layer, which owns the Argon2 implementation; the aggregate receives an already-computed
/// <see cref="PasswordHash"/> and a verification <i>result</i>. Keeping the plaintext out of
/// the Domain layer means it cannot end up in a domain event, an exception message or a
/// <c>ToString()</c>.
/// </para>
/// <para>
/// <b>Lockout state is persisted here</b> rather than held in memory, so restarting the
/// service does not clear an attacker's failure counter.
/// </para>
/// </remarks>
public sealed class AdminAccount : AggregateRoot<AdminAccountId>
{
    /// <summary>Name of the single built-in administrator in Milestone 2.</summary>
    public const string BuiltInAdministratorName = "Administrator";

    /// <summary>
    /// Rehydration constructor for the persistence layer. Applies no invariant checks; see
    /// <see cref="MailDomain"/> for why loading must not re-validate.
    /// </summary>
    public AdminAccount(
        AdminAccountId id,
        string name,
        PasswordHash passwordHash,
        PasswordHash? recoveryKeyHash,
        AdminPermission permissions,
        int consecutiveFailures,
        DateTimeOffset? lastFailureUtc,
        DateTimeOffset? lockedOutUntilUtc,
        DateTimeOffset? lastSignInUtc,
        bool mustChangePassword,
        DateTimeOffset createdUtc,
        DateTimeOffset? passwordChangedUtc) : base(id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(passwordHash);

        Name = name;
        PasswordHash = passwordHash;
        RecoveryKeyHash = recoveryKeyHash;
        Permissions = permissions;
        ConsecutiveFailures = consecutiveFailures;
        LastFailureUtc = lastFailureUtc;
        LockedOutUntilUtc = lockedOutUntilUtc;
        LastSignInUtc = lastSignInUtc;
        MustChangePassword = mustChangePassword;
        CreatedUtc = createdUtc;
        PasswordChangedUtc = passwordChangedUtc;
    }

    /// <summary>Display name, recorded in the audit trail.</summary>
    public string Name { get; }

    /// <summary>The master password verifier.</summary>
    public PasswordHash PasswordHash { get; private set; }

    /// <summary>
    /// Verifier for the recovery key, if one has been issued.
    /// </summary>
    /// <remarks>
    /// Hashed with the same algorithm as the password, and for the same reason: the recovery
    /// key grants full control of the server, so a database dump must not yield it.
    /// </remarks>
    public PasswordHash? RecoveryKeyHash { get; private set; }

    /// <summary>Permissions granted to this identity.</summary>
    public AdminPermission Permissions { get; private set; }

    /// <summary>Consecutive failed authentication attempts.</summary>
    public int ConsecutiveFailures { get; private set; }

    /// <summary>When the most recent failure occurred, for counter-reset purposes.</summary>
    public DateTimeOffset? LastFailureUtc { get; private set; }

    /// <summary>When the current lockout ends, if any.</summary>
    public DateTimeOffset? LockedOutUntilUtc { get; private set; }

    /// <summary>When this administrator last signed in successfully.</summary>
    public DateTimeOffset? LastSignInUtc { get; private set; }

    /// <summary>
    /// True when the password must be changed before anything else is permitted.
    /// </summary>
    /// <remarks>
    /// Set after a recovery-key reset: the administrator proved possession of the recovery key,
    /// which is enough to regain access but not a password they chose.
    /// </remarks>
    public bool MustChangePassword { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    /// <summary>When the password was last changed.</summary>
    public DateTimeOffset? PasswordChangedUtc { get; private set; }

    /// <summary>True when a recovery key has been issued and can be used.</summary>
    public bool HasRecoveryKey => RecoveryKeyHash is not null;

    /// <summary>
    /// Creates the administrator account with its initial password and recovery key.
    /// </summary>
    /// <remarks>
    /// Both hashes are supplied already computed. The recovery key is mandatory at creation:
    /// an installation whose only credential is a password nobody wrote down is one forgotten
    /// password away from a rebuild, and the moment to insist is while the administrator is
    /// already at the setup screen.
    /// </remarks>
    public static AdminAccount Create(
        AdminAccountId id,
        string name,
        PasswordHash passwordHash,
        PasswordHash recoveryKeyHash,
        DateTimeOffset nowUtc,
        AdminPermission permissions = AdminPermission.FullControl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(passwordHash);
        ArgumentNullException.ThrowIfNull(recoveryKeyHash);

        AdminAccount account = new(
            id,
            name,
            passwordHash,
            recoveryKeyHash,
            permissions,
            consecutiveFailures: 0,
            lastFailureUtc: null,
            lockedOutUntilUtc: null,
            lastSignInUtc: null,
            mustChangePassword: false,
            nowUtc,
            passwordChangedUtc: nowUtc);

        account.Raise(new MasterPasswordCreatedEvent(id, name, nowUtc));
        account.Raise(new RecoveryKeyIssuedEvent(id, nowUtc));

        return account;
    }

    /// <summary>True when a lockout is currently in force.</summary>
    public bool IsLockedOut(DateTimeOffset nowUtc) =>
        LockoutPolicy.IsLockedOut(LockedOutUntilUtc, nowUtc);

    /// <summary>How long remains on the current lockout.</summary>
    public TimeSpan GetRemainingLockout(DateTimeOffset nowUtc) =>
        LockoutPolicy.GetRemainingLockout(LockedOutUntilUtc, nowUtc);

    /// <summary>
    /// Records a successful authentication, clearing the failure state.
    /// </summary>
    /// <remarks>
    /// The caller has already verified the password. This method exists so that clearing the
    /// counter, clearing the lockout and stamping the sign-in time happen together — three
    /// separate assignments at a call site is three chances to forget one.
    /// </remarks>
    public void RecordSuccessfulSignIn(DateTimeOffset nowUtc)
    {
        ConsecutiveFailures = 0;
        LastFailureUtc = null;
        LockedOutUntilUtc = null;
        LastSignInUtc = nowUtc;
    }

    /// <summary>
    /// Records a failed authentication and applies the lockout policy.
    /// </summary>
    /// <returns>True when this failure triggered a lockout.</returns>
    public bool RecordFailedSignIn(LockoutPolicy policy, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(policy);

        // An old isolated failure should not compound with a new one; otherwise three
        // mistypes spread across a year would eventually lock an account under no attack.
        ConsecutiveFailures = policy.ShouldResetCounter(LastFailureUtc, nowUtc)
            ? 1
            : ConsecutiveFailures + 1;

        LastFailureUtc = nowUtc;

        if (!policy.ShouldLock(ConsecutiveFailures))
        {
            return false;
        }

        LockedOutUntilUtc = policy.GetLockoutExpiry(ConsecutiveFailures, nowUtc);

        Raise(new AdminAccountLockedOutEvent(
            Id,
            ConsecutiveFailures,
            LockedOutUntilUtc.Value,
            nowUtc));

        return true;
    }

    /// <summary>
    /// Replaces the master password.
    /// </summary>
    /// <remarks>
    /// Clears <see cref="MustChangePassword"/> and the failure state, and raises an event that
    /// obliges consumers to revoke every existing session — a password change intended to lock
    /// out an intruder achieves nothing if the intruder's session token keeps working.
    /// </remarks>
    public void ChangePassword(PasswordHash newHash, DateTimeOffset nowUtc, bool viaRecoveryKey = false)
    {
        ArgumentNullException.ThrowIfNull(newHash);

        if (newHash.Equals(PasswordHash))
        {
            // Reusing the identical verifier means the same password. Refusing is cheap and
            // stops a "change" that achieves nothing after a suspected compromise.
            throw new DomainRuleViolationException(
                "admin.password.unchanged",
                "The new password must differ from the current one.");
        }

        PasswordHash = newHash;
        PasswordChangedUtc = nowUtc;
        MustChangePassword = false;
        ConsecutiveFailures = 0;
        LastFailureUtc = null;
        LockedOutUntilUtc = null;

        Raise(new MasterPasswordChangedEvent(Id, Name, viaRecoveryKey, nowUtc));
    }

    /// <summary>
    /// Resets the password after the recovery key has been verified.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Forces a subsequent password change and <b>invalidates the recovery key</b>. A recovery
    /// key is single-use by design: one that still worked after being used would be a permanent
    /// second password, written on paper, with no expiry.
    /// </para>
    /// <para>
    /// A replacement key is issued in the same operation via <see cref="IssueRecoveryKey"/>,
    /// so an installation is never left without one.
    /// </para>
    /// </remarks>
    public void ResetPasswordWithRecoveryKey(PasswordHash newHash, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(newHash);

        if (!HasRecoveryKey)
        {
            throw new DomainRuleViolationException(
                "admin.recovery_key.absent",
                "No recovery key has been issued for this account.");
        }

        PasswordHash = newHash;
        PasswordChangedUtc = nowUtc;
        ConsecutiveFailures = 0;
        LastFailureUtc = null;
        LockedOutUntilUtc = null;

        // Consumed. A replacement must be issued before the operation completes.
        RecoveryKeyHash = null;

        // The administrator proved possession of the recovery key, not knowledge of a
        // password they chose. Make them choose one.
        MustChangePassword = true;

        Raise(new MasterPasswordChangedEvent(Id, Name, ViaRecoveryKey: true, nowUtc));
    }

    /// <summary>Issues (or replaces) the recovery key.</summary>
    public void IssueRecoveryKey(PasswordHash recoveryKeyHash, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(recoveryKeyHash);

        RecoveryKeyHash = recoveryKeyHash;
        Raise(new RecoveryKeyIssuedEvent(Id, nowUtc));
    }

    /// <summary>
    /// Replaces the stored verifier with one computed using stronger work factors.
    /// </summary>
    /// <remarks>
    /// Called after a successful sign-in, which is the only moment the plaintext is available.
    /// Unlike <see cref="ChangePassword"/> this is not a password change: it raises no event,
    /// revokes no session, and does not stamp <see cref="PasswordChangedUtc"/>, because from
    /// the administrator's point of view nothing happened.
    /// </remarks>
    public void UpgradePasswordHash(PasswordHash rehashed)
    {
        ArgumentNullException.ThrowIfNull(rehashed);
        PasswordHash = rehashed;
    }

    /// <summary>Clears a lockout administratively.</summary>
    public void ClearLockout()
    {
        ConsecutiveFailures = 0;
        LastFailureUtc = null;
        LockedOutUntilUtc = null;
    }

    /// <summary>True when every bit in <paramref name="permission"/> is held.</summary>
    public bool HasPermission(AdminPermission permission) =>
        (Permissions & permission) == permission;
}
