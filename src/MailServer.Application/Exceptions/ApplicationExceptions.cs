using MailServer.Domain.Enums;

namespace MailServer.Application.Exceptions;

/// <summary>
/// Base for failures originating in the Application layer.
/// </summary>
/// <remarks>
/// Like <c>DomainException</c>, these carry a stable machine-readable code. The IPC layer
/// maps that code onto a wire error so the admin application can react programmatically
/// without parsing English.
/// </remarks>
public abstract class ApplicationLayerException : Exception
{
    protected ApplicationLayerException(string code, string message) : base(message) => Code = code;

    protected ApplicationLayerException(string code, string message, Exception inner)
        : base(message, inner) => Code = code;

    public string Code { get; }

    /// <summary>
    /// Whether this is the server refusing a request as designed, rather than failing to serve it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A wrong password, a lockout, a maintenance window: the caller was answered correctly and
    /// there is nothing for an operator to fix. <c>UnhandledExceptionBehavior</c> logs these as
    /// warnings without a stack trace, so the error log stays a list of things that went wrong
    /// rather than a list of mistyped passwords with the server's call stack attached.
    /// </para>
    /// <para>
    /// <b>False unless a type says otherwise.</b> A new kind of failure is an error until
    /// somebody decides it is not, which is the safe direction to be wrong in.
    /// </para>
    /// </remarks>
    public virtual bool IsRefusal => false;
}

/// <summary>One or more validation rules rejected the request.</summary>
public sealed class ValidationFailedException : ApplicationLayerException
{
    public ValidationFailedException(IReadOnlyDictionary<string, string[]> errors)
        : base("validation.failed", BuildMessage(errors)) => Errors = errors;

    /// <summary>Failures keyed by property name.</summary>
    public IReadOnlyDictionary<string, string[]> Errors { get; }

    private static string BuildMessage(IReadOnlyDictionary<string, string[]> errors)
    {
        int count = errors.Values.Sum(v => v.Length);
        return count == 1
            ? errors.Values.First()[0]
            : $"{count} validation errors occurred.";
    }
}

/// <summary>The caller does not hold the permission the request requires.</summary>
/// <remarks>
/// The message names the missing permission but deliberately reveals nothing about the
/// target - not whether the domain exists, not how many mailboxes it has. Authorization runs
/// <b>before</b> validation in the pipeline precisely so that an unauthorized caller cannot
/// use validation messages as an existence oracle.
/// </remarks>
public sealed class AuthorizationFailedException : ApplicationLayerException
{
    public AuthorizationFailedException(AdminPermission required)
        : base("authorization.denied",
               $"The current administrative session does not hold the required permission " +
               $"'{required}'.") => RequiredPermission = required;

    public AdminPermission RequiredPermission { get; }
}

/// <summary>The request was rejected because the server is in a maintenance mode that forbids it.</summary>
public sealed class MaintenanceModeException : ApplicationLayerException
{
    public MaintenanceModeException(MaintenanceMode mode)
        : base("maintenance.write_blocked",
               $"The server is in {mode} mode and is not accepting administrative changes.")
        => Mode = mode;

    public MaintenanceMode Mode { get; }

    /// <inheritdoc />
    public override bool IsRefusal => true;
}

/// <summary>
/// An already-applied migration's checksum no longer matches its script.
/// </summary>
/// <remarks>
/// This aborts startup. Continuing would mean running against a schema whose recorded
/// history is a fiction, and every subsequent migration would compound the divergence.
/// </remarks>
public sealed class SchemaDriftException : ApplicationLayerException
{
    public SchemaDriftException(int version, string name, string expectedChecksum, string actualChecksum)
        : base("migration.checksum_mismatch",
               $"Migration {version:D4} '{name}' has already been applied, but the script on " +
               $"disk no longer matches what was applied (recorded {expectedChecksum[..12]}…, " +
               $"found {actualChecksum[..12]}…). Applied migrations must never be edited. " +
               $"Add a new migration instead, or restore the original script.")
    {
        Version = version;
        Name = name;
        ExpectedChecksum = expectedChecksum;
        ActualChecksum = actualChecksum;
    }

    public int Version { get; }

    public string Name { get; }

    public string ExpectedChecksum { get; }

    public string ActualChecksum { get; }
}

/// <summary>A migration script failed to apply.</summary>
public sealed class MigrationFailedException : ApplicationLayerException
{
    public MigrationFailedException(int version, string name, Exception inner)
        : base("migration.failed",
               $"Migration {version:D4} '{name}' failed and was rolled back. The service will " +
               $"not start against a partially migrated schema.",
               inner)
    {
        Version = version;
        Name = name;
    }

    public int Version { get; }

    public string Name { get; }
}

/// <summary>
/// Authentication failed.
/// </summary>
/// <remarks>
/// <para>
/// <b>The message is identical for every cause.</b> Whether the account does not exist, the
/// password is wrong, or the stored verifier is corrupt, the caller is told the same thing.
/// Distinguishable messages are an enumeration oracle: "that account exists but the password
/// is wrong" is precisely the fact an attacker is trying to establish.
/// </para>
/// <para>
/// The real reason is recorded in the security event log, where an operator can see it and an
/// attacker cannot.
/// </para>
/// </remarks>
public sealed class AuthenticationFailedException : ApplicationLayerException
{
    public AuthenticationFailedException(string message)
        : base("security.authentication.failed", message)
    {
    }

    /// <inheritdoc />
    /// <remarks>The security event log is the record of it, with the reason; this is not.</remarks>
    public override bool IsRefusal => true;
}

/// <summary>
/// Authentication was refused because the account is locked out.
/// </summary>
/// <remarks>
/// Distinct from <see cref="AuthenticationFailedException"/> on purpose. Lockout state is not
/// a secret — the setup-status query reports it to an unauthenticated caller already — and a
/// legitimate administrator who has mistyped needs to be told to wait rather than left
/// guessing at a password that is currently irrelevant.
/// </remarks>
public sealed class AccountLockedOutException : ApplicationLayerException
{
    public AccountLockedOutException(TimeSpan remaining)
        : base("security.account.locked_out",
               $"Too many failed attempts. Try again in " +
               $"{Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes))} minute(s).")
        => Remaining = remaining;

    /// <summary>How long is left on the lockout.</summary>
    public TimeSpan Remaining { get; }

    /// <inheritdoc />
    public override bool IsRefusal => true;
}

/// <summary>
/// The request was refused because the signed-in administrator owes a password change.
/// </summary>
/// <remarks>
/// Raised after a recovery-key reset for anything other than changing the password or signing
/// out. Without it, a recovery key would be a standing bypass of the password rather than a
/// route back in.
/// </remarks>
public sealed class PasswordChangeRequiredException : ApplicationLayerException
{
    public PasswordChangeRequiredException()
        : base("security.password_change_required",
               "The master password must be changed before any other operation is permitted.")
    {
    }

    /// <inheritdoc />
    public override bool IsRefusal => true;
}
