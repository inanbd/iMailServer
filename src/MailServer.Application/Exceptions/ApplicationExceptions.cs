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
