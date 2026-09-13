using MailServer.Application.Common;
using MailServer.Domain.Enums;

namespace MailServer.Application.Security.Dtos;

/// <summary>
/// What an unauthenticated client is allowed to learn before signing in.
/// </summary>
/// <remarks>
/// Deliberately minimal. It says whether setup is needed and whether the account is currently
/// locked — both of which the client must know to render a sensible screen — and nothing else.
/// It does not confirm the administrator's name, the number of failures so far, or when the
/// last sign-in happened, because none of that is needed to draw a password box.
/// </remarks>
public sealed record SetupStatusDto
{
    /// <summary>True when no administrator account exists yet and setup must run.</summary>
    public required bool RequiresSetup { get; init; }

    /// <summary>True when authentication is currently refused because of a lockout.</summary>
    public required bool IsLockedOut { get; init; }

    /// <summary>Seconds remaining on the lockout. Zero when not locked out.</summary>
    public required int LockoutSecondsRemaining { get; init; }

    /// <summary>Minimum acceptable master password length, so the UI can state the rule.</summary>
    public required int MinimumPasswordLength { get; init; }

    public required string ProductVersion { get; init; }
}

/// <summary>The result of a successful authentication.</summary>
public sealed record AuthenticationResultDto
{
    /// <summary>
    /// The session token. Returned <b>once</b> and never recoverable.
    /// </summary>
    /// <remarks>
    /// The client holds this in memory only. Writing it to disk would turn a stolen profile
    /// into an authenticated session that outlives the console it came from.
    /// </remarks>
    public required string SessionToken { get; init; }

    public required Guid SessionId { get; init; }

    public required string Administrator { get; init; }

    public required AdminPermission Permissions { get; init; }

    public required DateTimeOffset ExpiresUtc { get; init; }

    /// <summary>Idle seconds after which the session ends, so the client can lock in step.</summary>
    public required int IdleTimeoutSeconds { get; init; }

    /// <summary>True when the password must be changed before anything else is permitted.</summary>
    public required bool MustChangePassword { get; init; }
}

/// <summary>
/// A newly issued recovery key, shown exactly once.
/// </summary>
/// <remarks>
/// The only moment the plaintext key exists outside the administrator's head. It is hashed
/// server-side before this DTO is returned, so nothing can re-display it afterwards.
/// </remarks>
public sealed record RecoveryKeyDto
{
    /// <summary>The key, formatted in groups for accurate transcription.</summary>
    public required string RecoveryKey { get; init; }

    public required DateTimeOffset IssuedUtc { get; init; }
}

/// <summary>Setup result: the session to continue with, plus the recovery key to write down.</summary>
public sealed record SetupResultDto
{
    public required AuthenticationResultDto Authentication { get; init; }

    public required RecoveryKeyDto RecoveryKey { get; init; }
}

/// <summary>An active administrative session, for the sessions screen.</summary>
public sealed record AdminSessionDto
{
    public required Guid Id { get; init; }

    public required string Administrator { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }

    public required DateTimeOffset LastActivityUtc { get; init; }

    public required DateTimeOffset ExpiresUtc { get; init; }

    public string? Origin { get; init; }

    /// <summary>True for the session making this request, so the UI can mark it.</summary>
    public required bool IsCurrent { get; init; }
}

/// <summary>One row of the audit trail.</summary>
public sealed record AuditRecordDto
{
    public required Guid Id { get; init; }

    public required DateTimeOffset TimestampUtc { get; init; }

    public required string Administrator { get; init; }

    public required string Action { get; init; }

    public required string TargetType { get; init; }

    public string? TargetIdentifier { get; init; }

    public required AuditResult Result { get; init; }

    public string? Detail { get; init; }

    public required string MachineName { get; init; }

    public required string CorrelationId { get; init; }
}

/// <summary>One row of the security event log.</summary>
public sealed record SecurityEventDto
{
    public required Guid Id { get; init; }

    public required DateTimeOffset TimestampUtc { get; init; }

    public required SecurityEventType EventType { get; init; }

    public string? Subject { get; init; }

    public string? Origin { get; init; }

    public required string Description { get; init; }

    public required string CorrelationId { get; init; }

    /// <summary>True for events that warrant attention rather than merely a record.</summary>
    public required bool IsAlarming { get; init; }
}

/// <summary>The security overview screen.</summary>
public sealed record SecurityStatusDto
{
    public required string Administrator { get; init; }

    public required DateTimeOffset? LastSignInUtc { get; init; }

    public required DateTimeOffset? PasswordChangedUtc { get; init; }

    public required bool HasRecoveryKey { get; init; }

    public required bool MustChangePassword { get; init; }

    public required int ActiveSessionCount { get; init; }

    public required int FailedAttemptsInLastDay { get; init; }

    public required bool IsLockedOut { get; init; }

    /// <summary>Algorithm and work factors in use, e.g. <c>argon2id (m=65536,t=3,p=2)</c>.</summary>
    public required string PasswordHashingDescription { get; init; }

    /// <summary>Which secret protector is active.</summary>
    public required string SecretProtectionScheme { get; init; }

    /// <summary>
    /// False when the development protector is in use. Surfaced prominently rather than
    /// buried, because an installation running it in anger is a serious misconfiguration.
    /// </summary>
    public required bool SecretProtectionIsProductionGrade { get; init; }
}

/// <summary>Filter and paging parameters for the audit trail.</summary>
public sealed record AuditSearchRequest : PagedRequest
{
    public DateTimeOffset? FromUtc { get; init; }

    public DateTimeOffset? ToUtc { get; init; }

    /// <summary>Exact match on the action name, e.g. <c>Domain.Create</c>.</summary>
    public string? Action { get; init; }

    public string? Administrator { get; init; }

    public AuditResult? Result { get; init; }

    /// <summary>Every entry sharing one correlation id.</summary>
    public string? CorrelationId { get; init; }
}

/// <summary>Filter and paging parameters for the security event log.</summary>
public sealed record SecurityEventSearchRequest : PagedRequest
{
    public DateTimeOffset? FromUtc { get; init; }

    public DateTimeOffset? ToUtc { get; init; }

    public IReadOnlyList<SecurityEventType>? EventTypes { get; init; }

    /// <summary>Restricts to events flagged as warranting attention.</summary>
    public bool AlarmingOnly { get; init; }
}
