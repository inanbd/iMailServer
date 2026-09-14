using MailServer.Domain.Enums;

namespace MailServer.Application.Mailboxes.Dtos;

/// <summary>A mailbox as shown in the administration grid.</summary>
/// <remarks>
/// <b>Carries no password hash.</b> The verifier is useless to an attacker in the sense that it
/// cannot be reversed, but it is still offline-crackable material, and a DTO that travels over
/// IPC and is rendered has no business holding one.
/// </remarks>
public sealed record MailboxSummaryDto
{
    public required Guid Id { get; init; }

    public required Guid DomainId { get; init; }

    /// <summary>The address as the administrator typed it.</summary>
    public required string Address { get; init; }

    public string? DisplayName { get; init; }

    public required MailboxStatus Status { get; init; }

    public required MailboxAccess Access { get; init; }

    /// <summary>The mailbox's own quota. Zero means it inherits the domain default.</summary>
    public required long QuotaBytes { get; init; }

    /// <summary>
    /// The quota actually in force, after inheritance is resolved.
    /// </summary>
    /// <remarks>
    /// Resolved server-side. "Zero means inherit" is exactly the rule that gets reimplemented
    /// slightly differently in a view and then disagrees with delivery about whether a mailbox
    /// is full.
    /// </remarks>
    public required long EffectiveQuotaBytes { get; init; }

    public required long StorageUsedBytes { get; init; }

    /// <summary>How full the mailbox is. Null when the effective quota is unlimited.</summary>
    public double? QuotaPercentageUsed { get; init; }

    /// <summary>True when the mailbox is at or over its effective quota.</summary>
    public required bool IsOverQuota { get; init; }

    /// <summary>True when a password has been set.</summary>
    /// <remarks>
    /// A mailbox with no credential accepts mail and cannot be logged into, which is a valid
    /// state — a drop box, or an account not yet handed over — but an easy one to create by
    /// accident, so it is surfaced rather than inferred.
    /// </remarks>
    public required bool HasCredential { get; init; }

    /// <summary>True when the credential is locked out right now.</summary>
    public required bool IsLockedOut { get; init; }

    public DateTimeOffset? LastLoginUtc { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }
}

/// <summary>A mailbox in full, for the detail pane.</summary>
public sealed record MailboxDetailDto
{
    public required MailboxSummaryDto Summary { get; init; }

    public required string DomainName { get; init; }

    /// <summary>Largest accepted message. Zero means inherit the domain default.</summary>
    public required long MaxMessageSizeBytes { get; init; }

    public required long EffectiveMaxMessageSizeBytes { get; init; }

    public DateTimeOffset? PasswordChangedUtc { get; init; }

    /// <summary>Set when an administrator assigned the current password.</summary>
    public required bool MustChangePassword { get; init; }

    public required IReadOnlyList<MailboxFolderDto> Folders { get; init; }

    /// <summary>Aliases whose targets include this mailbox.</summary>
    /// <remarks>
    /// Shown because deleting a mailbox that several aliases point at silently breaks them,
    /// and the operator deleting it is the one person positioned to notice.
    /// </remarks>
    public required IReadOnlyList<string> IncomingAliases { get; init; }
}

/// <summary>An IMAP folder.</summary>
public sealed record MailboxFolderDto
{
    public required Guid Id { get; init; }

    public required string Path { get; init; }

    public required FolderSpecialUse SpecialUse { get; init; }

    public required bool IsSubscribed { get; init; }
}

/// <summary>An alias.</summary>
public sealed record AliasDto
{
    public required Guid Id { get; init; }

    public required Guid DomainId { get; init; }

    public required string Address { get; init; }

    public required IReadOnlyList<string> Targets { get; init; }

    public string? Description { get; init; }

    public required bool IsEnabled { get; init; }

    /// <summary>True when this alias fans one message out to several recipients.</summary>
    public required bool IsDistributionList { get; init; }

    /// <summary>
    /// Targets that are neither a local mailbox nor a local alias.
    /// </summary>
    /// <remarks>
    /// Surfaced because an external target has a consequence an operator should know about:
    /// forwarded mail arrives at the destination from this server, so SPF sees this server
    /// rather than the original sender. It is also how a typo shows up — a target that was
    /// meant to be local and is not.
    /// </remarks>
    public required IReadOnlyList<string> ExternalTargets { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }
}

/// <summary>A role address a domain is expected to answer but does not.</summary>
public sealed record MissingRoleAddressDto
{
    public required string LocalPart { get; init; }

    public required bool IsRequired { get; init; }

    /// <summary>What it is for, and what its absence costs.</summary>
    public required string Purpose { get; init; }
}
