using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Mailboxes.Dtos;
using MailServer.Application.Mailboxes.Queries;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Mailboxes.Commands;

/// <summary>Creates a mailbox, its credential and its standard folders.</summary>
/// <remarks>
/// Transactional: the mailbox, its credential and six folder rows either all exist or none do.
/// A mailbox created without folders would be one an IMAP client repairs by inventing its own,
/// which is the fragmentation the standard folder set exists to prevent.
/// </remarks>
public sealed record CreateMailboxCommand : ICommand<MailboxSummaryDto>,
                                            ITransactionalRequest,
                                            IAuditableRequest,
                                            IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    /// <summary>The local-part, e.g. <c>alice</c>.</summary>
    public required string LocalPart { get; init; }

    public string? DisplayName { get; init; }

    /// <summary>
    /// The initial password.
    /// </summary>
    /// <remarks>
    /// Optional. A mailbox with no credential accepts mail and cannot be logged into, which is
    /// a legitimate state for a drop box or an account not yet handed over.
    /// </remarks>
    public string? Password { get; init; }

    /// <summary>Quota in bytes. Zero inherits the domain default.</summary>
    public long QuotaBytes { get; init; }

    public MailboxAccess Access { get; init; } = MailboxAccess.Imap | MailboxAccess.Submission;

    public AdminPermission RequiredPermission => AdminPermission.ManageMailboxes;

    /// <remarks>
    /// The audit record names the address and whether a password was set — never the password.
    /// Rule 97: secret values are not audited.
    /// </remarks>
    public AuditDescriptor DescribeForAudit() =>
        new("Mailbox.Create",
            nameof(Mailbox),
            LocalPart,
            Password is null
                ? "Created without a password; the mailbox accepts mail but cannot be logged into."
                : "Created with an initial password.");
}

internal sealed class CreateMailboxCommandHandler(
    IMailboxRepository mailboxes,
    IAliasRepository aliases,
    IDomainRepository domains,
    IPasswordHasher passwordHasher,
    IClock clock,
    ILogger<CreateMailboxCommandHandler> logger)
    : IRequestHandler<CreateMailboxCommand, MailboxSummaryDto>
{
    public async Task<MailboxSummaryDto> Handle(
        CreateMailboxCommand request,
        CancellationToken cancellationToken)
    {
        DomainId domainId = new(request.DomainId);

        MailDomain domain =
            await domains.GetByIdAsync(domainId, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(MailDomain), request.DomainId.ToString());

        EmailAddress address = EmailAddress.Parse($"{request.LocalPart.Trim()}@{domain.Name.Value}");

        await EnsureAddressIsFreeAsync(mailboxes, aliases, address, cancellationToken)
            .ConfigureAwait(false);

        Mailbox mailbox = Mailbox.Create(
            domainId,
            address,
            domain,
            request.DisplayName,
            QuotaBytes.FromBytes(request.QuotaBytes),
            request.Access,
            clock.UtcNow);

        await mailboxes.AddAsync(mailbox, cancellationToken).ConfigureAwait(false);

        if (request.Password is not null)
        {
            MailboxCredential credential = MailboxCredential.Create(
                mailbox.Id,
                passwordHasher.Hash(request.Password),

                // An administrator-set password is flagged as one. Not enforced - neither IMAP
                // nor SMTP has a channel to demand a change - but it is what lets the UI show
                // which mailboxes are still on a password somebody else chose.
                mustChangePassword: true,
                clock.UtcNow);

            await mailboxes.AddCredentialAsync(credential, cancellationToken).ConfigureAwait(false);
        }

        await CreateStandardFoldersAsync(mailboxes, mailbox.Id, clock.UtcNow, cancellationToken)
            .ConfigureAwait(false);

        logger.LogInformation(
            "Created mailbox {Address} in {Domain}.",
            address.NormalizedValue,
            domain.Name);

        return MailboxMapper.ToSummary(
            mailbox,
            domain,
            hasCredential: request.Password is not null,
            isLockedOut: false);
    }

    /// <summary>
    /// Refuses an address already used by a mailbox or an alias.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An address is either a mailbox or an alias, never both — otherwise delivery has to
    /// choose, and whichever it chooses is wrong half the time. No SQL engine can express that
    /// uniqueness across two tables, so it is checked here.
    /// </para>
    /// <para>
    /// That makes it a race in principle. It is also the only option short of a merged address
    /// table, and the losing side of the race gets a unique-index violation rather than a
    /// silently ambiguous address — a clear error instead of a wrong answer.
    /// </para>
    /// </remarks>
    internal static async Task EnsureAddressIsFreeAsync(
        IMailboxRepository mailboxes,
        IAliasRepository aliases,
        EmailAddress address,
        CancellationToken cancellationToken)
    {
        if (await mailboxes.AddressExistsAsync(address, cancellationToken).ConfigureAwait(false))
        {
            throw new DuplicateEntityException(nameof(Mailbox), address.NormalizedValue);
        }

        if (await aliases.AddressExistsAsync(address, cancellationToken).ConfigureAwait(false))
        {
            throw new DomainRuleViolationException(
                "address.already_an_alias",
                $"'{address.Value}' is already an alias. An address is either a mailbox or an " +
                "alias, never both — delivery would otherwise have to guess which. Remove the " +
                "alias first if the address should become a mailbox.");
        }
    }

    /// <summary>Creates the standard folder set.</summary>
    /// <remarks>
    /// UIDVALIDITY comes from the current Unix time in seconds: it must be strictly increasing
    /// across recreations of the same folder name, and a clock is the simplest source with that
    /// property. Folders created in the same second share a value, which is harmless — the
    /// guarantee is per folder, not global.
    /// </remarks>
    internal static async Task CreateStandardFoldersAsync(
        IMailboxRepository mailboxes,
        MailboxId mailboxId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        long uidValidity = now.ToUnixTimeSeconds();

        foreach ((string path, FolderSpecialUse specialUse) in MailboxFolder.StandardFolders)
        {
            await mailboxes.AddFolderAsync(
                MailboxFolder.Create(mailboxId, path, specialUse, uidValidity, now),
                cancellationToken).ConfigureAwait(false);
        }
    }
}

// =========================================================================================

/// <summary>Sets or replaces a mailbox password.</summary>
public sealed record SetMailboxPasswordCommand : ICommand<Unit>,
                                                 ITransactionalRequest,
                                                 IAuditableRequest,
                                                 IAuthorizedRequest
{
    public required Guid MailboxId { get; init; }

    /// <summary>The new password. Never logged, never audited.</summary>
    public required string Password { get; init; }

    /// <summary>
    /// Whether to flag the password as administrator-set.
    /// </summary>
    /// <remarks>
    /// True when an administrator is assigning a password on someone's behalf; false when the
    /// user is setting their own.
    /// </remarks>
    public bool MustChange { get; init; } = true;

    public AdminPermission RequiredPermission => AdminPermission.ManageCredentials;

    public AuditDescriptor DescribeForAudit() =>
        new("Mailbox.SetPassword",
            nameof(Mailbox),
            MailboxId.ToString(),
            "The password was changed. Any lockout was cleared.");
}

internal sealed class SetMailboxPasswordCommandHandler(
    IMailboxRepository mailboxes,
    IPasswordHasher passwordHasher,
    ISecurityEventRecorder securityEvents,
    IClock clock)
    : IRequestHandler<SetMailboxPasswordCommand, Unit>
{
    public async Task<Unit> Handle(
        SetMailboxPasswordCommand request,
        CancellationToken cancellationToken)
    {
        MailboxId id = new(request.MailboxId);

        Mailbox mailbox =
            await mailboxes.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(Mailbox), request.MailboxId.ToString());

        PasswordHash hash = passwordHasher.Hash(request.Password);

        MailboxCredential? existing = await mailboxes
            .GetCredentialAsync(id, cancellationToken)
            .ConfigureAwait(false);

        if (existing is null)
        {
            await mailboxes.AddCredentialAsync(
                MailboxCredential.Create(id, hash, request.MustChange, clock.UtcNow),
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            // SetPassword clears the lockout: whoever set this has proved control by a stronger
            // route than the password, and leaving a user locked out of an account whose
            // password was just reset for them serves nobody.
            existing.SetPassword(hash, request.MustChange, clock.UtcNow);

            await mailboxes
                .UpdateCredentialAsync(existing, cancellationToken)
                .ConfigureAwait(false);
        }

        await securityEvents.RecordAsync(
            SecurityEventType.MasterPasswordChanged,
            mailbox.Address.NormalizedValue,
            origin: null,
            "The mailbox password was changed by an administrator.",
            cancellationToken).ConfigureAwait(false);

        return Unit.Value;
    }
}

// =========================================================================================

/// <summary>Changes a mailbox's status, quota, access flags or display name.</summary>
public sealed record UpdateMailboxCommand : ICommand<Unit>,
                                            ITransactionalRequest,
                                            IAuditableRequest,
                                            IAuthorizedRequest
{
    public required Guid MailboxId { get; init; }

    public string? DisplayName { get; init; }

    public MailboxStatus? Status { get; init; }

    /// <summary>Quota in bytes, or null to leave unchanged. Zero inherits the domain default.</summary>
    public long? QuotaBytes { get; init; }

    public long? MaxMessageSizeBytes { get; init; }

    public MailboxAccess? Access { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageMailboxes;

    public AuditDescriptor DescribeForAudit() =>
        new("Mailbox.Update",
            nameof(Mailbox),
            MailboxId.ToString(),
            Status is null ? null : $"Status set to {Status}.");
}

internal sealed class UpdateMailboxCommandHandler(
    IMailboxRepository mailboxes,
    IClock clock,
    ILogger<UpdateMailboxCommandHandler> logger)
    : IRequestHandler<UpdateMailboxCommand, Unit>
{
    public async Task<Unit> Handle(
        UpdateMailboxCommand request,
        CancellationToken cancellationToken)
    {
        MailboxId id = new(request.MailboxId);

        Mailbox mailbox =
            await mailboxes.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(Mailbox), request.MailboxId.ToString());

        DateTimeOffset now = clock.UtcNow;

        if (request.DisplayName is not null)
        {
            mailbox.SetDisplayName(request.DisplayName, now);
        }

        if (request.Status is { } status)
        {
            mailbox.SetStatus(status, now);

            // Worth a log line at Information. A suspended mailbox keeps accepting mail while
            // refusing logins, and an operator later wondering why someone cannot sign in
            // should find the answer here rather than by inspecting a row.
            logger.LogInformation(
                "Mailbox {Address} set to {Status}.",
                mailbox.Address.NormalizedValue,
                status);
        }

        if (request.QuotaBytes is { } quota)
        {
            mailbox.SetQuota(QuotaBytes.FromBytes(quota), now);
        }

        if (request.MaxMessageSizeBytes is { } maxSize)
        {
            mailbox.SetMaxMessageSize(maxSize, now);
        }

        if (request.Access is { } access)
        {
            mailbox.SetAccess(access, now);
        }

        await mailboxes.UpdateAsync(mailbox, cancellationToken).ConfigureAwait(false);

        return Unit.Value;
    }
}

// =========================================================================================

/// <summary>Deletes a mailbox and everything belonging to it.</summary>
public sealed record DeleteMailboxCommand : ICommand<Unit>,
                                            ITransactionalRequest,
                                            IAuditableRequest,
                                            IAuthorizedRequest
{
    public required Guid MailboxId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageMailboxes;

    public AuditDescriptor DescribeForAudit() =>
        new("Mailbox.Delete", nameof(Mailbox), MailboxId.ToString(), "Irreversible.");
}

/// <remarks>
/// Deletion is ordered, not cascaded. Folders are <c>ON DELETE RESTRICT</c> because a folder
/// holds messages and messages are files on disk: cascading would remove the rows and strand
/// the files, which is unreclaimable storage and unrecoverable mail.
/// </remarks>
internal sealed class DeleteMailboxCommandHandler(
    IMailboxRepository mailboxes,
    IAliasRepository aliases,
    ILogger<DeleteMailboxCommandHandler> logger)
    : IRequestHandler<DeleteMailboxCommand, Unit>
{
    public async Task<Unit> Handle(
        DeleteMailboxCommand request,
        CancellationToken cancellationToken)
    {
        MailboxId id = new(request.MailboxId);

        Mailbox mailbox =
            await mailboxes.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(Mailbox), request.MailboxId.ToString());

        // An alias pointing at a deleted mailbox would accept mail and then fail to deliver it,
        // which is worse than refusing the delete: the failure surfaces later, to a sender, as
        // a bounce nobody here sees.
        IReadOnlyList<Alias> pointingHere =
        [
            .. (await aliases.GetAllEnabledAsync(cancellationToken).ConfigureAwait(false))
                .Where(a => a.Targets.Any(t =>
                    string.Equals(
                        t.NormalizedValue,
                        mailbox.Address.NormalizedValue,
                        StringComparison.OrdinalIgnoreCase))),
        ];

        if (pointingHere.Count > 0)
        {
            throw new DomainRuleViolationException(
                "mailbox.delete.aliased",
                $"'{mailbox.Address.Value}' is the target of " +
                string.Join(", ", pointingHere.Select(a => $"'{a.Address.Value}'")) +
                ". Those aliases would accept mail and then fail to deliver it. Repoint or " +
                "remove them first.");
        }

        foreach (MailboxFolder folder in
                 await mailboxes.GetFoldersAsync(id, cancellationToken).ConfigureAwait(false))
        {
            await mailboxes
                .RemoveFolderAsync(folder.Id, cancellationToken)
                .ConfigureAwait(false);
        }

        // The credential is ON DELETE CASCADE - it references nothing on disk, so cascading
        // leaves nothing orphaned.
        await mailboxes.RemoveAsync(id, cancellationToken).ConfigureAwait(false);

        logger.LogInformation("Deleted mailbox {Address}.", mailbox.Address.NormalizedValue);

        return Unit.Value;
    }
}
