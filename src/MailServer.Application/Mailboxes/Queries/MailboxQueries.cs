using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Mailboxes.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Mailboxes.Queries;

/// <summary>Builds mailbox DTOs. Shared by the commands and the queries.</summary>
/// <remarks>
/// One mapper so a mailbox is described identically wherever it appears. Two would be how a
/// grid and a detail pane come to disagree about whether a mailbox is over quota.
/// </remarks>
internal static class MailboxMapper
{
    public static MailboxSummaryDto ToSummary(
        Mailbox mailbox,
        MailDomain domain,
        bool hasCredential,
        bool isLockedOut)
    {
        QuotaBytes effective = mailbox.EffectiveQuota(domain.DefaultMailboxQuota);

        return new MailboxSummaryDto
        {
            Id = mailbox.Id.Value,
            DomainId = mailbox.DomainId.Value,
            Address = mailbox.Address.Value,
            DisplayName = mailbox.DisplayName,
            Status = mailbox.Status,
            Access = mailbox.Access,
            QuotaBytes = mailbox.Quota.Bytes,
            EffectiveQuotaBytes = effective.Bytes,
            StorageUsedBytes = mailbox.StorageUsedBytes,

            // Null rather than zero for an unlimited quota. Zero would render as "0% used",
            // which reads as a fact about storage rather than the absence of a limit.
            QuotaPercentageUsed = effective.IsUnlimited
                ? null
                : mailbox.QuotaPercentageUsed(domain.DefaultMailboxQuota),

            IsOverQuota = effective.IsExceededBy(mailbox.StorageUsedBytes),
            HasCredential = hasCredential,
            IsLockedOut = isLockedOut,
            LastLoginUtc = mailbox.LastLoginUtc,
            CreatedUtc = mailbox.CreatedUtc,
        };
    }

    public static AliasDto ToDto(Alias alias, IReadOnlySet<string> localAddresses) => new()
    {
        Id = alias.Id.Value,
        DomainId = alias.DomainId.Value,
        Address = alias.Address.Value,
        Targets = [.. alias.Targets.Select(static t => t.Value)],
        Description = alias.Description,
        IsEnabled = alias.IsEnabled,
        IsDistributionList = alias.IsDistributionList,
        ExternalTargets =
        [
            .. alias.Targets
                .Where(t => !localAddresses.Contains(t.NormalizedValue))
                .Select(static t => t.Value),
        ],
        CreatedUtc = alias.CreatedUtc,
    };
}

// =========================================================================================

/// <summary>Every mailbox in a domain.</summary>
public sealed record GetMailboxesQuery : IQuery<IReadOnlyList<MailboxSummaryDto>>, IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetMailboxesQueryHandler(
    IMailboxRepository mailboxes,
    IDomainRepository domains,
    IClock clock)
    : IRequestHandler<GetMailboxesQuery, IReadOnlyList<MailboxSummaryDto>>
{
    public async Task<IReadOnlyList<MailboxSummaryDto>> Handle(
        GetMailboxesQuery request,
        CancellationToken cancellationToken)
    {
        DomainId domainId = new(request.DomainId);

        MailDomain domain =
            await domains.GetByIdAsync(domainId, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(MailDomain), request.DomainId.ToString());

        IReadOnlyList<Mailbox> all =
            await mailboxes.GetByDomainAsync(domainId, cancellationToken).ConfigureAwait(false);

        DateTimeOffset now = clock.UtcNow;
        List<MailboxSummaryDto> result = [];

        foreach (Mailbox mailbox in all)
        {
            // One credential read per mailbox. The alternative is a join, which would mean a
            // second query shape for the same data and a hash travelling through a read model
            // that has no business carrying one. A domain's mailbox count is small.
            MailboxCredential? credential = await mailboxes
                .GetCredentialAsync(mailbox.Id, cancellationToken)
                .ConfigureAwait(false);

            result.Add(MailboxMapper.ToSummary(
                mailbox,
                domain,
                credential is not null,
                credential?.IsLockedOut(now) ?? false));
        }

        return result;
    }
}

/// <summary>One mailbox in full.</summary>
public sealed record GetMailboxQuery : IQuery<MailboxDetailDto>, IAuthorizedRequest
{
    public required Guid MailboxId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetMailboxQueryHandler(
    IMailboxRepository mailboxes,
    IAliasRepository aliases,
    IDomainRepository domains,
    IClock clock)
    : IRequestHandler<GetMailboxQuery, MailboxDetailDto>
{
    public async Task<MailboxDetailDto> Handle(
        GetMailboxQuery request,
        CancellationToken cancellationToken)
    {
        MailboxId id = new(request.MailboxId);

        Mailbox mailbox =
            await mailboxes.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(Mailbox), request.MailboxId.ToString());

        MailDomain domain =
            await domains.GetByIdAsync(mailbox.DomainId, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(
                nameof(MailDomain),
                mailbox.DomainId.ToString());

        MailboxCredential? credential = await mailboxes
            .GetCredentialAsync(id, cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyList<MailboxFolder> folders =
            await mailboxes.GetFoldersAsync(id, cancellationToken).ConfigureAwait(false);

        // Which aliases point here. Shown because deleting a mailbox several aliases target
        // silently breaks them, and the operator deleting it is the one person positioned to
        // notice before mail starts failing.
        IReadOnlyList<Alias> incoming =
        [
            .. (await aliases.GetAllEnabledAsync(cancellationToken).ConfigureAwait(false))
                .Where(a => a.Targets.Any(t =>
                    string.Equals(
                        t.NormalizedValue,
                        mailbox.Address.NormalizedValue,
                        StringComparison.OrdinalIgnoreCase))),
        ];

        return new MailboxDetailDto
        {
            Summary = MailboxMapper.ToSummary(
                mailbox,
                domain,
                credential is not null,
                credential?.IsLockedOut(clock.UtcNow) ?? false),
            DomainName = domain.Name.Value,
            MaxMessageSizeBytes = mailbox.MaxMessageSizeBytes,
            EffectiveMaxMessageSizeBytes =
                mailbox.EffectiveMaxMessageSize(domain.MaxMessageSizeBytes),
            PasswordChangedUtc = credential?.PasswordChangedUtc,
            MustChangePassword = credential?.MustChangePassword ?? false,
            Folders =
            [
                .. folders.Select(static f => new MailboxFolderDto
                {
                    Id = f.Id.Value,
                    Path = f.Path,
                    SpecialUse = f.SpecialUse,
                    IsSubscribed = f.IsSubscribed,
                }),
            ],
            IncomingAliases = [.. incoming.Select(static a => a.Address.Value)],
        };
    }
}

/// <summary>Every alias in a domain.</summary>
public sealed record GetAliasesQuery : IQuery<IReadOnlyList<AliasDto>>, IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetAliasesQueryHandler(
    IAliasRepository aliases,
    IMailboxRepository mailboxes)
    : IRequestHandler<GetAliasesQuery, IReadOnlyList<AliasDto>>
{
    public async Task<IReadOnlyList<AliasDto>> Handle(
        GetAliasesQuery request,
        CancellationToken cancellationToken)
    {
        DomainId domainId = new(request.DomainId);

        IReadOnlyList<Alias> all =
            await aliases.GetByDomainAsync(domainId, cancellationToken).ConfigureAwait(false);

        HashSet<string> local = await BuildLocalAddressSetAsync(
            mailboxes,
            aliases,
            domainId,
            cancellationToken).ConfigureAwait(false);

        return [.. all.Select(a => MailboxMapper.ToDto(a, local))];
    }

    /// <summary>Every address this domain answers, whether mailbox or alias.</summary>
    internal static async Task<HashSet<string>> BuildLocalAddressSetAsync(
        IMailboxRepository mailboxes,
        IAliasRepository aliases,
        DomainId domainId,
        CancellationToken cancellationToken)
    {
        HashSet<string> local = new(StringComparer.OrdinalIgnoreCase);

        foreach (Mailbox mailbox in
                 await mailboxes.GetByDomainAsync(domainId, cancellationToken).ConfigureAwait(false))
        {
            local.Add(mailbox.Address.NormalizedValue);
        }

        foreach (Alias alias in
                 await aliases.GetByDomainAsync(domainId, cancellationToken).ConfigureAwait(false))
        {
            local.Add(alias.Address.NormalizedValue);
        }

        return local;
    }
}

/// <summary>
/// Which RFC 2142 role addresses a domain does not answer.
/// </summary>
/// <remarks>
/// A readiness check rather than something the server fixes. Whether <c>postmaster@</c> should
/// be a mailbox or an alias to a real person is the operator's decision — and on most domains
/// all of them should be aliases to one person, which is not something to guess at.
/// </remarks>
public sealed record GetMissingRoleAddressesQuery
    : IQuery<IReadOnlyList<MissingRoleAddressDto>>, IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetMissingRoleAddressesQueryHandler(
    IMailboxRepository mailboxes,
    IAliasRepository aliases)
    : IRequestHandler<GetMissingRoleAddressesQuery, IReadOnlyList<MissingRoleAddressDto>>
{
    public async Task<IReadOnlyList<MissingRoleAddressDto>> Handle(
        GetMissingRoleAddressesQuery request,
        CancellationToken cancellationToken)
    {
        DomainId domainId = new(request.DomainId);

        List<string> localParts = [];

        foreach (Mailbox mailbox in
                 await mailboxes.GetByDomainAsync(domainId, cancellationToken).ConfigureAwait(false))
        {
            localParts.Add(mailbox.Address.LocalPart);
        }

        // Aliases count. An alias to a real person satisfies the requirement perfectly, and is
        // usually the better arrangement - nobody wants to log into postmaster@ separately.
        foreach (Alias alias in
                 await aliases.GetByDomainAsync(domainId, cancellationToken).ConfigureAwait(false))
        {
            localParts.Add(alias.Address.LocalPart);
        }

        return
        [
            .. RoleAddressPolicy.FindMissing(localParts).Select(static r => new MissingRoleAddressDto
            {
                LocalPart = r.LocalPart,
                IsRequired = r.Expectation == RoleAddressExpectation.Required,
                Purpose = r.Purpose,
            }),
        ];
    }
}
