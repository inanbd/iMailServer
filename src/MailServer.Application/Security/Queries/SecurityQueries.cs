using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Common;
using MailServer.Application.Security.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MediatR;

namespace MailServer.Application.Security.Queries;

/// <summary>
/// Reports whether setup is required and whether authentication is currently locked out.
/// </summary>
/// <remarks>
/// The only thing an unauthenticated client may ask. It returns exactly what is needed to draw
/// the right screen and nothing more — not the administrator's name, not the failure count,
/// not the last sign-in time.
/// </remarks>
public sealed record GetSetupStatusQuery : IQuery<SetupStatusDto>,
                                           IAuthorizedRequest,
                                           IAnonymousRequest
{
    public AdminPermission RequiredPermission => AdminPermission.None;
}

internal sealed class GetSetupStatusQueryHandler(
    IAdminAccountRepository accounts,
    IEnvironmentInfo environment,
    ISecuritySettings settings,
    IClock clock) : IRequestHandler<GetSetupStatusQuery, SetupStatusDto>
{
    public async Task<SetupStatusDto> Handle(
        GetSetupStatusQuery request,
        CancellationToken cancellationToken)
    {
        AdminAccount? account = await accounts
            .GetBuiltInAsync(cancellationToken)
            .ConfigureAwait(false);

        DateTimeOffset now = clock.UtcNow;

        bool lockedOut = account?.IsLockedOut(now) ?? false;

        return new SetupStatusDto
        {
            RequiresSetup = account is null,
            IsLockedOut = lockedOut,
            LockoutSecondsRemaining = lockedOut
                ? (int)Math.Ceiling(account!.GetRemainingLockout(now).TotalSeconds)
                : 0,
            MinimumPasswordLength = settings.MinimumPasswordLength,
            ProductVersion = environment.ProductVersion,
        };
    }
}

/// <summary>The security overview screen.</summary>
public sealed record GetSecurityStatusQuery : IQuery<SecurityStatusDto>, IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetSecurityStatusQueryHandler(
    IAdminAccountRepository accounts,
    IAdminSessionManager sessions,
    ISecurityEventQueries securityEvents,
    IPasswordHasher passwordHasher,
    ISecretProtector secretProtector,
    IClock clock) : IRequestHandler<GetSecurityStatusQuery, SecurityStatusDto>
{
    public async Task<SecurityStatusDto> Handle(
        GetSecurityStatusQuery request,
        CancellationToken cancellationToken)
    {
        AdminAccount? account = await accounts
            .GetBuiltInAsync(cancellationToken)
            .ConfigureAwait(false);

        DateTimeOffset now = clock.UtcNow;

        IReadOnlyList<AdminSession> active = await sessions
            .GetActiveAsync(cancellationToken)
            .ConfigureAwait(false);

        int failures = await securityEvents
            .CountFailedSignInsSinceAsync(now.AddDays(-1), cancellationToken)
            .ConfigureAwait(false);

        return new SecurityStatusDto
        {
            Administrator = account?.Name ?? AdminAccount.BuiltInAdministratorName,
            LastSignInUtc = account?.LastSignInUtc,
            PasswordChangedUtc = account?.PasswordChangedUtc,
            HasRecoveryKey = account?.HasRecoveryKey ?? false,
            MustChangePassword = account?.MustChangePassword ?? false,
            ActiveSessionCount = active.Count,
            FailedAttemptsInLastDay = failures,
            IsLockedOut = account?.IsLockedOut(now) ?? false,
            PasswordHashingDescription = passwordHasher.Describe(),
            SecretProtectionScheme = secretProtector.SchemeName,
            SecretProtectionIsProductionGrade = secretProtector.IsProductionGrade,
        };
    }
}

/// <summary>Lists currently active administrative sessions.</summary>
public sealed record GetActiveSessionsQuery : IQuery<IReadOnlyList<AdminSessionDto>>, IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ViewAuditLog;
}

internal sealed class GetActiveSessionsQueryHandler(
    IAdminSessionManager sessions,
    IAdminContext adminContext)
    : IRequestHandler<GetActiveSessionsQuery, IReadOnlyList<AdminSessionDto>>
{
    public async Task<IReadOnlyList<AdminSessionDto>> Handle(
        GetActiveSessionsQuery request,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<AdminSession> active = await sessions
            .GetActiveAsync(cancellationToken)
            .ConfigureAwait(false);

        return
        [
            .. active
                .OrderByDescending(s => s.LastActivityUtc)
                .Select(s => new AdminSessionDto
                {
                    Id = s.Id.Value,
                    Administrator = s.Administrator,
                    CreatedUtc = s.CreatedUtc,
                    LastActivityUtc = s.LastActivityUtc,
                    ExpiresUtc = s.AbsoluteExpiryUtc,
                    Origin = s.Origin,

                    // So the UI can mark "this is you" and avoid offering to revoke it by
                    // accident.
                    IsCurrent = string.Equals(
                        s.Id.ToString(),
                        adminContext.SessionIdentifier,
                        StringComparison.OrdinalIgnoreCase),
                })
        ];
    }
}

/// <summary>Returns a page of the audit trail.</summary>
public sealed record GetAuditLogQuery : IQuery<PagedResult<AuditRecordDto>>, IAuthorizedRequest
{
    public DateTimeOffset? FromUtc { get; init; }

    public DateTimeOffset? ToUtc { get; init; }

    public string? Action { get; init; }

    public string? Administrator { get; init; }

    public AuditResult? Result { get; init; }

    public string? CorrelationId { get; init; }

    public int Page { get; init; }

    public int PageSize { get; init; } = PagedRequest.DefaultPageSize;

    public AdminPermission RequiredPermission => AdminPermission.ViewAuditLog;
}

internal sealed class GetAuditLogQueryHandler(IAuditQueries queries)
    : IRequestHandler<GetAuditLogQuery, PagedResult<AuditRecordDto>>
{
    public Task<PagedResult<AuditRecordDto>> Handle(
        GetAuditLogQuery request,
        CancellationToken cancellationToken) =>
        queries.SearchAsync(
            new AuditSearchRequest
            {
                FromUtc = request.FromUtc,
                ToUtc = request.ToUtc,
                Action = request.Action,
                Administrator = request.Administrator,
                Result = request.Result,
                CorrelationId = request.CorrelationId,
                Page = request.Page,
                PageSize = request.PageSize,
            },
            cancellationToken);
}

/// <summary>Returns a page of the security event log.</summary>
public sealed record GetSecurityEventsQuery : IQuery<PagedResult<SecurityEventDto>>, IAuthorizedRequest
{
    public DateTimeOffset? FromUtc { get; init; }

    public DateTimeOffset? ToUtc { get; init; }

    public IReadOnlyList<SecurityEventType>? EventTypes { get; init; }

    public bool AlarmingOnly { get; init; }

    public int Page { get; init; }

    public int PageSize { get; init; } = PagedRequest.DefaultPageSize;

    public AdminPermission RequiredPermission => AdminPermission.ViewAuditLog;
}

internal sealed class GetSecurityEventsQueryHandler(ISecurityEventQueries queries)
    : IRequestHandler<GetSecurityEventsQuery, PagedResult<SecurityEventDto>>
{
    public Task<PagedResult<SecurityEventDto>> Handle(
        GetSecurityEventsQuery request,
        CancellationToken cancellationToken) =>
        queries.SearchAsync(
            new SecurityEventSearchRequest
            {
                FromUtc = request.FromUtc,
                ToUtc = request.ToUtc,
                EventTypes = request.EventTypes,
                AlarmingOnly = request.AlarmingOnly,
                Page = request.Page,
                PageSize = request.PageSize,
            },
            cancellationToken);
}
