using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Acme.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MediatR;

namespace MailServer.Application.Acme.Queries;

/// <summary>The ACME configuration and what still stands between it and a certificate.</summary>
public sealed record GetAcmeStatusQuery : IQuery<AcmeStatusDto>, IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetAcmeStatusQueryHandler(
    IAcmeSettings settings,
    IAcmeRepository acme)
    : IRequestHandler<GetAcmeStatusQuery, AcmeStatusDto>
{
    public async Task<AcmeStatusDto> Handle(
        GetAcmeStatusQuery request,
        CancellationToken cancellationToken)
    {
        AcmeAccount? account = await acme
            .GetActiveAccountAsync(settings.DefaultDirectory, cancellationToken)
            .ConfigureAwait(false);

        List<string> blocking = [];

        // Assembled here rather than in the view, so the UI cannot drift out of step with what
        // the issuance path actually requires.
        if (string.IsNullOrWhiteSpace(settings.ContactEmail))
        {
            blocking.Add(
                "No contact address is configured. The certificate authority requires one; it " +
                "is where expiry warnings are sent.");
        }

        if (!settings.TermsOfServiceAccepted)
        {
            blocking.Add(
                "The certificate authority's terms of service have not been accepted.");
        }

        if (settings.DefaultChallengeType == AcmeChallengeType.Http01 &&
            !settings.EnableHttpChallengeListener)
        {
            blocking.Add(
                "HTTP-01 is selected but the challenge endpoint is disabled, so the " +
                "certificate authority would find nothing to fetch.");
        }

        return new AcmeStatusDto
        {
            ConfiguredDirectory = settings.DefaultDirectory,
            IssuesPubliclyTrustedCertificates =
                settings.DefaultDirectory is not AcmeDirectory.LetsEncryptStaging,
            ContactEmail = settings.ContactEmail,
            TermsOfServiceAccepted = settings.TermsOfServiceAccepted,
            DefaultChallengeType = settings.DefaultChallengeType,
            HttpChallengeListenerEnabled = settings.EnableHttpChallengeListener,
            HttpChallengePort = settings.HttpChallengePort,
            HasUsableAccount = account is { IsUsable: true },
            BlockingIssues = blocking,
        };
    }
}

/// <summary>Registered ACME accounts, across every directory.</summary>
public sealed record GetAcmeAccountsQuery : IQuery<IReadOnlyList<AcmeAccountDto>>, IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;
}

internal sealed class GetAcmeAccountsQueryHandler(IAcmeRepository acme)
    : IRequestHandler<GetAcmeAccountsQuery, IReadOnlyList<AcmeAccountDto>>
{
    public async Task<IReadOnlyList<AcmeAccountDto>> Handle(
        GetAcmeAccountsQuery request,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<AcmeAccount> accounts =
            await acme.GetAccountsAsync(cancellationToken).ConfigureAwait(false);

        return
        [
            .. accounts.Select(static a => new AcmeAccountDto
            {
                Id = a.Id.Value,
                Directory = a.Directory,
                DirectoryUrl = a.DirectoryUrl,
                ContactEmail = a.ContactEmail,
                IsRegistered = a.AccountUrl is not null,
                IsActive = a.IsActive,
                IssuesPubliclyTrustedCertificates = a.IssuesPubliclyTrustedCertificates,
                TermsAccepted = a.TermsOfServiceAccepted,
                TermsAcceptedUtc = a.TermsAcceptedUtc,
                CreatedUtc = a.CreatedUtc,
            }),
        ];
    }
}

/// <summary>Recent issuance attempts, newest first.</summary>
/// <remarks>
/// The history an operator needs after a failure: which hostnames, which challenge, what the CA
/// said, and whether the attempt reached the CA at all — the last of which decides whether
/// retrying immediately is safe.
/// </remarks>
public sealed record GetAcmeOrdersQuery : IQuery<IReadOnlyList<AcmeOrderDto>>, IAuthorizedRequest
{
    /// <summary>How many to return.</summary>
    public int Limit { get; init; } = 25;

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;
}

internal sealed class GetAcmeOrdersQueryHandler(IAcmeRepository acme)
    : IRequestHandler<GetAcmeOrdersQuery, IReadOnlyList<AcmeOrderDto>>
{
    public async Task<IReadOnlyList<AcmeOrderDto>> Handle(
        GetAcmeOrdersQuery request,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<AcmeOrder> orders = await acme
            .GetRecentOrdersAsync(Math.Clamp(request.Limit, 1, 200), cancellationToken)
            .ConfigureAwait(false);

        return
        [
            .. orders.Select(static o => new AcmeOrderDto
            {
                Id = o.Id.Value,
                Identifiers = [.. o.Identifiers.Select(static i => i.Value)],
                ChallengeType = o.ChallengeType,
                Status = o.Status,
                LastError = o.LastError,
                AttemptCount = o.AttemptCount,
                LastAttemptUtc = o.LastAttemptUtc,
                CompletedUtc = o.CompletedUtc,
                CreatedUtc = o.CreatedUtc,
                IssuedCertificateId = o.IssuedCertificateId?.Value,
                ReachedCertificateAuthority = o.ConsumedCaQuota,
            }),
        ];
    }
}
