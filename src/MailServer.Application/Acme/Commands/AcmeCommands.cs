using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Acme.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Acme.Commands;

/// <summary>
/// Requests a certificate from the configured certificate authority.
/// </summary>
/// <remarks>
/// <b>Deliberately not <see cref="ITransactionalRequest"/>.</b> Issuance performs network I/O
/// against the CA and can wait minutes for a challenge to validate — rule 105's "no network I/O
/// inside a transaction" exists precisely for this. Holding a write transaction open across an
/// ACME round trip would pin SQLite's single writer for the duration and stall every other
/// write on the server. The issuance service writes its order rows in short, separate
/// transactions instead.
/// </remarks>
public sealed record RequestCertificateCommand : ICommand<IssuanceResultDto>,
                                                 IAuditableRequest,
                                                 IAuthorizedRequest
{
    /// <summary>Hostnames the certificate must cover. The first becomes the subject.</summary>
    public required IReadOnlyList<string> Hostnames { get; init; }

    /// <summary>Challenge type, or null to use the configured default.</summary>
    public AcmeChallengeType? ChallengeType { get; init; }

    /// <summary>Bind the issued certificate to its first hostname.</summary>
    public bool BindOnSuccess { get; init; } = true;

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;

    public AuditDescriptor DescribeForAudit() =>
        new("Acme.RequestCertificate",
            nameof(Certificate),
            Hostnames.Count > 0 ? Hostnames[0] : "(none)",
            $"{Hostnames.Count} hostname(s), " +
            $"{ChallengeType?.ToString() ?? "default"} challenge.");
}

internal sealed class RequestCertificateCommandHandler(
    IAcmeIssuanceService issuance,
    IAcmeSettings settings,
    ITlsReloadCoordinator tlsReload,
    ILogger<RequestCertificateCommandHandler> logger)
    : IRequestHandler<RequestCertificateCommand, IssuanceResultDto>
{
    public async Task<IssuanceResultDto> Handle(
        RequestCertificateCommand request,
        CancellationToken cancellationToken)
    {
        List<DomainName> identifiers = [];

        foreach (string hostname in request.Hostnames)
        {
            identifiers.Add(DomainName.Parse(hostname));
        }

        IssuanceResult result = await issuance.IssueAsync(
            identifiers,
            request.ChallengeType ?? settings.DefaultChallengeType,
            request.BindOnSuccess,
            cancellationToken).ConfigureAwait(false);

        if (result.Succeeded && request.BindOnSuccess)
        {
            tlsReload.RequestReload();
        }
        else if (!result.Succeeded)
        {
            // Info, not Error. An ordinary failure here - DNS not ready, a record not yet
            // published - is a normal step in getting a certificate, and logging each one at
            // Error would train operators to ignore the level that matters.
            logger.LogInformation(
                "A certificate request for {HostnameCount} hostname(s) did not succeed: {Reason}",
                request.Hostnames.Count,
                result.Failure);
        }

        return new IssuanceResultDto
        {
            Succeeded = result.Succeeded,
            OrderId = result.OrderId.Value,
            CertificateId = result.Certificate?.Id.Value,
            Thumbprint = result.Certificate?.Thumbprint.Value,
            Failure = result.Failure,
            ManualDnsInstructions = result.ManualDnsInstructions,
        };
    }
}

/// <summary>
/// Runs the pre-flight checks without submitting anything to the CA.
/// </summary>
/// <remarks>
/// A separate operation so an operator can see what is wrong <i>before</i> committing to an
/// order. Everything it reports is checked again during issuance; this exists so the answer is
/// available at no cost to anyone's rate limit.
/// </remarks>
public sealed record CheckIssuanceReadinessCommand
    : ICommand<IReadOnlyList<PreflightFindingDto>>, IAuthorizedRequest
{
    public required IReadOnlyList<string> Hostnames { get; init; }

    public AcmeChallengeType? ChallengeType { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;
}

internal sealed class CheckIssuanceReadinessCommandHandler(
    IAcmePreflightCheck preflight,
    IAcmeSettings settings)
    : IRequestHandler<CheckIssuanceReadinessCommand, IReadOnlyList<PreflightFindingDto>>
{
    public async Task<IReadOnlyList<PreflightFindingDto>> Handle(
        CheckIssuanceReadinessCommand request,
        CancellationToken cancellationToken)
    {
        List<DomainName> identifiers = [];

        foreach (string hostname in request.Hostnames)
        {
            identifiers.Add(DomainName.Parse(hostname));
        }

        PreflightReport report = await preflight.CheckAsync(
            identifiers,
            request.ChallengeType ?? settings.DefaultChallengeType,
            cancellationToken).ConfigureAwait(false);

        return
        [
            .. report.Findings.Select(static f => new PreflightFindingDto
            {
                Identifier = f.Identifier.Value,
                Passed = f.Passed,
                Summary = f.Summary,
                IsBlocking = f.IsBlocking,
            }),
        ];
    }
}
