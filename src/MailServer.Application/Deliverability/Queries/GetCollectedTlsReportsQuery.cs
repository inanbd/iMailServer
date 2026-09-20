using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Exceptions;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Deliverability.Queries;

/// <summary>
/// The TLS reports other senders have delivered about a domain, newest first.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AdminPermission.ViewServerState"/>: this reads rows this server already collected
/// and reaches nothing.
/// </para>
/// <para>
/// <b>Everything it returns is a claim from outside.</b> A report is unauthenticated — anyone
/// who can reach the <c>rua</c> address can send one, and nothing in RFC 8460 proves the
/// organisation named actually sent it. Worth acting on when several independent senders agree;
/// never on its own grounds to change a policy.
/// </para>
/// </remarks>
public sealed record GetCollectedTlsReportsQuery : IQuery<IReadOnlyList<CollectedTlsReportDto>>, IAuthorizedRequest
{
    /// <summary>The domain to list reports for.</summary>
    public required string Domain { get; init; }

    /// <summary>The most to return.</summary>
    public int Limit { get; init; } = 50;

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetCollectedTlsReportsQueryHandler(ITlsReportRepository reports)
    : IRequestHandler<GetCollectedTlsReportsQuery, IReadOnlyList<CollectedTlsReportDto>>
{
    public async Task<IReadOnlyList<CollectedTlsReportDto>> Handle(
        GetCollectedTlsReportsQuery request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!DomainName.TryParse(request.Domain, out DomainName? domain))
        {
            throw new ValidationFailedException(new Dictionary<string, string[]>
            {
                [nameof(request.Domain)] = [$"'{request.Domain}' is not a domain name."],
            });
        }

        IReadOnlyList<CollectedTlsReport> collected = await reports
            .ListRecentAsync(domain.Value, Math.Clamp(request.Limit, 1, 200), cancellationToken)
            .ConfigureAwait(false);

        return
        [
            .. collected.Select(r => new CollectedTlsReportDto
            {
                Id = r.Id,
                PolicyDomain = r.PolicyDomain,
                OrganizationName = r.OrganizationName,
                ContactInfo = r.ContactInfo,
                ReportId = r.ReportId,
                StartUtc = r.StartUtc,
                EndUtc = r.EndUtc,
                SuccessfulSessionCount = r.SuccessfulSessionCount,
                FailedSessionCount = r.FailedSessionCount,
                CollectedUtc = r.CollectedUtc,
                Summary = r.Summary,
                Failures =
                [
                    .. r.Failures.Select(f => new TlsFailureSummaryDto
                    {
                        ResultType = TlsReport.NameOf(f.Result),
                        FailedSessionCount = f.FailedSessionCount,
                        ReceivingMxHostnames = f.ReceivingMxHostnames,
                        Remedy = TlsReport.RemedyFor(f.Result),
                    }),
                ],
            }),
        ];
    }
}
