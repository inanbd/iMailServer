using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Exceptions;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MediatR;

namespace MailServer.Application.Deliverability.Queries;

/// <summary>
/// Reads an RFC 8460 TLS report and says what it means.
/// </summary>
/// <remarks>
/// <para>
/// <b>The report is supplied rather than collected, and that is the current limit of this.</b>
/// RFC 8460 §3 has senders deliver reports to the <c>rua</c> address, usually as a gzipped JSON
/// attachment to a message. Recognising such a message in a mailbox, unpacking it and filing it
/// is a mail-processing pipeline, and this server's filtering milestone is where that belongs.
/// Until then an operator opens the report their <c>rua</c> mailbox received and submits it
/// here, which gets them the analysis — the part that has to be right — without the product
/// pretending to an automatic collection it does not have.
/// </para>
/// <para>
/// <b><see cref="AdminPermission.ViewServerState"/>.</b> This reads text the caller supplied and
/// reaches nothing: no DNS, no socket, no message store. It is the most inert query in the
/// deliverability set.
/// </para>
/// </remarks>
public sealed record AnalyseTlsReportQuery : IQuery<TlsReportDto>, IAuthorizedRequest
{
    /// <summary>The report's JSON, already decompressed.</summary>
    public required string Report { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class AnalyseTlsReportQueryHandler(ITlsReportReader reader)
    : IRequestHandler<AnalyseTlsReportQuery, TlsReportDto>
{
    public Task<TlsReportDto> Handle(AnalyseTlsReportQuery request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!reader.TryRead(request.Report, out TlsReport? report, out string? error))
        {
            throw new ValidationFailedException(new Dictionary<string, string[]>
            {
                [nameof(request.Report)] = [$"That is not an RFC 8460 TLS report: {error}"],
            });
        }

        return Task.FromResult(new TlsReportDto
        {
            OrganizationName = report!.OrganizationName,
            ContactInfo = report.ContactInfo,
            ReportId = report.ReportId,
            StartDate = report.StartDate,
            EndDate = report.EndDate,
            SuccessfulSessionCount = report.SuccessfulSessionCount,
            FailedSessionCount = report.FailedSessionCount,
            SuccessRate = report.SuccessRate,
            Summary = report.Summarise(),
            Failures =
            [
                .. report.FailuresByImpact().Select(f => new TlsFailureSummaryDto
                {
                    ResultType = TlsReport.NameOf(f.Result),
                    FailedSessionCount = f.FailedSessionCount,
                    ReceivingMxHostnames = f.ReceivingMxHostnames,
                    Remedy = TlsReport.RemedyFor(f.Result),
                }),
            ],
        });
    }
}
