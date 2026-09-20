using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Exceptions;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Deliverability.Queries;

/// <summary>
/// Runs the readiness report for a domain.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AdminPermission.ViewServerState"/> rather than a permission of its own: the report
/// reads this server's configuration, its certificate, its queue and public DNS. It reads no
/// message content, which is the boundary <c>ReadMessageContent</c> exists to guard.
/// </para>
/// <para>
/// <b>The run options are not a caller's free choice of how much to do.</b> They decide whether
/// this server opens an SMTP connection to itself, fetches a policy from a host the domain under
/// test names, and queries third-party blocklists — so they are on the request rather than
/// buried in configuration, and an operator who wants none of that can ask for none of it.
/// </para>
/// </remarks>
public sealed record GetDeliverabilityReportQuery : IQuery<DeliverabilityReportDto>, IAuthorizedRequest
{
    /// <summary>The domain to judge.</summary>
    public required string Domain { get; init; }

    /// <summary>Whether to open an SMTP connection to this server's own listener.</summary>
    public bool RunRelayTest { get; init; } = true;

    /// <summary>Whether to query the configured blocklists.</summary>
    public bool QueryReputationLists { get; init; } = true;

    /// <summary>Whether to fetch the MTA-STS policy over HTTPS.</summary>
    public bool FetchMtaStsPolicy { get; init; } = true;

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetDeliverabilityReportQueryHandler(IDeliverabilityReportService reports)
    : IRequestHandler<GetDeliverabilityReportQuery, DeliverabilityReportDto>
{
    public async Task<DeliverabilityReportDto> Handle(
        GetDeliverabilityReportQuery request,
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

        DeliverabilityReport report = await reports
            .RunAsync(
                domain,
                new DeliverabilityRunOptions(
                    request.RunRelayTest,
                    request.QueryReputationLists,
                    request.FetchMtaStsPolicy),
                cancellationToken)
            .ConfigureAwait(false);

        return Map(report);
    }

    internal static DeliverabilityReportDto Map(DeliverabilityReport report) => new()
    {
        Readiness = report.Readiness.ToString(),
        Score = report.Score,
        Summary = report.Summarise(),
        ProducedAt = report.ProducedAt,
        Categories = [.. report.Categories.Select(c => new DeliverabilityCategoryDto
        {
            Category = DeliverabilityCategories.NameOf(c.Category),
            Weight = c.Weight,
            Judged = c.Judged,
            Earned = c.Earned,
        })],
        Checks = [.. report.Checks.Select(Map)],
    };

    private static DeliverabilityCheckDto Map(DeliverabilityCheck check) => new()
    {
        Id = check.Id,
        Category = DeliverabilityCategories.NameOf(check.Category),
        Title = check.Title,
        Weight = check.Weight,
        Outcome = check.Outcome.ToString(),
        Detail = check.Detail,
        Expected = check.Evidence?.Expected,
        Found = check.Evidence?.Found,
        Source = check.Evidence?.Source,
        TtlSeconds = check.Evidence?.Ttl is { } ttl
            ? (int)Math.Clamp(ttl.TotalSeconds, 0, int.MaxValue)
            : null,
        Remedy = check.Remedy,
    };
}
