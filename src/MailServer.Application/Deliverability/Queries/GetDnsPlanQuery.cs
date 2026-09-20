using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Exceptions;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Deliverability.Queries;

/// <summary>
/// Writes the DNS records a domain needs in order to send mail that is accepted.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AdminPermission.ViewServerState"/>, like the report it accompanies: this reads the
/// server's own configuration and its DKIM key's <b>public</b> half, opens no message and
/// publishes nothing.
/// </para>
/// <para>
/// <b>The three optional fields are choices rather than settings.</b> Where reports should go is
/// a mailbox somebody has to read, and advertising an MTA-STS policy commits the operator to
/// serving one over HTTPS for as long as the record stands. Defaulting them would put records in
/// front of an operator that look like this server's findings rather than their own decisions.
/// </para>
/// </remarks>
public sealed record GetDnsPlanQuery : IQuery<DnsPlanDto>, IAuthorizedRequest
{
    /// <summary>The domain to write a plan for.</summary>
    public required string Domain { get; init; }

    /// <summary>Where aggregate DMARC reports should go, or null for none.</summary>
    public string? DmarcReportAddress { get; init; }

    /// <summary>Where TLS-RPT reports should go, or null to leave TLS-RPT out of the plan.</summary>
    public string? TlsReportAddress { get; init; }

    /// <summary>The MTA-STS policy id to advertise, or null to leave MTA-STS out of the plan.</summary>
    public string? MtaStsId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetDnsPlanQueryHandler(IDnsPlanService plans)
    : IRequestHandler<GetDnsPlanQuery, DnsPlanDto>
{
    public async Task<DnsPlanDto> Handle(GetDnsPlanQuery request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Dictionary<string, string[]> failures = [];

        if (!DomainName.TryParse(request.Domain, out DomainName? domain))
        {
            failures[nameof(request.Domain)] = [$"'{request.Domain}' is not a domain name."];
        }

        EmailAddress? dmarc = Address(
            request.DmarcReportAddress, nameof(request.DmarcReportAddress), failures);

        EmailAddress? tls = Address(
            request.TlsReportAddress, nameof(request.TlsReportAddress), failures);

        if (failures.Count > 0)
        {
            throw new ValidationFailedException(failures);
        }

        DnsZonePlan plan = await plans
            .CreateAsync(
                domain!,
                new DnsPlanOptions(dmarc, tls, request.MtaStsId),
                cancellationToken)
            .ConfigureAwait(false);

        return Map(plan);
    }

    /// <summary>
    /// Parses one optional address, collecting the failure rather than throwing on the first.
    /// </summary>
    /// <remarks>
    /// An operator filling in a form with two reporting addresses and a typo in each should be
    /// told about both, not sent round the loop twice. <c>MtaStsId</c> is deliberately not
    /// validated here: <see cref="DnsRecordPlan"/> answers a bad one with a caveat that quotes
    /// the grammar, which is more use than a rejected request that names the field.
    /// </remarks>
    private static EmailAddress? Address(
        string? text,
        string field,
        Dictionary<string, string[]> failures)
    {
        if (text is not { Length: > 0 })
        {
            return null;
        }

        if (EmailAddress.TryParse(text, out EmailAddress? address))
        {
            return address;
        }

        failures[field] = [$"'{text}' is not an email address."];

        return null;
    }

    internal static DnsPlanDto Map(DnsZonePlan plan) => new()
    {
        Records = [.. plan.Records.Select(r => new DnsRecordDto
        {
            Name = r.Name,
            Kind = r.Kind.ToString().ToUpperInvariant(),
            Values = r.Values,
            Placement = r.Placement.ToString(),
            Purpose = r.Purpose,
            IsOptional = r.IsOptional,
        })],
        Caveats = [.. plan.Caveats.Select(c => new DnsPlanCaveatDto
        {
            Subject = c.Subject,
            Text = c.Text,
        })],
        ZoneText = DnsRecordPlan.ToZoneText(plan),
    };
}
