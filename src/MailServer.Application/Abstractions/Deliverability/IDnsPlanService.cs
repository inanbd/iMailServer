using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>
/// Writes the DNS records a domain needs, from what this server knows about itself.
/// </summary>
/// <remarks>
/// <para>
/// The companion to <see cref="IDeliverabilityReportService"/> and deliberately its opposite:
/// the report reads DNS and grades it, this reads none and proposes it. An operator with nothing
/// published yet gets a perfect score of zero and a list of failures from the report; what they
/// need first is the list of records, which is this.
/// </para>
/// <para>
/// <b>It publishes nothing.</b> This product holds no credentials to any registrar and this
/// interface has no write side. Everything it returns is text for a person to read, check and
/// paste — see <see cref="DnsRecordPlan"/> on why every record carries its purpose.
/// </para>
/// </remarks>
public interface IDnsPlanService
{
    /// <summary>Assembles the plan for one domain.</summary>
    /// <param name="domain">The domain that sends and receives mail.</param>
    /// <param name="options">The choices only an operator can make.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task<DnsZonePlan> CreateAsync(
        DomainName domain,
        DnsPlanOptions options,
        CancellationToken cancellationToken);
}

/// <summary>
/// The parts of a plan this server cannot know for itself.
/// </summary>
/// <remarks>
/// Each of these is a decision rather than a fact: where reports should go is a mailbox somebody
/// has to read, and whether to advertise an MTA-STS policy commits the operator to serving one
/// over HTTPS for as long as the record stands. Defaulting them would put records in front of an
/// operator that look like this server's findings rather than their own choices.
/// </remarks>
/// <param name="DmarcReportAddress">Where aggregate DMARC reports go, or null for none.</param>
/// <param name="TlsReportAddress">Where TLS-RPT reports go, or null to leave TLS-RPT out.</param>
/// <param name="MtaStsId">The MTA-STS policy id to advertise, or null to leave MTA-STS out.</param>
public sealed record DnsPlanOptions(
    EmailAddress? DmarcReportAddress = null,
    EmailAddress? TlsReportAddress = null,
    string? MtaStsId = null);
