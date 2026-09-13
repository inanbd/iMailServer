using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>
/// The flat shape of a <c>Domains</c> row, as Dapper materialises it.
/// </summary>
/// <remarks>
/// A separate type from the aggregate on purpose. Letting Dapper populate
/// <see cref="MailDomain"/> directly would require public settable properties on the
/// aggregate, which would destroy every invariant the aggregate exists to enforce - any
/// caller could then bypass <c>Enable()</c> and set <c>Status = Active</c> on a domain with
/// no mail hostname.
/// </remarks>
internal sealed class DomainRow
{
    public Guid Id { get; set; }

    public string Name { get; set; } = string.Empty;

    public string UnicodeName { get; set; } = string.Empty;

    public int Status { get; set; }

    public string? MailHostname { get; set; }

    public string? ActiveDkimSelector { get; set; }

    public int CatchAllPolicy { get; set; }

    public string? CatchAllMailbox { get; set; }

    public long DefaultMailboxQuotaBytes { get; set; }

    public long DomainQuotaBytes { get; set; }

    public long MaxMessageSizeBytes { get; set; }

    public bool RequireTlsForOutbound { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }
}

/// <summary>Converts between <see cref="DomainRow"/> and <see cref="MailDomain"/>.</summary>
internal static class DomainRowMapper
{
    /// <summary>
    /// Rebuilds the aggregate from a row.
    /// </summary>
    /// <remarks>
    /// Uses the rehydration constructor, which applies no invariant checks: data already
    /// committed is by definition already valid, and re-validating here would make a row
    /// written by a newer version - or hand-edited during an incident - unloadable. Turning a
    /// small problem into an unbootable service is not an improvement.
    /// </remarks>
    public static MailDomain ToAggregate(DomainRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        return new MailDomain(
            new DomainId(row.Id),
            DomainName.Parse(row.Name),
            (DomainStatus)row.Status,
            row.MailHostname is null ? null : DomainName.Parse(row.MailHostname),
            row.ActiveDkimSelector is null ? null : DkimSelector.Parse(row.ActiveDkimSelector),
            (CatchAllPolicy)row.CatchAllPolicy,
            row.CatchAllMailbox is null ? null : EmailAddress.Parse(row.CatchAllMailbox),
            QuotaBytes.FromBytes(row.DefaultMailboxQuotaBytes),
            QuotaBytes.FromBytes(row.DomainQuotaBytes),
            row.MaxMessageSizeBytes,
            row.RequireTlsForOutbound,
            row.CreatedUtc,
            row.ModifiedUtc);
    }

    /// <summary>Flattens the aggregate into parameters for INSERT and UPDATE.</summary>
    public static object ToParameters(MailDomain domain)
    {
        ArgumentNullException.ThrowIfNull(domain);

        return new
        {
            Id = domain.Id.Value,
            Name = domain.Name.Value,
            UnicodeName = domain.Name.UnicodeValue,
            Status = (int)domain.Status,
            MailHostname = domain.MailHostname?.Value,
            ActiveDkimSelector = domain.ActiveDkimSelector?.Value,
            CatchAllPolicy = (int)domain.CatchAllPolicy,

            // Stored in normalised form so the unique index and every lookup agree on
            // case-folding; see EmailAddress for why the local-part is lower-cased.
            CatchAllMailbox = domain.CatchAllMailbox?.NormalizedValue,

            DefaultMailboxQuotaBytes = domain.DefaultMailboxQuota.Bytes,
            DomainQuotaBytes = domain.DomainQuota.Bytes,
            domain.MaxMessageSizeBytes,
            domain.RequireTlsForOutbound,
            domain.CreatedUtc,
            domain.ModifiedUtc,
        };
    }
}
