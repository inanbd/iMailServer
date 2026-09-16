using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Dns;

/// <summary>The result of fetching every TXT record at a domain — for SPF and DMARC policy retrieval alike.</summary>
/// <param name="Status">See <see cref="DnsLookupStatus"/>.</param>
/// <param name="Records">
/// Each TXT resource record's character-strings already concatenated, one entry per record.
/// Present only when <paramref name="Status"/> is <see cref="DnsLookupStatus.Success"/>. A
/// domain with no TXT records at all is still <see cref="DnsLookupStatus.Success"/> with an
/// empty list — RFC 7208 §4.5 and RFC 7489 §6.6.3 both treat "no matching record" as a fact
/// about content, not a lookup failure; only the caller knows what an empty match means for its
/// own policy (SPF's <see cref="Enums.SpfResult.None"/> at the top level versus a hard error for
/// an <c>include</c>/<c>redirect</c> target; DMARC's "no policy published" at the domain versus
/// its organizational-domain fallback).
/// </param>
/// <param name="Diagnostic">Human-readable detail, for logs and diagnostics.</param>
public sealed record TxtLookupResult(DnsLookupStatus Status, IReadOnlyList<string> Records, string? Diagnostic)
{
    public static TxtLookupResult Success(IReadOnlyList<string> records) =>
        new(DnsLookupStatus.Success, records, null);

    public static TxtLookupResult Temporary(string diagnostic) =>
        new(DnsLookupStatus.Temporary, [], diagnostic);

    public static TxtLookupResult Permanent(string diagnostic) =>
        new(DnsLookupStatus.Permanent, [], diagnostic);
}

/// <summary>
/// Fetches every TXT record at a domain — the top-level domain, an SPF <c>include</c>/<c>redirect</c>
/// target, or a DMARC policy name (<c>_dmarc.example.com</c>).
/// </summary>
/// <remarks>
/// A different, narrower interface than <see cref="Dkim.IDkimPublicKeyResolver"/>'s TXT lookup on
/// purpose: DKIM expects and requires exactly one record at a selector-specific name, while both
/// SPF and DMARC must tolerate a domain publishing several TXT records for unrelated purposes (a
/// DKIM key record, a domain-verification token) alongside — or instead of — the one they are
/// looking for. The caller, not this resolver, applies its own "exactly one matching record, or
/// PermError/fail" rule to the returned list.
/// </remarks>
public interface ITxtRecordResolver
{
    /// <summary>
    /// Fetches TXT records for <paramref name="domain"/>, given as plain text rather than as a
    /// <see cref="DomainName"/>: an SPF <c>include</c>/<c>redirect</c> target is very commonly an
    /// underscore-prefixed name (<c>_spf.google.com</c>, and a DMARC policy name always is —
    /// <c>_dmarc.example.com</c>), which <see cref="DomainName"/>'s stricter, mail-domain-oriented
    /// label rules reject. This grammar follows RFC 7208/RFC 7489's own domain-name conventions,
    /// not RFC 1123 hostname syntax.
    /// </summary>
    Task<TxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken);
}
