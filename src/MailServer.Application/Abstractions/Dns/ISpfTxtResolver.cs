using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Dns;

/// <summary>The result of fetching every TXT record at a domain, for SPF record retrieval.</summary>
/// <param name="Status">See <see cref="DnsLookupStatus"/>.</param>
/// <param name="Records">
/// Each TXT resource record's character-strings already concatenated, one entry per record.
/// Present only when <paramref name="Status"/> is <see cref="DnsLookupStatus.Success"/>. A
/// domain with no TXT records at all is still <see cref="DnsLookupStatus.Success"/> with an
/// empty list — RFC 7208 §4.5 treats "no matching record" as a fact about content, not a lookup
/// failure; only the caller knows whether zero matches means <see cref="Enums.SpfResult.None"/>
/// (the top-level domain) or a hard error (an <c>include</c>/<c>redirect</c> target).
/// </param>
/// <param name="Diagnostic">Human-readable detail, for logs and diagnostics.</param>
public sealed record SpfTxtLookupResult(DnsLookupStatus Status, IReadOnlyList<string> Records, string? Diagnostic)
{
    public static SpfTxtLookupResult Success(IReadOnlyList<string> records) =>
        new(DnsLookupStatus.Success, records, null);

    public static SpfTxtLookupResult Temporary(string diagnostic) =>
        new(DnsLookupStatus.Temporary, [], diagnostic);

    public static SpfTxtLookupResult Permanent(string diagnostic) =>
        new(DnsLookupStatus.Permanent, [], diagnostic);
}

/// <summary>Fetches TXT records for SPF record retrieval — the top-level domain, and every <c>include</c>/<c>redirect</c> target.</summary>
/// <remarks>
/// A different, narrower interface than <see cref="Dkim.IDkimPublicKeyResolver"/>'s TXT lookup on
/// purpose: DKIM expects and requires exactly one record at a selector-specific name, while SPF
/// must tolerate a domain publishing several TXT records for unrelated purposes (a DKIM key
/// record, a domain-verification token) alongside — or instead of — one starting with
/// <c>v=spf1</c>. The evaluator, not this resolver, is what applies RFC 7208 §4.5's "exactly one
/// record starting with v=spf1, or PermError" rule to the returned list.
/// </remarks>
public interface ISpfTxtResolver
{
    /// <summary>
    /// Fetches TXT records for <paramref name="domain"/>, given as plain text rather than as a
    /// <see cref="DomainName"/>: an <c>include</c>/<c>redirect</c> target is very commonly an
    /// underscore-prefixed name (<c>_spf.google.com</c>, and similar from most large mail
    /// providers), which <see cref="DomainName"/>'s stricter, mail-domain-oriented label rules
    /// reject. SPF domain-specs follow RFC 7208's own grammar, not RFC 1123 hostname syntax.
    /// </summary>
    Task<SpfTxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken);
}
