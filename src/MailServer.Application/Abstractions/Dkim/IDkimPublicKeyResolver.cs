using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Dkim;

/// <summary>The result of fetching one selector's public key record for DKIM verification.</summary>
/// <param name="Status">
/// Reuses <see cref="DnsLookupStatus"/>'s three-way split rather than inventing a parallel one:
/// the caller's next action (fail closed on this one signature but keep verifying others, versus
/// treat it as transient and defer the message) depends on exactly the same distinction
/// <c>docs/DNS.md</c> already makes for MX lookups.
/// </param>
/// <param name="Record">Present only when <paramref name="Status"/> is <see cref="DnsLookupStatus.Success"/>.</param>
/// <param name="Diagnostic">Human-readable detail, for the verification result and logs.</param>
public sealed record DkimPublicKeyLookupResult(
    DnsLookupStatus Status,
    DkimPublicKeyRecord? Record,
    string? Diagnostic)
{
    public static DkimPublicKeyLookupResult Success(DkimPublicKeyRecord record) =>
        new(DnsLookupStatus.Success, record, null);

    public static DkimPublicKeyLookupResult Temporary(string diagnostic) =>
        new(DnsLookupStatus.Temporary, null, diagnostic);

    public static DkimPublicKeyLookupResult Permanent(string diagnostic) =>
        new(DnsLookupStatus.Permanent, null, diagnostic);
}

/// <summary>Fetches a DKIM selector's public key record from DNS, for verifying inbound mail.</summary>
/// <remarks>
/// A different resolver than <see cref="IDnsResolver"/> on purpose: that one is the outbound
/// hot path (MX/A/AAAA, aggressively cached, implicit-MX-aware) and this one is a single TXT
/// lookup at a name a signature names explicitly. Sharing an interface for two lookups this
/// different in shape and cache profile would blur both.
/// </remarks>
public interface IDkimPublicKeyResolver
{
    Task<DkimPublicKeyLookupResult> ResolveAsync(
        DkimSelector selector,
        DomainName signingDomain,
        CancellationToken cancellationToken);
}
