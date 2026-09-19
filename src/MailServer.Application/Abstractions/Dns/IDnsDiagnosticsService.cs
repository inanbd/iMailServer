using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Dns;

/// <summary>The record types the diagnostic tools ask for.</summary>
public enum DnsDiagnosticRecordType
{
    /// <summary>IPv4 address.</summary>
    A = 0,

    /// <summary>IPv6 address.</summary>
    Aaaa = 1,

    /// <summary>Mail exchanger. Values are reported as <c>priority host</c>.</summary>
    Mx = 2,

    /// <summary>Text. Each record's character-strings already concatenated.</summary>
    Txt = 3,

    /// <summary>Reverse name. Values are the names pointed to.</summary>
    Ptr = 4,

    /// <summary>Certification authority authorisation. Values are <c>flags tag "value"</c>.</summary>
    Caa = 5,

    /// <summary>Name server.</summary>
    Ns = 6,

    /// <summary>Canonical name.</summary>
    Cname = 7,
}

/// <summary>
/// One diagnostic lookup's answer, with the provenance an operator needs.
/// </summary>
/// <param name="Status">
/// The same three-way classification <see cref="IDnsResolver"/> uses, and for the same reason:
/// a timeout and an NXDOMAIN lead to different advice.
/// </param>
/// <param name="Values">
/// The record data in the form it would be published in. Empty when the name exists but has no
/// record of the type asked for, which is a fact rather than a failure.
/// </param>
/// <param name="Ttl">The smallest TTL in the answer, or null when there was no answer.</param>
/// <param name="Server">
/// Which server answered. <c>docs/DNS.md</c>: "it works on my resolver" is exactly the problem a
/// diagnostic tool exists to solve, so the tool says whose answer it is reporting.
/// </param>
/// <param name="Diagnostic">Human-readable detail.</param>
public sealed record DnsDiagnosticAnswer(
    DnsLookupStatus Status,
    IReadOnlyList<string> Values,
    TimeSpan? Ttl = null,
    string? Server = null,
    string? Diagnostic = null)
{
    /// <summary>An answer, possibly an empty one.</summary>
    public static DnsDiagnosticAnswer Success(
        IReadOnlyList<string> values,
        TimeSpan? ttl = null,
        string? server = null) =>
        new(DnsLookupStatus.Success, values, ttl, server);

    /// <summary>A timeout or SERVFAIL. Worth retrying, and never a finding about the operator.</summary>
    public static DnsDiagnosticAnswer Temporary(string diagnostic, string? server = null) =>
        new(DnsLookupStatus.Temporary, [], null, server, diagnostic);

    /// <summary>NXDOMAIN. The name does not exist.</summary>
    public static DnsDiagnosticAnswer Permanent(string diagnostic, string? server = null) =>
        new(DnsLookupStatus.Permanent, [], null, server, diagnostic);

    /// <summary>Whether the lookup produced a usable answer, empty or not.</summary>
    public bool Answered => Status == DnsLookupStatus.Success;

    /// <summary>Whether the lookup answered with at least one record.</summary>
    public bool HasValues => Answered && Values.Count > 0;
}

/// <summary>
/// The admin tools' resolver: uncached, and it says who answered.
/// </summary>
/// <remarks>
/// <para>
/// <c>docs/DNS.md</c>: "<c>IDnsDiagnosticsService</c> is for the admin tools. It <b>bypasses the
/// cache</b> and may query authoritative nameservers directly, because 'it works on my resolver'
/// is exactly the problem a diagnostic tool exists to solve. It reports the TTL, the answering
/// server, and the actual versus expected value."
/// </para>
/// <para>
/// <b>Deliberately a different interface from <see cref="IDnsResolver"/> rather than a flag on
/// it.</b> The two want opposite things: the delivery hot path wants the fastest cached answer
/// and never wants to know which server gave it, and the diagnostic path wants the authoritative
/// answer and cannot use a cached one at all — an operator who has just corrected a record and
/// is asking whether the correction took would be told about the old one.
/// </para>
/// </remarks>
public interface IDnsDiagnosticsService
{
    /// <summary>Looks up one name, uncached.</summary>
    /// <param name="name">
    /// The name as published, which may be underscore-prefixed (<c>_dmarc.example.com</c>) and
    /// so is plain text rather than a <see cref="DomainName"/>.
    /// </param>
    /// <param name="type">Which record type.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task<DnsDiagnosticAnswer> LookupAsync(
        string name,
        DnsDiagnosticRecordType type,
        CancellationToken cancellationToken);

    /// <summary>
    /// Looks up an address's PTR records, building the reverse name itself.
    /// </summary>
    /// <remarks>
    /// The reverse name is <see cref="IpAddressValue.ToReverseDnsName"/>'s job and a caller
    /// should not have to know the difference between <c>in-addr.arpa</c> and the nibble-reversed
    /// <c>ip6.arpa</c> form.
    /// </remarks>
    Task<DnsDiagnosticAnswer> LookupPointerAsync(
        IpAddressValue address,
        CancellationToken cancellationToken);
}
