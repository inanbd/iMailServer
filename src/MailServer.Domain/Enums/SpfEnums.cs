namespace MailServer.Domain.Enums;

/// <summary>
/// The outcome of evaluating a domain's SPF policy against a sending IP address.
/// </summary>
/// <remarks>
/// RFC 7208 §2.6, all seven values. <c>docs/SPF.md</c>: this server does not hard-reject on
/// <see cref="Fail"/> alone — the result feeds DMARC alignment, and only <see cref="TempError"/>
/// acts immediately (a 4xx at <c>MAIL FROM</c>), because every other outcome needs the
/// <c>From:</c> header DMARC reads, which is not available until after <c>DATA</c>.
/// </remarks>
public enum SpfResult
{
    /// <summary>No applicable SPF policy: no record, or a record with no matching directive and no <c>redirect=</c>.</summary>
    None = 0,

    /// <summary>The domain neither asserts nor denies authorization.</summary>
    Neutral = 1,

    /// <summary>Explicitly authorized.</summary>
    Pass = 2,

    /// <summary>Explicitly not authorized (a matched mechanism with the <c>-</c> qualifier, or the default <c>-all</c>).</summary>
    Fail = 3,

    /// <summary>The domain believes the client is not authorized but does not want to assert it strongly.</summary>
    SoftFail = 4,

    /// <summary>Evaluation could not complete: a DNS lookup failed transiently.</summary>
    TempError = 5,

    /// <summary>
    /// The domain's own published record is malformed, or evaluating it would exceed the
    /// lookup/void-lookup budget. Never worth retrying — the domain owner must fix their record.
    /// </summary>
    PermError = 6,
}

/// <summary>
/// The qualifier prefixing an SPF mechanism (<c>+</c>/<c>-</c>/<c>~</c>/<c>?</c>), and what
/// result a match against it produces.
/// </summary>
public enum SpfQualifier
{
    /// <summary>+ (the default when no qualifier is written) → <see cref="SpfResult.Pass"/>.</summary>
    Pass = 0,

    /// <summary>- → <see cref="SpfResult.Fail"/>.</summary>
    Fail = 1,

    /// <summary>~ → <see cref="SpfResult.SoftFail"/>.</summary>
    SoftFail = 2,

    /// <summary>? → <see cref="SpfResult.Neutral"/>.</summary>
    Neutral = 3,
}

/// <summary>
/// An SPF mechanism's type. RFC 7208 §5.
/// </summary>
public enum SpfMechanismType
{
    All = 0,
    Include = 1,
    A = 2,
    Mx = 3,
    Ip4 = 4,
    Ip6 = 5,
    Exists = 6,

    /// <summary>
    /// RFC 7208 §5.5. Recognised so a record naming it is not treated as malformed, but never
    /// evaluated as a match — the mechanism itself is deprecated (it requires a reverse lookup
    /// followed by forward lookups to confirm FCrDNS, which is expensive against the lookup
    /// budget and unreliable across implementations) and this product does not implement it.
    /// A record containing it is evaluated as though the directive were absent.
    /// </summary>
    Ptr = 7,
}
