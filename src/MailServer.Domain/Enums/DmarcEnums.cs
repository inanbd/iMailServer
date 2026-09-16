namespace MailServer.Domain.Enums;

/// <summary>Whether a message aligns with the policy published at its <c>From:</c> domain.</summary>
/// <remarks>RFC 7489 §3.1. Pass requires at least one aligned, passing mechanism (SPF or DKIM).</remarks>
public enum DmarcResult
{
    Fail = 0,
    Pass = 1,
}

/// <summary>The disposition a domain requests for mail that fails its DMARC check.</summary>
/// <remarks>RFC 7489 §6.3, the <c>p=</c>/<c>sp=</c> tag values.</remarks>
public enum DmarcPolicy
{
    None = 0,
    Quarantine = 1,
    Reject = 2,
}

/// <summary>Strict or relaxed domain comparison for SPF/DKIM alignment. RFC 7489 §3.1.</summary>
public enum AlignmentMode
{
    /// <summary>The organizational domains must match (the default).</summary>
    Relaxed = 0,

    /// <summary>The domains must match exactly.</summary>
    Strict = 1,
}

/// <summary>Which mechanism(s) produced an aligned pass.</summary>
[Flags]
public enum DmarcAlignedMechanism
{
    None = 0,
    Spf = 1,
    Dkim = 2,
}
