namespace MailServer.Domain.Enums;

/// <summary>
/// The operational state of a certificate.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately richer than "valid / invalid". An operator whose mail clients have started
/// warning needs to know <i>which</i> problem they have: an expired certificate, a certificate
/// that does not cover the hostname it is bound to, and one whose chain does not build are
/// three different faults with three different fixes, and collapsing them into "Invalid"
/// turns a five-minute repair into an afternoon.
/// </para>
/// <para>
/// Computed from the certificate and the clock rather than stored, except where noted, so it
/// cannot drift out of date in the database.
/// </para>
/// </remarks>
public enum CertificateStatus
{
    /// <summary>Valid, trusted, covers its bound hostnames, and not near expiry.</summary>
    Healthy = 0,

    /// <summary>A renewal is in progress. Stored, because it describes an operation rather than the certificate.</summary>
    Renewing = 1,

    /// <summary>Still valid, but inside the renewal window. Severity escalates as expiry approaches.</summary>
    ExpiringSoon = 2,

    /// <summary>Past its not-after date. Every client will refuse it.</summary>
    Expired = 3,

    /// <summary>Not yet valid, malformed, or missing a usable private key.</summary>
    Invalid = 4,

    /// <summary>Valid, but does not cover a hostname it is bound to.</summary>
    HostnameMismatch = 5,

    /// <summary>
    /// Valid and correctly named, but the chain does not build to a trusted root. Expected
    /// and normal for <see cref="CertificateSource.SelfSigned"/>.
    /// </summary>
    Untrusted = 6,
}
