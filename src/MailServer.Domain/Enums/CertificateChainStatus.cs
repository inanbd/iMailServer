namespace MailServer.Domain.Enums;

/// <summary>
/// What building a certificate's chain established.
/// </summary>
/// <remarks>
/// <b>Four states rather than a boolean, because three of them have different remedies.</b> A
/// self-signed certificate is one to replace; a chain that does not build is almost always an
/// intermediate the server is not sending; a revoked certificate has to be reissued and is
/// urgent. Collapsing them into "trusted or not" would give an operator one finding for three
/// faults and a remedy that fits at most one of them.
/// </remarks>
public enum CertificateChainStatus
{
    /// <summary>No chain was built, so nothing was established either way.</summary>
    NotBuilt = 0,

    /// <summary>The chain builds to a root in the platform trust store.</summary>
    Trusted = 1,

    /// <summary>
    /// The chain does not build.
    /// </summary>
    /// <remarks>
    /// Revocation that could not be determined does not land here: a CRL endpoint that is
    /// unreachable says nothing about the chain, and reporting it as a broken one would send an
    /// operator to reinstall intermediates that were never missing.
    /// </remarks>
    Untrusted = 2,

    /// <summary>The issuer has revoked this certificate.</summary>
    Revoked = 3,
}
