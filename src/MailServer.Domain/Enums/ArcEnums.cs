namespace MailServer.Domain.Enums;

/// <summary>
/// An <c>ARC-Seal</c>'s <c>cv=</c> tag: what this hop found when it checked everything before it.
/// RFC 8617 §4.1.3.
/// </summary>
/// <remarks>
/// Read from the wire, never computed by this product — see <see cref="Mail.ArcChain"/>'s own
/// remarks on why cryptographic chain validation is out of scope for this milestone. Only
/// <see cref="None"/> is structurally required to appear anywhere in particular (exactly at
/// instance 1); <see cref="Pass"/> and <see cref="Fail"/> are simply what a later hop declared.
/// </remarks>
public enum ArcChainValidation
{
    None = 0,
    Pass = 1,
    Fail = 2,
}
