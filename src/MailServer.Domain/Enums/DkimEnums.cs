namespace MailServer.Domain.Enums;

/// <summary>
/// Where one DKIM signing key is in its rotation lifecycle.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately persisted and explicitly transitioned, unlike <see cref="CertificateStatus"/>,
/// which is derived fresh from the clock on every read. A certificate's status is a fact about
/// the world (has it expired yet); a DKIM key's rotation stage is a decision an operator or an
/// automation makes on purpose — "publish this key" and "start signing with it" are actions with
/// consequences (a key signing mail before it has propagated produces unverifiable signatures),
/// not something that becomes true by itself when a clock ticks.
/// </para>
/// <para>
/// See <c>docs/DKIM.md</c>'s rotation runbook: generate, publish, verify propagation, activate,
/// wait out the grace window, retire. <b>Never a hard swap</b> — retiring a key before mail
/// signed with it has finished being delivered turns valid mail into DKIM failures at every
/// receiver that has not yet seen the message.
/// </para>
/// </remarks>
public enum DkimKeyStatus
{
    /// <summary>Generated, not yet published to DNS. Never used for signing.</summary>
    Generated = 0,

    /// <summary>Published to DNS. Not yet used for signing — propagation has not been confirmed.</summary>
    Published = 1,

    /// <summary>Signing new outbound mail. At most one per domain.</summary>
    Active = 2,

    /// <summary>
    /// No longer used for new signatures. Never deleted from DNS immediately — see
    /// <c>docs/DKIM.md</c>'s grace-window requirement.
    /// </summary>
    Retired = 3,
}

/// <summary>The signing algorithm a DKIM key uses.</summary>
/// <remarks>
/// Both values are reserved now because <c>docs/Architecture.md</c>'s domain model already
/// names Ed25519 (RFC 8463) as a planned secondary signature, but only
/// <see cref="RsaSha256"/> is implemented in Milestone 9 — see the addendum recording that
/// decision. Reserving the enum value costs nothing and avoids a breaking rename later.
/// </remarks>
public enum DkimKeyAlgorithm
{
    /// <summary>RSA, at least 2048 bits, SHA-256. The only algorithm this milestone signs with.</summary>
    RsaSha256 = 0,

    /// <summary>Ed25519/SHA-256 (RFC 8463). Reserved; not implemented.</summary>
    Ed25519Sha256 = 1,
}

/// <summary>The outcome of verifying one DKIM signature found on a message.</summary>
/// <remarks>
/// Matches the subset of RFC 8601 <c>dkim-result</c> values this product actually distinguishes.
/// <c>Policy</c> and <c>Neutral</c> are not modelled: DMARC alignment only ever asks "did any
/// signature verify", and a result this product cannot act on differently is not worth a value.
/// </remarks>
public enum DkimVerificationResult
{
    /// <summary>No signature was present to verify.</summary>
    None = 0,

    /// <summary>The signature verified: the signed headers and body hash both matched.</summary>
    Pass = 1,

    /// <summary>The signature did not verify — a genuine cryptographic or hash mismatch.</summary>
    Fail = 2,

    /// <summary>Verification could not complete — the public key lookup failed transiently.</summary>
    TempError = 3,

    /// <summary>
    /// The signature itself is malformed, or the public key record is malformed or declares a
    /// revoked/empty key (<c>p=</c> empty). Never worth retrying.
    /// </summary>
    PermError = 4,
}

/// <summary>
/// One side (header or body) of a DKIM signature's <c>c=</c> canonicalization tag.
/// RFC 6376 §3.4.
/// </summary>
/// <remarks>
/// This product only ever signs with <see cref="Relaxed"/> on both sides — see
/// <c>docs/DKIM.md</c>. <see cref="Simple"/> is modelled anyway because a signature this server
/// did not produce (mail it is verifying) can legitimately declare it, and the tag must parse
/// rather than fail closed on an otherwise well-formed signature this product simply does not
/// implement verification for.
/// </remarks>
public enum DkimCanonicalizationMode
{
    Simple = 0,
    Relaxed = 1,
}
