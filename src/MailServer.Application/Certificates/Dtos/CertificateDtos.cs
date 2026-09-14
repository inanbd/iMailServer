using MailServer.Domain.Enums;

namespace MailServer.Application.Certificates.Dtos;

/// <summary>A certificate as shown in the administration application.</summary>
/// <remarks>
/// <para>
/// Everything the certificate view is specified to display, and deliberately nothing more:
/// no key material, no PFX passphrase, no secret name, and no file path. A DTO crosses the IPC
/// boundary and is rendered, logged on error and potentially written to a support bundle, so
/// the safest design is one where there is nothing sensitive to leak.
/// </para>
/// <para>
/// <see cref="Status"/> and <see cref="DaysRemaining"/> are computed server-side rather than in
/// the view. The client's clock is not authoritative, and two surfaces computing expiry
/// independently is how a dashboard and a detail page come to disagree.
/// </para>
/// </remarks>
public sealed record CertificateDto
{
    public required Guid Id { get; init; }

    public required string Thumbprint { get; init; }

    public required string Subject { get; init; }

    public required string Issuer { get; init; }

    public required string SerialNumber { get; init; }

    /// <summary>Every hostname this certificate covers, as written in subjectAltName.</summary>
    public required IReadOnlyList<string> SubjectAlternativeNames { get; init; }

    public required CertificateSource Source { get; init; }

    public required CertificateStatus Status { get; init; }

    public required DateTimeOffset NotBeforeUtc { get; init; }

    public required DateTimeOffset NotAfterUtc { get; init; }

    /// <summary>Whole days until expiry; negative once expired.</summary>
    public required int DaysRemaining { get; init; }

    public required bool AutoRenew { get; init; }

    public DateTimeOffset? LastRenewalUtc { get; init; }

    public string? LastRenewalError { get; init; }

    /// <summary>
    /// True when this certificate is not publicly trusted.
    /// </summary>
    /// <remarks>
    /// A flag rather than leaving the view to infer it from <see cref="Source"/>, so that every
    /// surface showing a certificate has one unambiguous thing to test before displaying the
    /// warning text.
    /// </remarks>
    public required bool IsSelfSigned { get; init; }

    /// <summary>Hostnames currently bound to this certificate.</summary>
    public required IReadOnlyList<CertificateBindingDto> Bindings { get; init; }
}

/// <summary>A hostname-to-certificate binding.</summary>
public sealed record CertificateBindingDto
{
    public required Guid Id { get; init; }

    public required string Hostname { get; init; }

    public required Guid CertificateId { get; init; }

    public required CertificatePurpose Purpose { get; init; }

    public required bool IsDefault { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }
}

/// <summary>The overall TLS posture, for the dashboard.</summary>
public sealed record CertificateHealthDto
{
    public required int TotalCertificates { get; init; }

    public required int SelfSignedCount { get; init; }

    public required int ExpiringSoonCount { get; init; }

    public required int ExpiredCount { get; init; }

    /// <summary>Days until the soonest expiry, or null when no certificate is configured.</summary>
    public required int? SoonestExpiryDays { get; init; }

    /// <summary>Hostname of the certificate expiring soonest.</summary>
    public string? SoonestExpiryHostname { get; init; }

    /// <summary>
    /// True when a handshake offering no SNI hostname has a certificate to be answered with.
    /// </summary>
    /// <remarks>
    /// Surfaced explicitly because its absence is invisible until a non-SNI MTA tries to
    /// deliver mail and fails, which can be weeks after the configuration was made.
    /// </remarks>
    public required bool HasDefaultBinding { get; init; }

    /// <summary>True once the TLS provider holds at least one usable certificate.</summary>
    public required bool TlsIsReady { get; init; }

    /// <summary>
    /// The verbatim self-signed warning, when any self-signed certificate is in use.
    /// </summary>
    /// <remarks>
    /// Sent from the server rather than hardcoded in the view, so there is exactly one copy of
    /// the wording in the product. Three hand-typed variants in three views is how a warning
    /// quietly softens into a hint.
    /// </remarks>
    public string? SelfSignedWarning { get; init; }
}

/// <summary>A certificate found in the Windows certificate store but not yet adopted.</summary>
public sealed record AvailableStoreCertificateDto
{
    public required string Thumbprint { get; init; }

    public required string Subject { get; init; }

    public required string Issuer { get; init; }

    public required IReadOnlyList<string> SubjectAlternativeNames { get; init; }

    public required DateTimeOffset NotAfterUtc { get; init; }

    public required bool HasPrivateKey { get; init; }

    /// <summary>True when this server already has a row for this thumbprint.</summary>
    public required bool AlreadyAdopted { get; init; }
}
