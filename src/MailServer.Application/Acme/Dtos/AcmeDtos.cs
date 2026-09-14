using MailServer.Domain.Enums;

namespace MailServer.Application.Acme.Dtos;

/// <summary>An ACME account registration, as shown in the administration application.</summary>
/// <remarks>
/// Carries no key material and not even the secret's name. The account key is the one thing
/// that can revoke certificates issued through the account, and a DTO that named its storage
/// location would put that into every log line and screenshot of this page.
/// </remarks>
public sealed record AcmeAccountDto
{
    public required Guid Id { get; init; }

    public required AcmeDirectory Directory { get; init; }

    public required string DirectoryUrl { get; init; }

    public required string ContactEmail { get; init; }

    /// <summary>True once the CA has acknowledged the registration.</summary>
    public required bool IsRegistered { get; init; }

    public required bool IsActive { get; init; }

    /// <summary>
    /// False for staging.
    /// </summary>
    /// <remarks>
    /// Surfaced as its own flag rather than left to be inferred from the directory, because
    /// "my certificate was issued but browsers still warn" is the single most common confusion
    /// with ACME and this is the field that answers it.
    /// </remarks>
    public required bool IssuesPubliclyTrustedCertificates { get; init; }

    public string? TermsAccepted { get; init; }

    public DateTimeOffset? TermsAcceptedUtc { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }
}

/// <summary>One issuance attempt.</summary>
public sealed record AcmeOrderDto
{
    public required Guid Id { get; init; }

    public required IReadOnlyList<string> Identifiers { get; init; }

    public required AcmeChallengeType ChallengeType { get; init; }

    public required AcmeOrderStatus Status { get; init; }

    /// <summary>The CA's explanation, or a local refusal.</summary>
    public string? LastError { get; init; }

    public required int AttemptCount { get; init; }

    public DateTimeOffset? LastAttemptUtc { get; init; }

    public DateTimeOffset? CompletedUtc { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>The certificate this order produced, if it succeeded.</summary>
    public Guid? IssuedCertificateId { get; init; }

    /// <summary>
    /// True when this attempt reached the CA and could have consumed quota.
    /// </summary>
    /// <remarks>
    /// Shown because it changes what an operator should do next. A local refusal can be retried
    /// immediately once the cause is fixed; one the CA rejected has spent a slot out of five
    /// per hour, and retrying before fixing the cause makes things worse.
    /// </remarks>
    public required bool ReachedCertificateAuthority { get; init; }
}

/// <summary>The result of requesting a certificate.</summary>
public sealed record IssuanceResultDto
{
    public required bool Succeeded { get; init; }

    public required Guid OrderId { get; init; }

    public Guid? CertificateId { get; init; }

    public string? Thumbprint { get; init; }

    public string? Failure { get; init; }

    /// <summary>
    /// DNS records the operator must publish before validation can be requested.
    /// </summary>
    /// <remarks>
    /// Present when the DNS provider cannot publish automatically. The order stays open and the
    /// CA has not been asked to validate, which is what protects the five-failures-per-hour
    /// limit from an operator pressing the button before the record exists.
    /// </remarks>
    public IReadOnlyList<string>? ManualDnsInstructions { get; init; }
}

/// <summary>One pre-flight finding, for the UI to show before an order is submitted.</summary>
public sealed record PreflightFindingDto
{
    public required string Identifier { get; init; }

    public required bool Passed { get; init; }

    public required string Summary { get; init; }

    public required bool IsBlocking { get; init; }
}

/// <summary>The ACME configuration and posture, for the settings page.</summary>
public sealed record AcmeStatusDto
{
    public required AcmeDirectory ConfiguredDirectory { get; init; }

    public required bool IssuesPubliclyTrustedCertificates { get; init; }

    public string? ContactEmail { get; init; }

    public required bool TermsOfServiceAccepted { get; init; }

    public required AcmeChallengeType DefaultChallengeType { get; init; }

    public required bool HttpChallengeListenerEnabled { get; init; }

    public required int HttpChallengePort { get; init; }

    /// <summary>True when an account exists and the CA knows about it.</summary>
    public required bool HasUsableAccount { get; init; }

    /// <summary>
    /// What still needs doing before a certificate can be requested, if anything.
    /// </summary>
    /// <remarks>
    /// Assembled server-side so the UI does not reimplement the same conditions and drift out
    /// of step with what the issuance path actually checks.
    /// </remarks>
    public required IReadOnlyList<string> BlockingIssues { get; init; }
}
