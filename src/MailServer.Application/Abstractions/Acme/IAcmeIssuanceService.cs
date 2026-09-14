using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Acme;

/// <summary>The outcome of an issuance attempt.</summary>
/// <param name="Succeeded">True when a certificate was issued and stored.</param>
/// <param name="OrderId">The order, whatever the outcome, so the attempt is traceable.</param>
/// <param name="Certificate">The issued certificate's metadata, when it succeeded.</param>
/// <param name="Failure">Why it did not, in terms an operator can act on.</param>
/// <param name="ManualDnsInstructions">
/// For manual DNS-01, the records the operator must publish before continuing.
/// </param>
public sealed record IssuanceResult(
    bool Succeeded,
    AcmeOrderId OrderId,
    Certificate? Certificate = null,
    string? Failure = null,
    IReadOnlyList<string>? ManualDnsInstructions = null);

/// <summary>
/// Runs one certificate issuance from pre-flight to installed certificate.
/// </summary>
/// <remarks>
/// <para>
/// A service rather than a handler, because the same sequence is driven from two places: an
/// operator requesting a certificate, and the lifecycle service renewing one. Duplicating it
/// would mean the renewal path and the manual path could drift, and the renewal path is the one
/// nobody watches.
/// </para>
/// <para>
/// It lives behind a port so the whole sequence can be exercised against a stub CA. Issuance is
/// the part of this product that cannot be tested against the real thing on a build agent, so
/// the seam has to be here.
/// </para>
/// </remarks>
public interface IAcmeIssuanceService
{
    /// <summary>
    /// Obtains a certificate for the identifiers, binding the first on success.
    /// </summary>
    /// <remarks>
    /// <b>Never throws for an ordinary failure.</b> A pre-flight refusal, a rate-limit refusal
    /// and a CA rejection are all outcomes rather than exceptions, because the caller —
    /// including the background renewal loop — must record them and carry on rather than treat
    /// them as faults.
    /// </remarks>
    Task<IssuanceResult> IssueAsync(
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        bool bindOnSuccess,
        CancellationToken cancellationToken);
}
