using System.Security.Cryptography.X509Certificates;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Acme;

/// <summary>What the CA wants published to prove control of one identifier.</summary>
/// <param name="Identifier">The hostname being authorised.</param>
/// <param name="Type">Which challenge this is.</param>
/// <param name="Token">The challenge token, as issued by the CA.</param>
/// <param name="KeyAuthorization">
/// For HTTP-01, the exact body to serve. For DNS-01, the already-digested TXT value.
/// </param>
/// <param name="DnsRecordName">
/// For DNS-01, the fully-qualified record name — <c>_acme-challenge.example.com</c>.
/// </param>
public sealed record AcmeChallenge(
    DomainName Identifier,
    AcmeChallengeType Type,
    string Token,
    string KeyAuthorization,
    string? DnsRecordName = null);

/// <summary>The outcome of registering or reusing an ACME account.</summary>
/// <param name="AccountUrl">The account's URL at the CA.</param>
/// <param name="TermsOfServiceUrl">The terms document that was accepted, if any.</param>
public sealed record AcmeAccountRegistration(string AccountUrl, string? TermsOfServiceUrl);

/// <summary>An issued certificate chain and the private key generated for it.</summary>
/// <remarks>
/// The key is generated at finalisation and never reused between issuances — reusing one would
/// mean compromising a single key compromised every certificate that ever succeeded it. The
/// caller owns the returned certificate and must dispose it.
/// </remarks>
public sealed record AcmeIssuedCertificate(X509Certificate2 Certificate) : IDisposable
{
    public void Dispose() => Certificate.Dispose();
}

/// <summary>Raised when the CA rejects something, carrying its problem document.</summary>
/// <remarks>
/// ACME errors are structured (RFC 8555 §6.7) and their <c>detail</c> field is written for
/// humans. Surfacing that rather than an exception dump is what makes a failed issuance
/// diagnosable a week later.
/// </remarks>
public sealed class AcmeProtocolException(string message, string? problemType = null)
    : Exception(message)
{
    /// <summary>The RFC 8555 problem type, e.g. <c>urn:ietf:params:acme:error:rateLimited</c>.</summary>
    public string? ProblemType { get; } = problemType;

    /// <summary>True when the CA refused because of a rate limit.</summary>
    /// <remarks>
    /// Treated differently everywhere: a rate-limited failure must not be retried, and it says
    /// nothing about whether the configuration is correct.
    /// </remarks>
    public bool IsRateLimit =>
        ProblemType?.Contains("rateLimited", StringComparison.OrdinalIgnoreCase) == true;
}

/// <summary>
/// The ACME protocol, as this server uses it.
/// </summary>
/// <remarks>
/// <para>
/// A port rather than a direct dependency on Certes, for the usual reason and one specific one:
/// this is the single interface that can be replaced by a stub to test issuance end to end. The
/// alternative — testing only against a live CA — means the issuance path is exercised on a
/// machine with a public DNS name, which no build agent has.
/// </para>
/// <para>
/// <b>No method returns the account key or a certificate's private key as bytes.</b> The
/// account key stays in the protected secret store; the certificate's key is generated inside
/// <see cref="FinalizeOrderAsync"/> and travels only inside the returned
/// <see cref="X509Certificate2"/>.
/// </para>
/// <para>
/// Implementations are stateful for the duration of an issuance: <see cref="CreateOrderAsync"/>
/// through <see cref="FinalizeOrderAsync"/> operate on the order most recently created. A
/// client is therefore scoped to one issuance, never shared.
/// </para>
/// </remarks>
public interface IAcmeClient
{
    /// <summary>
    /// Registers a new account, or confirms an existing one for the same key.
    /// </summary>
    /// <remarks>
    /// Idempotent by design: ACME returns the existing account when a known key registers
    /// again, so a retry after a crash mid-registration recovers rather than orphaning the key.
    /// </remarks>
    Task<AcmeAccountRegistration> EnsureAccountAsync(
        string directoryUrl,
        string accountKeyPem,
        string contactEmail,
        bool acceptTermsOfService,
        CancellationToken cancellationToken);

    /// <summary>Creates an order and returns the challenges that must be satisfied.</summary>
    Task<IReadOnlyList<AcmeChallenge>> CreateOrderAsync(
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        CancellationToken cancellationToken);

    /// <summary>The order's URL at the CA, once <see cref="CreateOrderAsync"/> has run.</summary>
    string? OrderUrl { get; }

    /// <summary>
    /// Tells the CA the challenges are published and waits for it to validate them.
    /// </summary>
    /// <remarks>
    /// Polls with bounded backoff and gives up rather than waiting forever: an authorisation
    /// that never becomes valid is a misconfiguration, and a client that waits indefinitely
    /// turns it into a hung renewal nobody notices.
    /// </remarks>
    Task ValidateChallengesAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Generates a fresh key pair, submits the CSR and downloads the issued chain.
    /// </summary>
    Task<AcmeIssuedCertificate> FinalizeOrderAsync(
        IReadOnlyList<DomainName> identifiers,
        int keySizeBits,
        CancellationToken cancellationToken);
}

/// <summary>Creates a client bound to one account and one issuance.</summary>
/// <remarks>
/// A factory because <see cref="IAcmeClient"/> is stateful and per-issuance, while the account
/// key it needs is fetched from the protected secret store at the moment of use and not
/// retained.
/// </remarks>
public interface IAcmeClientFactory
{
    Task<IAcmeClient> CreateAsync(
        string directoryUrl,
        string accountKeyPem,
        CancellationToken cancellationToken);
}
