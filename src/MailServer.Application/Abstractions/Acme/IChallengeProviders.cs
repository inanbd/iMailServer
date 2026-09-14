using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Acme;

/// <summary>
/// Holds HTTP-01 challenge responses for the web endpoint to serve.
/// </summary>
/// <remarks>
/// <para>
/// In-memory, deliberately. The token is valid for minutes, is useless to anyone who does not
/// also hold the account key, and writing it to the database or to disk would create a
/// persistent artefact to clean up — the exact hygiene problem that publishing a challenge is
/// supposed to be free of.
/// </para>
/// <para>
/// It does mean a service restart mid-issuance loses the published token. That is correct: the
/// order is retried, the CA issues a new token, and nothing is left behind.
/// </para>
/// </remarks>
public interface IHttpChallengeStore
{
    /// <summary>Publishes a response for one token.</summary>
    void Publish(string token, string keyAuthorization);

    /// <summary>Returns the response for a token, or null when it is unknown.</summary>
    /// <remarks>
    /// Reached from an unauthenticated public endpoint. Returning null for an unknown token —
    /// rather than throwing or logging at error — is what stops a scanner hitting
    /// <c>/.well-known/acme-challenge/</c> from filling the log.
    /// </remarks>
    string? TryGet(string token);

    /// <summary>Removes a published response. Idempotent.</summary>
    void Remove(string token);

    /// <summary>Number of responses currently published, for diagnostics.</summary>
    int Count { get; }
}

/// <summary>The result of asking a DNS provider to publish a challenge record.</summary>
/// <param name="Published">
/// False when the provider cannot publish automatically and the operator must do it by hand.
/// </param>
/// <param name="Instructions">
/// What the operator must create, when <paramref name="Published"/> is false.
/// </param>
public sealed record DnsChallengePublication(bool Published, string? Instructions = null);

/// <summary>
/// Publishes and removes the TXT records that satisfy a DNS-01 challenge.
/// </summary>
/// <remarks>
/// <para>
/// No DNS provider is named in the architecture. Cloudflare, Route 53, Azure DNS and the rest
/// are modules behind this interface, and the manual fallback is a first-class implementation
/// rather than an error path — plenty of domains are hosted somewhere with no usable API, and
/// DNS-01 is the only way those can obtain a wildcard.
/// </para>
/// <para>
/// Propagation must be checked at the <b>authoritative</b> nameservers. A recursive resolver
/// will happily report the record before the CA can see it, and asking the CA to validate too
/// early spends a failed-validation slot out of five per hour.
/// </para>
/// </remarks>
public interface IDnsChallengeProvider
{
    /// <summary>A name for this provider, for logs and the UI.</summary>
    string Name { get; }

    /// <summary>True when records can be published without operator action.</summary>
    bool SupportsAutomaticPublication { get; }

    /// <summary>Publishes the TXT record, or returns instructions for doing it by hand.</summary>
    Task<DnsChallengePublication> PublishAsync(
        DomainName identifier,
        string recordName,
        string recordValue,
        CancellationToken cancellationToken);

    /// <summary>
    /// Checks whether the record is visible at the authoritative nameservers.
    /// </summary>
    /// <remarks>
    /// Separate from publication so the manual provider can offer the operator a "check now"
    /// button, and so an automatic provider's write can be confirmed rather than assumed.
    /// </remarks>
    Task<bool> IsPublishedAsync(
        string recordName,
        string expectedValue,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes the record. Idempotent, and called on every path including failure.
    /// </summary>
    /// <remarks>
    /// A stale <c>_acme-challenge</c> TXT record is both untidy and a small standing signal
    /// about how this domain proves control. Cleanup belongs in a <c>finally</c>.
    /// </remarks>
    Task RemoveAsync(string recordName, CancellationToken cancellationToken);
}
