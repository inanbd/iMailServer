using System.Net;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;

namespace MailServer.Application.Abstractions.Acme;

/// <summary>Configured ACME behaviour, resolved once and injected rather than read ad hoc.</summary>
/// <remarks>
/// An interface rather than <c>IOptions</c> at each call site, so the Application layer stays
/// free of the Infrastructure configuration types and so tests can vary a single setting
/// without building a configuration tree.
/// </remarks>
public interface IAcmeSettings
{
    /// <summary>Which directory a new issuance uses by default.</summary>
    /// <remarks>
    /// Staging for a new installation, deliberately. An operator fixing DNS against production
    /// can exhaust the five-duplicates-per-week limit in an afternoon and then wait a week.
    /// </remarks>
    AcmeDirectory DefaultDirectory { get; }

    /// <summary>The directory endpoint for a given choice.</summary>
    string GetDirectoryUrl(AcmeDirectory directory);

    /// <summary>Contact address registered with the CA, for expiry warnings.</summary>
    string? ContactEmail { get; }

    /// <summary>Whether the operator has accepted the CA's terms of service.</summary>
    /// <remarks>
    /// Explicit configuration rather than an implicit yes. Accepting a legal agreement on an
    /// operator's behalf because it was convenient is not this software's decision to make.
    /// </remarks>
    bool TermsOfServiceAccepted { get; }

    /// <summary>Challenge type used unless one is chosen per request.</summary>
    AcmeChallengeType DefaultChallengeType { get; }

    /// <summary>Resolvers asked when checking whether a DNS-01 record has propagated.</summary>
    IReadOnlyList<IPAddress> ChallengeCheckResolvers { get; }

    /// <summary>Port the HTTP-01 challenge endpoint listens on.</summary>
    /// <remarks>
    /// 80, and effectively not configurable in practice: the CA fetches
    /// <c>http://&lt;host&gt;/.well-known/acme-challenge/…</c> on port 80 and follows no
    /// redirect to another port. A different value is useful only behind a reverse proxy that
    /// forwards to it.
    /// </remarks>
    int HttpChallengePort { get; }

    /// <summary>Whether the service should run the HTTP-01 endpoint itself.</summary>
    bool EnableHttpChallengeListener { get; }

    /// <summary>Key size for issued certificates.</summary>
    int CertificateKeySizeBits { get; }

    /// <summary>The rate limits enforced before an order is submitted.</summary>
    AcmeRateLimitPolicy RateLimitPolicy { get; }
}
