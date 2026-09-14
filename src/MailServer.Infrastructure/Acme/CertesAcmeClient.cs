using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Acme;

/// <summary>
/// <see cref="IAcmeClient"/> over the Certes library.
/// </summary>
/// <remarks>
/// <para>
/// Certes handles JWS signing, nonce management and key-authorisation digests. Everything
/// around that — polling policy, error translation, key generation, what gets logged — is here,
/// because those are the parts where a library's defaults and a mail server's needs differ.
/// </para>
/// <para>
/// <b>Stateful for one issuance.</b> The order created by <see cref="CreateOrderAsync"/> is the
/// one the later methods operate on. A client is resolved per issuance and never shared.
/// </para>
/// <para>
/// <b>Nothing here logs a key, a token or a key authorisation.</b> The token is short-lived and
/// useless without the account key, but it is still the secret half of a proof of control, and
/// a log line carrying one invites an operator to paste it into a support thread.
/// </para>
/// </remarks>
internal sealed class CertesAcmeClient(
    IAcmeContext context,
    IClock clock,
    ILogger<CertesAcmeClient> logger) : IAcmeClient
{
    /// <summary>
    /// How long to wait for the CA to validate before giving up.
    /// </summary>
    /// <remarks>
    /// Bounded rather than indefinite. An authorisation that never becomes valid is a
    /// misconfiguration, and a client that waits forever turns it into a hung renewal nobody
    /// notices until the certificate expires.
    /// </remarks>
    private static readonly TimeSpan ValidationTimeout = TimeSpan.FromMinutes(5);

    /// <summary>Initial gap between polls, doubling to <see cref="MaxPollInterval"/>.</summary>
    private static readonly TimeSpan InitialPollInterval = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Ceiling on the gap between polls.
    /// </summary>
    /// <remarks>
    /// Backing off is politeness to the CA, but an unbounded backoff would spend most of the
    /// timeout asleep and report failure long after validation actually succeeded.
    /// </remarks>
    private static readonly TimeSpan MaxPollInterval = TimeSpan.FromSeconds(15);

    private IOrderContext? _order;
    private IReadOnlyList<AuthorizationWork>? _work;

    public string? OrderUrl { get; private set; }

    public async Task<AcmeAccountRegistration> EnsureAccountAsync(
        string directoryUrl,
        string accountKeyPem,
        string contactEmail,
        bool acceptTermsOfService,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contactEmail);

        Uri? terms = null;

        try
        {
            terms = await context.TermsOfService().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Not fatal. Some CAs publish no terms document, and failing registration because
            // we could not read one would be refusing to work with a compliant CA.
            logger.LogDebug(ex, "The ACME directory did not advertise a terms-of-service URL.");
        }

        if (terms is not null && !acceptTermsOfService)
        {
            throw new AcmeProtocolException(
                $"The certificate authority requires its terms of service to be accepted: " +
                $"{terms}. Registration was not attempted.");
        }

        try
        {
            IAccountContext account = await context
                .NewAccount(contactEmail, termsOfServiceAgreed: acceptTermsOfService)
                .ConfigureAwait(false);

            // Certes returns the existing account when a known key registers again, so a retry
            // after a crash mid-registration recovers rather than orphaning the key.
            Uri location = account.Location;

            logger.LogInformation(
                "ACME account registered at {Directory} with contact {Contact}.",
                directoryUrl,
                contactEmail);

            return new AcmeAccountRegistration(location.ToString(), terms?.ToString());
        }
        catch (AcmeRequestException ex)
        {
            throw Translate(ex, "registering the ACME account");
        }
    }

    public async Task<IReadOnlyList<AcmeChallenge>> CreateOrderAsync(
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        if (identifiers.Count == 0)
        {
            throw new ArgumentException("An order must cover at least one hostname.", nameof(identifiers));
        }

        try
        {
            // A-label form: an ACME identifier is an ASCII dNSName, and a U-label would either
            // be rejected or silently mis-compared against what the CA validates.
            _order = await context
                .NewOrder([.. identifiers.Select(static i => i.Value)])
                .ConfigureAwait(false);

            OrderUrl = _order.Location.ToString();

            List<AuthorizationWork> work = [];
            List<AcmeChallenge> challenges = [];

            IEnumerable<IAuthorizationContext> authorizations =
                await _order.Authorizations().ConfigureAwait(false);

            foreach (IAuthorizationContext authorization in authorizations)
            {
                Authorization resource = await authorization.Resource().ConfigureAwait(false);

                DomainName identifier = DomainName.Parse(resource.Identifier.Value);

                IChallengeContext? challenge = challengeType == AcmeChallengeType.Dns01
                    ? await authorization.Dns().ConfigureAwait(false)
                    : await authorization.Http().ConfigureAwait(false);

                if (challenge is null)
                {
                    throw new AcmeProtocolException(
                        $"The certificate authority did not offer a {challengeType} challenge " +
                        $"for '{identifier}'. " +
                        (challengeType == AcmeChallengeType.Http01
                            ? "A wildcard identifier cannot be proved with HTTP-01; use DNS-01."
                            : "Check that the identifier is one this CA will issue for."));
                }

                work.Add(new AuthorizationWork(identifier, authorization, challenge));

                challenges.Add(challengeType == AcmeChallengeType.Dns01
                    ? new AcmeChallenge(
                        identifier,
                        AcmeChallengeType.Dns01,
                        challenge.Token,

                        // The DNS-01 value is a digest of the key authorisation, not the key
                        // authorisation itself. Publishing the wrong one is the single most
                        // common DNS-01 mistake, so the digest is computed here rather than
                        // left to each provider.
                        context.AccountKey.DnsTxt(challenge.Token),
                        BuildDnsRecordName(identifier))
                    : new AcmeChallenge(
                        identifier,
                        AcmeChallengeType.Http01,
                        challenge.Token,
                        challenge.KeyAuthz));
            }

            _work = work;

            logger.LogInformation(
                "ACME order created for {IdentifierCount} identifier(s) using {ChallengeType}.",
                identifiers.Count,
                challengeType);

            return challenges;
        }
        catch (AcmeRequestException ex)
        {
            throw Translate(ex, "creating the ACME order");
        }
    }

    /// <summary>
    /// Builds the challenge record name for an identifier.
    /// </summary>
    /// <remarks>
    /// A wildcard identifier is validated against its parent: the challenge for
    /// <c>*.example.com</c> is published at <c>_acme-challenge.example.com</c>, the same place
    /// as for the bare domain. Getting this wrong produces a validation failure that looks like
    /// a propagation problem and is not.
    /// </remarks>
    private static string BuildDnsRecordName(DomainName identifier) =>
        $"_acme-challenge.{identifier.Value}";

    public async Task ValidateChallengesAsync(CancellationToken cancellationToken)
    {
        if (_work is null || _order is null)
        {
            throw new InvalidOperationException(
                "No ACME order has been created on this client.");
        }

        try
        {
            foreach (AuthorizationWork item in _work)
            {
                await item.Challenge.Validate().ConfigureAwait(false);
            }

            DateTimeOffset deadline = clock.UtcNow + ValidationTimeout;

            foreach (AuthorizationWork item in _work)
            {
                await PollAuthorizationAsync(item, deadline, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (AcmeRequestException ex)
        {
            throw Translate(ex, "validating the ACME challenges");
        }
    }

    private async Task PollAuthorizationAsync(
        AuthorizationWork item,
        DateTimeOffset deadline,
        CancellationToken cancellationToken)
    {
        TimeSpan interval = InitialPollInterval;

        while (true)
        {
            Authorization resource = await item.Authorization.Resource().ConfigureAwait(false);

            if (resource.Status == AuthorizationStatus.Valid)
            {
                logger.LogInformation(
                    "The certificate authority validated control of {Identifier}.",
                    item.Identifier);

                return;
            }

            if (resource.Status is AuthorizationStatus.Invalid
                                or AuthorizationStatus.Revoked
                                or AuthorizationStatus.Deactivated
                                or AuthorizationStatus.Expired)
            {
                // The CA's own explanation, which is written for a human and is the single most
                // useful thing in a failed issuance. Surfaced verbatim rather than summarised.
                string detail = resource.Challenges?
                    .Select(static c => c.Error?.Detail)
                    .FirstOrDefault(static d => !string.IsNullOrWhiteSpace(d))
                    ?? "the certificate authority gave no further detail";

                throw new AcmeProtocolException(
                    $"The certificate authority could not validate control of " +
                    $"{item.Identifier}: {detail}",
                    resource.Challenges?.Select(static c => c.Error?.Type)
                        .FirstOrDefault(static t => t is not null));
            }

            if (clock.UtcNow >= deadline)
            {
                throw new AcmeProtocolException(
                    $"The certificate authority did not finish validating {item.Identifier} " +
                    $"within {ValidationTimeout.TotalMinutes:0} minutes. The authorisation is " +
                    "still pending, which usually means the challenge is not reachable from " +
                    "the Internet. Verify from outside your own network.");
            }

            await Task.Delay(interval, cancellationToken).ConfigureAwait(false);

            interval = interval < MaxPollInterval
                ? TimeSpan.FromTicks(Math.Min(interval.Ticks * 2, MaxPollInterval.Ticks))
                : MaxPollInterval;
        }
    }

    public async Task<AcmeIssuedCertificate> FinalizeOrderAsync(
        IReadOnlyList<DomainName> identifiers,
        int keySizeBits,
        CancellationToken cancellationToken)
    {
        if (_order is null)
        {
            throw new InvalidOperationException(
                "No ACME order has been created on this client.");
        }

        ArgumentNullException.ThrowIfNull(identifiers);

        try
        {
            // A NEW key for every issuance, never the account key and never a previous
            // certificate's key. Reusing one would mean a single compromised key compromised
            // every certificate that ever succeeded it, which is exactly what rotation is for.
            IKey certificateKey = KeyFactory.NewKey(
                keySizeBits >= 4096 ? KeyAlgorithm.RS256 : KeyAlgorithm.ES256);

            // Subject fields beyond the common name are deliberately empty. Public CAs ignore
            // them for domain-validated certificates, and sending an organisation name we have
            // not validated would be asserting something untrue.
            CsrInfo csr = new() { CommonName = identifiers[0].Value };

            await _order.Finalize(csr, certificateKey).ConfigureAwait(false);

            CertificateChain chain = await _order.Download(null).ConfigureAwait(false);

            // PFX with a throwaway passphrase: the bytes live for the length of this method and
            // are re-protected by the certificate store immediately afterwards under a
            // passphrase it generates. This one never leaves the stack.
            string transitPassphrase = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

            byte[] pfx = chain
                .ToPfx(certificateKey)
                .Build(identifiers[0].Value, transitPassphrase);

            try
            {
                X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12(
                    pfx,
                    transitPassphrase,
                    X509KeyStorageFlags.EphemeralKeySet);

                if (!certificate.HasPrivateKey)
                {
                    certificate.Dispose();

                    throw new AcmeProtocolException(
                        "The issued certificate arrived without a usable private key.");
                }

                logger.LogInformation(
                    "The certificate authority issued {Thumbprint}, valid until {NotAfter:u}.",
                    certificate.Thumbprint,
                    certificate.NotAfter);

                return new AcmeIssuedCertificate(certificate);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pfx);
            }
        }
        catch (AcmeRequestException ex)
        {
            throw Translate(ex, "finalising the ACME order");
        }
    }

    /// <summary>
    /// Turns a Certes exception into one carrying the CA's problem document.
    /// </summary>
    /// <remarks>
    /// The detail field of an RFC 8555 problem document is written for a human and is what an
    /// operator needs; the exception's own message is usually just the HTTP status. Keeping the
    /// problem type as well is what lets a rate-limit refusal be handled differently from a
    /// misconfiguration, which matters because one must not be retried.
    /// </remarks>
    private static AcmeProtocolException Translate(AcmeRequestException ex, string operation)
    {
        string detail = ex.Error?.Detail is { Length: > 0 } d ? d : ex.Message;
        string? type = ex.Error?.Type;

        return new AcmeProtocolException(
            $"The certificate authority rejected {operation}: {detail}",
            type);
    }

    /// <summary>One identifier's authorisation and the challenge selected for it.</summary>
    private sealed record AuthorizationWork(
        DomainName Identifier,
        IAuthorizationContext Authorization,
        IChallengeContext Challenge);
}
