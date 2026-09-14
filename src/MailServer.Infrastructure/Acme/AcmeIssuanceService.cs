using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Acme;

/// <summary>
/// Runs one issuance: pre-flight, rate limit, order, challenge, finalise, install.
/// </summary>
/// <remarks>
/// <para>
/// The order of the first two steps matters and is not arbitrary. Pre-flight runs <b>before</b>
/// the rate-limit check, because a misconfiguration should be reported as a misconfiguration
/// even when quota is also exhausted — telling an operator to wait a week when their DNS is
/// wrong sends them away to do nothing useful.
/// </para>
/// <para>
/// <b>Challenge cleanup is in a <c>finally</c> that covers every path.</b> A leftover HTTP
/// token or a stale <c>_acme-challenge</c> TXT record is both untidy and a small standing
/// signal about how this domain proves control. It runs on success, on failure, and on
/// cancellation.
/// </para>
/// <para>
/// <b>Nothing here can replace a working certificate with a self-signed one.</b> A failure
/// records the reason on the order and returns; the existing certificate and its binding are
/// untouched. See <see cref="CertificateRenewalPolicy"/>.
/// </para>
/// </remarks>
internal sealed class AcmeIssuanceService(
    IAcmeClientFactory clientFactory,
    IAcmeRepository acme,
    IAcmePreflightCheck preflight,
    IAcmeSettings settings,
    IHttpChallengeStore httpChallenges,
    IDnsChallengeProvider dnsProvider,
    AcmeAccountKeyStore keyStore,
    ICertificateManager certificates,
    ICertificateRepository certificateRepository,
    ISecurityEventRecorder securityEvents,
    IClock clock,
    ILogger<AcmeIssuanceService> logger) : IAcmeIssuanceService
{
    public async Task<IssuanceResult> IssueAsync(
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        bool bindOnSuccess,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        if (identifiers.Count == 0)
        {
            return new IssuanceResult(false, AcmeOrderId.Empty, Failure:
                "No hostnames were requested.");
        }

        AcmeAccount? account = await EnsureAccountAsync(cancellationToken).ConfigureAwait(false);

        if (account is null)
        {
            return new IssuanceResult(false, AcmeOrderId.Empty, Failure:
                "No usable ACME account is registered. Set a contact address and accept the " +
                "certificate authority's terms of service in the ACME settings first.");
        }

        AcmeOrder order = AcmeOrder.Create(account.Id, identifiers, challengeType, clock.UtcNow);

        string registeredDomain = RegisteredDomainResolver.ResolveForSet(identifiers);

        await acme.AddOrderAsync(order, registeredDomain, cancellationToken).ConfigureAwait(false);

        // ---- Pre-flight, before rate limiting ------------------------------------------------
        PreflightReport report = await preflight
            .CheckAsync(identifiers, challengeType, cancellationToken)
            .ConfigureAwait(false);

        if (!report.CanProceed)
        {
            return await AbandonAsync(order, report.BlockingSummary!, cancellationToken)
                .ConfigureAwait(false);
        }

        foreach (PreflightFinding finding in report.Findings.Where(static f => !f.Passed))
        {
            logger.LogWarning(
                "Pre-flight warning for {Identifier}: {Summary}",
                finding.Identifier,
                finding.Summary);
        }

        // ---- Rate limiting -------------------------------------------------------------------
        RateLimitDecision limit = await EvaluateRateLimitAsync(
            registeredDomain,
            order.IdentifierSetKey,
            cancellationToken).ConfigureAwait(false);

        if (!limit.IsAllowed)
        {
            logger.LogWarning(
                "Refusing to submit an ACME order: {Reason}",
                limit.Reason);

            return await AbandonAsync(order, limit.Reason!, cancellationToken)
                .ConfigureAwait(false);
        }

        return await RunOrderAsync(account, order, identifiers, challengeType, bindOnSuccess, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<IssuanceResult> RunOrderAsync(
        AcmeAccount account,
        AcmeOrder order,
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        bool bindOnSuccess,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<AcmeChallenge> challenges = [];

        try
        {
            string? keyPem = await keyStore
                .GetKeyAsync(account.AccountKeySecretName, cancellationToken)
                .ConfigureAwait(false);

            if (keyPem is null)
            {
                return await AbandonAsync(
                    order,
                    "The ACME account key could not be read, so no certificate can be " +
                    "requested or revoked through this account. Re-register the account.",
                    cancellationToken).ConfigureAwait(false);
            }

            IAcmeClient client = await clientFactory
                .CreateAsync(account.DirectoryUrl, keyPem, cancellationToken)
                .ConfigureAwait(false);

            challenges = await client
                .CreateOrderAsync(identifiers, challengeType, cancellationToken)
                .ConfigureAwait(false);

            order.MarkSubmitted(client.OrderUrl!, clock.UtcNow);
            await acme.UpdateOrderAsync(order, cancellationToken).ConfigureAwait(false);

            List<string> manualInstructions = [];

            foreach (AcmeChallenge challenge in challenges)
            {
                if (challenge.Type == AcmeChallengeType.Http01)
                {
                    httpChallenges.Publish(challenge.Token, challenge.KeyAuthorization);
                    continue;
                }

                DnsChallengePublication publication = await dnsProvider
                    .PublishAsync(
                        challenge.Identifier,
                        challenge.DnsRecordName!,
                        challenge.KeyAuthorization,
                        cancellationToken)
                    .ConfigureAwait(false);

                if (!publication.Published && publication.Instructions is not null)
                {
                    manualInstructions.Add(publication.Instructions);
                }
            }

            if (manualInstructions.Count > 0)
            {
                // Stopped here on purpose, with the order left open. Asking the CA to validate
                // a record the operator has not published yet spends one of five failed
                // validations per hostname per hour and teaches nobody anything.
                order.Advance(AcmeOrderStatus.Pending, clock.UtcNow);
                await acme.UpdateOrderAsync(order, cancellationToken).ConfigureAwait(false);

                logger.LogInformation(
                    "Order {OrderId} is waiting for {Count} DNS record(s) to be published by " +
                    "hand.",
                    order.Id,
                    manualInstructions.Count);

                return new IssuanceResult(
                    false,
                    order.Id,
                    ManualDnsInstructions: manualInstructions,
                    Failure: "The DNS records for this challenge must be published before the " +
                             "certificate authority is asked to validate.");
            }

            order.Advance(AcmeOrderStatus.Validating, clock.UtcNow);
            await acme.UpdateOrderAsync(order, cancellationToken).ConfigureAwait(false);

            await client.ValidateChallengesAsync(cancellationToken).ConfigureAwait(false);

            order.Advance(AcmeOrderStatus.Ready, clock.UtcNow);
            await acme.UpdateOrderAsync(order, cancellationToken).ConfigureAwait(false);

            using AcmeIssuedCertificate issued = await client
                .FinalizeOrderAsync(identifiers, settings.CertificateKeySizeBits, cancellationToken)
                .ConfigureAwait(false);

            Certificate certificate = await InstallAsync(
                issued.Certificate,
                identifiers,
                bindOnSuccess,
                cancellationToken).ConfigureAwait(false);

            order.MarkIssued(certificate.Id, clock.UtcNow);
            await acme.UpdateOrderAsync(order, cancellationToken).ConfigureAwait(false);

            await securityEvents.RecordAsync(
                SecurityEventType.CertificateIssued,
                account.ContactEmail,
                origin: null,
                $"A certificate was issued by {account.Directory} for " +
                $"{string.Join(", ", identifiers.Select(static i => i.Value))}.",
                cancellationToken).ConfigureAwait(false);

            logger.LogInformation(
                "Certificate {Thumbprint} issued for {IdentifierCount} identifier(s) by " +
                "{Directory}.",
                certificate.Thumbprint,
                identifiers.Count,
                account.Directory);

            return new IssuanceResult(true, order.Id, certificate);
        }
        catch (AcmeProtocolException ex)
        {
            // The CA saw this order and rejected it, so it consumed a slot. Recorded as a
            // failure rather than abandoned, which is what makes the rate limiter count it.
            order.MarkFailed(ex.Message, clock.UtcNow);
            await acme.UpdateOrderAsync(order, cancellationToken).ConfigureAwait(false);

            await securityEvents.RecordAsync(
                SecurityEventType.CertificateIssuanceFailed,
                account.ContactEmail,
                origin: null,
                $"Issuance failed for " +
                $"{string.Join(", ", identifiers.Select(static i => i.Value))}: {ex.Message}",
                cancellationToken).ConfigureAwait(false);

            logger.LogError(
                "ACME issuance failed for {IdentifierCount} identifier(s): {Reason}",
                identifiers.Count,
                ex.Message);

            return new IssuanceResult(false, order.Id, Failure: ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            order.MarkFailed(
                "An unexpected error occurred during issuance. See the service log for the " +
                "correlation id.",
                clock.UtcNow);

            await acme.UpdateOrderAsync(order, cancellationToken).ConfigureAwait(false);

            // The message is deliberately generic to the caller and detailed in the log. An
            // exception from deep in an HTTP or crypto stack can carry request content.
            logger.LogError(ex, "ACME issuance failed unexpectedly.");

            return new IssuanceResult(
                false,
                order.Id,
                Failure: "Issuance failed unexpectedly. See the service log.");
        }
        finally
        {
            // Always, on every path. A leftover token or a stale _acme-challenge record is a
            // hygiene problem and a small standing signal about this domain.
            await CleanUpChallengesAsync(challenges).ConfigureAwait(false);
        }
    }

    /// <summary>Stores the issued certificate and, optionally, binds it.</summary>
    private async Task<Certificate> InstallAsync(
        X509Certificate2 issued,
        IReadOnlyList<DomainName> identifiers,
        bool bind,
        CancellationToken cancellationToken)
    {
        // Stored with Source = Acme, NOT through the import path. The storage is identical
        // either way, but the source is what decides whether the lifecycle service will renew
        // it: a certificate recorded as an operator's import is one this server cannot
        // reissue, so it is never renewed. Routing ACME issuance through ImportPfxAsync
        // produced exactly that - certificates obtained automatically that would then have
        // expired without one renewal attempt.
        Certificate certificate = await certificates
            .StoreIssuedAsync(issued, CertificateSource.Acme, cancellationToken)
            .ConfigureAwait(false);

        if (bind)
        {
            await BindAsync(certificate, identifiers[0], cancellationToken).ConfigureAwait(false);
        }

        return certificate;
    }

    /// <summary>Creates or repoints the binding for the primary identifier.</summary>
    /// <remarks>
    /// Clears the default flag before claiming it, for the same reason as every other binding
    /// path: the unique filtered index rejects a second default, so the other order fails at
    /// the write.
    /// </remarks>
    private async Task BindAsync(
        Certificate certificate,
        DomainName hostname,
        CancellationToken cancellationToken)
    {
        CertificateBinding? existing = await certificateRepository
            .GetBindingByHostnameAsync(hostname, cancellationToken)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            existing.PointAt(certificate.Id, clock.UtcNow);

            await certificateRepository
                .UpdateBindingAsync(existing, cancellationToken)
                .ConfigureAwait(false);

            return;
        }

        bool isFirst = (await certificateRepository
            .GetBindingsAsync(cancellationToken)
            .ConfigureAwait(false)).Count == 0;

        CertificateBinding binding = CertificateBinding.Create(
            hostname,
            certificate.Id,
            CertificatePurpose.All,
            isFirst,
            clock.UtcNow);

        if (binding.IsDefault)
        {
            await certificateRepository
                .ClearOtherDefaultsAsync(binding.Id, cancellationToken)
                .ConfigureAwait(false);
        }

        await certificateRepository
            .AddBindingAsync(binding, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <remarks>
    /// Never throws. This runs in a <c>finally</c>, and an exception here would replace the
    /// real failure with a cleanup failure — losing the diagnosis the operator needs.
    /// </remarks>
    private async Task CleanUpChallengesAsync(IReadOnlyList<AcmeChallenge> challenges)
    {
        foreach (AcmeChallenge challenge in challenges)
        {
            try
            {
                if (challenge.Type == AcmeChallengeType.Http01)
                {
                    httpChallenges.Remove(challenge.Token);
                }
                else if (challenge.DnsRecordName is not null)
                {
                    await dnsProvider
                        .RemoveAsync(challenge.DnsRecordName, CancellationToken.None)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(
                    ex,
                    "A challenge artefact could not be cleaned up. It will expire on its own, " +
                    "but a stale record is worth removing by hand.");
            }
        }
    }

    private async Task<RateLimitDecision> EvaluateRateLimitAsync(
        string registeredDomain,
        string identifierSetKey,
        CancellationToken cancellationToken)
    {
        AcmeRateLimitPolicy policy = settings.RateLimitPolicy;
        DateTimeOffset now = clock.UtcNow;

        AcmeAttemptCounts counts = await acme.CountRecentAttemptsAsync(
            registeredDomain,
            identifierSetKey,
            now - policy.WeeklyWindow,
            now - policy.FailureWindow,
            cancellationToken).ConfigureAwait(false);

        return policy.Evaluate(
            counts.CertificatesForRegisteredDomain,
            counts.DuplicateCertificates,
            counts.RecentFailedValidations,
            counts.OldestRelevantAttemptUtc,
            now);
    }

    /// <summary>Registers an account for the configured directory, or returns the existing one.</summary>
    private async Task<AcmeAccount?> EnsureAccountAsync(CancellationToken cancellationToken)
    {
        AcmeDirectory directory = settings.DefaultDirectory;

        AcmeAccount? existing = await acme
            .GetActiveAccountAsync(directory, cancellationToken)
            .ConfigureAwait(false);

        if (existing is { IsUsable: true })
        {
            return existing;
        }

        if (string.IsNullOrWhiteSpace(settings.ContactEmail))
        {
            logger.LogError(
                "No ACME contact address is configured (MailServer:Acme:ContactEmail). The " +
                "certificate authority requires one; it is where expiry warnings are sent.");

            return null;
        }

        if (!settings.TermsOfServiceAccepted)
        {
            logger.LogError(
                "The certificate authority's terms of service have not been accepted " +
                "(MailServer:Acme:AcceptTermsOfService). Registration was not attempted: " +
                "accepting a legal agreement on an operator's behalf is not this software's " +
                "decision to make.");

            return null;
        }

        string directoryUrl = settings.GetDirectoryUrl(directory);
        string keyPem = await keyStore.EnsureKeyAsync(directory, cancellationToken).ConfigureAwait(false);

        // Reuse the row from an interrupted registration rather than creating a second one:
        // the key is the same, and ACME returns the existing account for a known key.
        AcmeAccount account = existing ?? AcmeAccount.Create(
            directory,
            directoryUrl,
            settings.ContactEmail!,
            AcmeAccountKeyStore.SecretNameFor(directory),
            clock.UtcNow);

        if (existing is null)
        {
            await acme.AddAccountAsync(account, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            IAcmeClient client = await clientFactory
                .CreateAsync(directoryUrl, keyPem, cancellationToken)
                .ConfigureAwait(false);

            AcmeAccountRegistration registration = await client.EnsureAccountAsync(
                directoryUrl,
                keyPem,
                settings.ContactEmail!,
                settings.TermsOfServiceAccepted,
                cancellationToken).ConfigureAwait(false);

            account.MarkRegistered(
                registration.AccountUrl,
                registration.TermsOfServiceUrl,
                clock.UtcNow);

            await acme.UpdateAccountAsync(account, cancellationToken).ConfigureAwait(false);

            return account;
        }
        catch (AcmeProtocolException ex)
        {
            logger.LogError("ACME account registration failed: {Reason}", ex.Message);

            return null;
        }
    }

    private async Task<IssuanceResult> AbandonAsync(
        AcmeOrder order,
        string reason,
        CancellationToken cancellationToken)
    {
        order.Abandon(reason, clock.UtcNow);

        await acme.UpdateOrderAsync(order, cancellationToken).ConfigureAwait(false);

        return new IssuanceResult(false, order.Id, Failure: reason);
    }
}
