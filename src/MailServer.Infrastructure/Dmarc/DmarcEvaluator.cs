using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dkim;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dmarc;

/// <summary>
/// The outcome of evaluating a message's DMARC alignment. RFC 7489 §3, §6.6.3, §6.7.
/// </summary>
/// <param name="Result">
/// Null when DMARC simply does not apply to this message: no usable <c>From:</c> header, or no
/// DMARC policy published anywhere along the discovery chain. Otherwise pass/fail per RFC 7489
/// §3.1 — at least one aligned, passing mechanism is a pass.
/// </param>
/// <param name="Disposition">
/// The handling actually requested for this specific message, after resolving <c>sp=</c> vs
/// <c>p=</c> and applying <c>pct=</c> sampling. <see cref="DmarcPolicy.None"/> whenever
/// <paramref name="Result"/> is null or <see cref="DmarcResult.Pass"/>, or the message was
/// excluded by sampling — there is nothing for a caller to enforce in any of those cases.
/// </param>
/// <param name="AlignedMechanisms">Which mechanism(s), if any, produced an aligned pass.</param>
/// <param name="FromDomain">The <c>From:</c> header's domain, when one could be extracted.</param>
/// <param name="PolicyDomain">
/// The domain a DMARC record was actually found at — <paramref name="FromDomain"/> itself, or its
/// organizational domain when discovery fell back to it. Null when no record was found.
/// </param>
/// <param name="Diagnostic">Human-readable detail, for a future Authentication-Results header and for logs.</param>
public sealed record DmarcEvaluationOutcome(
    DmarcResult? Result,
    DmarcPolicy Disposition,
    DmarcAlignedMechanism AlignedMechanisms,
    DomainName? FromDomain,
    DomainName? PolicyDomain,
    string? Diagnostic);

/// <summary>
/// Evaluates a received message's DMARC alignment against its <c>From:</c> header domain, per
/// RFC 7489.
/// </summary>
/// <remarks>
/// <para>
/// <b>Never trusts anything already on the message.</b> The <c>From:</c> domain comes from
/// <see cref="FromHeaderDomain"/>, reading the header this server itself received and stored; SPF
/// and DKIM results come from this server's own <see cref="SpfEvaluationOutcome"/> (recorded at
/// <c>MAIL FROM</c> time) and its own <c>DkimMessageVerifier</c> run — never from a pre-existing
/// <c>Authentication-Results</c> header on the inbound message, which an attacker controls
/// entirely. <c>docs/DMARC.md</c> is explicit that trusting such a header is a complete
/// authentication bypass.
/// </para>
/// <para>
/// <b>Aggregate/failure reporting (<c>rua=</c>/<c>ruf=</c>) is out of scope.</b> This evaluator
/// computes one message's outcome; it never generates or sends a report.
/// </para>
/// </remarks>
public sealed class DmarcEvaluator(ITxtRecordResolver txtResolver, IPublicSuffixListProvider pslProvider, ILogger<DmarcEvaluator> logger)
{
    /// <summary>Evaluates one message's DMARC alignment.</summary>
    /// <param name="randomSource">
    /// Source of sampling randomness in [0,1), for <c>pct=</c>. Injected so evaluation stays
    /// testable; defaults to <see cref="Random.Shared"/>.
    /// </param>
    public async Task<DmarcEvaluationOutcome> EvaluateAsync(
        RawMessageHeaders headers,
        SpfEvaluationOutcome? spfOutcome,
        IReadOnlyList<DkimVerifiedSignature> dkimResults,
        CancellationToken cancellationToken,
        Func<double>? randomSource = null)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(dkimResults);

        if (!FromHeaderDomain.TryExtract(headers, out DomainName? fromDomain))
        {
            return new DmarcEvaluationOutcome(
                null, DmarcPolicy.None, DmarcAlignedMechanism.None, null, null,
                "the message has no usable From: header domain.");
        }

        (DmarcRecord? record, DomainName? policyDomain, string? diagnostic, bool tempError) =
            await DiscoverPolicyAsync(fromDomain!, cancellationToken).ConfigureAwait(false);

        if (record is null)
        {
            if (tempError)
            {
                logger.LogInformation(
                    "DMARC policy discovery for {FromDomain} failed temporarily: {Diagnostic}",
                    fromDomain!.Value, diagnostic);
            }

            return new DmarcEvaluationOutcome(
                null, DmarcPolicy.None, DmarcAlignedMechanism.None, fromDomain, null, diagnostic);
        }

        DmarcAlignedMechanism aligned = ComputeAlignment(record, fromDomain!, spfOutcome, dkimResults);

        if (aligned != DmarcAlignedMechanism.None)
        {
            return new DmarcEvaluationOutcome(DmarcResult.Pass, DmarcPolicy.None, aligned, fromDomain, policyDomain, null);
        }

        // RFC 7489 §6.6.3: when the record was found only at the organizational domain - a
        // fallback from the exact From: domain - the "sp" tag governs, not "p". That is exactly
        // the distinction DmarcRecord.SubdomainPolicy already encodes.
        DmarcPolicy requestedPolicy = policyDomain!.Equals(fromDomain) ? record.Policy : record.SubdomainPolicy;

        Func<double> random = randomSource ?? Random.Shared.NextDouble;

        DmarcPolicy disposition = requestedPolicy == DmarcPolicy.None || !IsSampledIn(record.Percentage, random)
            ? DmarcPolicy.None
            : requestedPolicy;

        return new DmarcEvaluationOutcome(DmarcResult.Fail, disposition, aligned, fromDomain, policyDomain, null);
    }

    /// <summary>
    /// RFC 7489 §6.6.3's policy discovery: the exact <c>From:</c> domain first, falling back to
    /// its organizational domain (once, not label-by-label) only when the exact domain publishes
    /// no usable record and is not itself the organizational domain.
    /// </summary>
    private async Task<(DmarcRecord? Record, DomainName? PolicyDomain, string? Diagnostic, bool TempError)> DiscoverPolicyAsync(
        DomainName fromDomain, CancellationToken cancellationToken)
    {
        (DmarcRecord? exactRecord, string? exactDiagnostic, bool exactTempError) =
            await FetchRecordAsync(fromDomain, cancellationToken).ConfigureAwait(false);

        if (exactRecord is not null)
        {
            return (exactRecord, fromDomain, null, false);
        }

        if (exactTempError)
        {
            return (null, null, exactDiagnostic, true);
        }

        DomainName organizationalDomain = pslProvider.List.GetOrganizationalDomain(fromDomain);

        if (organizationalDomain.Equals(fromDomain))
        {
            // The From: domain already is the organizational domain; there is nothing further
            // up the chain left to try.
            return (null, null, exactDiagnostic, false);
        }

        (DmarcRecord? orgRecord, string? orgDiagnostic, bool orgTempError) =
            await FetchRecordAsync(organizationalDomain, cancellationToken).ConfigureAwait(false);

        if (orgRecord is not null)
        {
            return (orgRecord, organizationalDomain, null, false);
        }

        return (null, null, orgTempError ? orgDiagnostic : exactDiagnostic, orgTempError);
    }

    private async Task<(DmarcRecord? Record, string? Diagnostic, bool TempError)> FetchRecordAsync(
        DomainName domain, CancellationToken cancellationToken)
    {
        string name = $"_dmarc.{domain.Value}";
        TxtLookupResult txt = await txtResolver.GetTxtRecordsAsync(name, cancellationToken).ConfigureAwait(false);

        if (txt.Status == DnsLookupStatus.Temporary)
        {
            return (null, txt.Diagnostic, true);
        }

        // NXDOMAIN and "no matching record" both mean "no policy published here" - the caller
        // decides whether that ends discovery or falls back to the organizational domain.
        if (txt.Status == DnsLookupStatus.Permanent)
        {
            return (null, txt.Diagnostic, false);
        }

        List<string> candidates = [.. txt.Records.Where(IsDmarcRecord)];

        if (candidates.Count == 0)
        {
            return (null, $"{name} publishes no DMARC (v=DMARC1) record.", false);
        }

        if (candidates.Count > 1)
        {
            // RFC 7489 §6.6.3: more than one record at this name means the entire set is
            // discarded, not that the first one found wins.
            return (null, $"{name} publishes {candidates.Count} DMARC records; RFC 7489 section 6.6.3 permits exactly one.", false);
        }

        if (!DmarcRecord.TryParse(candidates[0], out DmarcRecord? record, out string? parseError))
        {
            return (null, $"{name}'s DMARC record is malformed: {parseError}", false);
        }

        return (record, null, false);
    }

    private DmarcAlignedMechanism ComputeAlignment(
        DmarcRecord record,
        DomainName fromDomain,
        SpfEvaluationOutcome? spfOutcome,
        IReadOnlyList<DkimVerifiedSignature> dkimResults)
    {
        DmarcAlignedMechanism aligned = DmarcAlignedMechanism.None;

        // RFC 7489 §3.1: SPF alignment requires an SPF Pass whose checked domain (the
        // RFC5321.MailFrom domain) aligns with the From: domain - a Fail/SoftFail/Neutral/
        // PermError never contributes, regardless of alignment.
        if (spfOutcome is { Result: SpfResult.Pass, CheckedDomain: not null } &&
            IsAligned(spfOutcome.CheckedDomain, fromDomain, record.SpfAlignment))
        {
            aligned |= DmarcAlignedMechanism.Spf;
        }

        foreach (DkimVerifiedSignature signature in dkimResults)
        {
            if (signature.Result == DkimVerificationResult.Pass && signature.SigningDomain is not null &&
                IsAligned(signature.SigningDomain, fromDomain, record.DkimAlignment))
            {
                aligned |= DmarcAlignedMechanism.Dkim;
                break;
            }
        }

        return aligned;
    }

    private bool IsAligned(DomainName candidate, DomainName fromDomain, AlignmentMode mode) => mode == AlignmentMode.Strict
        ? candidate.Equals(fromDomain)
        : pslProvider.List.GetOrganizationalDomain(candidate).Equals(pslProvider.List.GetOrganizationalDomain(fromDomain));

    /// <summary>RFC 7489 §6.3's <c>pct=</c>: whether this message falls inside the sampled percentage.</summary>
    private static bool IsSampledIn(int percentage, Func<double> random) => percentage switch
    {
        >= 100 => true,
        <= 0 => false,
        _ => random() * 100 < percentage,
    };

    private static bool IsDmarcRecord(string text) =>
        text == "v=DMARC1" ||
        text.StartsWith("v=DMARC1;", StringComparison.Ordinal) ||
        text.StartsWith("v=DMARC1 ", StringComparison.Ordinal);
}
