using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dmarc;
using MailServer.Infrastructure.Spf;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Reads a pasted header block, then checks what it claims against DNS.
/// </summary>
/// <remarks>
/// <para>
/// The half of the analyser that can look things up. <see cref="HeaderAnalyser"/> has already
/// said what the block contains; this says what is true of it — which selector keys exist, what
/// SPF actually returns for the address in the trace, and what the From domain's DMARC record
/// asks for.
/// </para>
/// <para>
/// <b>It reuses the evaluators the mail path uses rather than reimplementing them.</b> An
/// analyser that answered "SPF passes" by its own reasoning while the SMTP listener answered
/// otherwise would be worse than no analyser: the operator would trust the one that was not
/// deciding anything.
/// </para>
/// </remarks>
public sealed class HeaderAnalysisService(
    SpfEvaluator spf,
    IDkimPublicKeyResolver keys,
    ITxtRecordResolver txt,
    IPublicSuffixListProvider publicSuffixList,
    IClock clock,
    ILogger<HeaderAnalysisService> logger) : IHeaderAnalysisService
{
    /// <summary>No address to evaluate SPF against.</summary>
    public const string NoSpfAddressId = "headers.no-spf-address";

    /// <summary>SPF was evaluated against an address taken from the message's own trace.</summary>
    public const string SpfAddressFromTraceId = "headers.spf-address-from-trace";

    /// <summary>No <c>Return-Path</c>, so there is no MAIL FROM identity to check.</summary>
    public const string NoReturnPathId = "headers.no-return-path";

    /// <summary>A selector named by a signature publishes no usable key.</summary>
    public const string KeyNotPublishedId = "headers.dkim-key-not-published";

    /// <summary>The From domain publishes no DMARC record.</summary>
    public const string NoDmarcId = "headers.no-dmarc";

    /// <summary>Neither mechanism can align, so DMARC cannot pass however it is evaluated.</summary>
    public const string NothingAlignsId = "headers.nothing-aligns";

    /// <summary>The DKIM leg cannot be concluded from headers alone.</summary>
    public const string DkimUnverifiableId = "headers.dkim-unverifiable";

    /// <inheritdoc />
    public async Task<AnalysedHeaders> AnalyseAsync(
        string? text,
        IpAddressValue? clientAddress,
        CancellationToken cancellationToken)
    {
        HeaderAnalysis headers = HeaderAnalyser.Analyse(text, clock.UtcNow);

        List<HeaderObservation> observations = [.. headers.Observations];

        // The address SPF is checked against. Supplied by the operator when they know it;
        // otherwise the topmost hop's observed address, which is what connected to the last
        // server before the paste - and which is only as trustworthy as that hop.
        IpAddressValue? address = clientAddress ?? TraceAddress(headers.Chain);
        bool fromTrace = clientAddress is null && address is not null;

        DomainName? fromDomain = Parse(headers.From?.Domain);
        DomainName? returnPathDomain = Parse(headers.ReturnPath?.Domain) ?? fromDomain;

        (SpfResult? spfResult, string? spfDiagnostic) =
            await EvaluateSpfAsync(returnPathDomain, address, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<AnalysedKey> analysedKeys =
            await LookUpKeysAsync(headers.Signatures, cancellationToken).ConfigureAwait(false);

        (string? dmarcText, DmarcRecord? dmarc) =
            await ReadDmarcAsync(fromDomain, cancellationToken).ConfigureAwait(false);

        bool spfAligned = fromDomain is not null &&
                          returnPathDomain is not null &&
                          spfResult == SpfResult.Pass &&
                          Aligns(returnPathDomain, fromDomain, dmarc?.SpfAlignment ?? AlignmentMode.Relaxed);

        bool dkimCouldAlign = fromDomain is not null && analysedKeys
            .Where(k => k.State == AnalysedKeyState.Published)
            .Any(k => Parse(k.Domain) is { } signing &&
                      Aligns(signing, fromDomain, dmarc?.DkimAlignment ?? AlignmentMode.Relaxed));

        Observe(
            observations,
            headers,
            address,
            fromTrace,
            returnPathDomain,
            analysedKeys,
            fromDomain,
            dmarc,
            spfAligned,
            dkimCouldAlign);

        HeaderAuthentication authentication = new(
            spfResult,
            returnPathDomain,
            address,
            fromTrace,
            spfDiagnostic,
            analysedKeys,
            dmarcText,
            dmarc?.Policy,
            spfAligned,
            dkimCouldAlign);

        return new AnalysedHeaders(headers, authentication, observations);
    }

    // -------------------------------------------------------------------------------------------
    // The lookups.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The address the most recent hop observed.
    /// </summary>
    /// <remarks>
    /// The topmost hop rather than the bottom one: RFC 5321 §4.4 has servers prepend, so the top
    /// is the last host to handle the message and the one whose claim is nearest to being
    /// checkable. Every hop below it wrote its own header and could have written anything.
    /// </remarks>
    private static IpAddressValue? TraceAddress(ReceivedChain chain)
    {
        foreach (ReceivedHopTiming hop in chain.Hops)
        {
            if (hop.Hop.From?.ObservedAddress is { } text &&
                IpAddressValue.TryParse(text, out IpAddressValue? address))
            {
                return address;
            }
        }

        return null;
    }

    private async Task<(SpfResult? Result, string? Diagnostic)> EvaluateSpfAsync(
        DomainName? domain,
        IpAddressValue? address,
        CancellationToken cancellationToken)
    {
        if (domain is null || address is null)
        {
            return (null, null);
        }

        try
        {
            SpfEvaluationResult result = await spf
                .EvaluateAsync(domain, address, cancellationToken)
                .ConfigureAwait(false);

            return (result.Result, result.Diagnostic);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // A failed evaluation leaves the result null, which reads as "not established" - the
            // analyser reporting an SPF failure it did not actually observe would send an
            // operator to rewrite a record that is fine.
            logger.LogWarning(ex, "SPF evaluation failed while analysing pasted headers.");

            return (null, ex.Message);
        }
    }

    private async Task<IReadOnlyList<AnalysedKey>> LookUpKeysAsync(
        IReadOnlyList<AnalysedSignature> signatures,
        CancellationToken cancellationToken)
    {
        List<AnalysedKey> results = [];

        foreach (AnalysedSignature signature in signatures)
        {
            if (signature.Selector is not { Length: > 0 } selectorText ||
                signature.Domain is not { Length: > 0 } domainText ||
                !DkimSelector.TryParse(selectorText, out DkimSelector? selector) ||
                !DomainName.TryParse(domainText, out DomainName? domain))
            {
                continue;
            }

            results.Add(await LookUpKeyAsync(selector, domain, cancellationToken).ConfigureAwait(false));
        }

        return results;
    }

    private async Task<AnalysedKey> LookUpKeyAsync(
        DkimSelector selector,
        DomainName domain,
        CancellationToken cancellationToken)
    {
        try
        {
            DkimPublicKeyLookupResult lookup = await keys
                .ResolveAsync(selector, domain, cancellationToken)
                .ConfigureAwait(false);

            if (lookup.Status != DnsLookupStatus.Success || lookup.Record is null)
            {
                // Permanent means the name does not exist, which is a configuration fact;
                // temporary means the resolver did not answer, which is not. Reporting the
                // second as "no key published" would tell an operator to republish a record
                // that is already there.
                return new AnalysedKey(
                    selector.Value,
                    domain.Value,
                    lookup.Status == DnsLookupStatus.Permanent
                        ? AnalysedKeyState.NotPublished
                        : AnalysedKeyState.LookupFailed,
                    null,
                    lookup.Diagnostic);
            }

            if (lookup.Record.IsRevoked)
            {
                return new AnalysedKey(
                    selector.Value,
                    domain.Value,
                    AnalysedKeyState.Revoked,
                    null,
                    "the record's p= tag is empty, which RFC 6376 §3.6.1 defines as revocation.");
            }

            int? bits = AuthenticationChecks.RsaKeyBits(lookup.Record.PublicKeyBase64);

            return new AnalysedKey(
                selector.Value,
                domain.Value,
                AnalysedKeyState.Published,
                bits,
                null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "A DKIM key lookup failed while analysing pasted headers.");

            return new AnalysedKey(
                selector.Value,
                domain.Value,
                AnalysedKeyState.LookupFailed,
                null,
                ex.Message);
        }
    }

    private async Task<(string? Text, DmarcRecord? Record)> ReadDmarcAsync(
        DomainName? fromDomain,
        CancellationToken cancellationToken)
    {
        if (fromDomain is null)
        {
            return (null, null);
        }

        try
        {
            TxtLookupResult lookup = await txt
                .GetTxtRecordsAsync($"_dmarc.{fromDomain.Value}", cancellationToken)
                .ConfigureAwait(false);

            if (lookup.Status != DnsLookupStatus.Success)
            {
                return (null, null);
            }

            string? text = lookup.Records
                .FirstOrDefault(r => r.TrimStart().StartsWith("v=DMARC1", StringComparison.Ordinal));

            return text is not null && DmarcRecord.TryParse(text, out DmarcRecord? record, out _)
                ? (text, record)
                : (text, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "A DMARC lookup failed while analysing pasted headers.");

            return (null, null);
        }
    }

    /// <summary>
    /// Whether two domains align under a mode.
    /// </summary>
    /// <remarks>
    /// RFC 7489 §3.1.1: "In relaxed mode, the Organizational Domains of both the [DKIM]-
    /// authenticated signing domain (taken from the value of the 'd=' tag in the signature) and
    /// that of the RFC5322.From domain must be equal if the identifiers are to be considered
    /// aligned. In strict mode, only an exact match between both of the Fully Qualified Domain
    /// Names (FQDNs) is considered to produce Identifier Alignment." §3.1.2 says the same of the
    /// SPF-authenticated domain.
    /// </remarks>
    private bool Aligns(DomainName authenticated, DomainName fromDomain, AlignmentMode mode)
    {
        if (string.Equals(authenticated.Value, fromDomain.Value, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (mode == AlignmentMode.Strict)
        {
            return false;
        }

        PublicSuffixList list = publicSuffixList.List;

        return string.Equals(
            list.GetOrganizationalDomain(authenticated).Value,
            list.GetOrganizationalDomain(fromDomain).Value,
            StringComparison.OrdinalIgnoreCase);
    }

    private static DomainName? Parse(string? value) =>
        value is { Length: > 0 } && DomainName.TryParse(value, out DomainName? domain) ? domain : null;

    // -------------------------------------------------------------------------------------------
    // What the lookups add.
    // -------------------------------------------------------------------------------------------

    private static void Observe(
        List<HeaderObservation> observations,
        HeaderAnalysis headers,
        IpAddressValue? address,
        bool fromTrace,
        DomainName? returnPathDomain,
        IReadOnlyList<AnalysedKey> keys,
        DomainName? fromDomain,
        DmarcRecord? dmarc,
        bool spfAligned,
        bool dkimCouldAlign)
    {
        if (address is null)
        {
            observations.Add(new HeaderObservation(
                NoSpfAddressId,
                "No sending address could be found, so SPF was not evaluated. Supply the address " +
                "the message was received from, or paste a Received header that carries one."));
        }
        else if (fromTrace)
        {
            observations.Add(new HeaderObservation(
                SpfAddressFromTraceId,
                $"SPF was evaluated against {address.Value}, taken from the message's own trace. " +
                "That address is only as trustworthy as the hop that wrote it — supply the " +
                "address your server actually saw if you have it."));
        }

        if (headers.ReturnPath is null && headers.From is not null)
        {
            observations.Add(new HeaderObservation(
                NoReturnPathId,
                $"There is no Return-Path, so SPF was checked for {returnPathDomain?.Value ?? "the From domain"} " +
                "instead. RFC 7208 §2.2 says checking an identity other than MAIL FROM is not " +
                "recommended, so treat this result with care."));
        }

        foreach (AnalysedKey key in keys.Where(k =>
                     k.State is AnalysedKeyState.NotPublished or AnalysedKeyState.Revoked or AnalysedKeyState.Unusable))
        {
            observations.Add(new HeaderObservation(
                KeyNotPublishedId,
                $"{key.Selector}._domainkey.{key.Domain} publishes no usable key " +
                $"({Describe(key.State)}), so every signature it made fails verification."));
        }

        if (fromDomain is not null && dmarc is null)
        {
            observations.Add(new HeaderObservation(
                NoDmarcId,
                $"{fromDomain.Value} publishes no DMARC record that parses, so receivers have no " +
                "instruction for this message and send no reports about it."));
        }

        if (headers.Signatures.Count > 0)
        {
            observations.Add(new HeaderObservation(
                DkimUnverifiableId,
                "Whether a DKIM signature actually verifies cannot be established from headers " +
                "alone: RFC 6376 §3.7 hashes the body, and a paste has none. What is reported " +
                "is whether the signature could have helped — a published key, and a d= that " +
                "aligns with From."));
        }

        if (fromDomain is not null && !spfAligned && !dkimCouldAlign)
        {
            observations.Add(new HeaderObservation(
                NothingAlignsId,
                $"Nothing aligns with {fromDomain.Value}: SPF did not pass for an aligned domain, " +
                "and no signature with a published key names one. DMARC cannot pass on this " +
                "message however a receiver evaluates it."));
        }
    }

    private static string Describe(AnalysedKeyState state) => state switch
    {
        AnalysedKeyState.NotPublished => "the name does not resolve",
        AnalysedKeyState.Revoked => "the key is revoked",
        _ => "the record is not a usable key",
    };
}
