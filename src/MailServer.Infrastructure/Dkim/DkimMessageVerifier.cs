using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dkim;

/// <summary>The outcome of verifying one <c>DKIM-Signature</c> header found on a message.</summary>
/// <param name="Result">See <see cref="DkimVerificationResult"/>.</param>
/// <param name="SigningDomain">
/// The signature's <c>d=</c> value, present whenever the signature at least parsed — DMARC
/// alignment needs this regardless of whether the signature ultimately passed.
/// </param>
/// <param name="Diagnostic">Human-readable detail, for logs and for a future Authentication-Results header.</param>
public sealed record DkimVerifiedSignature(
    DkimVerificationResult Result,
    DomainName? SigningDomain,
    string? Diagnostic);

/// <summary>
/// Verifies every <c>DKIM-Signature</c> header on a message, per RFC 6376.
/// </summary>
/// <remarks>
/// A message may legitimately carry several signatures; each is verified independently, and one
/// signature this product cannot evaluate (an algorithm or canonicalization it does not
/// implement) never prevents evaluating the others — see <see cref="DkimSignatureTags.TryParse"/>'s
/// own remarks.
/// </remarks>
public sealed class DkimMessageVerifier(
    IDkimPublicKeyResolver publicKeyResolver, IClock clock, ILogger<DkimMessageVerifier> logger)
{
    private const int BodyReadBufferSize = 64 * 1024;

    /// <summary>
    /// Verifies <paramref name="body"/> against every DKIM-Signature header in
    /// <paramref name="headers"/>.
    /// </summary>
    /// <returns>
    /// One result per signature found, in header order; a single
    /// <see cref="DkimVerificationResult.None"/> entry if the message carries no signature at
    /// all.
    /// </returns>
    public async Task<IReadOnlyList<DkimVerifiedSignature>> VerifyAsync(
        RawMessageHeaders headers,
        Stream body,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(body);

        List<RawHeaderField> signatureFields = [.. headers.GetAll("DKIM-Signature")];

        if (signatureFields.Count == 0)
        {
            return [new DkimVerifiedSignature(DkimVerificationResult.None, null, null)];
        }

        var parsed = new List<(RawHeaderField Field, DkimSignatureTags? Tags, string? Error)>(signatureFields.Count);

        foreach (RawHeaderField field in signatureFields)
        {
            bool ok = DkimSignatureTags.TryParse(ExtractValue(field), out DkimSignatureTags? tags, out string? error);
            parsed.Add((field, ok ? tags : null, ok ? null : error));
        }

        // The body is a forward-only stream and can be read exactly once. Every signature this
        // product can evaluate uses relaxed body canonicalization (simple is rejected below
        // without ever touching the body), so one shared hash serves all of them.
        bool anyNeedsRelaxedBodyHash = parsed.Exists(
            p => p.Tags is { BodyCanonicalization: DkimCanonicalizationMode.Relaxed });

        string? relaxedBodyHashBase64 = anyNeedsRelaxedBodyHash
            ? await ComputeBodyHashAsync(body, cancellationToken).ConfigureAwait(false)
            : null;

        var results = new List<DkimVerifiedSignature>(parsed.Count);

        foreach ((RawHeaderField field, DkimSignatureTags? tags, string? parseError) in parsed)
        {
            results.Add(await VerifyOneAsync(
                headers, field, tags, parseError, relaxedBodyHashBase64, cancellationToken).ConfigureAwait(false));
        }

        return results;
    }

    private async Task<DkimVerifiedSignature> VerifyOneAsync(
        RawMessageHeaders headers,
        RawHeaderField field,
        DkimSignatureTags? tags,
        string? parseError,
        string? relaxedBodyHashBase64,
        CancellationToken cancellationToken)
    {
        if (tags is null)
        {
            return new DkimVerifiedSignature(DkimVerificationResult.PermError, null, parseError);
        }

        if (tags.Algorithm != DkimKeyAlgorithm.RsaSha256 ||
            tags.HeaderCanonicalization != DkimCanonicalizationMode.Relaxed ||
            tags.BodyCanonicalization != DkimCanonicalizationMode.Relaxed)
        {
            return new DkimVerifiedSignature(
                DkimVerificationResult.PermError,
                tags.SigningDomain,
                $"algorithm '{tags.Algorithm}' with canonicalization " +
                $"'{tags.HeaderCanonicalization}/{tags.BodyCanonicalization}' is not implemented " +
                "by this product.");
        }

        if (!string.Equals(relaxedBodyHashBase64, tags.BodyHashBase64, StringComparison.Ordinal))
        {
            return new DkimVerifiedSignature(DkimVerificationResult.Fail, tags.SigningDomain, "body hash mismatch.");
        }

        // RFC 6376 §3.5's x= is a fallback for key compromise: a signature is only as good as
        // its stated validity window. Without this check, a captured, legitimately-signed old
        // message could be replayed indefinitely and would still verify, for as long as the
        // origin's key has not since rotated.
        if (tags.ExpiresUtc is { } expires && clock.UtcNow > expires)
        {
            return new DkimVerifiedSignature(
                DkimVerificationResult.Fail, tags.SigningDomain, $"signature expired at {expires:O}.");
        }

        DkimPublicKeyLookupResult keyLookup = await publicKeyResolver
            .ResolveAsync(tags.Selector, tags.SigningDomain, cancellationToken)
            .ConfigureAwait(false);

        if (keyLookup.Status == DnsLookupStatus.Temporary)
        {
            return new DkimVerifiedSignature(DkimVerificationResult.TempError, tags.SigningDomain, keyLookup.Diagnostic);
        }

        if (keyLookup.Status == DnsLookupStatus.Permanent || keyLookup.Record is null)
        {
            return new DkimVerifiedSignature(DkimVerificationResult.PermError, tags.SigningDomain, keyLookup.Diagnostic);
        }

        if (keyLookup.Record.IsRevoked)
        {
            return new DkimVerifiedSignature(
                DkimVerificationResult.PermError, tags.SigningDomain, "the selector's key has been revoked (empty p=).");
        }

        byte[] dataToVerify = BuildVerificationInput(headers, tags, field);

        bool verified;

        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(keyLookup.Record.PublicKeyBase64), out _);

            // DkimKey.Generate enforces this floor for keys this product creates, but a DNS TXT
            // record is someone else's key, published under someone else's control - including,
            // for an old selector, a legacy short key that may since have been factored. Nothing
            // about RFC 6376 requires trusting whatever key size a record happens to publish.
            if (rsa.KeySize < DkimKey.MinimumRsaKeyLengthBits)
            {
                return new DkimVerifiedSignature(
                    DkimVerificationResult.PermError,
                    tags.SigningDomain,
                    $"the selector's key is {rsa.KeySize} bits, below the " +
                    $"{DkimKey.MinimumRsaKeyLengthBits}-bit minimum this product accepts.");
            }

            verified = rsa.VerifyData(
                dataToVerify,
                Convert.FromBase64String(tags.SignatureValueBase64),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            logger.LogInformation(
                ex, "DKIM signature for d={SigningDomain} s={Selector} could not be checked: malformed key or signature.",
                tags.SigningDomain, tags.Selector);

            return new DkimVerifiedSignature(
                DkimVerificationResult.PermError, tags.SigningDomain, "malformed public key or signature value.");
        }

        return verified
            ? new DkimVerifiedSignature(DkimVerificationResult.Pass, tags.SigningDomain, null)
            : new DkimVerifiedSignature(DkimVerificationResult.Fail, tags.SigningDomain, "signature did not verify.");
    }

    private static async Task<string> ComputeBodyHashAsync(Stream body, CancellationToken cancellationToken)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var canonicalizer = new DkimBodyCanonicalizer(hash);

        byte[] buffer = new byte[BodyReadBufferSize];
        int read;

        while ((read = await body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            canonicalizer.Append(buffer.AsSpan(0, read));
        }

        canonicalizer.Finish();

        return Convert.ToBase64String(hash.GetHashAndReset());
    }

    /// <summary>
    /// Reconstructs the same byte sequence <see cref="DkimMessageSigner"/> would have signed:
    /// the selected headers in <c>h=</c> order, then the received DKIM-Signature field itself
    /// with only its <c>b=</c> value blanked — see <see cref="DkimSignatureTags.BlankSignatureValue"/>.
    /// </summary>
    private static byte[] BuildVerificationInput(
        RawMessageHeaders headers,
        DkimSignatureTags tags,
        RawHeaderField signatureField)
    {
        List<byte> result = [];

        DkimHeaderSelection.AppendSelectedHeaders(result, headers, tags.SignedHeaderNames);

        RawHeaderField blanked = DkimSignatureTags.BlankSignatureValue(signatureField);
        byte[] canonical = DkimHeaderCanonicalizer.Canonicalize(blanked);

        // No trailing CRLF - the signature header is always the last one hashed, whether
        // signing or verifying.
        result.AddRange(canonical[..^2]);

        return [.. result];
    }

    private static string ExtractValue(RawHeaderField field)
    {
        ReadOnlySpan<byte> raw = field.RawBytes.Span;
        int colon = raw.IndexOf((byte)':');
        return Encoding.ASCII.GetString(raw[(colon + 1)..^2]);
    }
}
