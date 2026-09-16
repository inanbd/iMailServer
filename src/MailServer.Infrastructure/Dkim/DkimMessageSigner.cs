using System.Security.Cryptography;
using System.Text;
using MailServer.Domain.Entities;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Dkim;

/// <summary>
/// Computes a <c>DKIM-Signature</c> for a message, per RFC 6376, using
/// <see cref="DkimHeaderCanonicalizer"/>, <see cref="DkimBodyCanonicalizer"/> and RSA-SHA256.
/// </summary>
/// <remarks>
/// Pure orchestration and one RSA operation — no I/O beyond reading the supplied
/// <see cref="Stream"/>, no repository or DNS access. Where the private key and the headers to
/// sign come from is entirely the caller's concern, which is what makes this class testable with
/// an in-memory message and a throwaway key pair.
/// </remarks>
internal sealed class DkimMessageSigner
{
    /// <summary>
    /// The curated, stable header set this product signs, per <c>docs/DKIM.md</c>.
    /// </summary>
    /// <remarks>
    /// <c>from</c> is listed twice — oversigned — so a relay cannot add a second <c>From</c>
    /// header without invalidating the signature: RFC 6376 §5.4.2 treats an <c>h=</c> entry with
    /// no corresponding header field as though that field were present with the empty string as
    /// its value, so a lone real <c>From</c> plus an oversigned phantom hashes differently from
    /// two real <c>From</c> headers. Several of the others (<c>Cc</c>, <c>Reply-To</c>-adjacent
    /// headers this product does not add here) are commonly absent from a given message — that
    /// is deliberate too: signing a name that is not present today means the signature breaks
    /// the moment one is added later, by the same oversigning mechanism.
    /// </remarks>
    public static readonly IReadOnlyList<string> DefaultSignedHeaderNames =
    [
        "from", "from", "to", "cc", "subject", "date", "message-id", "mime-version",
        "content-type", "content-transfer-encoding",
    ];

    /// <summary>Bytes read per <see cref="Stream.ReadAsync(Memory{byte}, CancellationToken)"/> call while hashing the body.</summary>
    private const int BodyReadBufferSize = 64 * 1024;

    /// <summary>
    /// Signs a message.
    /// </summary>
    /// <param name="headers">The message's already-parsed header block.</param>
    /// <param name="body">
    /// The message body, positioned at its first octet. Read to completion; not disposed.
    /// </param>
    /// <param name="signingDomain">The <c>d=</c> value: the domain whose key this is.</param>
    /// <param name="selector">The <c>s=</c> value.</param>
    /// <param name="pkcs8PrivateKey">The signing domain's plaintext PKCS#8 private key.</param>
    /// <param name="now">The signature's <c>t=</c> timestamp.</param>
    /// <param name="headerNamesToSign">Defaults to <see cref="DefaultSignedHeaderNames"/>.</param>
    /// <returns>The completed tags, with <c>b=</c> filled in.</returns>
    public async Task<DkimSignatureTags> SignAsync(
        RawMessageHeaders headers,
        Stream body,
        DomainName signingDomain,
        DkimSelector selector,
        byte[] pkcs8PrivateKey,
        DateTimeOffset now,
        IReadOnlyList<string>? headerNamesToSign = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(body);
        ArgumentNullException.ThrowIfNull(signingDomain);
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(pkcs8PrivateKey);

        IReadOnlyList<string> namesToSign = headerNamesToSign ?? DefaultSignedHeaderNames;

        string bodyHashBase64 = await ComputeBodyHashAsync(body, cancellationToken).ConfigureAwait(false);

        DkimSignatureTags placeholderTags = DkimSignatureTags.CreateForSigning(
            signingDomain, selector, namesToSign, bodyHashBase64, now);

        byte[] dataToSign = BuildSigningInput(headers, namesToSign, placeholderTags);

        using RSA rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);

        byte[] signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return placeholderTags.WithSignatureValue(Convert.ToBase64String(signature));
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
    /// Builds the exact byte sequence RFC 6376 §3.7 signs: the selected headers, canonicalized
    /// in <c>h=</c> order, followed by the DKIM-Signature header being created itself —
    /// canonicalized the same way, but without its trailing CRLF, since it has not actually been
    /// added to the message yet.
    /// </summary>
    private static byte[] BuildSigningInput(
        RawMessageHeaders headers,
        IReadOnlyList<string> namesToSign,
        DkimSignatureTags placeholderTags)
    {
        List<byte> result = [];

        DkimHeaderSelection.AppendSelectedHeaders(result, headers, namesToSign);

        byte[] placeholderField = Encoding.ASCII.GetBytes($"DKIM-Signature: {placeholderTags.Compose()}\r\n");
        byte[] placeholderCanonical = DkimHeaderCanonicalizer.Canonicalize(
            new RawHeaderField("DKIM-Signature", placeholderField));

        // Drop the trailing CRLF: this header field is being created, not yet present in the
        // message, so its own eventual line terminator is not part of what gets signed.
        result.AddRange(placeholderCanonical[..^2]);

        return [.. result];
    }
}
