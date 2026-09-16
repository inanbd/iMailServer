using System.Diagnostics.CodeAnalysis;
using System.Text;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// The tag-value list carried by one <c>DKIM-Signature</c> header. RFC 6376 §3.5.
/// </summary>
/// <remarks>
/// <para>
/// Operates purely on the header's <i>value</i> — the tag-list text after the colon — never on
/// the header field's name, its folding, or its position among other headers. Splitting the
/// field from its folding is <see cref="Mail.RawMessageHeaders"/>'s job; canonicalizing it for
/// hashing is <see cref="Mail.DkimHeaderCanonicalizer"/>'s. This type only interprets what the
/// signature declares about itself: which algorithm, whose key, which headers it covers, and
/// the hash and signature values.
/// </para>
/// <para>
/// <see cref="TryParse"/> exists for verifying a signature this server did not produce — a
/// message can carry several, from different signers, and a signature this product cannot act
/// on (an unrecognised algorithm, a missing required tag) should fail only for itself, not take
/// down parsing of a message's other signatures. <see cref="CreateForSigning"/> and
/// <see cref="Compose"/> exist for the reverse direction — building the value this server's own
/// signer emits. This product only ever composes with <see cref="DkimCanonicalizationMode.Relaxed"/>
/// on both sides and <see cref="DkimKeyAlgorithm.RsaSha256"/>; <see cref="TryParse"/> accepts the
/// wider grammar because inbound mail is not obliged to share this product's choices.
/// </para>
/// </remarks>
public sealed class DkimSignatureTags
{
    private DkimSignatureTags(
        DkimKeyAlgorithm algorithm,
        DkimCanonicalizationMode headerCanonicalization,
        DkimCanonicalizationMode bodyCanonicalization,
        DomainName signingDomain,
        DkimSelector selector,
        IReadOnlyList<string> signedHeaderNames,
        string bodyHashBase64,
        string signatureValueBase64,
        DateTimeOffset? signedAtUtc,
        DateTimeOffset? expiresUtc,
        long? bodyLengthLimit)
    {
        Algorithm = algorithm;
        HeaderCanonicalization = headerCanonicalization;
        BodyCanonicalization = bodyCanonicalization;
        SigningDomain = signingDomain;
        Selector = selector;
        SignedHeaderNames = signedHeaderNames;
        BodyHashBase64 = bodyHashBase64;
        SignatureValueBase64 = signatureValueBase64;
        SignedAtUtc = signedAtUtc;
        ExpiresUtc = expiresUtc;
        BodyLengthLimit = bodyLengthLimit;
    }

    /// <summary><c>a=</c>.</summary>
    public DkimKeyAlgorithm Algorithm { get; }

    /// <summary>The header side of <c>c=</c>.</summary>
    public DkimCanonicalizationMode HeaderCanonicalization { get; }

    /// <summary>The body side of <c>c=</c>.</summary>
    public DkimCanonicalizationMode BodyCanonicalization { get; }

    /// <summary><c>d=</c> — the SDID. What DMARC alignment compares against the <c>From:</c> domain.</summary>
    public DomainName SigningDomain { get; }

    /// <summary><c>s=</c> — where in DNS under <see cref="SigningDomain"/> the public key is published.</summary>
    public DkimSelector Selector { get; }

    /// <summary>
    /// <c>h=</c>, split on <c>:</c>, in the order and with the repeats it declared. A name
    /// repeated (e.g. <c>from:from</c>, an oversigned <c>From</c>) consumes one more occurrence
    /// of that header from the message when verifying — RFC 6376 §5.4.2 — which is exactly why
    /// the list is kept in wire order rather than deduplicated.
    /// </summary>
    public IReadOnlyList<string> SignedHeaderNames { get; }

    /// <summary><c>bh=</c> — base64 body hash.</summary>
    public string BodyHashBase64 { get; }

    /// <summary>
    /// <c>b=</c> — base64 signature value. Empty exactly when this instance is the placeholder
    /// being hashed to produce the signature (RFC 6376 §3.7 step 1: the value is treated as
    /// empty while computing what will become this very tag).
    /// </summary>
    public string SignatureValueBase64 { get; }

    /// <summary><c>t=</c>, if present.</summary>
    public DateTimeOffset? SignedAtUtc { get; }

    /// <summary><c>x=</c>, if present.</summary>
    public DateTimeOffset? ExpiresUtc { get; }

    /// <summary>
    /// <c>l=</c>, if present — the receiver's promise to hash only this many leading body
    /// octets. Never set by <see cref="CreateForSigning"/>: see <c>docs/DKIM.md</c>'s note on
    /// why this product omits it (a truncation length invites a content-append attack). Carried
    /// through when parsing an inbound signature purely so no information is silently dropped;
    /// this product does not yet act on it during verification.
    /// </summary>
    public long? BodyLengthLimit { get; }

    /// <summary>Builds the tags for a signature this server is about to compute, with <c>b=</c> empty.</summary>
    /// <remarks>Always RSA-SHA256, relaxed/relaxed — this product's only supported signing configuration.</remarks>
    public static DkimSignatureTags CreateForSigning(
        DomainName signingDomain,
        DkimSelector selector,
        IReadOnlyList<string> signedHeaderNames,
        string bodyHashBase64,
        DateTimeOffset signedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(signingDomain);
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(signedHeaderNames);
        ArgumentException.ThrowIfNullOrWhiteSpace(bodyHashBase64);

        if (signedHeaderNames.Count == 0)
        {
            throw new ArgumentException("At least one header must be signed.", nameof(signedHeaderNames));
        }

        return new DkimSignatureTags(
            DkimKeyAlgorithm.RsaSha256,
            DkimCanonicalizationMode.Relaxed,
            DkimCanonicalizationMode.Relaxed,
            signingDomain,
            selector,
            [.. signedHeaderNames],
            bodyHashBase64,
            signatureValueBase64: string.Empty,
            signedAtUtc,
            expiresUtc: null,
            bodyLengthLimit: null);
    }

    /// <summary>Returns a copy with <c>b=</c> filled in, once the RSA signature has been computed.</summary>
    public DkimSignatureTags WithSignatureValue(string signatureValueBase64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureValueBase64);

        return new DkimSignatureTags(
            Algorithm, HeaderCanonicalization, BodyCanonicalization, SigningDomain, Selector,
            SignedHeaderNames, BodyHashBase64, signatureValueBase64, SignedAtUtc, ExpiresUtc,
            BodyLengthLimit);
    }

    /// <summary>Renders the tag-value list exactly as it belongs after <c>DKIM-Signature:</c>.</summary>
    public string Compose()
    {
        var sb = new StringBuilder();
        sb.Append("v=1; a=").Append(AlgorithmTag(Algorithm));
        sb.Append("; c=").Append(CanonTag(HeaderCanonicalization)).Append('/').Append(CanonTag(BodyCanonicalization));
        sb.Append("; d=").Append(SigningDomain.Value);
        sb.Append("; s=").Append(Selector.Value);

        if (SignedAtUtc is { } signedAt)
        {
            sb.Append("; t=").Append(signedAt.ToUnixTimeSeconds());
        }

        if (ExpiresUtc is { } expires)
        {
            sb.Append("; x=").Append(expires.ToUnixTimeSeconds());
        }

        if (BodyLengthLimit is { } l)
        {
            sb.Append("; l=").Append(l);
        }

        sb.Append("; h=").Append(string.Join(':', SignedHeaderNames));
        sb.Append("; bh=").Append(BodyHashBase64);
        sb.Append("; b=").Append(SignatureValueBase64);

        return sb.ToString();
    }

    /// <summary>
    /// Returns a copy of a received <c>DKIM-Signature</c> header field with its <c>b=</c> tag's
    /// value removed, leaving every other byte — tag order, spacing, folding — exactly as
    /// received.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §3.5: verifying a signature means canonicalizing this header field as it was
    /// actually sent, with only the <c>b=</c> value blanked out. Recomposing the header from the
    /// parsed <see cref="TryParse"/> result instead — via <see cref="Compose"/> — would use
    /// whatever tag order and spacing this product's own composer happens to choose, which is
    /// not necessarily what the original signer wrote; canonicalization collapses whitespace
    /// differences but not a difference in tag order, so recomposing risks failing a perfectly
    /// valid signature. This operates on the received bytes directly instead.
    /// </remarks>
    public static RawHeaderField BlankSignatureValue(RawHeaderField field)
    {
        byte[] raw = field.RawBytes.ToArray();

        if (raw.Length < 2 || raw[^2] != (byte)'\r' || raw[^1] != (byte)'\n')
        {
            throw new ArgumentException(
                "A raw header field produced by RawMessageHeaders always ends in CRLF.",
                nameof(field));
        }

        int colon = Array.IndexOf(raw, (byte)':');

        if (colon < 0)
        {
            throw new ArgumentException(
                "A raw header field produced by RawMessageHeaders always contains a colon.",
                nameof(field));
        }

        int valueStart = colon + 1;
        int valueEnd = raw.Length - 2; // exclusive; excludes the final CRLF

        List<byte> result = [.. raw[..valueStart]];
        int i = valueStart;

        while (i <= valueEnd)
        {
            int segEnd = Array.IndexOf(raw, (byte)';', i, valueEnd - i);

            if (segEnd < 0)
            {
                segEnd = valueEnd;
            }

            AppendSegment(result, raw, i, segEnd);

            if (segEnd < valueEnd)
            {
                result.Add((byte)';');
            }

            i = segEnd + 1;
        }

        result.AddRange(raw[^2..]);

        return new RawHeaderField(field.Name, result.ToArray());
    }

    /// <summary>Appends one tag segment, truncated right after its <c>=</c> when it is the b= tag.</summary>
    private static void AppendSegment(List<byte> result, byte[] raw, int start, int end)
    {
        int? equalsIndex = null;
        int significantSeen = 0;
        bool isBTag = false;

        for (int j = start; j < end; j++)
        {
            byte b = raw[j];

            if (b is (byte)'\r' or (byte)'\n' or (byte)' ' or (byte)'\t')
            {
                continue;
            }

            if (significantSeen == 0 && b == (byte)'b')
            {
                significantSeen = 1;
                continue;
            }

            if (significantSeen == 1 && b == (byte)'=')
            {
                isBTag = true;
                equalsIndex = j;
                break;
            }

            // Any other significant character before '=' means this is some other tag
            // (e.g. "bh=..."), not "b=" itself.
            significantSeen = -1;
            break;
        }

        if (isBTag && equalsIndex is { } eq)
        {
            result.AddRange(raw[start..(eq + 1)]);
            return;
        }

        result.AddRange(raw[start..end]);
    }

    /// <summary>Parses an inbound <c>DKIM-Signature</c> header's value for verification.</summary>
    /// <remarks>
    /// Accepts the full RFC 6376 grammar, not just this product's own signing configuration — a
    /// signature declaring <c>simple</c> canonicalization or the <c>ed25519-sha256</c> algorithm
    /// parses successfully here even though this product cannot yet verify one; that decision
    /// belongs to whatever calls this, which can look at <see cref="Algorithm"/> and
    /// <see cref="HeaderCanonicalization"/>/<see cref="BodyCanonicalization"/> and decide the
    /// signature is unsupported rather than malformed.
    /// </remarks>
    public static bool TryParse(
        string? tagListValue,
        [NotNullWhen(true)] out DkimSignatureTags? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;
        error = null;

        if (string.IsNullOrWhiteSpace(tagListValue))
        {
            error = "the tag-value list is empty.";
            return false;
        }

        // Folding inserts CRLF before a WSP run; removing just the CRLF leaves the WSP in place
        // as an ordinary separator, which the per-value whitespace-stripping below then handles
        // along with any other incidental spacing RFC 6376 §3.2's FWS allows around tags.
        string flattened = tagListValue.Replace("\r", "").Replace("\n", "");

        var tags = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (string rawSegment in flattened.Split(';'))
        {
            string segment = rawSegment.Trim();

            if (segment.Length == 0)
            {
                continue;
            }

            int eq = segment.IndexOf('=');

            if (eq <= 0)
            {
                error = $"the tag segment '{segment}' has no '=' separator.";
                return false;
            }

            string name = segment[..eq].Trim();
            string value = StripWhitespace(segment[(eq + 1)..]);

            if (!tags.TryAdd(name, value))
            {
                error = $"tag '{name}' appears more than once.";
                return false;
            }
        }

        if (!tags.TryGetValue("v", out string? version) || version != "1")
        {
            error = "the v= tag is missing or is not '1'.";
            return false;
        }

        if (!tags.TryGetValue("a", out string? algorithmTag) ||
            !TryParseAlgorithm(algorithmTag, out DkimKeyAlgorithm algorithm))
        {
            error = $"the a= tag is missing or names an unrecognised algorithm.";
            return false;
        }

        string canonTag = tags.GetValueOrDefault("c", "simple/simple");
        string[] canonParts = canonTag.Split('/', 2);

        if (!TryParseCanon(canonParts[0], out DkimCanonicalizationMode headerCanon) ||
            !TryParseCanon(canonParts.Length > 1 ? canonParts[1] : "simple", out DkimCanonicalizationMode bodyCanon))
        {
            error = $"the c= tag '{canonTag}' names an unrecognised canonicalization.";
            return false;
        }

        if (!tags.TryGetValue("d", out string? domainTag) || !DomainName.TryParse(domainTag, out DomainName? signingDomain))
        {
            error = "the d= tag is missing or is not a valid domain name.";
            return false;
        }

        if (!tags.TryGetValue("s", out string? selectorTag) || !DkimSelector.TryParse(selectorTag, out DkimSelector? selector))
        {
            error = "the s= tag is missing or is not a valid selector.";
            return false;
        }

        if (!tags.TryGetValue("h", out string? headerListTag) || headerListTag.Length == 0)
        {
            error = "the h= tag is missing or empty.";
            return false;
        }

        string[] signedHeaderNames = [.. headerListTag.Split(':').Where(n => n.Length > 0)];

        if (signedHeaderNames.Length == 0)
        {
            error = "the h= tag names no headers.";
            return false;
        }

        if (!tags.TryGetValue("bh", out string? bodyHash) || bodyHash.Length == 0)
        {
            error = "the bh= tag is missing or empty.";
            return false;
        }

        if (!tags.TryGetValue("b", out string? signatureValue) || signatureValue.Length == 0)
        {
            error = "the b= tag is missing or empty.";
            return false;
        }

        DateTimeOffset? signedAt = ParseUnixSeconds(tags, "t");
        DateTimeOffset? expires = ParseUnixSeconds(tags, "x");
        long? bodyLengthLimit = tags.TryGetValue("l", out string? lengthTag) && long.TryParse(lengthTag, out long length)
            ? length
            : null;

        result = new DkimSignatureTags(
            algorithm, headerCanon, bodyCanon, signingDomain, selector, signedHeaderNames,
            bodyHash, signatureValue, signedAt, expires, bodyLengthLimit);
        return true;
    }

    /// <summary>
    /// Parses a <c>t=</c>/<c>x=</c> Unix-seconds tag, tolerating a value so large it cannot name
    /// any real <see cref="DateTimeOffset"/> - a signature is signed data from an unauthenticated
    /// sender at this point in parsing, and a single malformed timestamp must fail only this one
    /// tag, not throw out of <see cref="TryParse"/> and abort verifying the message's other
    /// signatures along with it.
    /// </summary>
    private static DateTimeOffset? ParseUnixSeconds(Dictionary<string, string> tags, string tagName)
    {
        if (!tags.TryGetValue(tagName, out string? raw) || !long.TryParse(raw, out long seconds))
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static string StripWhitespace(string value)
    {
        Span<char> buffer = value.Length <= 256 ? stackalloc char[value.Length] : new char[value.Length];
        int o = 0;

        foreach (char c in value)
        {
            if (!char.IsWhiteSpace(c))
            {
                buffer[o++] = c;
            }
        }

        return new string(buffer[..o]);
    }

    private static bool TryParseAlgorithm(string tag, out DkimKeyAlgorithm algorithm)
    {
        switch (tag)
        {
            case "rsa-sha256":
                algorithm = DkimKeyAlgorithm.RsaSha256;
                return true;
            case "ed25519-sha256":
                algorithm = DkimKeyAlgorithm.Ed25519Sha256;
                return true;
            default:
                algorithm = default;
                return false;
        }
    }

    private static bool TryParseCanon(string tag, out DkimCanonicalizationMode mode)
    {
        switch (tag)
        {
            case "simple":
                mode = DkimCanonicalizationMode.Simple;
                return true;
            case "relaxed":
                mode = DkimCanonicalizationMode.Relaxed;
                return true;
            default:
                mode = default;
                return false;
        }
    }

    private static string AlgorithmTag(DkimKeyAlgorithm algorithm) => algorithm switch
    {
        DkimKeyAlgorithm.RsaSha256 => "rsa-sha256",
        DkimKeyAlgorithm.Ed25519Sha256 => "ed25519-sha256",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unrecognised DKIM algorithm."),
    };

    private static string CanonTag(DkimCanonicalizationMode mode) => mode switch
    {
        DkimCanonicalizationMode.Simple => "simple",
        DkimCanonicalizationMode.Relaxed => "relaxed",
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unrecognised canonicalization mode."),
    };
}
