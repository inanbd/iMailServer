using System.Diagnostics.CodeAnalysis;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Mail;

/// <summary>One <c>ARC-Seal</c> header's tags. RFC 8617 §4.1.3.</summary>
public sealed record ArcSealTags(
    int Instance,
    string Algorithm,
    ArcChainValidation ChainValidation,
    DomainName SigningDomain,
    DkimSelector Selector,
    string SignatureValueBase64)
{
    public static bool TryParse(string? tagListValue, [NotNullWhen(true)] out ArcSealTags? result, [NotNullWhen(false)] out string? error)
    {
        result = null;

        if (!ArcTagList.TryParse(tagListValue, out Dictionary<string, string>? tags, out error))
        {
            return false;
        }

        if (!ArcTagList.TryParseInstance(tags, out int instance, out error))
        {
            return false;
        }

        if (!tags.TryGetValue("a", out string? algorithm) || algorithm.Length == 0)
        {
            error = "the a= tag is missing.";
            return false;
        }

        if (!tags.TryGetValue("cv", out string? cvTag) || !TryParseChainValidation(cvTag, out ArcChainValidation cv))
        {
            error = "the cv= tag is missing or is not one of 'none', 'pass', 'fail'.";
            return false;
        }

        if (!tags.TryGetValue("d", out string? domainTag) || !DomainName.TryParse(domainTag, out DomainName? signingDomain))
        {
            error = "the d= tag is missing or is not a valid domain.";
            return false;
        }

        if (!tags.TryGetValue("s", out string? selectorTag) || !DkimSelector.TryParse(selectorTag, out DkimSelector? selector))
        {
            error = "the s= tag is missing or is not a valid selector.";
            return false;
        }

        if (!tags.TryGetValue("b", out string? signatureValue) || signatureValue.Length == 0)
        {
            error = "the b= tag is missing.";
            return false;
        }

        // RFC 8617 §4.1.3, on the tags an ARC-Seal may carry: "Note especially that the DKIM 'h'
        // tag is NOT allowed and, if found, MUST result in a cv status of 'fail'". A seal
        // carrying one is therefore not a seal whose chain can be valid, and reporting it as
        // well-formed would hand a consumer a chain the RFC requires them to reject.
        if (tags.ContainsKey("h"))
        {
            error = "an ARC-Seal carries an h= tag, which RFC 8617 §4.1.3 does not allow.";
            return false;
        }

        error = null;
        result = new ArcSealTags(instance, algorithm, cv, signingDomain, selector, signatureValue);
        return true;
    }

    private static bool TryParseChainValidation(string tag, out ArcChainValidation value)
    {
        switch (tag.ToLowerInvariant())
        {
            case "none":
                value = ArcChainValidation.None;
                return true;
            case "pass":
                value = ArcChainValidation.Pass;
                return true;
            case "fail":
                value = ArcChainValidation.Fail;
                return true;
            default:
                value = default;
                return false;
        }
    }
}

/// <summary>
/// One <c>ARC-Message-Signature</c> header's tags — the same tag grammar as a
/// <see cref="DkimSignatureTags"/>, plus the <c>i=</c> instance number RFC 8617 adds. RFC 8617 §4.1.2.
/// </summary>
public sealed record ArcMessageSignatureTags(
    int Instance,
    string Algorithm,
    DomainName SigningDomain,
    DkimSelector Selector,
    IReadOnlyList<string> SignedHeaderNames,
    string BodyHashBase64,
    string SignatureValueBase64)
{
    public static bool TryParse(
        string? tagListValue, [NotNullWhen(true)] out ArcMessageSignatureTags? result, [NotNullWhen(false)] out string? error)
    {
        result = null;

        if (!ArcTagList.TryParse(tagListValue, out Dictionary<string, string>? tags, out error))
        {
            return false;
        }

        if (!ArcTagList.TryParseInstance(tags, out int instance, out error))
        {
            return false;
        }

        if (!tags.TryGetValue("a", out string? algorithm) || algorithm.Length == 0)
        {
            error = "the a= tag is missing.";
            return false;
        }

        if (!tags.TryGetValue("d", out string? domainTag) || !DomainName.TryParse(domainTag, out DomainName? signingDomain))
        {
            error = "the d= tag is missing or is not a valid domain.";
            return false;
        }

        if (!tags.TryGetValue("s", out string? selectorTag) || !DkimSelector.TryParse(selectorTag, out DkimSelector? selector))
        {
            error = "the s= tag is missing or is not a valid selector.";
            return false;
        }

        if (!tags.TryGetValue("h", out string? headerListTag) || headerListTag.Length == 0)
        {
            error = "the h= tag is missing.";
            return false;
        }

        if (!tags.TryGetValue("bh", out string? bodyHash) || bodyHash.Length == 0)
        {
            error = "the bh= tag is missing.";
            return false;
        }

        if (!tags.TryGetValue("b", out string? signatureValue) || signatureValue.Length == 0)
        {
            error = "the b= tag is missing.";
            return false;
        }

        string[] signedHeaderNames = [.. headerListTag.Split(':').Where(n => n.Length > 0)];

        error = null;
        result = new ArcMessageSignatureTags(instance, algorithm, signingDomain, selector, signedHeaderNames, bodyHash, signatureValue);
        return true;
    }
}

/// <summary>
/// One <c>ARC-Authentication-Results</c> header: its <c>i=</c> instance number and everything
/// after it, kept as opaque text. RFC 8617 §4.1.1.
/// </summary>
/// <remarks>
/// The payload after <c>i=N;</c> is an ordinary <c>Authentication-Results</c> header body (RFC
/// 8601) — this groundwork records what a hop claimed, grouped by instance, without re-parsing or
/// acting on its resinfo. Nothing here treats that text as this server's own authentication
/// verdict: see <see cref="ArcChain"/>'s own remarks.
/// </remarks>
public sealed record ArcAuthenticationResultsTags(int Instance, string ResultsText)
{
    public static bool TryParse(
        string? tagListValue, [NotNullWhen(true)] out ArcAuthenticationResultsTags? result, [NotNullWhen(false)] out string? error)
    {
        result = null;
        error = null;

        if (string.IsNullOrWhiteSpace(tagListValue))
        {
            error = "the header value is empty.";
            return false;
        }

        string flattened = tagListValue.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal);
        int firstSemicolon = flattened.IndexOf(';');

        if (firstSemicolon < 0)
        {
            error = "the header has no ';' separating the i= tag from its results text.";
            return false;
        }

        string instanceTag = flattened[..firstSemicolon].Trim();
        int eq = instanceTag.IndexOf('=');

        if (eq <= 0 || !string.Equals(instanceTag[..eq].Trim(), "i", StringComparison.Ordinal))
        {
            error = "the header does not begin with an i= tag.";
            return false;
        }

        if (!ArcTagList.TryParseInstanceValue(instanceTag[(eq + 1)..].Trim(), out int instance))
        {
            error = "the i= tag is not an integer from 1 to 50.";
            return false;
        }

        result = new ArcAuthenticationResultsTags(instance, flattened[(firstSemicolon + 1)..].Trim());
        return true;
    }
}

/// <summary>
/// One ARC set: the <c>ARC-Seal</c>, <c>ARC-Message-Signature</c> and
/// <c>ARC-Authentication-Results</c> headers sharing one <c>i=</c> instance number. RFC 8617 §4.
/// </summary>
public sealed record ArcSet(
    int Instance,
    ArcSealTags? Seal,
    ArcMessageSignatureTags? MessageSignature,
    ArcAuthenticationResultsTags? AuthenticationResults)
{
    /// <summary>All three headers RFC 8617 requires are present for this instance.</summary>
    public bool IsComplete => Seal is not null && MessageSignature is not null && AuthenticationResults is not null;
}

/// <summary>The result of parsing and grouping a message's ARC headers.</summary>
/// <param name="Sets">Every instance found, 1..N in order, whether or not each is complete.</param>
/// <param name="IsWellFormed">
/// True when the chain has no structural defect this groundwork checks for: every ARC-* header
/// parsed, instances run 1..N with no gaps and no instance repeated, every instance is complete,
/// and every <c>ARC-Seal</c>'s <c>cv=</c> is what RFC 8617 §5.2 step 3C requires of it —
/// <c>none</c> at instance 1, <c>pass</c> above it, and <c>fail</c> nowhere.
/// </param>
/// <remarks>
/// <b>Still not a validation.</b> Every one of those checks reads a tag; none verifies a
/// signature, which is what RFC 8617 §5.2's other six steps are for. A well-formed chain is one
/// whose structure does not already rule it out, not one that has been shown to be genuine.
/// </remarks>
/// <param name="Diagnostic">What was wrong, when <paramref name="IsWellFormed"/> is false.</param>
public sealed record ArcChainParseResult(IReadOnlyList<ArcSet> Sets, bool IsWellFormed, string? Diagnostic);

/// <summary>
/// Parses and groups a message's ARC header sets. RFC 8617 groundwork only.
/// </summary>
/// <remarks>
/// <para>
/// <b>No cryptographic chain validation.</b> This recognises and structurally validates ARC
/// headers - well-formed tag lists, contiguous instance numbers, a correctly placed <c>cv=none</c>
/// - but never verifies an <see cref="ArcSealTags"/>'s seal or an <see cref="ArcMessageSignatureTags"/>'s
/// signature. Nothing in this product currently trusts an ARC chain's claims about anything;
/// building that trust (verifying signatures back through the chain and folding a validated ARC
/// pass into DMARC's own forwarding exception, RFC 8617 §5) is future work this groundwork
/// prepares for, not something it does.
/// </para>
/// <para>
/// Consistent with <c>docs/DMARC.md</c>'s "Inbound handling": parsing these headers for
/// observation is fine; nothing here, or anywhere downstream, may treat an unverified ARC or
/// Authentication-Results claim from the wire as this server's own authentication verdict.
/// </para>
/// </remarks>
public static class ArcChain
{
    private const string SealHeaderName = "ARC-Seal";
    private const string MessageSignatureHeaderName = "ARC-Message-Signature";
    private const string AuthResultsHeaderName = "ARC-Authentication-Results";

    public static ArcChainParseResult Parse(RawMessageHeaders headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        List<string> errors = [];

        Dictionary<int, ArcSealTags> seals = CollectSeals(headers, errors);
        Dictionary<int, ArcMessageSignatureTags> signatures = CollectMessageSignatures(headers, errors);
        Dictionary<int, ArcAuthenticationResultsTags> authResults = CollectAuthResults(headers, errors);

        HashSet<int> instances = [.. seals.Keys, .. signatures.Keys, .. authResults.Keys];

        if (instances.Count == 0)
        {
            // No ARC headers at all: an unremarkable, unsealed message - not malformed.
            return new ArcChainParseResult([], errors.Count == 0, errors.Count == 0 ? null : string.Join(" ", errors));
        }

        int highest = instances.Max();
        List<ArcSet> sets = new(highest);

        for (int i = 1; i <= highest; i++)
        {
            seals.TryGetValue(i, out ArcSealTags? seal);
            signatures.TryGetValue(i, out ArcMessageSignatureTags? signature);
            authResults.TryGetValue(i, out ArcAuthenticationResultsTags? authResult);

            sets.Add(new ArcSet(i, seal, signature, authResult));

            if (seal is null || signature is null || authResult is null)
            {
                errors.Add($"instance {i} is missing its {(seal is null ? SealHeaderName : signature is null ? MessageSignatureHeaderName : AuthResultsHeaderName)} header.");
            }
        }

        if (seals.TryGetValue(1, out ArcSealTags? firstSeal) && firstSeal.ChainValidation != ArcChainValidation.None)
        {
            errors.Add("instance 1's ARC-Seal must declare cv=none; it has nothing earlier to validate.");
        }

        foreach ((int instance, ArcSealTags seal) in seals)
        {
            if (instance > 1 && seal.ChainValidation == ArcChainValidation.None)
            {
                errors.Add($"instance {instance}'s ARC-Seal declares cv=none, but only instance 1 may.");
            }

            // RFC 8617 §5.2 step 3C: "The 'cv' value for all ARC-Seal header fields MUST NOT be
            // 'fail'. For ARC Sets with instance values > 1, the values MUST be 'pass'. For the
            // ARC Set with instance value = 1, the value MUST be 'none'." §5.1.3 is what makes
            // this terminal rather than advisory - "Once broken, the chain cannot be continued" -
            // so a set declaring cv=fail is a chain that is already over, and no amount of
            // structure below it changes that.
            // The other half of step 3C - "For ARC Sets with instance values > 1, the values MUST
            // be 'pass'" - needs no branch of its own: cv is one of three values, and the check
            // above has already rejected cv=none above instance 1, so anything reaching here
            // that is not "pass" is "fail".
            if (seal.ChainValidation == ArcChainValidation.Fail)
            {
                errors.Add($"instance {instance}'s ARC-Seal declares cv=fail, which RFC 8617 §5.2 forbids on any seal.");
            }
        }

        return new ArcChainParseResult(sets, errors.Count == 0, errors.Count == 0 ? null : string.Join(" ", errors));
    }

    private static Dictionary<int, ArcSealTags> CollectSeals(RawMessageHeaders headers, List<string> errors)
    {
        Dictionary<int, ArcSealTags> seals = [];

        foreach (RawHeaderField field in headers.GetAll(SealHeaderName))
        {
            if (!ArcSealTags.TryParse(ExtractValueText(field), out ArcSealTags? tags, out string? error))
            {
                errors.Add($"a malformed {SealHeaderName} header: {error}");
                continue;
            }

            if (!seals.TryAdd(tags.Instance, tags))
            {
                errors.Add($"more than one {SealHeaderName} header declares instance {tags.Instance}.");
            }
        }

        return seals;
    }

    private static Dictionary<int, ArcMessageSignatureTags> CollectMessageSignatures(RawMessageHeaders headers, List<string> errors)
    {
        Dictionary<int, ArcMessageSignatureTags> signatures = [];

        foreach (RawHeaderField field in headers.GetAll(MessageSignatureHeaderName))
        {
            if (!ArcMessageSignatureTags.TryParse(ExtractValueText(field), out ArcMessageSignatureTags? tags, out string? error))
            {
                errors.Add($"a malformed {MessageSignatureHeaderName} header: {error}");
                continue;
            }

            if (!signatures.TryAdd(tags.Instance, tags))
            {
                errors.Add($"more than one {MessageSignatureHeaderName} header declares instance {tags.Instance}.");
            }
        }

        return signatures;
    }

    private static Dictionary<int, ArcAuthenticationResultsTags> CollectAuthResults(RawMessageHeaders headers, List<string> errors)
    {
        Dictionary<int, ArcAuthenticationResultsTags> authResults = [];

        foreach (RawHeaderField field in headers.GetAll(AuthResultsHeaderName))
        {
            if (!ArcAuthenticationResultsTags.TryParse(ExtractValueText(field), out ArcAuthenticationResultsTags? tags, out string? error))
            {
                errors.Add($"a malformed {AuthResultsHeaderName} header: {error}");
                continue;
            }

            if (!authResults.TryAdd(tags.Instance, tags))
            {
                errors.Add($"more than one {AuthResultsHeaderName} header declares instance {tags.Instance}.");
            }
        }

        return authResults;
    }

    private static string ExtractValueText(RawHeaderField field)
    {
        ReadOnlySpan<byte> raw = field.RawBytes.Span;
        int colon = raw.IndexOf((byte)':');
        return System.Text.Encoding.ASCII.GetString(raw[(colon + 1)..^2]);
    }
}

/// <summary>Shared tag-list parsing for the two ARC headers that use one (RFC 6376 §3.2's grammar, plus <c>i=</c>).</summary>
internal static class ArcTagList
{
    public static bool TryParse(
        string? tagListValue, [NotNullWhen(true)] out Dictionary<string, string>? result, [NotNullWhen(false)] out string? error)
    {
        result = null;
        error = null;

        if (string.IsNullOrWhiteSpace(tagListValue))
        {
            error = "the tag-value list is empty.";
            return false;
        }

        // Folding inserts CRLF before a WSP run; removing just the CRLF leaves the WSP as an
        // ordinary separator, which the per-value whitespace-stripping below then handles along
        // with any other incidental FWS around tags.
        string flattened = tagListValue.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal);

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

        result = tags;
        return true;
    }

    public static bool TryParseInstance(Dictionary<string, string> tags, out int instance, [NotNullWhen(false)] out string? error)
    {
        instance = 0;

        if (!tags.TryGetValue("i", out string? instanceTag) || !TryParseInstanceValue(instanceTag, out instance))
        {
            error = "the i= tag is missing or is not an integer from 1 to 50.";
            return false;
        }

        error = null;
        return true;
    }

    /// <summary>RFC 8617 §4.1.1: an ARC instance number is an integer from 1 to 50 inclusive.</summary>
    public static bool TryParseInstanceValue(string text, out int instance) =>
        int.TryParse(text, out instance) && instance is >= 1 and <= 50;

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
}
