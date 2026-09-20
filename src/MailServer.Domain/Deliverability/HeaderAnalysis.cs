using System.Text;
using MailServer.Domain.Imap;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>An address header, split into the parts a diagnosis compares.</summary>
/// <param name="Raw">The field body as written, display name and all.</param>
/// <param name="Mailbox">The addr-spec, or null when none could be found.</param>
/// <param name="Domain">Its domain, lowercased, or null.</param>
public sealed record AnalysedAddress(string Raw, string? Mailbox, string? Domain);

/// <summary>One <c>DKIM-Signature</c> header, read for what it claims to have signed.</summary>
/// <param name="Selector">The <c>s=</c> tag.</param>
/// <param name="Domain">The <c>d=</c> tag — the domain whose key must verify this.</param>
/// <param name="Algorithm">The <c>a=</c> tag.</param>
/// <param name="SignedHeaders">The <c>h=</c> list, in wire order and with repeats kept.</param>
/// <param name="SignedAt">The <c>t=</c> tag.</param>
/// <param name="Expires">The <c>x=</c> tag.</param>
/// <param name="BodyLengthLimit">The <c>l=</c> tag.</param>
/// <param name="ParseError">Why the header could not be read, when it could not.</param>
/// <remarks>
/// <b>No verdict, because a header block cannot support one.</b> RFC 6376 §3.7 computes the
/// body hash over the message body, which is not present in a paste. What is present is what the
/// signer claimed to sign and under whose name — and that is enough to tell an operator whether
/// the signature could ever have helped them.
/// </remarks>
public sealed record AnalysedSignature(
    string? Selector,
    string? Domain,
    string? Algorithm,
    IReadOnlyList<string> SignedHeaders,
    DateTimeOffset? SignedAt,
    DateTimeOffset? Expires,
    long? BodyLengthLimit,
    string? ParseError);

/// <summary>Something the header block says, that an operator would want pointed out.</summary>
/// <param name="Id">A stable identifier, so a UI can link to an explanation.</param>
/// <param name="Text">What it says, in a sentence.</param>
public sealed record HeaderObservation(string Id, string Text);

/// <summary>What a pasted header block turned out to contain.</summary>
public sealed record HeaderAnalysis(
    ReceivedChain Chain,
    AnalysedAddress? From,
    AnalysedAddress? ReturnPath,
    AnalysedAddress? ReplyTo,
    IReadOnlyList<string> ListUnsubscribe,
    bool OneClickUnsubscribe,
    IReadOnlyList<AnalysedSignature> Signatures,
    IReadOnlyList<HeaderObservation> Observations);

/// <summary>
/// Reads a pasted header block and says what is in it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing here reads an authentication verdict off the wire.</b> The analyser reports what
/// the headers claim and what this server can establish for itself; it never treats a header
/// asserting that some earlier hop authenticated the message as evidence that anybody did.
/// <c>docs/DMARC.md</c> puts the reason plainly: "Trusting an attacker-supplied
/// <c>Authentication-Results: dmarc=pass</c> header is a complete authentication bypass, and it
/// is trivially easy to do by accident." An analyser that echoed one back would be presenting
/// the forgery as its finding.
/// </para>
/// <para>
/// <b>Every observation is about the text, never about the truth.</b> Judgements that need DNS —
/// whether a selector's key is published, whether SPF authorises the connecting address, what a
/// DMARC record asks for — belong to the half of the analyser that can make lookups. This half
/// is pure, so it can be tested exhaustively against header text that no resolver would ever
/// answer for.
/// </para>
/// </remarks>
public static class HeaderAnalyser
{
    /// <summary>No <c>Received</c> header at all.</summary>
    public const string NoTraceId = "headers.no-trace";

    /// <summary>A hop whose clause structure cannot be read unambiguously.</summary>
    public const string AmbiguousTraceId = "headers.ambiguous-trace";

    /// <summary>A hop stamped as arriving before the one that handed it over.</summary>
    public const string TraceClockSkewId = "headers.trace-clock-skew";

    /// <summary>No <c>From</c> header.</summary>
    public const string NoFromId = "headers.no-from";

    /// <summary>No <c>DKIM-Signature</c> header.</summary>
    public const string NoDkimId = "headers.no-dkim";

    /// <summary>A signature whose <c>x=</c> has passed.</summary>
    public const string DkimExpiredId = "headers.dkim-expired";

    /// <summary>No signature whose <c>d=</c> is the <c>From</c> domain.</summary>
    public const string DkimDomainDiffersId = "headers.dkim-domain-differs";

    /// <summary>The <c>Return-Path</c> domain is not the <c>From</c> domain.</summary>
    public const string ReturnPathDiffersId = "headers.return-path-differs";

    /// <summary>A signature carrying <c>l=</c>, which bounds what it covers.</summary>
    public const string DkimBodyLengthId = "headers.dkim-body-length";

    /// <summary>One-click unsubscribe offered without the signature RFC 8058 requires.</summary>
    public const string UnsignedOneClickId = "headers.one-click-unsigned";

    /// <summary>The largest paste this will read.</summary>
    /// <remarks>
    /// A header block is a few kilobytes and this one is typed or pasted by a person. The bound
    /// is here because the input is a string from outside and every parser below walks it more
    /// than once.
    /// </remarks>
    public const int MaxInputBytes = 256 * 1024;

    /// <summary>Reads a pasted header block.</summary>
    /// <param name="text">The headers, as pasted. Bare LF line endings are accepted.</param>
    /// <param name="now">The instant to judge <c>x=</c> against.</param>
    public static HeaderAnalysis Analyse(string? text, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return Empty();
        }

        string bounded = text.Length > MaxInputBytes ? text[..MaxInputBytes] : text;

        // Latin-1, for the reason ImapHeaderFields gives: every octet round-trips, so a header
        // carrying raw 8-bit bytes survives the read instead of becoming U+FFFD. A person
        // pasting a header block that made it through a mail client has often lost the original
        // octets already, and this at least does not lose any more of them.
        IReadOnlyList<ImapHeaderField> fields =
            ImapHeaderFields.Read(Encoding.Latin1.GetBytes(bounded));

        ReceivedChain chain = ReceivedTrace.ParseChain(
            [.. Values(fields, "Received")]);

        AnalysedAddress? from = Address(fields, "From");
        AnalysedAddress? returnPath = Address(fields, "Return-Path");
        AnalysedAddress? replyTo = Address(fields, "Reply-To");

        List<string> unsubscribe = [.. Values(fields, "List-Unsubscribe")];

        // RFC 8058 §3.1: one-click is signalled by the pair, and the value is fixed - "The
        // List-Unsubscribe-Post header MUST contain the single key/value pair
        // 'List-Unsubscribe=One-Click'."
        bool oneClick = unsubscribe.Count > 0 &&
                        Values(fields, "List-Unsubscribe-Post")
                            .Any(v => v.Replace(" ", string.Empty, StringComparison.Ordinal)
                                .Equals("List-Unsubscribe=One-Click", StringComparison.OrdinalIgnoreCase));

        List<AnalysedSignature> signatures = [.. Values(fields, "DKIM-Signature").Select(ReadSignature)];

        List<HeaderObservation> observations = Observe(
            chain,
            from,
            returnPath,
            signatures,
            unsubscribe,
            oneClick,
            now);

        return new HeaderAnalysis(
            chain,
            from,
            returnPath,
            replyTo,
            unsubscribe,
            oneClick,
            signatures,
            observations);
    }

    private static HeaderAnalysis Empty() => new(
        new ReceivedChain([], null),
        null,
        null,
        null,
        [],
        false,
        [],
        []);

    // -------------------------------------------------------------------------------------------
    // Observations.
    // -------------------------------------------------------------------------------------------

    private static List<HeaderObservation> Observe(
        ReceivedChain chain,
        AnalysedAddress? from,
        AnalysedAddress? returnPath,
        IReadOnlyList<AnalysedSignature> signatures,
        IReadOnlyList<string> unsubscribe,
        bool oneClick,
        DateTimeOffset now)
    {
        List<HeaderObservation> observations = [];

        if (chain.Hops.Count == 0)
        {
            observations.Add(new HeaderObservation(
                NoTraceId,
                "There is no Received header. RFC 5321 §4.4 requires every SMTP server to add " +
                "one, so a message with none either never travelled or has had its trace " +
                "removed."));
        }

        if (chain.Hops.Any(h => h.Hop.AmbiguousClauses))
        {
            observations.Add(new HeaderObservation(
                AmbiguousTraceId,
                "A Received header repeats a clause keyword, which RFC 5321 §4.4's grammar never " +
                "produces. No reading of that hop is authoritative; the bracketed address is the " +
                "part whoever wrote it could not choose."));
        }

        if (chain.Hops.FirstOrDefault(h => h.Delay < TimeSpan.Zero) is { Delay: { } skew })
        {
            observations.Add(new HeaderObservation(
                TraceClockSkewId,
                $"A hop is stamped {FormatDelay(-skew)} before the hop that handed the message to " +
                "it. Two hops keep independent clocks, so this means one of them is wrong — and " +
                "it distorts every other delay in the chain."));
        }

        if (from is null)
        {
            observations.Add(new HeaderObservation(
                NoFromId,
                "There is no From header. RFC 5322 §3.6 makes it the one originator field a " +
                "message must have, and DMARC has nothing to align against without it."));
        }

        if (signatures.Count == 0)
        {
            observations.Add(new HeaderObservation(
                NoDkimId,
                "The message carries no DKIM signature, so DMARC can only pass through SPF — " +
                "which does not survive forwarding."));
        }

        foreach (AnalysedSignature signature in signatures.Where(s => s.Expires is { } x && x < now))
        {
            observations.Add(new HeaderObservation(
                DkimExpiredId,
                $"The signature from {signature.Domain ?? "an unnamed domain"} expired on " +
                $"{signature.Expires:yyyy-MM-dd}. RFC 6376 §3.5 makes a verifier treat an " +
                "expired signature as though it had failed."));
        }

        foreach (AnalysedSignature signature in signatures.Where(s => s.BodyLengthLimit is not null))
        {
            observations.Add(new HeaderObservation(
                DkimBodyLengthId,
                $"The signature from {signature.Domain ?? "an unnamed domain"} carries l=" +
                $"{signature.BodyLengthLimit}, so it covers only the first part of the body. " +
                "RFC 6376 §8.2 warns that anything appended after that point is unsigned and " +
                "still verifies."));
        }

        // Exact comparison only: relaxed alignment needs the organisational domain, which needs
        // the public suffix list, which is not something a pure type can have. So this reports
        // the difference and stops short of calling it a DMARC failure - the half of the
        // analyser that can make lookups is what decides that.
        if (from?.Domain is { } fromDomain && signatures.Count > 0 &&
            !signatures.Any(s => string.Equals(s.Domain, fromDomain, StringComparison.OrdinalIgnoreCase)))
        {
            observations.Add(new HeaderObservation(
                DkimDomainDiffersId,
                $"No signature is from {fromDomain} itself. DMARC needs the signing domain to " +
                "align with From — exactly, or on the organisational domain when the policy is " +
                "relaxed — so this may still align."));
        }

        if (from?.Domain is { } origin &&
            returnPath?.Domain is { } bounce &&
            !string.Equals(origin, bounce, StringComparison.OrdinalIgnoreCase))
        {
            observations.Add(new HeaderObservation(
                ReturnPathDiffersId,
                $"Return-Path is {bounce} but From is {origin}. SPF authorises the Return-Path " +
                "domain, not the one the recipient sees, so SPF alone cannot make DMARC pass " +
                "here unless the two align."));
        }

        // RFC 8058 §3.1: "the message MUST have a valid DomainKeys Identified Mail (DKIM)
        // signature that covers at least the List-Unsubscribe and List-Unsubscribe-Post
        // headers." Whether the signature verifies needs the body; whether it claims to cover
        // those two headers is in the h= list, and a signature that does not is one this
        // requirement was never met by.
        if (oneClick && !signatures.Any(CoversUnsubscribe))
        {
            observations.Add(new HeaderObservation(
                UnsignedOneClickId,
                "One-click unsubscribe is offered, but no signature's h= list covers both " +
                "List-Unsubscribe and List-Unsubscribe-Post. RFC 8058 §3.1 requires a signature " +
                "over both, and a receiver enforcing it will not show the one-click button."));
        }

        _ = unsubscribe;

        return observations;
    }

    private static bool CoversUnsubscribe(AnalysedSignature signature) =>
        signature.SignedHeaders.Contains("List-Unsubscribe", StringComparer.OrdinalIgnoreCase) &&
        signature.SignedHeaders.Contains("List-Unsubscribe-Post", StringComparer.OrdinalIgnoreCase);

    private static string FormatDelay(TimeSpan span) =>
        span.TotalSeconds < 120
            ? $"{span.TotalSeconds:0} seconds"
            : $"{span.TotalMinutes:0} minutes";

    // -------------------------------------------------------------------------------------------
    // Field reading.
    // -------------------------------------------------------------------------------------------

    private static IEnumerable<string> Values(IReadOnlyList<ImapHeaderField> fields, string name) =>
        fields.Where(f => f.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(f => f.Value);

    private static AnalysedAddress? Address(IReadOnlyList<ImapHeaderField> fields, string name)
    {
        string? raw = Values(fields, name).FirstOrDefault();

        if (raw is null)
        {
            return null;
        }

        string? mailbox = ExtractAddrSpec(raw);

        string? domain = mailbox is not null && mailbox.LastIndexOf('@') is var at && at > 0 && at < mailbox.Length - 1
            ? mailbox[(at + 1)..].Trim().ToLowerInvariant()
            : null;

        return new AnalysedAddress(raw, mailbox, domain);
    }

    /// <summary>
    /// Pulls the addr-spec out of a mailbox field.
    /// </summary>
    /// <remarks>
    /// RFC 5322 §3.4: <c>mailbox = name-addr / addr-spec</c> and
    /// <c>name-addr = [display-name] angle-addr</c>. The angle brackets win when present, and the
    /// scan for them skips quoted text — a display name may legitimately contain one, and
    /// <c>"&lt;not@an.address&gt;" &lt;real@example.com&gt;</c> is exactly the shape somebody
    /// sends when they want a tool to read the wrong one.
    /// </remarks>
    private static string? ExtractAddrSpec(string value)
    {
        bool quoted = false;

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            if (c == '\\')
            {
                i++;
                continue;
            }

            if (quoted)
            {
                if (c == '"')
                {
                    quoted = false;
                }

                continue;
            }

            if (c == '"')
            {
                quoted = true;
                continue;
            }

            if (c == '<')
            {
                int close = value.IndexOf('>', i + 1);

                return close > i + 1 ? value[(i + 1)..close].Trim() : null;
            }
        }

        // No angle-addr, so the whole field is the addr-spec - unless it plainly is not one.
        string bare = value.Trim();

        return bare.Contains('@', StringComparison.Ordinal) ? bare : null;
    }

    private static AnalysedSignature ReadSignature(string value)
    {
        if (!DkimSignatureTags.TryParse(value, out DkimSignatureTags? tags, out string? error))
        {
            return new AnalysedSignature(null, null, null, [], null, null, null, error);
        }

        return new AnalysedSignature(
            tags.Selector.Value,
            tags.SigningDomain.Value,
            tags.Algorithm.ToString(),
            tags.SignedHeaderNames,
            tags.SignedAtUtc,
            tags.ExpiresUtc,
            tags.BodyLengthLimit,
            ParseError: null);
    }
}
