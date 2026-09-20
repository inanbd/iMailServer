using System.Buffers.Text;
using System.IO.Compression;
using System.Text;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Imap;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Pulls an RFC 8460 report out of the message a sender delivered it in.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three layers, each of which a stranger chose the size of.</b> §3 has the report arrive as
/// a gzipped JSON attachment: a MIME part, transfer-encoded, compressed. Every one of those is
/// an expansion an attacker controls, so each is bounded independently — a 4 MB attachment that
/// decompresses to 4 GB is the classic version of this attack, and a bound on the attachment
/// alone would not catch it.
/// </para>
/// <para>
/// <b>Transfer-decoding lives here rather than in the MIME reader.</b>
/// <c>docs/Standards.md</c> records that <c>ImapMimeTree</c> deliberately does not decode
/// transfer encodings, because a server owes an IMAP client the octets it stored and nothing
/// else. That is still true; this is a different consumer, which needs the bytes a human would
/// see rather than the bytes on the wire, and doing it here leaves IMAP's behaviour untouched.
/// </para>
/// <para>
/// <b>Lenient about the media type, because senders differ.</b> §3 registers
/// <c>application/tlsrpt+gzip</c>, and reports arrive as <c>application/gzip</c>,
/// <c>application/octet-stream</c> and occasionally <c>application/x-gzip</c> with a
/// <c>.json.gz</c> filename. Insisting on the registered type would mean discarding most real
/// reports, so anything that gunzips into something <see cref="ITlsReportReader"/> accepts is
/// treated as a report — the parse is the real test of whether it was one.
/// </para>
/// </remarks>
public sealed class TlsReportExtractor(ITlsReportReader reader) : ITlsReportExtractor
{
    /// <summary>The largest attachment this will transfer-decode.</summary>
    public const int MaxEncodedBytes = 8 * 1024 * 1024;

    /// <summary>
    /// The largest amount of JSON this will decompress to.
    /// </summary>
    /// <remarks>
    /// The bound that matters: gzip's ratio is unbounded, so without a ceiling on the *output*
    /// a small attachment can ask for arbitrary memory. Decompression stops at this and the
    /// report is refused rather than truncated — a half-read report would parse into a smaller
    /// set of failures than the sender counted, which is worse than no report at all.
    /// </remarks>
    public const int MaxDecompressedBytes = 16 * 1024 * 1024;

    /// <summary>
    /// The most MIME parts this will walk.
    /// </summary>
    /// <remarks>
    /// A deeply nested or very wide message is somebody else's choice too. Reports are a
    /// one-part or two-part message in practice.
    /// </remarks>
    public const int MaxPartsExamined = 64;

    public bool TryExtract(
        ReadOnlyMemory<byte> message,
        out TlsReport? report,
        out string? error)
    {
        report = null;
        error = null;

        ImapBodyPart root;

        try
        {
            root = ImapMimeTree.Parse(message);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            error = $"the message could not be parsed as MIME: {ex.Message}";
            return false;
        }

        int examined = 0;
        List<string> attempts = [];

        foreach (ImapBodyPart part in Walk(root))
        {
            if (++examined > MaxPartsExamined)
            {
                break;
            }

            if (part.IsMultipart || part.Content.IsEmpty)
            {
                continue;
            }

            // A text part is never the report. §3 attaches it as a binary gzip, and the text
            // part in a report message is the human-readable covering note every sender
            // includes. Trying it anyway would mean telling an operator that "text/plain is not
            // gzip" about a message that simply had no attachment, which is a worse diagnosis
            // than saying so.
            if (part.Type.Equals("TEXT", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!TryDecode(part, out byte[]? decoded, out string? decodeError))
            {
                attempts.Add($"{part.Type}/{part.Subtype}: {decodeError}");
                continue;
            }

            // Only gzip is tried. §3 says the report "MUST be" gzipped, and a plain-JSON part
            // in a report message is far more likely to be the human-readable covering note
            // than the report - treating that as a candidate would mean reporting a parse
            // failure for a part that was never meant to be one.
            if (!TryDecompress(decoded!, out byte[]? json, out string? unzipError))
            {
                attempts.Add($"{part.Type}/{part.Subtype}: {unzipError}");
                continue;
            }

            if (reader.TryRead(Encoding.UTF8.GetString(json!), out TlsReport? parsed, out string? readError))
            {
                report = parsed;
                return true;
            }

            attempts.Add($"{part.Type}/{part.Subtype}: {readError}");
        }

        // Every candidate's own reason is kept. "No report found" on a message that had one
        // part which failed to gunzip and another that failed to parse is a diagnosis nobody
        // can act on.
        error = attempts.Count == 0
            ? "the message has no attachment that could hold a report."
            : $"no part held a readable report ({string.Join("; ", attempts)})";

        return false;
    }

    /// <summary>Every part of the message, depth first.</summary>
    private static IEnumerable<ImapBodyPart> Walk(ImapBodyPart part)
    {
        yield return part;

        foreach (ImapBodyPart child in part.Children)
        {
            foreach (ImapBodyPart descendant in Walk(child))
            {
                yield return descendant;
            }
        }

        // A message/rfc822 part carries its own tree. A forwarded report is a real case: an
        // operator forwarding one to the postmaster address is how several of these arrive.
        if (part.Message is not null)
        {
            foreach (ImapBodyPart inner in Walk(part.Message))
            {
                yield return inner;
            }
        }
    }

    /// <summary>
    /// Undoes the part's content-transfer-encoding.
    /// </summary>
    /// <remarks>
    /// Base64 and the identity encodings only. RFC 8460 §3's attachment is binary, and the
    /// encodings that carry binary through SMTP are base64 and (on an 8BITMIME path) none at
    /// all. <c>quoted-printable</c> is not attempted: it is for mostly-text content, no sender
    /// uses it for a gzip attachment, and a wrong decode would produce plausible-looking bytes
    /// that fail later with a confusing error rather than here with a clear one.
    /// </remarks>
    private static bool TryDecode(ImapBodyPart part, out byte[]? decoded, out string? error)
    {
        decoded = null;
        error = null;

        if (part.Content.Length > MaxEncodedBytes)
        {
            error = $"the part is larger than the {MaxEncodedBytes}-byte limit";
            return false;
        }

        string encoding = part.Encoding.Trim();

        if (encoding.Equals("BASE64", StringComparison.OrdinalIgnoreCase))
        {
            // Whitespace is stripped rather than rejected: RFC 2045 §6.8 requires base64 to be
            // line-wrapped, so every real attachment carries CRLFs that Convert would refuse.
            Span<char> chars = part.Content.Length <= 1024
                ? stackalloc char[part.Content.Length]
                : new char[part.Content.Length];

            int written = 0;

            foreach (byte b in part.Content.Span)
            {
                if (!char.IsWhiteSpace((char)b))
                {
                    chars[written++] = (char)b;
                }
            }

            try
            {
                decoded = Convert.FromBase64String(new string(chars[..written]));
                return true;
            }
            catch (FormatException ex)
            {
                error = $"the base64 content is malformed ({ex.Message})";
                return false;
            }
        }

        if (encoding.Equals("7BIT", StringComparison.OrdinalIgnoreCase) ||
            encoding.Equals("8BIT", StringComparison.OrdinalIgnoreCase) ||
            encoding.Equals("BINARY", StringComparison.OrdinalIgnoreCase))
        {
            decoded = part.Content.ToArray();
            return true;
        }

        error = $"the transfer encoding {encoding} is not one this reads";
        return false;
    }

    /// <summary>
    /// Decompresses, refusing rather than truncating at the ceiling.
    /// </summary>
    /// <remarks>
    /// The read is bounded by asking for one byte more than the limit allows and failing if it
    /// arrives. Stopping silently at the limit would hand the parser a truncated document,
    /// which either fails to parse with a misleading error or — worse — parses into a smaller
    /// set of failures than the sender actually counted.
    /// </remarks>
    private static bool TryDecompress(byte[] input, out byte[]? output, out string? error)
    {
        output = null;
        error = null;

        try
        {
            using MemoryStream source = new(input);
            using GZipStream gzip = new(source, CompressionMode.Decompress);
            using MemoryStream destination = new();

            byte[] buffer = new byte[81_920];
            long total = 0;
            int read;

            while ((read = gzip.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += read;

                if (total > MaxDecompressedBytes)
                {
                    error = $"it decompresses to more than the {MaxDecompressedBytes}-byte limit";
                    return false;
                }

                destination.Write(buffer, 0, read);
            }

            output = destination.ToArray();
            return true;
        }
        catch (InvalidDataException)
        {
            error = "it is not gzip";
            return false;
        }
    }
}
