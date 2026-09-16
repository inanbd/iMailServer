namespace MailServer.Domain.Mail;

/// <summary>One logical header field, exactly as it appeared on the wire.</summary>
/// <param name="Name">The field name, trimmed of surrounding whitespace, case preserved.</param>
/// <param name="RawBytes">
/// The complete field — name, colon, value, every folded continuation line — through and
/// including its terminating CRLF. Byte-identical to what was received; nothing is unfolded,
/// re-cased or re-spaced here. Canonicalization (RFC 6376 §3.4) is a separate, later step that
/// consumes these bytes; a parser that "helpfully" normalized them first would make the
/// <c>simple</c> canonicalization it feeds impossible to implement correctly.
/// </param>
public readonly record struct RawHeaderField(string Name, ReadOnlyMemory<byte> RawBytes);

/// <summary>
/// Splits a stored message's header block from its body, without touching the body at all.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not a MIME parser. It does exactly two things: locate each header field's raw
/// bytes (handling RFC 5322 §2.2.3 folding — a continuation line starts with SP or TAB), and
/// locate the blank line that ends the header block. It has no concept of a message body's
/// structure, multipart boundaries, <c>Content-Transfer-Encoding</c>, or character sets — DKIM,
/// SPF's <c>From:</c>-adjacent needs, DMARC and ARC's header recognition all operate purely on
/// header field lines and never need any of that, and hand-rolling a *header-only* parser is a
/// far smaller, far lower-risk piece of code than a general MIME parser. See
/// <c>docs/Architecture.md</c>'s addendum on why this codebase does not depend on MimeKit for
/// Milestone 9.
/// </para>
/// <para>
/// Assumes the buffer uses CRLF line endings throughout, which every message this server stores
/// already does — <c>SmtpDataDecoder</c> normalizes bare CR/LF to CRLF on receipt, and every
/// message this server generates itself (DSNs, the <c>DKIM-Signature</c> line this server
/// prepends) is written with CRLF from the start. A parser that had to tolerate bare LF as well
/// would be solving a problem that does not reach this far into the pipeline.
/// </para>
/// <para>Pure: no I/O. The caller is responsible for bounding how much of the message it reads
/// before calling this (headers are typically a few kilobytes; nothing here assumes that, but
/// nothing here reads a stream either — see <see cref="TryParse"/>'s "incomplete" outcome).</para>
/// </remarks>
public sealed class RawMessageHeaders
{
    private const byte Cr = (byte)'\r';
    private const byte Lf = (byte)'\n';
    private const byte Colon = (byte)':';

    private readonly List<RawHeaderField> _fields;

    private RawMessageHeaders(List<RawHeaderField> fields, int headerBlockLength)
    {
        _fields = fields;
        HeaderBlockLength = headerBlockLength;
    }

    /// <summary>Every header field, in the order it appeared on the wire.</summary>
    public IReadOnlyList<RawHeaderField> Fields => _fields;

    /// <summary>
    /// Octets from the start of the buffer through and including the blank line that ends the
    /// header block. The body begins at this offset.
    /// </summary>
    public int HeaderBlockLength { get; }

    /// <summary>
    /// Parses every header field in <paramref name="buffer"/>, up to the header/body blank line.
    /// </summary>
    /// <returns>
    /// False when the buffer does not yet contain a complete header block (no blank line found,
    /// or a folded field runs past the end of the buffer) — the caller supplied too little of
    /// the message and must read further before trying again — or when a line before the first
    /// colon cannot be a header field at all. Never throws on malformed input: a hostile or
    /// merely broken message is data, not an exceptional condition, on this path.
    /// </returns>
    public static bool TryParse(
        ReadOnlyMemory<byte> buffer,
        out RawMessageHeaders? result,
        out string? error)
    {
        ReadOnlySpan<byte> span = buffer.Span;
        List<RawHeaderField> fields = [];
        int pos = 0;

        while (true)
        {
            if (IsBlankLine(span, pos))
            {
                result = new RawMessageHeaders(fields, pos + 2);
                error = null;
                return true;
            }

            if (pos >= span.Length)
            {
                result = null;
                error = "The supplied buffer ends before the header block's terminating blank line.";
                return false;
            }

            int fieldStart = pos;

            while (true)
            {
                int crlfOffset = span[pos..].IndexOf("\r\n"u8);

                if (crlfOffset < 0)
                {
                    result = null;
                    error = $"The header field starting at offset {fieldStart} is not terminated " +
                        "within the supplied buffer.";
                    return false;
                }

                int afterCrlf = pos + crlfOffset + 2;

                if (afterCrlf < span.Length && IsFoldingWhitespace(span[afterCrlf]))
                {
                    // A continuation line. Keep scanning for the field's real end.
                    pos = afterCrlf;
                    continue;
                }

                ReadOnlySpan<byte> fieldSpan = span[fieldStart..afterCrlf];
                int colon = fieldSpan.IndexOf(Colon);

                if (colon <= 0)
                {
                    result = null;
                    error = $"The header field starting at offset {fieldStart} has no name " +
                        "(no ':' separator, or an empty name before it).";
                    return false;
                }

                string name = System.Text.Encoding.ASCII.GetString(fieldSpan[..colon]).Trim();
                fields.Add(new RawHeaderField(name, buffer[fieldStart..afterCrlf]));

                pos = afterCrlf;
                break;
            }
        }
    }

    /// <summary>Every field with the given name, case-insensitively, in wire order.</summary>
    public IEnumerable<RawHeaderField> GetAll(string name) =>
        _fields.Where(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase));

    private static bool IsBlankLine(ReadOnlySpan<byte> span, int pos) =>
        pos + 1 < span.Length && span[pos] == Cr && span[pos + 1] == Lf;

    private static bool IsFoldingWhitespace(byte b) => b is (byte)' ' or (byte)'\t';
}
