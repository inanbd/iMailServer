using System.Text;

namespace MailServer.Domain.Imap;

/// <summary>
/// Cuts the octets a <c>BODY[…]</c> names out of a stored message.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything here works in bytes, never in a string.</b> RFC 3501 §6.3.11 permits "8-bit
/// characters […] in the message" and a stored message may be in any charset or none. Decoding
/// it to text to find a blank line would corrupt every message that is not UTF-8, and would do
/// so invisibly: the header scan only needs CR, LF and colon, all of which are the same byte in
/// every encoding this could meet.
/// </para>
/// <para>
/// <b>The result is a slice of the input, not a copy.</b> A mailbox fetch of a large message
/// should not double its memory to answer, and every shape below except a header subset is a
/// contiguous run of the original.
/// </para>
/// </remarks>
public static class ImapBodySection
{
    /// <summary>
    /// The octets for a section, or null when this server cannot produce them yet.
    /// </summary>
    /// <remarks>
    /// Null for a numbered part or a <c>MIME</c> specifier — see
    /// <see cref="ImapSection.NeedsMimeTree"/>. The caller turns that into a tagged <c>NO</c>
    /// naming the item, which RFC 3501 §6.4.5 separates from a syntax error: "NO - fetch error:
    /// can't fetch that data".
    /// </remarks>
    public static ReadOnlyMemory<byte>? Extract(ReadOnlyMemory<byte> message, ImapSection section)
    {
        ArgumentNullException.ThrowIfNull(section);

        if (section.NeedsMimeTree)
        {
            return null;
        }

        ReadOnlyMemory<byte> whole = section.Kind switch
        {
            ImapSectionKind.Full => message,
            ImapSectionKind.Header => HeaderBlock(message),
            ImapSectionKind.Text => BodyBlock(message),
            ImapSectionKind.HeaderFields => Subset(message, section.Fields, keep: true),
            ImapSectionKind.HeaderFieldsNot => Subset(message, section.Fields, keep: false),
            _ => message,
        };

        return Partial(whole, section);
    }

    /// <summary>
    /// Applies the client's <c>&lt;origin.length&gt;</c>, if it gave one.
    /// </summary>
    /// <remarks>
    /// §6.4.5: "If the origin octet is specified, this string is a substring of the entire body
    /// contents, starting at that origin octet. This means that BODY[]&lt;0&gt; MAY be truncated,
    /// but BODY[] is NEVER truncated." An origin past the end yields nothing rather than an
    /// error — the client asked for the part of a shorter string that is not there, and the
    /// honest answer is an empty one.
    /// </remarks>
    private static ReadOnlyMemory<byte> Partial(ReadOnlyMemory<byte> whole, ImapSection section)
    {
        if (section.Origin is not { } origin)
        {
            return whole;
        }

        if (origin >= whole.Length)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        int start = (int)origin;
        int available = whole.Length - start;
        int take = section.Length is { } length ? (int)Math.Min(length, available) : available;

        return whole.Slice(start, take);
    }

    /// <summary>
    /// Where the header ends: the offset just past the blank line that terminates it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both line endings are accepted. A stored message arrived over SMTP and is CRLF, but a
    /// message written by another tool may be bare LF, and a header scan that recognised only
    /// CRLF would treat such a message as all header and no body — returning the whole thing for
    /// <c>BODY[HEADER]</c> and nothing for <c>BODY[TEXT]</c>.
    /// </para>
    /// <para>
    /// §6.4.5: "the [RFC-2822] delimiting blank line between the header and the body is not
    /// affected by header line subsetting; the blank line is always included as part of header
    /// data, except in the case of a message which has no body and no blank line." So the
    /// boundary returned here is past the blank line, and a message with no blank line has a
    /// header that runs to the end and an empty body.
    /// </para>
    /// </remarks>
    private static int HeaderLength(ReadOnlySpan<byte> message)
    {
        for (int i = 0; i < message.Length; i++)
        {
            if (message[i] != (byte)'\n')
            {
                continue;
            }

            // The blank line is either "\n\n" or "\r\n\r\n"; in both cases the byte after this LF
            // begins a line that is itself empty.
            int next = i + 1;

            if (next >= message.Length)
            {
                return message.Length;
            }

            if (message[next] == (byte)'\n')
            {
                return next + 1;
            }

            if (message[next] == (byte)'\r' &&
                next + 1 < message.Length &&
                message[next + 1] == (byte)'\n')
            {
                return next + 2;
            }
        }

        return message.Length;
    }

    private static ReadOnlyMemory<byte> HeaderBlock(ReadOnlyMemory<byte> message) =>
        message[..HeaderLength(message.Span)];

    private static ReadOnlyMemory<byte> BodyBlock(ReadOnlyMemory<byte> message) =>
        message[HeaderLength(message.Span)..];

    /// <summary>
    /// The header with only the named fields kept, or only them removed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §6.4.5: "The subset returned by HEADER.FIELDS contains only those header fields with a
    /// field-name that matches one of the names in the list; similarly, the subset returned by
    /// HEADER.FIELDS.NOT contains only the header fields with a non-matching field-name. The
    /// field-matching is case-insensitive but otherwise exact."
    /// </para>
    /// <para>
    /// <b>Continuation lines travel with their field.</b> RFC 2822 folds a long header onto
    /// following lines beginning with whitespace, and a subset that kept the first line of a
    /// folded <c>Subject</c> and dropped the rest would hand the client a truncated subject with
    /// no indication anything was missing.
    /// </para>
    /// <para>
    /// The blank line is always appended, per the sentence quoted in
    /// <see cref="HeaderLength"/> — a client parsing the result expects a header block, and a
    /// header block ends with one.
    /// </para>
    /// </remarks>
    private static ReadOnlyMemory<byte> Subset(
        ReadOnlyMemory<byte> message,
        IReadOnlyList<string> fields,
        bool keep)
    {
        ReadOnlySpan<byte> header = message.Span[..HeaderLength(message.Span)];

        HashSet<string> wanted = new(fields, StringComparer.OrdinalIgnoreCase);

        List<byte> kept = [];

        int position = 0;
        bool including = false;

        while (position < header.Length)
        {
            int lineEnd = LineEnd(header, position);
            ReadOnlySpan<byte> line = header[position..lineEnd];

            if (IsBlank(line))
            {
                break;
            }

            if (line.Length > 0 && line[0] is (byte)' ' or (byte)'\t')
            {
                // A folded continuation belongs to whatever decision the last field got.
                if (including)
                {
                    kept.AddRange(line);
                }
            }
            else
            {
                string name = FieldName(line);
                including = wanted.Contains(name) == keep;

                if (including)
                {
                    kept.AddRange(line);
                }
            }

            position = lineEnd;
        }

        kept.AddRange("\r\n"u8);

        return kept.ToArray();
    }

    /// <summary>The offset just past this line's terminator.</summary>
    private static int LineEnd(ReadOnlySpan<byte> header, int start)
    {
        for (int i = start; i < header.Length; i++)
        {
            if (header[i] == (byte)'\n')
            {
                return i + 1;
            }
        }

        return header.Length;
    }

    private static bool IsBlank(ReadOnlySpan<byte> line)
    {
        foreach (byte b in line)
        {
            if (b is not ((byte)'\r' or (byte)'\n'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The field name of a header line, without its colon.</summary>
    /// <remarks>
    /// A line with no colon is malformed and yields an empty name, which matches nothing — so a
    /// damaged header drops out of a <c>HEADER.FIELDS</c> subset rather than corrupting it.
    /// </remarks>
    private static string FieldName(ReadOnlySpan<byte> line)
    {
        int colon = line.IndexOf((byte)':');

        if (colon <= 0)
        {
            return string.Empty;
        }

        return Encoding.ASCII.GetString(line[..colon]).Trim();
    }
}
