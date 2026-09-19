using System.Text;

namespace MailServer.Domain.Imap;

/// <summary>One header field, unfolded, split at its colon.</summary>
/// <param name="Name">The field name, without the colon and without surrounding whitespace.</param>
/// <param name="Value">
/// The field body with its folding removed and its outer spaces and tabs trimmed. Empty when the
/// field is present but carries nothing, which RFC 3501 §7.4.2 distinguishes from absent.
/// </param>
public readonly record struct ImapHeaderField(string Name, string Value);

/// <summary>
/// Reads a message's header block into fields.
/// </summary>
/// <remarks>
/// <para>
/// <b>Decoded as Latin-1, which is a round trip rather than a guess about the charset.</b> Every
/// octet from 0x00 to 0xFF maps to the character of the same value and back again, so a header
/// carrying raw 8-bit bytes — which RFC 2822 §2.2 forbids and which arrives anyway — survives
/// the parse and reaches the client unaltered. A UTF-8 decode would replace each unpaired byte
/// with U+FFFD and lose it for good, and a charset guess would be wrong for some of the mail it
/// was applied to. The alternative, working in bytes throughout, buys nothing here: every
/// character this file makes a decision about — colon, quote, backslash, angle bracket, comma,
/// semicolon, space, tab — is the same octet in every encoding a header can be in.
/// </para>
/// <para>
/// <b>Unfolding keeps the whitespace and removes only the line break.</b> RFC 2822 §2.2.3:
/// "Unfolding is accomplished by simply removing any CRLF that is immediately followed by WSP".
/// Replacing the break with a single space instead would alter a subject that was folded inside
/// a run of spaces, and the envelope is text the client displays to a person.
/// </para>
/// </remarks>
public static class ImapHeaderFields
{
    /// <summary>Reads every field of a header block, in the order it appears.</summary>
    /// <remarks>
    /// A line with no colon, or one whose colon is first, is dropped: RFC 2822 §2.2 makes the
    /// field name "1*ftext" followed by the colon, so neither shape is a field. Dropping is the
    /// right answer rather than failing, because the rest of the header is still worth reading
    /// and a message this server cannot parse is one it would otherwise refuse to show at all.
    /// </remarks>
    public static IReadOnlyList<ImapHeaderField> Read(ReadOnlyMemory<byte> header)
    {
        string text = Encoding.Latin1.GetString(header.Span);

        List<ImapHeaderField> fields = [];
        StringBuilder current = new();
        int index = 0;

        while (index < text.Length)
        {
            int newline = text.IndexOf('\n', index);
            string line = newline < 0 ? text[index..] : text[index..newline];

            index = newline < 0 ? text.Length : newline + 1;

            if (line.EndsWith('\r'))
            {
                line = line[..^1];
            }

            // The blank line ends the header block. A caller that passed the whole message
            // rather than just its header relies on this.
            if (line.Length == 0)
            {
                break;
            }

            if (line[0] is ' ' or '\t')
            {
                // A continuation before any field has nothing to continue.
                if (current.Length > 0)
                {
                    current.Append(line);
                }

                continue;
            }

            Flush(current, fields);
            current.Append(line);
        }

        Flush(current, fields);

        return fields;
    }

    /// <summary>
    /// The first field with a name, or null when there is none.
    /// </summary>
    /// <remarks>
    /// <b>The first, not the last and not a join.</b> RFC 2822 §3.6 allows each of the fields an
    /// envelope is built from at most once, so a message with two <c>Subject</c> lines is
    /// malformed and the server has to pick one. The first is what a reader sees at the top of
    /// the file and what the transport prepended last; picking the second would let a message
    /// carry a subject that a header-display and an envelope disagree about.
    /// </remarks>
    public static string? First(IReadOnlyList<ImapHeaderField> fields, string name)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(name);

        foreach (ImapHeaderField field in fields)
        {
            if (field.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return field.Value;
            }
        }

        return null;
    }

    private static void Flush(StringBuilder current, List<ImapHeaderField> fields)
    {
        if (current.Length == 0)
        {
            return;
        }

        string line = current.ToString();

        current.Clear();

        int colon = line.IndexOf(':', StringComparison.Ordinal);

        if (colon <= 0)
        {
            return;
        }

        // Trimmed on the two ASCII blanks rather than with Trim(), which also strips U+00A0 and
        // the other Unicode spaces - and after a Latin-1 decode U+00A0 is octet 0xA0, a byte of
        // somebody's subject line rather than whitespace.
        fields.Add(new ImapHeaderField(
            line[..colon].Trim(' ', '\t'),
            line[(colon + 1)..].Trim(' ', '\t')));
    }
}
