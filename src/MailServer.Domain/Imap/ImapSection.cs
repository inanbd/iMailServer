using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace MailServer.Domain.Imap;

/// <summary>
/// Which part of a message a <c>BODY[…]</c> names.
/// </summary>
/// <remarks>
/// RFC 3501 §6.4.5: "The section specification is a set of zero or more part specifiers delimited
/// by periods. A part specifier is either a part number or one of the following: HEADER,
/// HEADER.FIELDS, HEADER.FIELDS.NOT, MIME, and TEXT. An empty section specification refers to the
/// entire message, including the header."
/// </remarks>
public enum ImapSectionKind
{
    /// <summary><c>BODY[]</c> — the whole message, header and all.</summary>
    Full = 0,

    /// <summary><c>BODY[HEADER]</c> — the RFC 2822 header, including the blank line.</summary>
    Header = 1,

    /// <summary><c>BODY[HEADER.FIELDS (…)]</c> — only the named fields.</summary>
    HeaderFields = 2,

    /// <summary><c>BODY[HEADER.FIELDS.NOT (…)]</c> — everything except the named fields.</summary>
    HeaderFieldsNot = 3,

    /// <summary><c>BODY[TEXT]</c> — the body, with the header omitted.</summary>
    Text = 4,

    /// <summary><c>BODY[1.MIME]</c> — a part's own MIME header. Needs a numeric prefix.</summary>
    Mime = 5,

    /// <summary><c>BODY[1]</c>, <c>BODY[1.2]</c> — a numbered MIME part.</summary>
    Part = 6,
}

/// <summary>
/// A parsed <c>BODY[…]</c> or <c>BODY.PEEK[…]</c> data item.
/// </summary>
/// <param name="Kind">Which part specifier it is.</param>
/// <param name="Part">
/// The numeric prefix, outermost first. Empty for a specifier with none. RFC 3501 §6.4.5:
/// "Multipart messages are assigned consecutive part numbers, as they occur in the message."
/// Held as 64-bit values because §9's <c>nz-number</c> is annotated "Non-zero unsigned 32-bit
/// integer; (0 &lt; n &lt; 4,294,967,296)" — a range no signed 32-bit type covers, and a part
/// number above <c>int.MaxValue</c> is a grammatical argument naming a part that does not exist
/// rather than a syntax error.
/// </param>
/// <param name="Fields">The field names of a <c>HEADER.FIELDS</c> list, in the order written.</param>
/// <param name="Peek">
/// Whether the client wrote <c>BODY.PEEK</c>. §6.4.5 makes the difference one of side effect:
/// <c>BODY[…]</c> implicitly sets <c>\Seen</c>, and <c>BODY.PEEK[…]</c> is "An alternate form of
/// BODY[&lt;section&gt;] that does not implicitly set the \Seen flag."
/// </param>
/// <param name="Origin">
/// The first octet to return, when the client asked for a substring. §6.4.5's partial.
/// </param>
/// <param name="Length">How many octets at most, when a partial was asked for.</param>
public sealed record ImapSection(
    ImapSectionKind Kind,
    IReadOnlyList<long> Part,
    IReadOnlyList<string> Fields,
    bool Peek,
    long? Origin,
    long? Length)
{
    /// <summary>The most field names a <c>HEADER.FIELDS</c> list may carry.</summary>
    /// <remarks>
    /// A real client asks for a handful. The cap bounds the work one line can force, as the
    /// other list caps in this namespace do.
    /// </remarks>
    public const int MaxFieldCount = 64;

    /// <summary>The deepest numeric part specifier accepted.</summary>
    /// <remarks>
    /// Each level is a nested multipart, and a message nested sixteen deep is a decompression
    /// bomb rather than mail. Bounding the specifier bounds the tree walk it would ask for.
    /// </remarks>
    public const int MaxPartDepth = 16;

    /// <summary>Whether this names something outside the top-level message.</summary>
    /// <remarks>
    /// True for a numbered part or a <c>MIME</c> specifier — the shapes that need the message's
    /// MIME tree walked rather than its header and body separated.
    /// </remarks>
    public bool NeedsMimeTree => Part.Count > 0 || Kind is ImapSectionKind.Mime;

    /// <summary>
    /// Renders the section the way a response must echo it.
    /// </summary>
    /// <remarks>
    /// <b><c>.PEEK</c> is never echoed.</b> RFC 3501 §9's response grammar has
    /// <c>msg-att-static = … "BODY" section ["&lt;" number "&gt;"] SP nstring</c> and no
    /// <c>BODY.PEEK</c> anywhere in it: the peek is a property of the request, not of the answer.
    /// A server that echoed it would be sending a data item name the grammar does not contain.
    /// </remarks>
    public string Format()
    {
        StringBuilder builder = new("BODY[");

        // §9: section-part = nz-number *("." nz-number), and section-spec joins it to a trailing
        // text specifier with section-part "." section-text. So the dot goes *between* pieces
        // and never after the last one: BODY[2.] is not a specifier the grammar has, and a
        // client comparing the echo against what it asked for would find they differ.
        for (int i = 0; i < Part.Count; i++)
        {
            if (i > 0)
            {
                builder.Append('.');
            }

            builder.Append(Part[i].ToString(CultureInfo.InvariantCulture));
        }

        string text = Kind switch
        {
            ImapSectionKind.Header => "HEADER",
            ImapSectionKind.HeaderFields => "HEADER.FIELDS",
            ImapSectionKind.HeaderFieldsNot => "HEADER.FIELDS.NOT",
            ImapSectionKind.Text => "TEXT",
            ImapSectionKind.Mime => "MIME",
            _ => string.Empty,
        };

        if (text.Length > 0)
        {
            if (Part.Count > 0)
            {
                builder.Append('.');
            }

            builder.Append(text);
        }

        if (Kind is ImapSectionKind.HeaderFields or ImapSectionKind.HeaderFieldsNot)
        {
            builder.Append(" (").Append(string.Join(' ', Fields)).Append(')');
        }

        builder.Append(']');

        // Only the origin, never the length. §7.4.2: "BODY[<section>]<<origin octet>>" - the
        // response form carries one number, and §9 types it "["<" number ">"]". Echoing the
        // length would be a token the grammar has no place for.
        if (Origin is not null)
        {
            builder.Append('<').Append(Origin.Value.ToString(CultureInfo.InvariantCulture)).Append('>');
        }

        return builder.ToString();
    }

    /// <summary>
    /// Parses a <c>BODY[…]</c> or <c>BODY.PEEK[…]</c> data item.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The whole item, brackets and partial included, because none of those pieces means anything
    /// apart from the others: <c>BODY</c> without brackets is <c>BODYSTRUCTURE</c>'s
    /// non-extensible sibling and a different data item entirely.
    /// </para>
    /// <para>
    /// §9: <c>"BODY" section ["&lt;" number "." nz-number "&gt;"]</c> — the partial's length is an
    /// <c>nz-number</c>, so <c>&lt;0.0&gt;</c> is a syntax error rather than a request for
    /// nothing, while an origin of 0 is perfectly ordinary.
    /// </para>
    /// </remarks>
    public static bool TryParse(string item, [NotNullWhen(true)] out ImapSection? section)
    {
        ArgumentNullException.ThrowIfNull(item);

        section = null;

        int open = item.IndexOf('[', StringComparison.Ordinal);

        if (open < 0)
        {
            return false;
        }

        string head = item[..open];
        bool peek;

        if (head.Equals("BODY", StringComparison.OrdinalIgnoreCase))
        {
            peek = false;
        }
        else if (head.Equals("BODY.PEEK", StringComparison.OrdinalIgnoreCase))
        {
            peek = true;
        }
        else
        {
            return false;
        }

        int close = item.LastIndexOf(']');

        if (close < open)
        {
            return false;
        }

        string inner = item[(open + 1)..close];
        string tail = item[(close + 1)..];

        long? origin = null;
        long? length = null;

        if (tail.Length > 0 && !TryParsePartial(tail, out origin, out length))
        {
            return false;
        }

        if (!TryParseSpecifier(inner, out ImapSectionKind kind, out long[] part, out string[] fields))
        {
            return false;
        }

        section = new ImapSection(kind, part, fields, peek, origin, length);
        return true;
    }

    private static bool TryParsePartial(string tail, out long? origin, out long? length)
    {
        origin = null;
        length = null;

        if (tail.Length < 2 || tail[0] != '<' || tail[^1] != '>')
        {
            return false;
        }

        string body = tail[1..^1];
        int dot = body.IndexOf('.', StringComparison.Ordinal);

        if (dot < 0)
        {
            return false;
        }

        if (!TryParseNumber(body[..dot], out long start) ||
            !TryParseNumber(body[(dot + 1)..], out long count))
        {
            return false;
        }

        // §9 types the length an nz-number: a zero-length partial is not a request for nothing,
        // it is outside the grammar.
        if (count < 1)
        {
            return false;
        }

        origin = start;
        length = count;
        return true;
    }

    private static bool TryParseNumber(string text, out long value)
    {
        value = 0;

        if (text.Length is 0 or > 10)
        {
            return false;
        }

        foreach (char c in text)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryParseSpecifier(
        string inner,
        out ImapSectionKind kind,
        out long[] part,
        out string[] fields)
    {
        kind = ImapSectionKind.Full;
        part = [];
        fields = [];

        if (inner.Length == 0)
        {
            // "An empty section specification refers to the entire message, including the header."
            return true;
        }

        // The field list, if any, is the parenthesised tail and is split off before the periods
        // are looked at - a field name may itself contain one.
        string specifier = inner;
        string? list = null;

        int bracket = inner.IndexOf('(', StringComparison.Ordinal);

        if (bracket >= 0)
        {
            if (!inner.EndsWith(')'))
            {
                return false;
            }

            list = inner[(bracket + 1)..^1];
            specifier = inner[..bracket].TrimEnd();
        }

        List<long> numbers = [];
        string[] pieces = specifier.Split('.');
        int index = 0;

        while (index < pieces.Length && TryReadPartNumber(pieces[index], out long number))
        {
            numbers.Add(number);
            index++;
        }

        // §9: section-part = nz-number *("." nz-number) - a period always has a number after it,
        // so an empty piece means a trailing or doubled one and is not a specifier the grammar
        // has. Accepting it would silently rename the item: a client that asked for BODY[3.]
        // would be answered BODY[3], and two spellings of one part would collapse into one
        // answer while the client waited for a second that never came.
        foreach (string piece in pieces)
        {
            if (piece.Length == 0)
            {
                return false;
            }
        }

        if (numbers.Count > MaxPartDepth)
        {
            return false;
        }

        part = [.. numbers];

        string rest = string.Join('.', pieces[index..]);

        if (rest.Length == 0)
        {
            // Numbers and nothing else: a numbered part.
            kind = ImapSectionKind.Part;
            return part.Length > 0 && list is null;
        }

        kind = rest.ToUpperInvariant() switch
        {
            "HEADER" => ImapSectionKind.Header,
            "HEADER.FIELDS" => ImapSectionKind.HeaderFields,
            "HEADER.FIELDS.NOT" => ImapSectionKind.HeaderFieldsNot,
            "TEXT" => ImapSectionKind.Text,
            "MIME" => ImapSectionKind.Mime,
            _ => (ImapSectionKind)(-1),
        };

        if (kind == (ImapSectionKind)(-1))
        {
            return false;
        }

        // §6.4.5: "The MIME part specifier MUST be prefixed by one or more numeric part
        // specifiers." Without one it names nothing.
        if (kind == ImapSectionKind.Mime && part.Length == 0)
        {
            return false;
        }

        bool wantsList = kind is ImapSectionKind.HeaderFields or ImapSectionKind.HeaderFieldsNot;

        if (wantsList != (list is not null))
        {
            return false;
        }

        if (list is null)
        {
            return true;
        }

        string[] names = list.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (names.Length is 0 or > MaxFieldCount)
        {
            return false;
        }

        foreach (string name in names)
        {
            if (!IsFieldName(name))
            {
                return false;
            }
        }

        fields = names;
        return true;
    }

    /// <summary>Whether a name is an RFC 2822 <c>field-name</c> this server will echo.</summary>
    /// <remarks>
    /// Checked because the name is echoed back in the response's data item, which is the one
    /// place client text reaches a line this server composes. RFC 2822 §2.2 makes a field name
    /// "printable US-ASCII characters […] except colon"; anything else could not have come from a
    /// real header and must not reach the wire.
    /// </remarks>
    /// <summary>
    /// Reads one <c>nz-number</c>.
    /// </summary>
    /// <remarks>
    /// §9: <c>nz-number = digit-nz *DIGIT</c> with <c>digit-nz = %x31-39</c>, annotated
    /// "Non-zero unsigned 32-bit integer; (0 &lt; n &lt; 4,294,967,296)". Three things follow and
    /// all three matter: there is no part zero; <b>a leading zero is not a part number</b>,
    /// because <c>digit-nz</c> excludes it — so <c>BODY[01]</c> is a syntax error rather than a
    /// second way to spell <c>BODY[1]</c>, which is what keeps the response's item name equal to
    /// the one the client wrote; and the range runs past <c>int.MaxValue</c>, so a value up to
    /// 4,294,967,295 parses and is answered NIL by the tree walk rather than earning a BAD for an
    /// argument the grammar allows.
    /// </remarks>
    private static bool TryReadPartNumber(string piece, out long number)
    {
        number = 0;

        // Ten digits is the most 4,294,967,295 needs. Refusing anything longer up front is what
        // keeps the accumulation below from overflowing.
        if (piece.Length is 0 or > 10 || piece[0] is < '1' or > '9')
        {
            return false;
        }

        foreach (char c in piece)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }

            number = (number * 10) + (c - '0');
        }

        return number <= uint.MaxValue;
    }

    private static bool IsFieldName(string name)
    {
        if (name.Length is 0 or > 128)
        {
            return false;
        }

        foreach (char c in name)
        {
            if (c is < (char)0x21 or > (char)0x7E || c == ':')
            {
                return false;
            }

            if (c is '(' or ')' or '[' or ']' or '"' or '\\')
            {
                return false;
            }
        }

        return true;
    }
}
