using System.Text;

namespace MailServer.Domain.Imap;

/// <summary>
/// One node of a message's MIME structure.
/// </summary>
/// <remarks>
/// <para>
/// The shape RFC 3501 §7.4.2 describes, with the octets each node covers kept alongside it so
/// that <c>BODYSTRUCTURE</c> and <c>BODY[1.2]</c> are answered from one parse rather than two.
/// </para>
/// <para>
/// <b>The octet ranges are slices of the stored message, not copies.</b> A fetch of a large
/// multipart should not duplicate it in memory to describe it, and every range here is a
/// contiguous run of the original.
/// </para>
/// </remarks>
public sealed record ImapBodyPart
{
    /// <summary>The media type, upper-cased. <c>TEXT</c>, <c>MULTIPART</c>, <c>MESSAGE</c>, …</summary>
    public required string Type { get; init; }

    /// <summary>The media subtype, upper-cased.</summary>
    public required string Subtype { get; init; }

    /// <summary>
    /// The <c>Content-Type</c> parameters, flattened to name, value, name, value.
    /// </summary>
    /// <remarks>
    /// §9's <c>body-fld-param = "(" string SP string *(SP string SP string) ")" / nil</c> is a
    /// flat list of pairs rather than nested ones, so this holds what goes on the wire. Names are
    /// upper-cased — RFC 2045 §5.1 makes them case-insensitive — and <b>values are kept exactly
    /// as written</b>, because a <c>NAME</c> or <c>FILENAME</c> parameter is a user's filename.
    /// </remarks>
    public IReadOnlyList<string> Parameters { get; init; } = [];

    /// <summary><c>Content-ID</c>, or null.</summary>
    public string? Id { get; init; }

    /// <summary><c>Content-Description</c>, or null.</summary>
    public string? Description { get; init; }

    /// <summary><c>Content-Transfer-Encoding</c>, upper-cased. <c>7BIT</c> when absent.</summary>
    public string Encoding { get; init; } = ImapMimeTree.DefaultEncoding;

    /// <summary>This part's own MIME header, for <c>BODY[n.MIME]</c>.</summary>
    public ReadOnlyMemory<byte> MimeHeader { get; init; }

    /// <summary>This part's content, for <c>BODY[n]</c>.</summary>
    public ReadOnlyMemory<byte> Content { get; init; }

    /// <summary>
    /// The content's size in text lines, for the types whose structure reports one.
    /// </summary>
    /// <remarks>
    /// §7.4.2 adds it to <c>TEXT</c> and to <c>MESSAGE/RFC822</c>, and notes for both that it is
    /// "the size in its content transfer encoding and not the resulting size after any decoding".
    /// </remarks>
    public long LineCount { get; init; }

    /// <summary>The nested parts of a multipart, in the order they occur.</summary>
    public IReadOnlyList<ImapBodyPart> Children { get; init; } = [];

    /// <summary>Whether this part's children are its structure.</summary>
    public bool IsMultipart { get; init; }

    /// <summary>The envelope of the message a <c>MESSAGE/RFC822</c> part carries.</summary>
    public ImapEnvelope? Envelope { get; init; }

    /// <summary>The structure of the message a <c>MESSAGE/RFC822</c> part carries.</summary>
    public ImapBodyPart? Message { get; init; }

    /// <summary><c>Content-MD5</c>, or null. Reported, never computed.</summary>
    public string? Md5 { get; init; }

    /// <summary>The <c>Content-Disposition</c> type, or null.</summary>
    public string? DispositionType { get; init; }

    /// <summary>The <c>Content-Disposition</c> parameters, flattened as <see cref="Parameters"/>.</summary>
    public IReadOnlyList<string> DispositionParameters { get; init; } = [];

    /// <summary>The <c>Content-Language</c> tags, in the order written.</summary>
    public IReadOnlyList<string> Languages { get; init; } = [];

    /// <summary><c>Content-Location</c>, or null.</summary>
    public string? Location { get; init; }

    /// <summary>Whether this part carries an encapsulated message.</summary>
    public bool IsMessage => Message is not null;
}

/// <summary>
/// Parses a stored message into the structure RFC 3501 §7.4.2 describes, and finds the octets a
/// section specifier names.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything here works in bytes.</b> A message may be in any charset or none, and the only
/// characters this needs to recognise — CR, LF, colon, semicolon, quote, hyphen — are the same
/// octet in every encoding it could meet. Header values are read through
/// <see cref="ImapHeaderFields"/>, which decodes Latin-1 and so round trips.
/// </para>
/// <para>
/// <b>It never fails.</b> A message is whatever a sending agent wrote, and a mailbox that refused
/// to describe a message because its boundaries are broken would hide the message rather than the
/// defect. Every shape that cannot be taken apart is reported as an opaque part of its declared
/// type, which is both grammatical — §9's <c>media-basic</c> ends in a bare <c>string</c>, so any
/// type name is legal there — and true.
/// </para>
/// </remarks>
public static class ImapMimeTree
{
    /// <summary>
    /// RFC 2045 §6.1: "Content-Transfer-Encoding: 7BIT" is assumed if the field is absent.
    /// </summary>
    public const string DefaultEncoding = "7BIT";

    /// <summary>
    /// The deepest nesting taken apart before a part is reported opaque.
    /// </summary>
    /// <remarks>
    /// Matches <see cref="ImapSection.MaxPartDepth"/>, which bounds what a client can ask for. A
    /// message nested deeper than this is a decompression bomb rather than mail, and stopping
    /// leaves a part that is described truthfully rather than one that is described at all costs.
    /// </remarks>
    public const int MaxDepth = ImapSection.MaxPartDepth;

    /// <summary>Parses a whole stored message.</summary>
    public static ImapBodyPart Parse(ReadOnlyMemory<byte> message) => Build(message, false, 0);

    /// <summary>
    /// Builds one part from the octets that make it up, header and all.
    /// </summary>
    /// <param name="part">The part's header, blank line, and content.</param>
    /// <param name="inDigest">
    /// Whether the enclosing multipart is a <c>digest</c>. RFC 2046 §5.1.5: "In a digest, the
    /// default Content-Type value for a body part is changed from 'text/plain' to
    /// 'message/rfc822'."
    /// </param>
    /// <param name="depth">How far down the tree this is.</param>
    private static ImapBodyPart Build(ReadOnlyMemory<byte> part, bool inDigest, int depth)
    {
        ReadOnlyMemory<byte> header = ImapBodySection.HeaderBlock(part);
        ReadOnlyMemory<byte> content = ImapBodySection.BodyBlock(part);

        IReadOnlyList<ImapHeaderField> fields = ImapHeaderFields.Read(header);

        ImapContentType type = ImapContentType.Read(
            ImapHeaderFields.First(fields, "Content-Type"),
            inDigest);

        ImapBodyPart node = new()
        {
            Type = type.Type,
            Subtype = type.Subtype,
            Parameters = type.Parameters,
            Id = ImapHeaderFields.First(fields, "Content-ID"),
            Description = ImapHeaderFields.First(fields, "Content-Description"),
            Encoding = Upper(ImapHeaderFields.First(fields, "Content-Transfer-Encoding"))
                ?? DefaultEncoding,
            MimeHeader = header,
            Content = content,
            LineCount = CountLines(content.Span),
            Md5 = ImapHeaderFields.First(fields, "Content-MD5"),
            Location = ImapHeaderFields.First(fields, "Content-Location"),
            Languages = SplitLanguages(ImapHeaderFields.First(fields, "Content-Language")),
        };

        if (ImapContentType.ReadDisposition(
                ImapHeaderFields.First(fields, "Content-Disposition")) is { } disposition)
        {
            node = node with
            {
                DispositionType = disposition.Type,
                DispositionParameters = disposition.Parameters,
            };
        }

        if (depth >= MaxDepth)
        {
            return node;
        }

        if (type.Type.Equals("MULTIPART", StringComparison.Ordinal))
        {
            IReadOnlyList<ImapBodyPart> children = Split(
                content,
                ParameterOf(type.Parameters, "BOUNDARY"),
                type.Subtype.Equals("DIGEST", StringComparison.Ordinal),
                depth);

            // A multipart whose parts cannot be found is reported as what it is: an opaque part
            // of type MULTIPART. §9's body-type-mpart is "1*body SP media-subtype" and has no
            // form for a multipart with no parts, so inventing one is not available either.
            return children.Count == 0 ? node : node with { IsMultipart = true, Children = children };
        }

        if (type.Type.Equals("MESSAGE", StringComparison.Ordinal) &&
            type.Subtype.Equals("RFC822", StringComparison.Ordinal))
        {
            return node with
            {
                Envelope = ImapEnvelopes.Read(content),
                Message = Build(content, false, depth + 1),
            };
        }

        return node;
    }

    /// <summary>
    /// Cuts a multipart's content into its parts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 2046 §5.1.1 defines the delimiter as <c>--</c> followed by the boundary parameter at
    /// the start of a line, and the closing delimiter as the same with a trailing <c>--</c>.
    /// Anything before the first delimiter is the preamble and anything after the closing one is
    /// the epilogue; §5.1.1 says both "are to be ignored".
    /// </para>
    /// <para>
    /// <b>The CRLF before a delimiter belongs to the delimiter, not to the part.</b> §5.1.1: "The
    /// boundary delimiter MUST occur at the beginning of a line, i.e., following a CRLF, and the
    /// initial CRLF is considered to be attached to the boundary delimiter line rather than part
    /// of the preceding part." A server that kept it would report every part two octets longer
    /// than it is and hand the client two octets that are not its.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<ImapBodyPart> Split(
        ReadOnlyMemory<byte> content,
        string? boundary,
        bool digest,
        int depth)
    {
        if (string.IsNullOrEmpty(boundary))
        {
            return [];
        }

        byte[] marker = System.Text.Encoding.Latin1.GetBytes(boundary);

        List<ImapBodyPart> parts = [];
        ReadOnlySpan<byte> span = content.Span;

        int index = 0;
        int start = -1;

        while (index < span.Length)
        {
            int feed = span[index..].IndexOf((byte)'\n');
            int next = feed < 0 ? span.Length : index + feed + 1;
            int textEnd = feed < 0 ? span.Length : index + feed;

            if (textEnd > index && span[textEnd - 1] == (byte)'\r')
            {
                textEnd--;
            }

            if (IsDelimiter(span[index..textEnd], marker, out bool closing))
            {
                if (start >= 0)
                {
                    parts.Add(Build(content[start..TrimTerminator(span, start, index)], digest, depth + 1));
                }

                if (closing)
                {
                    return parts;
                }

                start = next;
            }

            index = next;
        }

        // No closing delimiter: the last part runs to the end of the content, which is what a
        // client would see if it cut the message up itself.
        if (start >= 0 && start <= span.Length)
        {
            parts.Add(Build(content[start..span.Length], digest, depth + 1));
        }

        return parts;
    }

    /// <summary>Drops the line ending that introduced a delimiter from the part before it.</summary>
    private static int TrimTerminator(ReadOnlySpan<byte> span, int start, int end)
    {
        int cut = end;

        if (cut > start && span[cut - 1] == (byte)'\n')
        {
            cut--;
        }

        if (cut > start && span[cut - 1] == (byte)'\r')
        {
            cut--;
        }

        return cut;
    }

    /// <summary>
    /// Whether a line is this multipart's delimiter.
    /// </summary>
    /// <remarks>
    /// §5.1.1's <c>delimiter := CRLF dash-boundary</c> and <c>close-delimiter := delimiter "--"</c>,
    /// with "transport padding" — white space — permitted after either. The match on the boundary
    /// itself is exact: a longer boundary that merely begins with this one belongs to a nested
    /// multipart, and treating it as this one's would cut the nested message in half.
    /// </remarks>
    private static bool IsDelimiter(ReadOnlySpan<byte> line, ReadOnlySpan<byte> marker, out bool closing)
    {
        closing = false;

        if (line.Length < marker.Length + 2 ||
            line[0] != (byte)'-' ||
            line[1] != (byte)'-' ||
            !line[2..].StartsWith(marker))
        {
            return false;
        }

        ReadOnlySpan<byte> rest = line[(marker.Length + 2)..];

        if (rest.Length >= 2 && rest[0] == (byte)'-' && rest[1] == (byte)'-')
        {
            closing = true;
            rest = rest[2..];
        }

        foreach (byte b in rest)
        {
            if (b is not ((byte)' ' or (byte)'\t'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// How many text lines a run of octets holds.
    /// </summary>
    /// <remarks>
    /// Counted as line feeds, plus one for a final line that was never terminated — the octets
    /// after the last one are a line a reader would see. Empty content is nought lines rather
    /// than one, which is the difference between an empty part and a part holding a blank line.
    /// </remarks>
    private static long CountLines(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0)
        {
            return 0;
        }

        long lines = 0;

        foreach (byte b in content)
        {
            if (b == (byte)'\n')
            {
                lines++;
            }
        }

        return content[^1] == (byte)'\n' ? lines : lines + 1;
    }

    /// <summary>The value of one parameter, matched without regard to case.</summary>
    private static string? ParameterOf(IReadOnlyList<string> parameters, string name)
    {
        for (int i = 0; i + 1 < parameters.Count; i += 2)
        {
            if (parameters[i].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return parameters[i + 1];
            }
        }

        return null;
    }

    /// <summary>
    /// RFC 3282's <c>Content-Language</c>, which is a comma-separated list of tags.
    /// </summary>
    private static IReadOnlyList<string> SplitLanguages(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        List<string> tags = [];

        foreach (string tag in value.Split(','))
        {
            string trimmed = tag.Trim(' ', '\t');

            if (trimmed.Length > 0)
            {
                tags.Add(trimmed);
            }
        }

        return tags;
    }

    private static string? Upper(string? value) =>
        value is null ? null : value.Trim(' ', '\t').ToUpperInvariant();

    // -------------------------------------------------------------------------------------------
    // Finding what a section specifier names.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The octets a section names, or null when this message has no such part.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null rather than an error, because whether a part exists is a fact about one message and a
    /// <c>FETCH 1:*</c> covers many. §9's <c>nstring</c> has <c>NIL</c> for exactly this, and
    /// §6.4.5 makes a client's request for a part that is not there a question with an answer
    /// rather than a protocol fault.
    /// </para>
    /// <para>
    /// §6.4.5: "The HEADER, HEADER.FIELDS, HEADER.FIELDS.NOT, and TEXT part specifiers can be the
    /// sole part specifier or can be prefixed by one or more numeric part specifiers, provided
    /// that the numeric part specifier refers to a part of type MESSAGE/RFC822." A prefix naming
    /// anything else has no answer, and gets <c>NIL</c>.
    /// </para>
    /// </remarks>
    public static ReadOnlyMemory<byte>? Extract(
        ImapBodyPart root,
        ReadOnlyMemory<byte> message,
        ImapSection section)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(section);

        if (section.Part.Count == 0)
        {
            // Nothing numeric: MIME is the one specifier §6.4.5 says "MUST be prefixed by one or
            // more numeric part specifiers", so it has no meaning here.
            return section.Kind == ImapSectionKind.Mime
                ? null
                : ImapBodySection.Extract(message, section);
        }

        if (Find(root, section.Part) is not { } part)
        {
            return null;
        }

        ReadOnlyMemory<byte> whole;

        switch (section.Kind)
        {
            case ImapSectionKind.Part:
                whole = part.Content;
                break;

            case ImapSectionKind.Mime:
                whole = part.MimeHeader;
                break;

            default:
                // HEADER, HEADER.FIELDS, HEADER.FIELDS.NOT and TEXT, which only a MESSAGE/RFC822
                // part has, and which are read out of the message it carries.
                if (!part.IsMessage)
                {
                    return null;
                }

                // The numeric prefix has done its work; what is left addresses the encapsulated
                // message itself, which is read the same way the top-level one is.
                return ImapBodySection.Extract(part.Content, section with { Part = [] });
        }

        return ImapBodySection.Partial(whole, section);
    }

    /// <summary>
    /// Walks a numeric part specifier down the tree.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §6.4.5: "Every message has at least one part number. Non-[MIME-IMB] messages, and
    /// non-multipart [MIME-IMB] messages with no encapsulated message, only have a part 1." So a
    /// message that is not a multipart is its own part 1 — and a message that <i>is</i> one has
    /// no number of its own, its parts being 1, 2, 3 as they occur.
    /// </para>
    /// <para>
    /// <b>A <c>MESSAGE/RFC822</c> part's numbers address the message it carries, without a level
    /// in between.</b> §6.4.5's worked example makes part 3 a <c>MESSAGE/RFC822</c> whose
    /// encapsulated body is a multipart, and numbers that multipart's parts <c>3.1</c> and
    /// <c>3.2</c> rather than <c>3.1.1</c> and <c>3.1.2</c>.
    /// </para>
    /// </remarks>
    public static ImapBodyPart? Find(ImapBodyPart root, IReadOnlyList<int> numbers)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(numbers);

        if (numbers.Count == 0)
        {
            return root;
        }

        ImapBodyPart current = root;
        int index = 0;

        if (!root.IsMultipart)
        {
            if (numbers[0] != 1)
            {
                return null;
            }

            index = 1;
        }

        while (index < numbers.Count)
        {
            ImapBodyPart container = current.Message ?? current;
            int number = numbers[index];

            if (container.IsMultipart)
            {
                if (number < 1 || number > container.Children.Count)
                {
                    return null;
                }

                current = container.Children[number - 1];
            }
            else if (!ReferenceEquals(container, current) && number == 1)
            {
                // A MESSAGE/RFC822 carrying a single part: that part is number 1.
                current = container;
            }
            else
            {
                return null;
            }

            index++;
        }

        return current;
    }
}

/// <summary>One <c>Content-Type</c> or <c>Content-Disposition</c>, taken apart.</summary>
/// <param name="Type">The media type or disposition type, upper-cased.</param>
/// <param name="Subtype">The media subtype, upper-cased. Empty for a disposition.</param>
/// <param name="Parameters">The parameters, flattened to name, value, name, value.</param>
public sealed record ImapContentType(
    string Type,
    string Subtype,
    IReadOnlyList<string> Parameters)
{
    /// <summary>RFC 2045 §5.2's default, "Content-type: text/plain; charset=us-ascii".</summary>
    public static ImapContentType Default { get; } =
        new("TEXT", "PLAIN", ["CHARSET", "us-ascii"]);

    /// <summary>RFC 2046 §5.1.5's default inside a <c>multipart/digest</c>.</summary>
    public static ImapContentType DigestDefault { get; } = new("MESSAGE", "RFC822", []);

    /// <summary>The most parameters kept from one header.</summary>
    /// <remarks>
    /// A conformant header carries a handful. The cap bounds the response one crafted header can
    /// force, as the other list caps in this namespace do.
    /// </remarks>
    public const int MaxParameterCount = 64;

    /// <summary>
    /// Reads a <c>Content-Type</c>, applying RFC 2045 §5.2's default when there is none.
    /// </summary>
    /// <remarks>
    /// §5.2: "Default RFC 822 messages without a MIME Content-Type header are taken by this
    /// protocol to be plain text in the US-ASCII character set". A header that is present but
    /// unreadable gets the same treatment, for the same reason: the message still has to be
    /// describable.
    /// </remarks>
    public static ImapContentType Read(string? value, bool inDigest)
    {
        ImapContentType fallback = inDigest ? DigestDefault : Default;

        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        IReadOnlyList<string> pieces = SplitOnSemicolons(value);

        if (pieces.Count == 0)
        {
            return fallback;
        }

        string media = pieces[0].Trim(' ', '\t');
        int slash = media.IndexOf('/', StringComparison.Ordinal);

        if (slash <= 0 || slash == media.Length - 1)
        {
            return fallback;
        }

        return new ImapContentType(
            media[..slash].Trim(' ', '\t').ToUpperInvariant(),
            media[(slash + 1)..].Trim(' ', '\t').ToUpperInvariant(),
            ReadParameters(pieces));
    }

    /// <summary>
    /// Reads a <c>Content-Disposition</c>, or null when there is none.
    /// </summary>
    /// <remarks>
    /// RFC 2183 §2: <c>disposition := "Content-Disposition" ":" disposition-type
    /// *(";" disposition-parm)</c>. §7.4.2's <c>body-fld-dsp</c> is "a disposition type string,
    /// followed by a parenthesized list of disposition attribute/value pairs".
    /// </remarks>
    public static ImapContentType? ReadDisposition(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        IReadOnlyList<string> pieces = SplitOnSemicolons(value);
        string type = pieces.Count == 0 ? string.Empty : pieces[0].Trim(' ', '\t');

        return type.Length == 0
            ? null
            : new ImapContentType(type.ToUpperInvariant(), string.Empty, ReadParameters(pieces));
    }

    /// <summary>
    /// Reads <c>attribute=value</c> pairs from everything after the first semicolon.
    /// </summary>
    /// <remarks>
    /// RFC 2045 §5.1: <c>parameter := attribute "=" value</c> and
    /// <c>value := token / quoted-string</c>. The attribute is upper-cased because §5.1 makes
    /// parameter names case-insensitive; the value is kept exactly as written, because a
    /// <c>name</c> or <c>filename</c> parameter carries a user's filename and its case is theirs.
    /// </remarks>
    private static IReadOnlyList<string> ReadParameters(IReadOnlyList<string> pieces)
    {
        List<string> parameters = [];

        for (int i = 1; i < pieces.Count && parameters.Count < MaxParameterCount * 2; i++)
        {
            string piece = pieces[i];
            int equals = FindTopLevel(piece, '=');

            if (equals <= 0)
            {
                continue;
            }

            string name = piece[..equals].Trim(' ', '\t');

            if (name.Length == 0)
            {
                continue;
            }

            parameters.Add(name.ToUpperInvariant());
            parameters.Add(Unquote(piece[(equals + 1)..].Trim(' ', '\t')));
        }

        return parameters;
    }

    /// <summary>
    /// Splits a structured header value at its semicolons.
    /// </summary>
    /// <remarks>
    /// A semicolon inside a quoted string or a comment is content rather than a separator — a
    /// filename of <c>report;final.pdf</c> is perfectly legal — so both are stepped over whole.
    /// </remarks>
    private static IReadOnlyList<string> SplitOnSemicolons(string value)
    {
        List<string> pieces = [];
        StringBuilder current = new();
        int i = 0;

        while (i < value.Length)
        {
            char c = value[i];

            if (c == ';')
            {
                pieces.Add(current.ToString());
                current.Clear();
                i++;
                continue;
            }

            if (c == '"')
            {
                int end = SkipQuoted(value, i);

                current.Append(value[i..end]);
                i = end;
                continue;
            }

            if (c == '(')
            {
                i = SkipComment(value, i);
                continue;
            }

            current.Append(c);
            i++;
        }

        pieces.Add(current.ToString());

        return pieces;
    }

    private static int FindTopLevel(string value, char target)
    {
        int i = 0;

        while (i < value.Length)
        {
            char c = value[i];

            if (c == target)
            {
                return i;
            }

            i = c == '"' ? SkipQuoted(value, i) : i + 1;
        }

        return -1;
    }

    /// <summary>Removes a value's quoting, and the backslashes of its quoted-pairs.</summary>
    private static string Unquote(string value)
    {
        if (value.Length < 2 || value[0] != '"')
        {
            return value;
        }

        int end = value[^1] == '"' ? value.Length - 1 : value.Length;

        StringBuilder result = new(end - 1);

        for (int i = 1; i < end; i++)
        {
            if (value[i] == '\\' && i + 1 < end)
            {
                i++;
            }

            result.Append(value[i]);
        }

        return result.ToString();
    }

    private static int SkipQuoted(string value, int index)
    {
        int i = index + 1;

        while (i < value.Length)
        {
            if (value[i] == '\\')
            {
                i += 2;
                continue;
            }

            if (value[i] == '"')
            {
                return i + 1;
            }

            i++;
        }

        return value.Length;
    }

    private static int SkipComment(string value, int index)
    {
        int depth = 0;
        int i = index;

        while (i < value.Length)
        {
            char c = value[i];

            if (c == '\\')
            {
                i += 2;
                continue;
            }

            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;

                if (depth == 0)
                {
                    return i + 1;
                }
            }

            i++;
        }

        return value.Length;
    }
}
