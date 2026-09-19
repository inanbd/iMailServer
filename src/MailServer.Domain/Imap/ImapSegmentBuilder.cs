using System.Globalization;
using System.Text;

namespace MailServer.Domain.Imap;

/// <summary>
/// Builds one response fragment that may carry literals part-way through.
/// </summary>
/// <remarks>
/// <para>
/// <b>An <c>ENVELOPE</c> can need a literal in the middle of itself, which is why this is not a
/// <see cref="StringBuilder"/>.</b> RFC 3501 §9 types every envelope member as an
/// <c>nstring</c>, and <c>string = quoted / literal</c>: a quoted string holds only
/// <c>TEXT-CHAR</c>, which is US-ASCII, so a subject carrying a raw 8-bit octet — forbidden by
/// RFC 2822 §2.2 and common in real mail — has no quoted form at all. The value then goes out as
/// <c>{n}CRLF</c> followed by exactly n octets, and everything after it in the same envelope
/// follows those octets. The result is a sequence of pieces rather than a line of text.
/// </para>
/// <para>
/// <b>Nothing here sanitises, and that is the point.</b>
/// <see cref="ImapResponse.Format"/> reduces its text to printable ASCII, which is right for
/// text this server composes and wrong for a header field it is quoting back: a subject is the
/// user's own words and a client that displays them has to receive them.
/// </para>
/// </remarks>
public sealed class ImapSegmentBuilder
{
    private readonly List<ImapResponseSegment> _segments = [];
    private readonly StringBuilder _text = new();

    /// <summary>Appends server-composed text.</summary>
    public ImapSegmentBuilder Append(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        _text.Append(text);

        return this;
    }

    /// <summary>Appends a number.</summary>
    public ImapSegmentBuilder Append(long value)
    {
        _text.Append(value.ToString(CultureInfo.InvariantCulture));

        return this;
    }

    /// <summary>
    /// Appends an <c>nstring</c>: <c>NIL</c>, a quoted string, or a literal.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The quoted form is used whenever it is available and a literal only when it is not.</b>
    /// Both are grammatical everywhere a <c>string</c> may appear, but a literal makes the client
    /// read a byte count and then that many octets, and a server that wrapped every subject in
    /// one would turn a single-line response into several for no gain.
    /// </para>
    /// <para>
    /// <b>The count is octets, not characters.</b> §9's <c>literal = "{" number "}" CRLF
    /// *CHAR8</c> counts what the client will read off the socket, and getting it wrong by one
    /// desynchronises the connection for good rather than corrupting one field.
    /// </para>
    /// </remarks>
    public ImapSegmentBuilder AppendNString(string? value)
    {
        if (value is null)
        {
            return Append("NIL");
        }

        if (IsQuotable(value))
        {
            return Append(Quote(value));
        }

        byte[] octets = Encode(value);

        _text.Append(CultureInfo.InvariantCulture, $"{{{octets.Length}}}\r\n");

        _segments.Add(ImapResponseSegment.FromText(_text.ToString()));
        _text.Clear();
        _segments.Add(ImapResponseSegment.FromOctets(octets));

        return this;
    }

    /// <summary>The pieces built so far, with any trailing text closed off.</summary>
    public IReadOnlyList<ImapResponseSegment> Build()
    {
        if (_text.Length > 0)
        {
            _segments.Add(ImapResponseSegment.FromText(_text.ToString()));
            _text.Clear();
        }

        return _segments;
    }

    /// <summary>
    /// Whether a value can be sent as a quoted string.
    /// </summary>
    /// <remarks>
    /// §9: <c>quoted = DQUOTE *QUOTED-CHAR DQUOTE</c>, <c>QUOTED-CHAR = &lt;any TEXT-CHAR except
    /// quoted-specials&gt;</c> and <c>TEXT-CHAR = &lt;any CHAR except CR and LF&gt;</c>, where
    /// <c>CHAR</c> is <c>%x01-7F</c>. So US-ASCII without CR, LF or NUL — and the two
    /// <c>quoted-specials</c>, which are allowed as long as they are escaped and so do not
    /// disqualify a value. HTAB is a <c>CHAR</c> and is kept quotable on purpose: a header folded
    /// with a tab unfolds to one, and forcing a literal for that alone would put a byte count in
    /// the middle of most multi-line subjects.
    /// </remarks>
    private static bool IsQuotable(string value)
    {
        foreach (char c in value)
        {
            if (c is not '\t' && (c < ' ' || c > '~'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Wraps a value in quotes, escaping §9's two <c>quoted-specials</c>.</summary>
    private static string Quote(string value)
    {
        StringBuilder quoted = new(value.Length + 2);

        quoted.Append('"');

        foreach (char c in value)
        {
            if (c is '"' or '\\')
            {
                quoted.Append('\\');
            }

            quoted.Append(c);
        }

        return quoted.Append('"').ToString();
    }

    /// <summary>
    /// Turns a value back into the octets it was read from.
    /// </summary>
    /// <remarks>
    /// Latin-1 when every character fits in a byte, which is the exact inverse of the decode
    /// <see cref="ImapHeaderFields.Read"/> performs, so a header field goes back on the wire as
    /// the octets it arrived as. A value carrying anything above U+00FF did not come from a
    /// header block and is encoded as UTF-8 instead — the only lossless choice left, and one
    /// that still produces the octet count the literal declares.
    /// </remarks>
    private static byte[] Encode(string value)
    {
        foreach (char c in value)
        {
            if (c > 'ÿ')
            {
                return Encoding.UTF8.GetBytes(value);
            }
        }

        return Encoding.Latin1.GetBytes(value);
    }
}
