using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace MailServer.Domain.Imap;

/// <summary>Which of RFC 3501 §4.3's forms an argument arrived in.</summary>
public enum ImapAstringKind
{
    /// <summary>Nothing left to read.</summary>
    None = 0,

    /// <summary>A bare run of <c>ASTRING-CHAR</c> — <c>INBOX</c>, <c>NIL</c>, <c>42</c>.</summary>
    Unquoted = 1,

    /// <summary>A quoted string — <c>"My Folder"</c>, or <c>""</c> for the empty one.</summary>
    Quoted = 2,

    /// <summary>
    /// A literal specifier, whose octets arrive after this line.
    /// </summary>
    /// <remarks>
    /// Reported rather than resolved. This reader is handed one line and a literal's content is
    /// not on it, so a reader that pretended otherwise would either block on I/O it has no
    /// access to or silently return the wrong argument. Whatever owns the connection reads the
    /// octets; see <see cref="ImapAstringToken.Literal"/>.
    /// </remarks>
    Literal = 3,

    /// <summary>The argument was not any of the above.</summary>
    Malformed = 4,
}

/// <summary>One argument, as read.</summary>
/// <param name="Kind">Which form it arrived in.</param>
/// <param name="Value">
/// The argument's text, with a quoted string's quotes removed and its escapes resolved. Empty
/// for <see cref="ImapAstringKind.Literal"/>, <see cref="ImapAstringKind.Malformed"/> and
/// <see cref="ImapAstringKind.None"/>.
/// </param>
/// <param name="Literal">The specifier, for <see cref="ImapAstringKind.Literal"/>.</param>
public readonly record struct ImapAstringToken(
    ImapAstringKind Kind,
    string Value,
    ImapLiteralSpecifier Literal)
{
    /// <summary>True when an argument was read and is usable as it stands.</summary>
    public bool IsText => Kind is ImapAstringKind.Unquoted or ImapAstringKind.Quoted;
}

/// <summary>
/// Reads RFC 3501 §4.3's <c>astring</c> arguments from one command line, left to right.
/// </summary>
/// <remarks>
/// <para>
/// Almost every IMAP command's arguments are astrings: <c>SELECT</c>'s mailbox, <c>RENAME</c>'s
/// two, <c>LIST</c>'s reference and pattern, and <c>LOGIN</c>'s userid and password. One reader
/// for all of them, because the grammar is one grammar, and because the alternative — each
/// handler splitting on spaces — gets <c>SELECT "My Folder"</c> wrong in the same way every
/// time.
/// </para>
/// <para>
/// <b>A cursor rather than a split.</b> <c>astring</c> is not space-delimited in any useful
/// sense: a quoted string may contain spaces, and an escaped quote may contain the delimiter of
/// the quoting itself. Reading one argument at a time and reporting where it ended is the only
/// form that can express that.
/// </para>
/// <para>
/// <b>Nothing here is normalised, and that is a correctness requirement rather than
/// minimalism.</b> Mailbox names are case-sensitive (RFC 3501 §5.1, with <c>INBOX</c> the one
/// exception, which is the caller's to apply) and a name's leading or trailing space is part of
/// the name when it arrived inside quotes. A reader that trimmed or folded case would make
/// two different mailboxes look like one.
/// </para>
/// <para>Not thread-safe. One reader belongs to one command line.</para>
/// </remarks>
public sealed class ImapAstringReader
{
    private readonly string _text;
    private int _position;

    /// <summary>Creates a reader over one command's argument text.</summary>
    /// <param name="text">Everything after the command word — <see cref="ImapCommand.Argument"/>.</param>
    public ImapAstringReader(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        _text = text;
    }

    /// <summary>Whether every argument has been read.</summary>
    /// <remarks>
    /// Skips the spaces between arguments, so a trailing space does not read as another
    /// argument. A caller that has read what a command takes should check this: RFC 3501 §9's
    /// productions are exact, and a command carrying more arguments than its grammar allows is
    /// malformed rather than generously interpretable.
    /// </remarks>
    public bool AtEnd
    {
        get
        {
            SkipSpaces();
            return _position >= _text.Length;
        }
    }

    /// <summary>What has not been read yet, verbatim.</summary>
    /// <remarks>
    /// For a caller that needs the tail as it arrived rather than as arguments — a <c>FETCH</c>
    /// attribute list, say, whose grammar is its own. Never for logging: on a <c>LOGIN</c> line
    /// the tail is a password.
    /// </remarks>
    public string Remainder => _position >= _text.Length ? string.Empty : _text[_position..];

    /// <summary>Reads the next argument.</summary>
    /// <remarks>
    /// Every outcome is a value, including the failures. A caller decides what a malformed
    /// argument earns — a tagged <c>BAD</c>, in practice — and nothing here throws on input a
    /// client chose, because a client choosing its input is the normal case rather than an
    /// exceptional one.
    /// </remarks>
    public ImapAstringToken Read()
    {
        SkipSpaces();

        if (_position >= _text.Length)
        {
            return new ImapAstringToken(ImapAstringKind.None, string.Empty, default);
        }

        return _text[_position] switch
        {
            '"' => ReadQuoted(),
            '{' => ReadLiteralSpecifier(),
            _ => ReadUnquoted(),
        };
    }

    /// <summary>Reads the next argument when it is usable text, and nothing else.</summary>
    /// <remarks>
    /// The convenience the ordinary commands want: a mailbox name that arrived as a literal, or
    /// did not arrive at all, is not something most handlers can proceed with, and collapsing
    /// those cases into <c>false</c> keeps their own code about what they are for. A handler
    /// that genuinely supports a literal argument calls <see cref="Read"/> and looks at
    /// <see cref="ImapAstringToken.Kind"/>.
    /// </remarks>
    public bool TryReadText([NotNullWhen(true)] out string? value)
    {
        ImapAstringToken token = Read();

        value = token.IsText ? token.Value : null;

        return value is not null;
    }

    private void SkipSpaces()
    {
        while (_position < _text.Length && _text[_position] == ' ')
        {
            _position++;
        }
    }

    /// <summary>
    /// <c>quoted = DQUOTE *QUOTED-CHAR DQUOTE</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>QUOTED-CHAR</c> is "any TEXT-CHAR except quoted-specials" or a backslash followed by
    /// one of them, and <c>quoted-specials</c> is exactly <c>"</c> and <c>\</c>. So those two
    /// are the only escapes there are: <b><c>\n</c> and <c>\t</c> are not IMAP</b>, and a server
    /// that resolved them would hand a client a character no client asked for. A backslash
    /// before anything else is malformed, not a literal backslash.
    /// </para>
    /// <para>
    /// An empty quoted string is legal and meaningful — <c>LIST "" "*"</c> is how every client
    /// opens a mailbox listing, the empty reference being the point. An implementation that
    /// required at least one character would break the first thing every client does.
    /// </para>
    /// </remarks>
    private ImapAstringToken ReadQuoted()
    {
        int start = _position;

        // Past the opening quote.
        _position++;

        StringBuilder value = new();

        while (_position < _text.Length)
        {
            char c = _text[_position];

            if (c == '"')
            {
                _position++;
                return new ImapAstringToken(ImapAstringKind.Quoted, value.ToString(), default);
            }

            if (c == '\\')
            {
                // A backslash at the very end of the line escapes nothing.
                if (_position + 1 >= _text.Length)
                {
                    break;
                }

                char escaped = _text[_position + 1];

                if (escaped is not ('"' or '\\'))
                {
                    break;
                }

                value.Append(escaped);
                _position += 2;
                continue;
            }

            if (c is '\r' or '\n')
            {
                // TEXT-CHAR excludes both. Neither can reach here through ImapLineReader, which
                // ends a line at the LF - but a caller composing an argument some other way
                // must not get a quoted string that spans lines.
                break;
            }

            value.Append(c);
            _position++;
        }

        // Unterminated, or carrying an escape the grammar does not have. The cursor is left
        // where the argument began, because there is no sensible place to resume from inside a
        // string whose extent is unknown.
        _position = start;

        return new ImapAstringToken(ImapAstringKind.Malformed, string.Empty, default);
    }

    /// <summary>
    /// <c>astring = 1*ASTRING-CHAR / string</c>, the first branch.
    /// </summary>
    /// <remarks>
    /// <c>ASTRING-CHAR</c> is <c>ATOM-CHAR</c> plus <c>resp-specials</c>, which is the same
    /// double negative <see cref="ImapCommand"/> documents for the tag: <c>]</c> is excluded by
    /// <c>atom-specials</c> and added straight back, so <b><c>]</c> is legal here and illegal in
    /// a bare atom</b>. A mailbox genuinely named <c>Invoices]2026</c> may therefore arrive
    /// unquoted, and refusing it would refuse a conformant client.
    /// </remarks>
    private ImapAstringToken ReadUnquoted()
    {
        int start = _position;

        while (_position < _text.Length && IsAstringChar(_text[_position]))
        {
            _position++;
        }

        if (_position == start)
        {
            // The first character was one ASTRING-CHAR excludes, and neither a quote nor a
            // brace, so this is not an argument at all - a stray ')' or a control character.
            return new ImapAstringToken(ImapAstringKind.Malformed, string.Empty, default);
        }

        return new ImapAstringToken(ImapAstringKind.Unquoted, _text[start.._position], default);
    }

    private ImapAstringToken ReadLiteralSpecifier()
    {
        int close = _text.IndexOf('}', _position);

        if (close < 0)
        {
            return new ImapAstringToken(ImapAstringKind.Malformed, string.Empty, default);
        }

        if (!ImapLiteralSpecifier.TryParse(_text[_position..(close + 1)], out ImapLiteralSpecifier specifier))
        {
            return new ImapAstringToken(ImapAstringKind.Malformed, string.Empty, default);
        }

        _position = close + 1;

        return new ImapAstringToken(ImapAstringKind.Literal, string.Empty, specifier);
    }

    /// <summary>RFC 3501 §9's <c>ASTRING-CHAR</c>.</summary>
    private static bool IsAstringChar(char c)
    {
        // CTL, SP and everything outside CHAR in one range test.
        if (c is < (char)0x21 or > (char)0x7E)
        {
            return false;
        }

        // atom-specials, minus resp-specials (']'), which ASTRING-CHAR adds back.
        return c is not ('(' or ')' or '{' or '%' or '*' or '"' or '\\');
    }
}

/// <summary>Writing an <c>astring</c> back out.</summary>
/// <remarks>
/// The other direction from <see cref="ImapAstringReader"/>, and the one that decides whether a
/// client can parse this server's <c>LIST</c> and <c>STATUS</c> responses at all.
/// </remarks>
public static class ImapAstring
{
    /// <summary>
    /// Formats a value as an <c>astring</c> for a response.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The empty string has no unquoted form and must be sent as <c>""</c>.</b>
    /// <c>astring</c>'s first branch is <c>1*ASTRING-CHAR</c> — one or more — so an empty
    /// argument can only be a quoted string. It comes up immediately: the hierarchy-delimiter
    /// probe every client makes is answered with an empty mailbox name, and emitting nothing at
    /// all there shifts every following token in the response.
    /// </para>
    /// <para>
    /// <b>Only <c>"</c> and <c>\</c> are escaped, and both must be.</b> They are RFC 3501 §9's
    /// entire <c>quoted-specials</c> set. Escaping anything else is not IMAP and delivers a
    /// backslash to the user as a character; failing to escape a backslash in an ordinary
    /// folder name like <c>Projects\2026</c> terminates the string early on the client side and
    /// shifts every token after it — a parse desynchronisation produced by a user's own folder
    /// name rather than by an attacker.
    /// </para>
    /// <para>
    /// <b>A literal is never needed for anything this server emits.</b> A literal is required
    /// when the octets contain CR, LF, NUL or 8-bit data, and
    /// <see cref="ImapMailboxName.Encode"/> emits printable US-ASCII by construction — so every
    /// mailbox name reaching here is quotable. Rather than assume that, this method refuses what
    /// it cannot quote: silently emitting a broken quoted string would desynchronise a client,
    /// and the byte count a literal needs is octets rather than characters, which is its own
    /// bug waiting to be written.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// The value contains an octet that would require a literal.
    /// </exception>
    public static string Format(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (!NeedsQuoting(value))
        {
            return value;
        }

        StringBuilder quoted = new(value.Length + 2);

        quoted.Append('"');

        foreach (char c in value)
        {
            if (c is '\r' or '\n' or '\0' || c > (char)0x7E)
            {
                throw new ArgumentException(
                    "This value needs a literal rather than a quoted string; encode it first.",
                    nameof(value));
            }

            if (c is '"' or '\\')
            {
                quoted.Append('\\');
            }

            quoted.Append(c);
        }

        return quoted.Append('"').ToString();
    }

    /// <summary>Whether a value has to be sent as a quoted string rather than bare.</summary>
    public static bool NeedsQuoting(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length == 0)
        {
            return true;
        }

        foreach (char c in value)
        {
            if (c is < (char)0x21 or > (char)0x7E ||
                c is '(' or ')' or '{' or '%' or '*' or '"' or '\\')
            {
                return true;
            }
        }

        return false;
    }
}
