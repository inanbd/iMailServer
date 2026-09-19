using System.Diagnostics.CodeAnalysis;

namespace MailServer.Domain.Pop3;

/// <summary>
/// The commands this server recognises.
/// </summary>
/// <remarks>
/// <para>
/// RFC 1939 §9 divides them: <c>USER</c>, <c>PASS</c>, <c>QUIT</c>, <c>STAT</c>, <c>LIST</c>,
/// <c>RETR</c>, <c>DELE</c>, <c>NOOP</c> and <c>RSET</c> are the "Minimal POP3 Commands" every
/// implementation must support, and <c>TOP</c>, <c>UIDL</c> and <c>APOP</c> are optional.
/// <c>CAPA</c> is RFC 2449's and <c>STLS</c> is RFC 2595's.
/// </para>
/// <para>
/// <b><c>APOP</c> is named here and refused.</b> §7's <c>APOP</c> requires the server to hold a
/// shared secret it can hash with a timestamp — that is, the password in a recoverable form.
/// This server stores password verifiers it cannot reverse, so APOP is not something it has
/// declined to implement but something its storage makes impossible. Recognising the keyword
/// means saying so rather than answering "unknown command" to a client that would then wonder
/// whether it mistyped. RFC 2449 §6 notes there is deliberately no APOP capability: "Clients
/// discover server support of APOP by the presence in the greeting banner of an initial
/// challenge enclosed in angle brackets" — so a greeting carrying no angle brackets already
/// tells a client not to try, and <see cref="Pop3Responses.Greeting"/> guarantees it carries
/// none.
/// </para>
/// </remarks>
public enum Pop3Verb
{
    /// <summary>A keyword this server does not know.</summary>
    Unknown = 0,

    /// <summary><c>USER</c> — "a string identifying a mailbox".</summary>
    User = 1,

    /// <summary><c>PASS</c> — "a server/mailbox-specific password".</summary>
    Pass = 2,

    /// <summary><c>QUIT</c> — ends the session, and from TRANSACTION also commits the deletions.</summary>
    Quit = 3,

    /// <summary><c>STAT</c> — the drop listing.</summary>
    Stat = 4,

    /// <summary><c>LIST</c> — the scan listing, for one message or for all.</summary>
    List = 5,

    /// <summary><c>RETR</c> — a whole message.</summary>
    Retr = 6,

    /// <summary><c>DELE</c> — marks a message for removal at UPDATE.</summary>
    Dele = 7,

    /// <summary><c>NOOP</c> — "The POP3 server does nothing, it merely replies".</summary>
    Noop = 8,

    /// <summary><c>RSET</c> — unmarks everything marked.</summary>
    Rset = 9,

    /// <summary><c>TOP</c> — a message's header and the first n lines of its body.</summary>
    Top = 10,

    /// <summary><c>UIDL</c> — the unique-id listing.</summary>
    Uidl = 11,

    /// <summary><c>CAPA</c> — RFC 2449's capability listing.</summary>
    Capa = 12,

    /// <summary><c>STLS</c> — RFC 2595's TLS upgrade.</summary>
    Stls = 13,

    /// <summary><c>APOP</c> — recognised so it can be refused by name.</summary>
    Apop = 14,
}

/// <summary>
/// One parsed command line.
/// </summary>
/// <param name="Verb">Which command, or <see cref="Pop3Verb.Unknown"/>.</param>
/// <param name="Keyword">The keyword as written, upper-cased. For a refusal's text.</param>
/// <param name="Argument">
/// Everything after the keyword and its single separating space, verbatim and untrimmed at the
/// end.
/// </param>
/// <remarks>
/// <b>The argument is not split.</b> RFC 1939's <c>PASS</c> says why: "Since the PASS command has
/// exactly one argument, a POP3 server may treat spaces in the argument as part of the password,
/// instead of as argument separators." A parser that tokenised every command would quietly
/// truncate every password containing a space, and the user would see nothing but a refusal.
/// Commands that do take two arguments — <c>TOP</c> and <c>APOP</c> — split this themselves.
/// </remarks>
public sealed record Pop3Command(Pop3Verb Verb, string Keyword, string Argument)
{
    /// <summary>
    /// The longest command line accepted.
    /// </summary>
    /// <remarks>
    /// RFC 2449 §4: "The maximum length of a command is increased from 47 characters (4 character
    /// command, single space, 40 character argument, CRLF) to 255 octets, including the
    /// terminating CRLF. Servers which support the CAPA command MUST support commands up to 255
    /// octets." This server supports CAPA, so 255 is a floor rather than a choice — and the
    /// count includes the CRLF the reader has already removed, so the text may be 253.
    /// </remarks>
    public const int MaxLineOctets = 255;

    /// <summary>The longest keyword. §3: <c>keyword = 3*4VCHAR</c>.</summary>
    public const int MaxKeywordLength = 4;

    /// <summary>The shortest keyword.</summary>
    public const int MinKeywordLength = 3;

    /// <summary>
    /// Parses one line, without its CRLF.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §3: <c>command = keyword *(SP param) CRLF</c>, <c>keyword = 3*4VCHAR</c>,
    /// <c>param = 1*VCHAR</c>. <c>VCHAR</c> is <c>%x21-7E</c> — printable ASCII, no space and no
    /// control character — which is what makes this parse safe to echo back: nothing that gets
    /// through can carry a CR or an LF into a response.
    /// </para>
    /// <para>
    /// <b>An unknown keyword parses.</b> §3 requires a server to "respond to an unrecognized,
    /// unimplemented, or syntactically invalid command by responding with a negative status
    /// indicator", and all three are the same reply — so the difference between them is only
    /// what the text says, and a keyword that is well-formed but unknown deserves to be told so.
    /// A keyword that is not well-formed does not parse at all.
    /// </para>
    /// </remarks>
    public static bool TryParse(string line, [NotNullWhen(true)] out Pop3Command? command)
    {
        ArgumentNullException.ThrowIfNull(line);

        command = null;

        // The CRLF is counted by §4's limit and has already been removed by the reader.
        if (line.Length == 0 || line.Length > MaxLineOctets - 2)
        {
            return false;
        }

        int space = line.IndexOf(' ', StringComparison.Ordinal);
        string keyword = space < 0 ? line : line[..space];
        string argument = space < 0 ? string.Empty : line[(space + 1)..];

        if (keyword.Length is < MinKeywordLength or > MaxKeywordLength || !IsVisible(keyword))
        {
            return false;
        }

        // A param is 1*VCHAR, so a space is a separator and nothing else may be a control
        // character. PASS's "spaces are part of the password" licence is about separators, not
        // about smuggling a CRLF through.
        foreach (char c in argument)
        {
            if (c != ' ' && !IsVisible(c))
            {
                return false;
            }
        }

        command = new Pop3Command(Recognise(keyword), keyword.ToUpperInvariant(), argument);

        return true;
    }

    /// <summary>Matches a keyword. §3's keywords are case-insensitive.</summary>
    private static Pop3Verb Recognise(string keyword) => keyword.ToUpperInvariant() switch
    {
        "USER" => Pop3Verb.User,
        "PASS" => Pop3Verb.Pass,
        "QUIT" => Pop3Verb.Quit,
        "STAT" => Pop3Verb.Stat,
        "LIST" => Pop3Verb.List,
        "RETR" => Pop3Verb.Retr,
        "DELE" => Pop3Verb.Dele,
        "NOOP" => Pop3Verb.Noop,
        "RSET" => Pop3Verb.Rset,
        "TOP" => Pop3Verb.Top,
        "UIDL" => Pop3Verb.Uidl,
        "CAPA" => Pop3Verb.Capa,
        "STLS" => Pop3Verb.Stls,
        "APOP" => Pop3Verb.Apop,
        _ => Pop3Verb.Unknown,
    };

    private static bool IsVisible(string value)
    {
        foreach (char c in value)
        {
            if (!IsVisible(c))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>§3's <c>VCHAR</c>: <c>%x21-7E</c>.</summary>
    private static bool IsVisible(char c) => c is >= '!' and <= '~';

    /// <summary>
    /// Reads a message number argument.
    /// </summary>
    /// <remarks>
    /// §5: "In POP3 commands and responses, all message-numbers and message sizes are expressed
    /// in base-10 (i.e., decimal)." Parsed strictly: no sign, no leading plus, no whitespace, and
    /// nothing that would let <c>+1</c> or <c>1 </c> name message one by a second spelling.
    /// </remarks>
    public static bool TryReadNumber(string text, out int number)
    {
        ArgumentNullException.ThrowIfNull(text);

        number = 0;

        if (text.Length == 0 || text.Length > 9)
        {
            return false;
        }

        foreach (char c in text)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }

            number = (number * 10) + (c - '0');
        }

        return true;
    }
}
