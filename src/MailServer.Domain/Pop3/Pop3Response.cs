using System.Globalization;
using System.Text;

namespace MailServer.Domain.Pop3;

/// <summary>
/// One response: a status line, and for a multi-line response the body that follows it.
/// </summary>
/// <remarks>
/// <para>
/// RFC 1939 §3: "Responses in the POP3 consist of a status indicator and a keyword possibly
/// followed by additional information. […] There are currently two status indicators: positive
/// ("+OK") and negative ("-ERR"). Servers MUST send the "+OK" and "-ERR" in upper case."
/// </para>
/// <para>
/// <b>The status line is sanitised and the body is not.</b> The line is text this server
/// composes, and a CR or LF in it would end the response early and turn whatever followed into a
/// second response — the injection <see cref="Format"/> exists to prevent. The body is a stored
/// message, which §3 sends verbatim apart from the byte-stuffing
/// <see cref="Pop3DotStuffing"/> applies; sanitising it would corrupt every attachment.
/// </para>
/// </remarks>
public sealed record Pop3Response
{
    /// <summary>Stands in for text that sanitised away to nothing.</summary>
    public const string EmptyTextPlaceholder = "(text omitted)";

    /// <summary>
    /// The longest status line, including its CRLF.
    /// </summary>
    /// <remarks>
    /// RFC 2449 §4: "The maximum length of the first line of a command response (including the
    /// initial greeting) is unchanged at 512 octets (including the terminating CRLF)." §5 puts
    /// the same limit on each capability line.
    /// </remarks>
    public const int MaxLineOctets = 512;

    private Pop3Response(
        bool isPositive,
        string? code,
        string text,
        IReadOnlyList<string>? lines,
        ReadOnlyMemory<byte>? octets)
    {
        IsPositive = isPositive;
        Code = code;
        Text = text;
        Lines = lines;
        Octets = octets;
    }

    /// <summary>Whether the status indicator is <c>+OK</c>.</summary>
    public bool IsPositive { get; }

    /// <summary>RFC 2449 §8's extended response code, without its brackets, or null.</summary>
    public string? Code { get; }

    /// <summary>The text after the status indicator and any code. May be empty.</summary>
    public string Text { get; }

    /// <summary>The lines of a multi-line response this server composed, or null.</summary>
    public IReadOnlyList<string>? Lines { get; }

    /// <summary>The octets of a multi-line response's body, already stuffed, or null.</summary>
    public ReadOnlyMemory<byte>? Octets { get; }

    /// <summary>Whether a body follows the status line.</summary>
    public bool IsMultiLine => Lines is not null || Octets is not null;

    /// <summary><c>+OK</c> with text.</summary>
    public static Pop3Response Ok(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return new Pop3Response(true, null, text, null, null);
    }

    /// <summary><c>-ERR</c> with text.</summary>
    public static Pop3Response Error(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return new Pop3Response(false, null, text, null, null);
    }

    /// <summary>
    /// <c>-ERR</c> carrying one of RFC 2449 §8's extended response codes.
    /// </summary>
    /// <remarks>
    /// §8: "an optional response code, enclosed in square brackets, at the beginning of the human
    /// readable text portion". The brackets are added by <see cref="Format"/> rather than written
    /// into the text, because the same method strips brackets out of ordinary text precisely so
    /// that text can never be mistaken for a code.
    /// </remarks>
    public static Pop3Response ErrorWithCode(string code, string text)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(text);

        return new Pop3Response(false, code, text, null, null);
    }

    /// <summary><c>+OK</c> followed by lines this server composed, then the terminator.</summary>
    public static Pop3Response OkWithLines(string text, IReadOnlyList<string> lines)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(lines);

        return new Pop3Response(true, null, text, lines, null);
    }

    /// <summary><c>+OK</c> followed by a message's octets, then the terminator.</summary>
    public static Pop3Response OkWithOctets(string text, ReadOnlyMemory<byte> octets)
    {
        ArgumentNullException.ThrowIfNull(text);

        return new Pop3Response(true, null, text, null, octets);
    }

    /// <summary>
    /// Renders the status line, with its CRLF.
    /// </summary>
    /// <remarks>
    /// The only place a status line becomes text, and therefore the only place the sanitisation
    /// has to hold. Nothing that reaches here can produce more than one line.
    /// </remarks>
    public string Format()
    {
        StringBuilder builder = new(IsPositive ? "+OK" : "-ERR");

        if (SanitiseCode(Code) is { Length: > 0 } code)
        {
            builder.Append(" [").Append(code).Append(']');
        }

        if (Sanitise(Text) is { Length: > 0 } text)
        {
            builder.Append(' ').Append(text);
        }

        return builder.Append("\r\n").ToString();
    }

    /// <summary>
    /// A record's generated <c>ToString</c> would print the unsanitised text.
    /// </summary>
    /// <remarks>
    /// The same defect <c>ImapResponse</c> carries in the same place, and the same fix: a log
    /// line or an assertion message built from a response must not be able to show a CR or LF
    /// that the wire form would never carry.
    /// </remarks>
    private bool PrintMembers(StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Append(Format().TrimEnd('\r', '\n'));

        if (IsMultiLine)
        {
            builder.Append(" (multi-line)");
        }

        return true;
    }

    /// <summary>
    /// Reduces text to what §3's grammar allows after a status indicator.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 2449 §3: <c>text = *schar / resp-code *CHAR</c> with
    /// <c>schar = %x21-5A / %x5C-7F</c> — printable ASCII excluding <c>[</c>, which is reserved
    /// for the response code that may precede the text. Space is not an <c>schar</c> either, but
    /// it plainly belongs in human-readable text and every example in both documents contains
    /// one; it is kept, and everything outside the printable range is not.
    /// </para>
    /// <para>
    /// <b>Brackets are dropped rather than escaped.</b> A server advertising <c>RESP-CODES</c>
    /// has told its clients that "any response text issued by this server which begins with an
    /// open square bracket ("[") is an extended response code", so text that happened to start
    /// with one would be read as a code.
    /// </para>
    /// </remarks>
    private static string Sanitise(string text)
    {
        if (text.Length == 0)
        {
            return string.Empty;
        }

        StringBuilder safe = new(text.Length);

        foreach (char c in text)
        {
            if (c is '[' or ']')
            {
                continue;
            }

            if (c is ' ' || c is >= '!' and <= '~')
            {
                safe.Append(c);
            }
        }

        // The status line is bounded and "-ERR ", any code, and the CRLF come out of the same
        // budget. Truncation beats a line a client will not read to the end of.
        string result = safe.ToString().Trim();

        return result.Length > MaxLineOctets - 64 ? result[..(MaxLineOctets - 64)] : result;
    }

    /// <summary>
    /// Reduces a response code to §3's <c>resp-level</c> characters.
    /// </summary>
    /// <remarks>
    /// §3: <c>resp-code = "[" resp-level *("/" resp-level) "]"</c> and
    /// <c>resp-level = 1*rchar</c>, where <c>rchar = %x21-2E / %x30-5C / %x5E-7F</c> — printable
    /// ASCII excluding <c>/</c> and <c>]</c>. The slash is kept because it is the separator
    /// between levels; the bracket is not, because it would close the code early.
    /// </remarks>
    private static string? SanitiseCode(string? code)
    {
        if (code is null)
        {
            return null;
        }

        StringBuilder safe = new(code.Length);

        foreach (char c in code)
        {
            if (c is '[' or ']')
            {
                continue;
            }

            if (c is >= '!' and <= '~')
            {
                safe.Append(c);
            }
        }

        return safe.ToString();
    }
}

/// <summary>The responses this server sends, written once each.</summary>
public static class Pop3Responses
{
    /// <summary>
    /// The greeting, which must not look like an APOP challenge.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 1939 §4: "the POP3 server issues a one line greeting. This can be any positive
    /// response."
    /// </para>
    /// <para>
    /// <b>No angle brackets, ever.</b> RFC 2449 §6: "there is no APOP capability […] Clients
    /// discover server support of APOP by the presence in the greeting banner of an initial
    /// challenge enclosed in angle brackets ("&lt;&gt;")." A greeting that happened to contain
    /// one — from a product name, say — would advertise an authentication mechanism this server
    /// cannot perform, and the client would fail on a command it was invited to send. The
    /// brackets are removed rather than the greeting rejected: an operator's product name is not
    /// a protocol error.
    /// </para>
    /// </remarks>
    public static Pop3Response Greeting(string product)
    {
        ArgumentNullException.ThrowIfNull(product);

        string safe = product
            .Replace("<", string.Empty, StringComparison.Ordinal)
            .Replace(">", string.Empty, StringComparison.Ordinal)
            .Trim();

        return Pop3Response.Ok(safe.Length == 0 ? "POP3 server ready" : $"{safe} POP3 server ready");
    }

    /// <summary>
    /// The drop listing. §5: <c>"+OK"</c> SP message-count SP octets.
    /// </summary>
    /// <remarks>
    /// §5 on <c>STAT</c>: "The positive response consists of "+OK" followed by a single space,
    /// the number of messages in the maildrop, a single space, and the size of the maildrop in
    /// octets." And: "This memo STRONGLY discourages implementations from supplying additional
    /// information in the drop listing", so nothing follows the size.
    /// </remarks>
    public static Pop3Response Stat(long count, long octets) =>
        Pop3Response.Ok(string.Create(CultureInfo.InvariantCulture, $"{count} {octets}"));

    /// <summary>
    /// One scan listing. §5: "the message-number of the message, followed by a single space and
    /// the exact size of the message in octets".
    /// </summary>
    public static string ScanLine(int number, long octets) =>
        string.Create(CultureInfo.InvariantCulture, $"{number} {octets}");

    /// <summary>
    /// One unique-id listing. §7: "the message-number of the message, followed by a single space
    /// and the unique-id of the message. No information follows the unique-id".
    /// </summary>
    public static string UniqueLine(int number, string uniqueId) =>
        string.Create(CultureInfo.InvariantCulture, $"{number} {uniqueId}");

    /// <summary>
    /// The reply to a command sent in the wrong state.
    /// </summary>
    /// <remarks>
    /// §3: "A server MUST respond to a command issued when the session is in an incorrect state
    /// by responding with a negative status indicator."
    /// </remarks>
    public static Pop3Response WrongState(string keyword) =>
        Pop3Response.Error($"{keyword} is not valid in this state");

    /// <summary>
    /// The reply to an unknown, unimplemented or malformed command.
    /// </summary>
    /// <remarks>
    /// §3 makes all three one reply: "A server MUST respond to an unrecognized, unimplemented, or
    /// syntactically invalid command by responding with a negative status indicator." Only the
    /// text differs, and it never quotes the client's own line — a keyword that parsed is
    /// printable by construction, but a line that did not parse is not.
    /// </remarks>
    public static Pop3Response Unknown() => Pop3Response.Error("Unrecognised command");

    /// <summary>The reply to a message number that names nothing.</summary>
    /// <remarks>
    /// §5's own wording for the case, in every command that takes a number: "-ERR no such
    /// message". The count is included because §5's example does — "no such message, only 2
    /// messages in maildrop" — and it tells a client that has lost track what to expect.
    /// </remarks>
    public static Pop3Response NoSuchMessage(long available) =>
        Pop3Response.Error(string.Create(
            CultureInfo.InvariantCulture,
            $"no such message, only {available} messages in maildrop"));
}
