using System.Globalization;

namespace MailServer.Domain.Imap;

/// <summary>
/// A parsed IMAP literal specifier — RFC 3501 §9's <c>{number}</c>, and RFC 7888 LITERAL+'s
/// <c>{number+}</c>.
/// </summary>
/// <remarks>
/// <para>
/// A literal lets a client send arbitrary octets (including <c>CRLF</c>, which would otherwise
/// end the line) as a single atom: <c>{5}\r\nhello</c> names the five bytes that follow the
/// specifier's own line. The synchronising form <c>{5}</c> requires the server to send a
/// continuation response (<c>+ OK</c>) before those bytes arrive, which is the server's one
/// chance to refuse a literal it will not accept before any of it is transmitted.
/// </para>
/// <para>
/// <b>The non-synchronising form <c>{5+}</c> removes that chance.</b> RFC 7888 LITERAL+ lets a
/// client send the byte count and the bytes together, with no round trip in between — which is
/// exactly why <c>docs/IMAP.md</c> calls an unbounded one "a trivial memory exhaustion": by the
/// time this specifier is even fully parsed, a client that declared <c>{4000000000+}</c> may
/// already be sending four billion bytes with nothing left for the server to say no to. This
/// type only parses the specifier's own two-integer-and-a-flag syntax; deciding whether
/// <see cref="ByteCount"/> is small enough to accept — and, per <c>docs/IMAP.md</c>, whether it
/// is large enough that the bytes belong on disk rather than in memory — is deliberately not
/// this type's job, the same way <see cref="MailServer.Domain.Smtp.SmtpPath.ReadSizeParameter"/>
/// parses a claimed message size without itself enforcing one: the acceptable limit is
/// configuration, decided once at the point that actually reads the bytes, not scattered into
/// whatever parses text that happens to contain a number.
/// </para>
/// </remarks>
public readonly record struct ImapLiteralSpecifier(long ByteCount, bool IsSynchronizing)
{
    /// <summary>Parses a literal specifier, e.g. <c>{5}</c> or <c>{5+}</c>.</summary>
    /// <param name="text">
    /// The specifier only — the enclosing braces and everything between them, with nothing
    /// before or after (the caller has already located it at the end of a command line).
    /// </param>
    public static bool TryParse(string text, out ImapLiteralSpecifier result)
    {
        ArgumentNullException.ThrowIfNull(text);

        result = default;

        if (text.Length < 3 || text[0] != '{' || text[^1] != '}')
        {
            return false;
        }

        string inner = text[1..^1];
        bool nonSynchronizing = inner.EndsWith('+');
        string digits = nonSynchronizing ? inner[..^1] : inner;

        // Strict 1*DIGIT: no sign, no whitespace, no thousands separator - everything
        // long.TryParse's default NumberStyles would otherwise tolerate.
        if (digits.Length == 0 ||
            !long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out long byteCount))
        {
            return false;
        }

        result = new ImapLiteralSpecifier(byteCount, !nonSynchronizing);
        return true;
    }
}
