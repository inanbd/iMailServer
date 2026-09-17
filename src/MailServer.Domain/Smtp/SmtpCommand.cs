using System.Diagnostics.CodeAnalysis;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Smtp;

/// <summary>The SMTP verbs this server understands.</summary>
public enum SmtpVerb
{
    /// <summary>Not a verb this server implements.</summary>
    Unknown = 0,

    Ehlo,
    Helo,
    MailFrom,
    RcptTo,
    Data,
    Rset,
    Noop,
    Quit,
    StartTls,
    Auth,

    /// <summary>
    /// VRFY. Recognised so it can be refused explicitly.
    /// </summary>
    /// <remarks>
    /// Answering VRFY truthfully turns the server into an address-enumeration oracle: a
    /// spammer walks a dictionary and learns which addresses exist. RFC 5321 §7.3 explicitly
    /// permits refusing it for this reason, and every serious MTA does.
    /// </remarks>
    Vrfy,

    /// <summary>EXPN. Refused for the same reason as VRFY, and more so — it expands lists.</summary>
    Expn,

    Help,
}

/// <summary>A parsed SMTP command line.</summary>
/// <param name="Verb">The verb.</param>
/// <param name="Argument">Everything after the verb, trimmed. Empty when there was none.</param>
/// <param name="Raw">The line as received, for logging an unrecognised command.</param>
public sealed record SmtpCommand(SmtpVerb Verb, string Argument, string Raw)
{
    /// <summary>
    /// Prints the verb, and deliberately never the argument or the raw line.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A record's generated <c>ToString</c> prints every property, and two of these
    /// properties can carry a credential.</b> <c>AUTH PLAIN AGFsaWNlAGh1bnRlcjI=</c> puts a
    /// base64-wrapped username and password in <see cref="Argument"/> and again in
    /// <see cref="Raw"/>. Base64 is an encoding, not a protection — anyone reading the log
    /// decodes it in one step — so the generated rendering would have made
    /// <c>logger.LogWarning("Unexpected command {Command}", command)</c>, a bare string
    /// interpolation, an exception message or a debugger-attached crash dump write a customer's
    /// password down.
    /// </para>
    /// <para>
    /// <c>SmtpProtocolSecurityTests</c>'s rule-77 scan cannot catch that shape: it matches the
    /// identifiers <c>command.Raw</c> and <c>line.Text</c> on logging lines, and a line passing
    /// the whole command object names neither. The defence therefore belongs in the type rather
    /// than in a rule every future call site has to remember, because the call site that forgets
    /// will not be the one anybody reviews.
    /// </para>
    /// <para>
    /// Nothing in this repository logs a command object today, so this closes a latent trap
    /// rather than a live leak. Its IMAP counterpart is
    /// <see cref="Imap.ImapCommand"/>, where the same defect is worse: RFC 3501's <c>LOGIN</c>
    /// carries the password with no encoding at all.
    /// </para>
    /// <para>
    /// The verb is safe to print — it is one of a fixed set of enum values, never client text.
    /// The argument remains reachable on the type; it is redacted from rendering, not from the
    /// handler that has to read it.
    /// </para>
    /// </remarks>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Append("Verb = ").Append(Verb);

        return true;
    }

    /// <summary>
    /// Parses a command line.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Verbs are matched case-insensitively against a fixed table. Not by prefix, and not by
    /// <c>StartsWith</c>: <c>MAILFROM</c> is not <c>MAIL FROM</c>, and a parser that treated
    /// them alike would accept commands no client sends and no specification describes.
    /// </para>
    /// <para>
    /// <c>MAIL FROM:</c> and <c>RCPT TO:</c> are two-word verbs, which is why the split is not
    /// simply on the first space.
    /// </para>
    /// </remarks>
    public static SmtpCommand Parse(string line)
    {
        ArgumentNullException.ThrowIfNull(line);

        string trimmed = line.TrimEnd('\r', '\n');

        if (trimmed.Length == 0)
        {
            return new SmtpCommand(SmtpVerb.Unknown, string.Empty, line);
        }

        // The two-word verbs first: 'MAIL FROM:<a@b>' must not be read as verb 'MAIL'.
        if (TryMatchPrefixed(trimmed, "MAIL FROM:", out string? mailArgument))
        {
            return new SmtpCommand(SmtpVerb.MailFrom, mailArgument, trimmed);
        }

        if (TryMatchPrefixed(trimmed, "RCPT TO:", out string? rcptArgument))
        {
            return new SmtpCommand(SmtpVerb.RcptTo, rcptArgument, trimmed);
        }

        int space = trimmed.IndexOf(' ', StringComparison.Ordinal);

        string verb = space < 0 ? trimmed : trimmed[..space];
        string argument = space < 0 ? string.Empty : trimmed[(space + 1)..].Trim();

        return new SmtpCommand(MapVerb(verb), argument, trimmed);
    }

    /// <remarks>
    /// Tolerates whitespace between the colon and the address, which several clients emit
    /// despite RFC 5321 §4.1.2 forbidding it. Refusing would reject mail over a formatting
    /// detail no recipient cares about; accepting costs a <c>TrimStart</c>.
    /// </remarks>
    private static bool TryMatchPrefixed(
        string line,
        string prefix,
        [NotNullWhen(true)] out string? argument)
    {
        if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            argument = line[prefix.Length..].Trim();
            return true;
        }

        argument = null;
        return false;
    }

    private static SmtpVerb MapVerb(string verb) => verb.ToUpperInvariant() switch
    {
        "EHLO" => SmtpVerb.Ehlo,
        "HELO" => SmtpVerb.Helo,
        "DATA" => SmtpVerb.Data,
        "RSET" => SmtpVerb.Rset,
        "NOOP" => SmtpVerb.Noop,
        "QUIT" => SmtpVerb.Quit,
        "STARTTLS" => SmtpVerb.StartTls,
        "AUTH" => SmtpVerb.Auth,
        "VRFY" => SmtpVerb.Vrfy,
        "EXPN" => SmtpVerb.Expn,
        "HELP" => SmtpVerb.Help,
        _ => SmtpVerb.Unknown,
    };
}

/// <summary>Parsing for the address forms that appear in MAIL FROM and RCPT TO.</summary>
public static class SmtpPath
{
    /// <summary>
    /// Parses a reverse-path or forward-path argument.
    /// </summary>
    /// <param name="argument">The text after <c>MAIL FROM:</c> or <c>RCPT TO:</c>.</param>
    /// <param name="address">
    /// The address, or null for the null reverse-path <c>&lt;&gt;</c> — which is legal and
    /// meaningful: it is what a bounce message uses as its sender, precisely so that a bounce
    /// cannot itself bounce and create a loop.
    /// </param>
    /// <param name="parameters">ESMTP parameters, e.g. <c>SIZE=12345</c>.</param>
    /// <remarks>
    /// <para>
    /// The angle brackets are required by RFC 5321 and are also load-bearing here: without them
    /// the address and the ESMTP parameters cannot be told apart, since a parameter is
    /// whitespace-separated and an address may not contain whitespace unquoted.
    /// </para>
    /// <para>
    /// Returns false rather than throwing. This parses bytes from the network, and an
    /// unparseable path is an ordinary event that deserves a 501 reply, not an exception.
    /// </para>
    /// </remarks>
    public static bool TryParse(
        string argument,
        out EmailAddress? address,
        out IReadOnlyList<string> parameters)
    {
        address = null;
        parameters = [];

        if (string.IsNullOrWhiteSpace(argument))
        {
            return false;
        }

        string trimmed = argument.Trim();

        if (!trimmed.StartsWith('<'))
        {
            return false;
        }

        int close = FindClosingBracket(trimmed);

        if (close < 0)
        {
            return false;
        }

        string inner = trimmed[1..close];
        string rest = trimmed[(close + 1)..].Trim();

        parameters = rest.Length == 0
            ? []
            : rest.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        // The null reverse-path. Legal, and the correct sender for a bounce: a bounce with a
        // real sender could itself bounce, and two servers each bouncing the other's bounces
        // is a mail loop that ends when someone notices.
        if (inner.Length == 0)
        {
            return true;
        }

        // A source route - '<@relay:user@host>' - is stripped rather than honoured. RFC 5321
        // §F.2 deprecates them, and honouring one would let a sender direct this server to
        // relay through a third party.
        int lastColon = inner.LastIndexOf(':');

        if (inner.StartsWith('@') && lastColon > 0)
        {
            inner = inner[(lastColon + 1)..];
        }

        if (!EmailAddress.TryParse(inner, out EmailAddress? parsed))
        {
            return false;
        }

        address = parsed;
        return true;
    }


    /// <summary>
    /// Finds the angle bracket that closes the path, ignoring any inside a quoted local-part.
    /// </summary>
    /// <remarks>
    /// <c>&lt;"a&gt;b"@example.com&gt;</c> is a legal address: RFC 5321 §4.1.2 permits a quoted
    /// local-part, and a quoted string may contain <c>&gt;</c>. Scanning for the first bracket
    /// would cut the address in half and reject mail that is perfectly well formed. The address
    /// model accepts quoted local-parts, so the path parser must not be the component that
    /// cannot read them back.
    /// </remarks>
    /// <returns>The index of the closing bracket, or -1 if there is none.</returns>
    private static int FindClosingBracket(string path)
    {
        bool inQuotes = false;

        for (int i = 1; i < path.Length; i++)
        {
            char c = path[i];

            if (inQuotes && c == '\\')
            {
                // A quoted-pair escapes whatever follows, including a closing quote.
                i++;
                continue;
            }

            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (c == '>' && !inQuotes)
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>Reads a <c>SIZE=</c> parameter, if present.</summary>
    /// <remarks>
    /// Advisory: the sender's claim about how large the message will be, which lets the server
    /// refuse early rather than after receiving megabytes. It is not trusted — the actual size
    /// is counted during DATA, and a sender who understates it is refused then.
    /// </remarks>
    public static long? ReadSizeParameter(IReadOnlyList<string> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        foreach (string parameter in parameters)
        {
            if (parameter.StartsWith("SIZE=", StringComparison.OrdinalIgnoreCase) &&
                long.TryParse(parameter.AsSpan(5), out long size) &&
                size >= 0)
            {
                return size;
            }
        }

        return null;
    }
}
