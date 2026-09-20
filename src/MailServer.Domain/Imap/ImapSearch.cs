using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace MailServer.Domain.Imap;

/// <summary>
/// One of RFC 3501 §6.4.4's search keys.
/// </summary>
/// <remarks>
/// The whole list, including the three this server can only ever answer one way. <c>RECENT</c>
/// and <c>NEW</c> match nothing and <c>OLD</c> matches everything, because <c>\Recent</c> is
/// never set here — and answering them truthfully is better than refusing a client's perfectly
/// ordinary criteria.
/// </remarks>
public enum ImapSearchKind
{
    All,
    And,
    Answered,
    Bcc,
    Before,
    Body,
    Cc,
    Deleted,
    Draft,
    Flagged,
    From,
    Header,
    Keyword,
    Larger,
    New,
    Not,
    Old,
    On,
    Or,
    Recent,
    Seen,
    SentBefore,
    SentOn,
    SentSince,
    SequenceSet,
    Since,
    Smaller,
    Subject,
    Text,
    To,
    Uid,
    Unanswered,
    Undeleted,
    Undraft,
    Unflagged,
    Unkeyword,
    Unseen,
}

/// <summary>
/// A parsed search criterion, as a tree.
/// </summary>
/// <remarks>
/// <para>
/// A tree rather than a list, because §6.4.4's <c>OR</c> and <c>NOT</c> take search keys as
/// arguments and "A search key can also be a parenthesized list of one or more search keys". A
/// flat list could not express <c>OR (FROM alice SEEN) (FROM bob UNSEEN)</c>, which is an
/// ordinary thing for a client to send.
/// </para>
/// <para>
/// Several keys side by side are an <see cref="ImapSearchKind.And"/>: §6.4.4, "When multiple keys
/// are specified, the result is the intersection (AND function) of all the messages that match
/// those keys."
/// </para>
/// </remarks>
public sealed record ImapSearchKey(
    ImapSearchKind Kind,
    IReadOnlyList<ImapSearchKey> Children,
    string? Text = null,
    string? Field = null,
    DateOnly? Date = null,
    long? Number = null,
    ImapSequenceSet? Set = null)
{
    /// <summary>Whether answering this needs the message's octets rather than its stored columns.</summary>
    /// <remarks>
    /// Checked before a search runs so that a criteria of flags and dates never opens a single
    /// message. §6.4.4 warns that search "is not guaranteed to be fast", but a client asking
    /// <c>UNSEEN</c> should not pay for that.
    /// </remarks>
    public bool NeedsContent =>
        Kind is ImapSearchKind.Bcc or ImapSearchKind.Body or ImapSearchKind.Cc
            or ImapSearchKind.From or ImapSearchKind.Header or ImapSearchKind.SentBefore
            or ImapSearchKind.SentOn or ImapSearchKind.SentSince or ImapSearchKind.Subject
            or ImapSearchKind.Text or ImapSearchKind.To ||
        Children.Any(c => c.NeedsContent);

    /// <summary>A leaf with no arguments.</summary>
    public static ImapSearchKey Simple(ImapSearchKind kind) => new(kind, []);
}

/// <summary>Reading RFC 3501 §6.4.4's searching criteria.</summary>
public static class ImapSearch
{
    /// <summary>The most search keys one command may carry.</summary>
    /// <remarks>
    /// A criteria tree is evaluated once per message, so its size multiplies the folder's. The
    /// cap bounds what a single line can ask for, as every other list limit here does.
    /// </remarks>
    public const int MaxKeys = 256;

    /// <summary>
    /// Parses a whole <c>SEARCH</c> criteria argument.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A leading <c>CHARSET</c> is accepted only for US-ASCII and UTF-8.</b> §6.4.4: "US-ASCII
    /// MUST be supported; other [CHARSET]s MAY be supported", and a server that cannot honour one
    /// answers "NO - search error: can't search that [CHARSET] or criteria". Claiming to search
    /// in a charset this server does not decode would return wrong results rather than an honest
    /// refusal.
    /// </para>
    /// <para>
    /// UTF-8 is accepted because the comparison below is a case-insensitive substring match over
    /// text decoded as UTF-8, which is exactly what a UTF-8 client asks for.
    /// </para>
    /// </remarks>
    public static bool TryParse(
        string criteria,
        [NotNullWhen(true)] out ImapSearchKey? key,
        out bool unsupportedCharset) =>
        TryParse(criteria, null, out key, out unsupportedCharset);

    /// <summary>
    /// Parses search criteria whose strings may have arrived as literals.
    /// </summary>
    /// <remarks>
    /// <b>This is the command literals matter most for.</b> RFC 3501 §6.4.4 takes an
    /// <c>astring</c> for every text key — <c>FROM</c>, <c>SUBJECT</c>, <c>BODY</c>, <c>TEXT</c>
    /// and the rest — and §6.4.4's own <c>CHARSET</c> argument exists precisely so a client can
    /// search for text outside ASCII, which is exactly the text a client sends as a literal
    /// rather than an atom. A tokeniser without this would read <c>FROM {5}</c> as a search for
    /// the five characters <c>{5}</c>, and return a confidently empty result.
    /// </remarks>
    /// <param name="criteria">The criteria text, with each literal left as its <c>{n}</c>.</param>
    /// <param name="literals">The literals already read for this command, in order of appearance.</param>
    /// <param name="key">The parsed criteria, when they parsed.</param>
    /// <param name="unsupportedCharset">Whether the refusal was a charset this server cannot decode.</param>
    public static bool TryParse(
        string criteria,
        IReadOnlyList<string>? literals,
        [NotNullWhen(true)] out ImapSearchKey? key,
        out bool unsupportedCharset)
    {
        ArgumentNullException.ThrowIfNull(criteria);

        key = null;
        unsupportedCharset = false;

        if (!TryTokenise(criteria, literals, out List<Token> tokens) || tokens.Count == 0)
        {
            return false;
        }

        int position = 0;

        if (tokens[0].Kind == TokenKind.Atom &&
            tokens[0].Text.Equals("CHARSET", StringComparison.OrdinalIgnoreCase))
        {
            if (tokens.Count < 2)
            {
                return false;
            }

            string charset = tokens[1].Text;

            if (!charset.Equals("US-ASCII", StringComparison.OrdinalIgnoreCase) &&
                !charset.Equals("UTF-8", StringComparison.OrdinalIgnoreCase))
            {
                unsupportedCharset = true;
                return false;
            }

            position = 2;
        }

        if (!TryParseSequence(tokens, ref position, out ImapSearchKey? parsed) ||
            position != tokens.Count)
        {
            return false;
        }

        key = parsed;
        return true;
    }

    /// <summary>One or more keys side by side, which §6.4.4 intersects.</summary>
    private static bool TryParseSequence(
        List<Token> tokens,
        ref int position,
        [NotNullWhen(true)] out ImapSearchKey? key)
    {
        key = null;

        List<ImapSearchKey> keys = [];

        while (position < tokens.Count && tokens[position].Kind != TokenKind.Close)
        {
            if (!TryParseKey(tokens, ref position, out ImapSearchKey? one))
            {
                return false;
            }

            keys.Add(one);

            if (keys.Count > MaxKeys)
            {
                return false;
            }
        }

        if (keys.Count == 0)
        {
            return false;
        }

        key = keys.Count == 1 ? keys[0] : new ImapSearchKey(ImapSearchKind.And, keys);
        return true;
    }

    private static bool TryParseKey(
        List<Token> tokens,
        ref int position,
        [NotNullWhen(true)] out ImapSearchKey? key)
    {
        key = null;

        if (position >= tokens.Count)
        {
            return false;
        }

        Token token = tokens[position];

        if (token.Kind == TokenKind.Open)
        {
            position++;

            if (!TryParseSequence(tokens, ref position, out ImapSearchKey? inner) ||
                position >= tokens.Count ||
                tokens[position].Kind != TokenKind.Close)
            {
                return false;
            }

            position++;
            key = inner;
            return true;
        }

        if (token.Kind != TokenKind.Atom)
        {
            // A bare quoted string is not a search key; §9's search-key has no such production.
            return false;
        }

        position++;

        string name = token.Text.ToUpperInvariant();

        switch (name)
        {
            case "ALL":
            case "ANSWERED":
            case "DELETED":
            case "DRAFT":
            case "FLAGGED":
            case "NEW":
            case "OLD":
            case "RECENT":
            case "SEEN":
            case "UNANSWERED":
            case "UNDELETED":
            case "UNDRAFT":
            case "UNFLAGGED":
            case "UNSEEN":
                key = ImapSearchKey.Simple(Simple(name));
                return true;

            case "NOT":
                if (!TryParseKey(tokens, ref position, out ImapSearchKey? negated))
                {
                    return false;
                }

                key = new ImapSearchKey(ImapSearchKind.Not, [negated]);
                return true;

            case "OR":
                if (!TryParseKey(tokens, ref position, out ImapSearchKey? left) ||
                    !TryParseKey(tokens, ref position, out ImapSearchKey? right))
                {
                    return false;
                }

                key = new ImapSearchKey(ImapSearchKind.Or, [left, right]);
                return true;

            case "BCC":
            case "BODY":
            case "CC":
            case "FROM":
            case "SUBJECT":
            case "TEXT":
            case "TO":
                if (!TryTakeString(tokens, ref position, out string? text))
                {
                    return false;
                }

                key = new ImapSearchKey(Simple(name), [], Text: text);
                return true;

            case "KEYWORD":
            case "UNKEYWORD":
                if (!TryTakeString(tokens, ref position, out string? flag))
                {
                    return false;
                }

                key = new ImapSearchKey(Simple(name), [], Text: flag);
                return true;

            case "HEADER":
                if (!TryTakeString(tokens, ref position, out string? field) ||
                    !TryTakeString(tokens, ref position, out string? value))
                {
                    return false;
                }

                key = new ImapSearchKey(ImapSearchKind.Header, [], Text: value, Field: field);
                return true;

            case "BEFORE":
            case "ON":
            case "SINCE":
            case "SENTBEFORE":
            case "SENTON":
            case "SENTSINCE":
                if (!TryTakeString(tokens, ref position, out string? dateText) ||
                    !TryParseDate(dateText, out DateOnly date))
                {
                    return false;
                }

                key = new ImapSearchKey(Simple(name), [], Date: date);
                return true;

            case "LARGER":
            case "SMALLER":
                if (!TryTakeString(tokens, ref position, out string? sizeText) ||
                    !long.TryParse(
                        sizeText, NumberStyles.None, CultureInfo.InvariantCulture, out long size))
                {
                    return false;
                }

                key = new ImapSearchKey(Simple(name), [], Number: size);
                return true;

            case "UID":
                if (!TryTakeString(tokens, ref position, out string? uidSet) ||
                    !ImapSequenceSet.TryParse(uidSet, out ImapSequenceSet? uids))
                {
                    return false;
                }

                key = new ImapSearchKey(ImapSearchKind.Uid, [], Set: uids);
                return true;

            default:
                // §9's search-key ends with "sequence-set", so a bare set is a criterion.
                if (ImapSequenceSet.TryParse(token.Text, out ImapSequenceSet? sequence))
                {
                    key = new ImapSearchKey(ImapSearchKind.SequenceSet, [], Set: sequence);
                    return true;
                }

                return false;
        }
    }

    private static ImapSearchKind Simple(string name) => name switch
    {
        "ALL" => ImapSearchKind.All,
        "ANSWERED" => ImapSearchKind.Answered,
        "BCC" => ImapSearchKind.Bcc,
        "BEFORE" => ImapSearchKind.Before,
        "BODY" => ImapSearchKind.Body,
        "CC" => ImapSearchKind.Cc,
        "DELETED" => ImapSearchKind.Deleted,
        "DRAFT" => ImapSearchKind.Draft,
        "FLAGGED" => ImapSearchKind.Flagged,
        "FROM" => ImapSearchKind.From,
        "KEYWORD" => ImapSearchKind.Keyword,
        "LARGER" => ImapSearchKind.Larger,
        "NEW" => ImapSearchKind.New,
        "OLD" => ImapSearchKind.Old,
        "ON" => ImapSearchKind.On,
        "RECENT" => ImapSearchKind.Recent,
        "SEEN" => ImapSearchKind.Seen,
        "SENTBEFORE" => ImapSearchKind.SentBefore,
        "SENTON" => ImapSearchKind.SentOn,
        "SENTSINCE" => ImapSearchKind.SentSince,
        "SINCE" => ImapSearchKind.Since,
        "SMALLER" => ImapSearchKind.Smaller,
        "SUBJECT" => ImapSearchKind.Subject,
        "TEXT" => ImapSearchKind.Text,
        "TO" => ImapSearchKind.To,
        "UNANSWERED" => ImapSearchKind.Unanswered,
        "UNDELETED" => ImapSearchKind.Undeleted,
        "UNDRAFT" => ImapSearchKind.Undraft,
        "UNFLAGGED" => ImapSearchKind.Unflagged,
        "UNKEYWORD" => ImapSearchKind.Unkeyword,
        "UNSEEN" => ImapSearchKind.Unseen,
        _ => ImapSearchKind.All,
    };

    /// <summary>
    /// RFC 3501 §9's <c>date</c>, as a search key writes it.
    /// </summary>
    /// <remarks>
    /// <c>date-text = date-day "-" date-month "-" date-year</c>, and <c>date-day</c> is
    /// "1*2DIGIT" — unpadded, unlike the fixed-width form <c>INTERNALDATE</c> uses. Both are
    /// accepted here, because a client that pads costs nothing to understand.
    /// </remarks>
    private static bool TryParseDate(string text, out DateOnly date) =>
        DateOnly.TryParseExact(
            text.Trim('"'),
            ["d-MMM-yyyy", "dd-MMM-yyyy"],
            CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out date);

    private static bool TryTakeString(
        List<Token> tokens,
        ref int position,
        [NotNullWhen(true)] out string? text)
    {
        text = null;

        if (position >= tokens.Count || tokens[position].Kind == TokenKind.Close)
        {
            return false;
        }

        text = tokens[position].Text;
        position++;
        return true;
    }

    private enum TokenKind
    {
        Atom,
        Quoted,
        Open,
        Close,
    }

    private readonly record struct Token(TokenKind Kind, string Text);

    /// <summary>
    /// Splits the criteria into atoms, quoted strings and brackets.
    /// </summary>
    /// <remarks>
    /// Quoted strings are taken whole, so <c>SUBJECT "quarterly report"</c> is one argument
    /// rather than two keys — and a bracket inside quotes is text, not structure.
    /// </remarks>
    private static bool TryTokenise(string text, IReadOnlyList<string>? literals, out List<Token> tokens)
    {
        tokens = [];

        int literalIndex = 0;
        int i = 0;

        while (i < text.Length)
        {
            char c = text[i];

            if (c == ' ')
            {
                i++;
                continue;
            }

            if (c == '(')
            {
                tokens.Add(new Token(TokenKind.Open, "("));
                i++;
                continue;
            }

            if (c == ')')
            {
                tokens.Add(new Token(TokenKind.Close, ")"));
                i++;
                continue;
            }

            if (c == '"')
            {
                int close = text.IndexOf('"', i + 1);

                if (close < 0)
                {
                    return false;
                }

                tokens.Add(new Token(TokenKind.Quoted, text[(i + 1)..close]));
                i = close + 1;
                continue;
            }

            // A literal specifier stands where a string would, so it produces a Quoted token
            // rather than an Atom: an atom can be a key name - FROM, SUBJECT, ALL - and a
            // literal never is. Reading it as an atom would let a client whose search text
            // happened to be "NOT" have it parsed as the operator.
            if (c == '{')
            {
                int close = text.IndexOf('}', i);

                if (close < 0 || !ImapLiteralSpecifier.TryParse(text[i..(close + 1)], out _))
                {
                    return false;
                }

                if (literals is null || literalIndex >= literals.Count)
                {
                    // The specifier is here but its octets are not, so there is nothing to
                    // search for. Refusing beats searching for the specifier's own text.
                    return false;
                }

                tokens.Add(new Token(TokenKind.Quoted, literals[literalIndex++]));
                i = close + 1;
                continue;
            }

            int end = i;

            while (end < text.Length && text[end] is not (' ' or '(' or ')'))
            {
                end++;
            }

            tokens.Add(new Token(TokenKind.Atom, text[i..end]));
            i = end;
        }

        return true;
    }
}
