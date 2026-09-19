using System.Text;

namespace MailServer.Domain.Imap;

/// <summary>
/// One of RFC 3501 §7.4.2's address structures.
/// </summary>
/// <remarks>
/// <para>
/// §7.4.2: "An address structure is a parenthesized list that describes an electronic mail
/// address. The fields of an address structure are in the following order: personal name, [SMTP]
/// at-domain-list (source route), mailbox name, and host name."
/// </para>
/// <para>
/// <b>A NIL host is not a missing host — it means this is a group marker.</b> §7.4.2:
/// "[RFC-2822] group syntax is indicated by a special form of address structure in which the host
/// name field is NIL. If the mailbox name field is also NIL, this is an end of group marker […]
/// If the mailbox name field is non-NIL, this is a start of group marker, and the mailbox name
/// field holds the group name phrase." So the two markers are addresses in the list rather than
/// nesting, and a parser that emitted NIL for an address it merely failed to split would turn one
/// malformed recipient into an unterminated group. See <see cref="ImapAddressList.Parse"/>.
/// </para>
/// </remarks>
/// <param name="Name">The display name with its RFC 2822 quoting removed, or null.</param>
/// <param name="Route">The <c>obs-route</c> from an <c>angle-addr</c>, or null. Almost always null.</param>
/// <param name="Mailbox">The local part with its quoting removed, the group name, or null.</param>
/// <param name="Host">The domain, or null for a group marker.</param>
public sealed record ImapAddress(string? Name, string? Route, string? Mailbox, string? Host)
{
    /// <summary>The marker that opens a group: the name, and nothing else.</summary>
    public static ImapAddress GroupStart(string name) => new(null, null, name, null);

    /// <summary>The marker that closes a group — RFC 2822's semicolon.</summary>
    public static ImapAddress GroupEnd { get; } = new(null, null, null, null);

    /// <summary>Whether this opens a group rather than naming a mailbox.</summary>
    public bool IsGroupStart => Host is null && Mailbox is not null;

    /// <summary>Whether this closes a group.</summary>
    public bool IsGroupEnd => Host is null && Mailbox is null;
}

/// <summary>
/// Turns an RFC 2822 <c>address-list</c> header body into address structures.
/// </summary>
/// <remarks>
/// <para>
/// <b>It never fails.</b> A header field is whatever a sending agent wrote, and a mailbox that
/// refused to describe a message because its <c>To</c> line is malformed would hide the message
/// rather than the defect. Every shape this cannot parse still produces an address, and the parts
/// it could not identify are simply not filled in.
/// </para>
/// <para>
/// <b>Comments are dropped and quoting is removed, because §7.4.2 asks for both.</b> The personal
/// name "holds phrase from [RFC-2822] mailbox after removing [RFC-2822] quoting" and the mailbox
/// name "holds [RFC-2822] local-part after removing [RFC-2822] quoting". RFC 2822 §3.2.3 makes a
/// comment part of the folding whitespace and therefore not part of either.
/// </para>
/// <para>
/// <b>Encoded words are left alone.</b> A display name of <c>=?utf-8?B?…?=</c> is passed through
/// exactly as written: RFC 2047 §6.2 puts the decoding in the client, and a server that decoded
/// it would have to re-encode the result into a charset the envelope has no field to name.
/// </para>
/// </remarks>
public static class ImapAddressList
{
    /// <summary>
    /// Parses a header body into addresses, in the order they were written.
    /// </summary>
    /// <remarks>
    /// Returns an empty list for a field that is present but blank, which RFC 3501 §7.4.2 turns
    /// into <c>NIL</c>: "If the From, To, cc, and bcc header lines are absent […] or are present
    /// but empty, the corresponding member of the envelope is NIL."
    /// </remarks>
    public static IReadOnlyList<ImapAddress> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        List<ImapAddress> addresses = [];
        int index = 0;

        while (index < text.Length)
        {
            int before = index;

            index = ParseOne(text, index, addresses, allowGroup: true);

            // Nothing in ParseOne should stand still, but a malformed header is exactly where a
            // scanner acquires an off-by-one, and a server that spun on one would stop answering
            // every other connection too.
            if (index <= before)
            {
                index = before + 1;
            }
        }

        return addresses;
    }

    /// <summary>
    /// Reads one <c>address</c>, returning where the next one starts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §3.4: <c>address = mailbox / group</c>, <c>mailbox = name-addr / addr-spec</c> and
    /// <c>name-addr = [display-name] angle-addr</c>. The three are told apart by what ends the
    /// leading phrase rather than by looking ahead: <c>&lt;</c> makes it a <c>name-addr</c>,
    /// <c>:</c> makes it a group, and a comma or the end of the field makes the phrase itself the
    /// <c>addr-spec</c>.
    /// </para>
    /// <para>
    /// <b>A group inside a group is read as text.</b> §3.4's <c>group</c> takes a
    /// <c>mailbox-list</c>, not an <c>address-list</c>, so nesting is not grammatical — and
    /// letting a colon open a second group would let a crafted header drive this method as deep
    /// as the field is long.
    /// </para>
    /// </remarks>
    private static int ParseOne(string text, int index, List<ImapAddress> into, bool allowGroup)
    {
        StringBuilder raw = new();
        int i = index;

        while (i < text.Length)
        {
            char c = text[i];

            if (c == '"')
            {
                int end = SkipQuoted(text, i);

                raw.Append(text[i..end]);
                i = end;
                continue;
            }

            if (c == '(')
            {
                i = SkipComment(text, i);
                continue;
            }

            if (c == '[')
            {
                int end = SkipDomainLiteral(text, i);

                raw.Append(text[i..end]);
                i = end;
                continue;
            }

            if (c is '<' or ',' or ';' || (c == ':' && allowGroup))
            {
                break;
            }

            raw.Append(c);
            i++;
        }

        if (i < text.Length && text[i] == '<')
        {
            int close = FindAngleEnd(text, i);
            string inner = close < 0 ? text[(i + 1)..] : text[(i + 1)..close];

            into.Add(FromAngleAddr(Phrase(raw.ToString()), inner));

            return SkipToSeparator(text, close < 0 ? text.Length : close + 1);
        }

        if (i < text.Length && text[i] == ':' && allowGroup)
        {
            into.Add(ImapAddress.GroupStart(Phrase(raw.ToString())));

            i++;

            while (i < text.Length && text[i] != ';')
            {
                int before = i;

                i = ParseOne(text, i, into, allowGroup: false);

                if (i <= before)
                {
                    i = before + 1;
                }
            }

            into.Add(ImapAddress.GroupEnd);

            // The semicolon, then whatever separates this group from the next address.
            return SkipToSeparator(text, i < text.Length ? i + 1 : i);
        }

        string spec = raw.ToString().Trim(' ', '\t');

        if (spec.Length > 0)
        {
            into.Add(FromAddrSpec(null, null, spec));
        }

        // A semicolon is the caller's to consume; it ends a group rather than an address.
        return i < text.Length && text[i] == ',' ? i + 1 : i;
    }

    /// <summary>
    /// Splits an <c>angle-addr</c> into its optional route and its <c>addr-spec</c>.
    /// </summary>
    /// <remarks>
    /// §4.4: <c>obs-angle-addr = [CFWS] "&lt;" [obs-route] addr-spec "&gt;" [CFWS]</c> with
    /// <c>obs-route = [CFWS] obs-domain-list ":" [CFWS]</c>. So a colon inside the brackets marks
    /// the end of a source route, and RFC 3501 §9's <c>addr-adl</c> "holds route from [RFC-2822]
    /// route-addr if non-NIL" — the domains, without the colon that terminated them.
    /// </remarks>
    private static ImapAddress FromAngleAddr(string? name, string inner)
    {
        int colon = FindTopLevel(inner, ':');

        if (colon < 0)
        {
            return FromAddrSpec(name, null, inner);
        }

        string route = StripComments(inner[..colon]).Trim(' ', '\t');

        return FromAddrSpec(name, route.Length == 0 ? null : route, inner[(colon + 1)..]);
    }

    /// <summary>
    /// Splits an <c>addr-spec</c> into its local part and its domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Split at the last unquoted at-sign, not the first.</b> §3.4.1 allows exactly one, but
    /// <c>a@b@c</c> arrives anyway; splitting last keeps the domain a domain, which is the half a
    /// client routes and displays on. A quoted local part may contain its own at-sign and a
    /// domain literal may contain one too, so both are stepped over whole.
    /// </para>
    /// <para>
    /// <b>A spec with no at-sign gets an empty host rather than NIL.</b> §7.4.2 reserves a NIL
    /// host for group syntax, so answering NIL for <c>From: Mailer Daemon</c> would tell the
    /// client a group had opened and never closed — and every address after it in the list would
    /// be read as one of its members. An empty string is not NIL, says the same thing about the
    /// message being malformed, and leaves the list's shape alone.
    /// </para>
    /// </remarks>
    private static ImapAddress FromAddrSpec(string? name, string? route, string spec)
    {
        string clean = StripComments(spec).Trim(' ', '\t');
        int at = FindTopLevelLast(clean, '@');

        string local = at < 0 ? clean : clean[..at];
        string host = at < 0 ? string.Empty : clean[(at + 1)..];

        return new ImapAddress(
            string.IsNullOrEmpty(name) ? null : name,
            route,
            Unquote(local.Trim(' ', '\t')),
            host.Trim(' ', '\t'));
    }

    /// <summary>
    /// Reduces a <c>phrase</c> to the text it stands for.
    /// </summary>
    /// <remarks>
    /// §3.2.6: <c>phrase = 1*word</c> and <c>word = atom / quoted-string</c>, with the folding
    /// whitespace between words carrying no meaning — so the words are rejoined with one space
    /// each however many blanks separated them. Inside a quoted string the blanks are content and
    /// are kept: §3.2.5 makes "the quoted-string […] what is contained between the two quote
    /// characters", less the backslashes of its quoted-pairs.
    /// </remarks>
    private static string Phrase(string raw)
    {
        StringBuilder result = new();
        bool pendingSpace = false;
        int i = 0;

        while (i < raw.Length)
        {
            char c = raw[i];

            if (c is ' ' or '\t')
            {
                pendingSpace = result.Length > 0;
                i++;
                continue;
            }

            if (pendingSpace)
            {
                result.Append(' ');
                pendingSpace = false;
            }

            if (c == '"')
            {
                int end = SkipQuoted(raw, i);

                result.Append(Unescape(raw[i..end]));
                i = end;
                continue;
            }

            result.Append(c);
            i++;
        }

        return result.ToString();
    }

    /// <summary>Removes the quoting from a value that may be part quoted and part not.</summary>
    private static string Unquote(string value)
    {
        if (!value.Contains('"', StringComparison.Ordinal))
        {
            return value;
        }

        StringBuilder result = new(value.Length);
        int i = 0;

        while (i < value.Length)
        {
            if (value[i] == '"')
            {
                int end = SkipQuoted(value, i);

                result.Append(Unescape(value[i..end]));
                i = end;
                continue;
            }

            result.Append(value[i]);
            i++;
        }

        return result.ToString();
    }

    /// <summary>Strips one quoted string's delimiters and its quoted-pair backslashes.</summary>
    private static string Unescape(string quoted)
    {
        int start = quoted.Length > 0 && quoted[0] == '"' ? 1 : 0;
        int end = quoted.Length > start && quoted[^1] == '"' ? quoted.Length - 1 : quoted.Length;

        StringBuilder result = new(end - start);

        for (int i = start; i < end; i++)
        {
            // §3.2.2: quoted-pair = "\" text. The backslash is not part of the value, and a
            // trailing one with nothing after it is dropped rather than kept as a character.
            if (quoted[i] == '\\' && i + 1 < end)
            {
                i++;
            }
            else if (quoted[i] == '\\')
            {
                break;
            }

            result.Append(quoted[i]);
        }

        return result.ToString();
    }

    /// <summary>Drops every comment, leaving quoted strings and domain literals untouched.</summary>
    private static string StripComments(string value)
    {
        if (!value.Contains('(', StringComparison.Ordinal))
        {
            return value;
        }

        StringBuilder result = new(value.Length);
        int i = 0;

        while (i < value.Length)
        {
            char c = value[i];

            if (c == '(')
            {
                i = SkipComment(value, i);
                continue;
            }

            int end = c switch
            {
                '"' => SkipQuoted(value, i),
                '[' => SkipDomainLiteral(value, i),
                _ => i + 1,
            };

            result.Append(value[i..end]);
            i = end;
        }

        return result.ToString();
    }

    /// <summary>The first occurrence of a character outside any quoted or bracketed run.</summary>
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

            i = c switch
            {
                '"' => SkipQuoted(value, i),
                '(' => SkipComment(value, i),
                '[' => SkipDomainLiteral(value, i),
                _ => i + 1,
            };
        }

        return -1;
    }

    /// <summary>The last occurrence of a character outside any quoted or bracketed run.</summary>
    private static int FindTopLevelLast(string value, char target)
    {
        int found = -1;
        int i = 0;

        while (i < value.Length)
        {
            char c = value[i];

            if (c == target)
            {
                found = i;
                i++;
                continue;
            }

            i = c switch
            {
                '"' => SkipQuoted(value, i),
                '(' => SkipComment(value, i),
                '[' => SkipDomainLiteral(value, i),
                _ => i + 1,
            };
        }

        return found;
    }

    /// <summary>Advances past the separator between two addresses, stopping at a group's end.</summary>
    private static int SkipToSeparator(string text, int index)
    {
        int i = index;

        while (i < text.Length)
        {
            char c = text[i];

            if (c == ';')
            {
                return i;
            }

            if (c == ',')
            {
                return i + 1;
            }

            i = c switch
            {
                '"' => SkipQuoted(text, i),
                '(' => SkipComment(text, i),
                '[' => SkipDomainLiteral(text, i),
                _ => i + 1,
            };
        }

        return i;
    }

    /// <summary>
    /// The index just past a quoted string, or the end of the text if it is unterminated.
    /// </summary>
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

    /// <summary>
    /// The index just past a comment. §3.2.3 makes comments nest, so the depth is counted.
    /// </summary>
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

    /// <summary>
    /// The index just past a domain literal. §3.4.1's <c>dtext</c> excludes the brackets, so
    /// these do not nest, but a quoted-pair may hide one.
    /// </summary>
    private static int SkipDomainLiteral(string value, int index)
    {
        int i = index + 1;

        while (i < value.Length)
        {
            if (value[i] == '\\')
            {
                i += 2;
                continue;
            }

            if (value[i] == ']')
            {
                return i + 1;
            }

            i++;
        }

        return value.Length;
    }

    /// <summary>The matching close of an <c>angle-addr</c>, or -1 when it is unterminated.</summary>
    private static int FindAngleEnd(string text, int index)
    {
        int i = index + 1;

        while (i < text.Length)
        {
            char c = text[i];

            if (c == '>')
            {
                return i;
            }

            i = c switch
            {
                '"' => SkipQuoted(text, i),
                '(' => SkipComment(text, i),
                '[' => SkipDomainLiteral(text, i),
                _ => i + 1,
            };
        }

        return -1;
    }
}
