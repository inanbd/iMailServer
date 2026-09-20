using System.Globalization;

namespace MailServer.Domain.Mail;

/// <summary>
/// The peer, as one hop described it.
/// </summary>
/// <param name="GreetedName">
/// The name the client gave in EHLO. <b>A claim.</b> RFC 5321 §4.4's FROM clause "SHOULD contain
/// both (1) the name of the source host as presented in the EHLO command and (2) an address
/// literal containing the IP address of the source, determined from the TCP connection" — and
/// only the second of those is something the receiving server established for itself.
/// </param>
/// <param name="ObservedName">
/// The name in the parenthesised <c>TCP-info</c>, which a receiving server puts there after a
/// reverse lookup. Absent from most headers.
/// </param>
/// <param name="ObservedAddress">
/// The address literal in the <c>TCP-info</c>. <b>The one thing in a Received header the hop
/// that wrote it could not have been lied to about</b>, since RFC 5321 §4.4's ABNF annotates
/// <c>TCP-info</c> as "Information derived by server from TCP connection not client EHLO".
/// </param>
public sealed record ReceivedFrom(string? GreetedName, string? ObservedName, string? ObservedAddress);

/// <summary>
/// One <c>Received:</c> header, read back into the clauses RFC 5321 §4.4 defines.
/// </summary>
/// <param name="From">The FROM clause, or null when the header has none.</param>
/// <param name="By">The BY clause — the host that wrote this header.</param>
/// <param name="Via">The VIA clause, which almost nothing emits.</param>
/// <param name="With">The WITH clause — the protocol, per RFC 3848's registry.</param>
/// <param name="Id">The ID clause — that hop's own identifier for the message.</param>
/// <param name="For">The FOR clause, which RFC 5321 §4.4 says "MUST contain exactly one path".</param>
/// <param name="Timestamp">
/// The date-time after the semicolon, or null when it is absent or unreadable. Independent of
/// every other hop's clock — see <see cref="ReceivedChain"/>.
/// </param>
/// <param name="Comments">Every parenthesised comment, in order, with the parentheses removed.</param>
/// <param name="Unparsed">
/// True when the header carried no recognisable clause at all. Reported rather than discarded:
/// a hop whose header this parser cannot read is still a hop, and dropping it would shorten a
/// path the operator is trying to count.
/// </param>
/// <param name="AmbiguousClauses">
/// True when a clause keyword appears more than once, which RFC 5321 §4.4's <c>Stamp</c> never
/// produces. <b>No reading of such a header is authoritative</b>: the extra keyword was written
/// by something not following the grammar, and in practice that means a greeting name chosen to
/// look like a clause. See <see cref="ReceivedTrace"/>.
/// </param>
public sealed record ReceivedHop(
    ReceivedFrom? From,
    string? By,
    string? Via,
    string? With,
    string? Id,
    string? For,
    DateTimeOffset? Timestamp,
    IReadOnlyList<string> Comments,
    bool Unparsed,
    bool AmbiguousClauses = false);

/// <summary>One hop and how long the message took to reach it.</summary>
/// <param name="Hop">The hop.</param>
/// <param name="Delay">
/// The time between the hop below this one and this one, or null when either lacks a timestamp.
/// <b>May be negative</b>, and is reported that way — see <see cref="ReceivedChain"/>.
/// </param>
public sealed record ReceivedHopTiming(ReceivedHop Hop, TimeSpan? Delay);

/// <summary>
/// A message's trace chain.
/// </summary>
/// <param name="Hops">
/// The hops in the order they appear in the header block, which RFC 5321 §4.4 makes newest
/// first: "SMTP servers MUST prepend Received lines to messages; they MUST NOT change the order
/// of existing lines or insert Received lines in any other location."
/// </param>
/// <param name="TotalTransit">
/// The time from the earliest readable timestamp to the latest, or null when fewer than two
/// hops carry one.
/// </param>
/// <remarks>
/// <para>
/// <b>Every delay here is a difference between two independent clocks.</b> RFC 5321 §4.4 asks
/// for the comparison anyway — "As the Internet grows, comparability of Received header fields
/// is important for detecting problems, especially slow relays" — but nothing makes two hops
/// agree about the time, and a negative delay is a routine consequence rather than a parse
/// failure.
/// </para>
/// <para>
/// <b>Negative delays are reported, not clamped.</b> Clamping to zero would hide the one thing a
/// negative delay actually tells an operator: that one of those two hosts has a clock problem —
/// which is itself a deliverability finding, and which silently distorts every other delay in
/// the chain.
/// </para>
/// </remarks>
public sealed record ReceivedChain(IReadOnlyList<ReceivedHopTiming> Hops, TimeSpan? TotalTransit);

/// <summary>
/// Reads <c>Received:</c> headers back into their clauses.
/// </summary>
/// <remarks>
/// <para>
/// <b>Tolerant on purpose.</b> RFC 5322 §3.6.7's grammar for the field is
/// <c>received = "Received:" *received-token ";" date-time CRLF</c> and the section says outright
/// that "the trace fields are strictly informational, and any formal interpretation of them is
/// outside of the scope of this document". The clause structure this parser looks for comes from
/// RFC 5321 §4.4 instead, and a great deal of real mail does not follow it. So nothing here
/// fails: a header that yields no clause is returned as one, marked
/// <see cref="ReceivedHop.Unparsed"/>.
/// </para>
/// <para>
/// <b>Nothing this parser returns is evidence of anything.</b> Any host in a path can write any
/// Received header it likes, including ones describing hops that never happened, and the hops
/// below the first one this server trusts are attacker-controlled in exactly the way a message
/// body is. The value of the chain is that it shows what was claimed, in order; treating it as a
/// record of what occurred is the mistake it exists to expose.
/// </para>
/// </remarks>
public static class ReceivedTrace
{
    /// <summary>The clause keywords RFC 5321 §4.4 defines, lowercase.</summary>
    private static readonly string[] Clauses = ["from", "by", "via", "with", "id", "for"];

    /// <summary>
    /// The obsolete zone names RFC 5322 §4.3 still permits, and their offsets.
    /// </summary>
    /// <remarks>
    /// <c>obs-zone = "UT" / "GMT" / "EST" / "EDT" / "CST" / "CDT" / "MST" / "MDT" / "PST" /
    /// "PDT"</c>. <see cref="DateTimeOffset.TryParse(string, out DateTimeOffset)"/> reads none of
    /// them, so a header stamped by an older relay would lose its timestamp — and with it every
    /// delay either side of that hop.
    /// </remarks>
    private static readonly Dictionary<string, TimeSpan> ObsoleteZones = new(StringComparer.OrdinalIgnoreCase)
    {
        ["UT"] = TimeSpan.Zero,
        ["GMT"] = TimeSpan.Zero,
        ["EST"] = TimeSpan.FromHours(-5),
        ["EDT"] = TimeSpan.FromHours(-4),
        ["CST"] = TimeSpan.FromHours(-6),
        ["CDT"] = TimeSpan.FromHours(-5),
        ["MST"] = TimeSpan.FromHours(-7),
        ["MDT"] = TimeSpan.FromHours(-6),
        ["PST"] = TimeSpan.FromHours(-8),
        ["PDT"] = TimeSpan.FromHours(-7),
    };

    /// <summary>
    /// Reads one header's value — everything after <c>Received:</c>, unfolded.
    /// </summary>
    public static ReceivedHop Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return new ReceivedHop(null, null, null, null, null, null, null, [], Unparsed: true);
        }

        string unfolded = Unfold(value);

        (string body, DateTimeOffset? timestamp) = SplitTimestamp(unfolded);

        List<string> comments = [];
        string stripped = StripComments(body, comments);

        (Dictionary<string, string> clauses, bool ambiguous) = ReadClauses(stripped);

        ReceivedFrom? from = clauses.TryGetValue("from", out string? fromValue)
            ? ReadFrom(fromValue, body)
            : null;

        bool anything = from is not null ||
                        clauses.Count > 0 ||
                        timestamp is not null;

        return new ReceivedHop(
            from,
            Clause(clauses, "by"),
            Clause(clauses, "via"),
            Clause(clauses, "with"),
            Clause(clauses, "id"),
            Clause(clauses, "for"),
            timestamp,
            comments,
            Unparsed: !anything,
            AmbiguousClauses: ambiguous);
    }

    /// <summary>
    /// Reads a whole chain and computes the time between consecutive hops.
    /// </summary>
    /// <param name="values">
    /// The <c>Received:</c> header values in the order they appear in the header block, newest
    /// first. Reordering them would invert every delay, and RFC 5321 §4.4 guarantees the order:
    /// "An Internet mail program MUST NOT change or delete a Received: line that was previously
    /// added to the message header section."
    /// </param>
    public static ReceivedChain ParseChain(IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        List<ReceivedHop> hops = [.. values.Select(Parse)];
        List<ReceivedHopTiming> timings = [];

        for (int i = 0; i < hops.Count; i++)
        {
            // The hop below this one in the header block handed the message to it, so the delay
            // is this hop's stamp minus that one's. The last hop in the block is the first in
            // time and has nothing before it.
            ReceivedHop? earlier = i + 1 < hops.Count ? hops[i + 1] : null;

            TimeSpan? delay = hops[i].Timestamp is { } later && earlier?.Timestamp is { } before
                ? later - before
                : null;

            timings.Add(new ReceivedHopTiming(hops[i], delay));
        }

        List<DateTimeOffset> stamps = [.. hops.Where(h => h.Timestamp is not null).Select(h => h.Timestamp!.Value)];

        TimeSpan? total = stamps.Count >= 2 ? stamps.Max() - stamps.Min() : null;

        return new ReceivedChain(timings, total);
    }

    // -------------------------------------------------------------------------------------------
    // The pieces.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Splits the clause body from the timestamp at the last top-level semicolon.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 5321 §4.4: <c>Stamp = From-domain By-domain Opt-info [CFWS] ";" FWS date-time</c>. One
    /// semicolon, at the end — but a comment may contain others, and
    /// <c>with ESMTPS (TLS1.3; AEAD-AES256)</c> is a shape real servers emit. So the split is at
    /// the last semicolon that is not inside a comment, a quoted string or an angle-addr, and
    /// scanning from the right is what makes an unbalanced comment earlier in the header
    /// harmless.
    /// </para>
    /// </remarks>
    private static (string Body, DateTimeOffset? Timestamp) SplitTimestamp(string value)
    {
        int semicolon = LastTopLevelSemicolon(value);

        if (semicolon < 0)
        {
            return (value, null);
        }

        string body = value[..semicolon];
        string date = value[(semicolon + 1)..].Trim();

        return (body, ParseDate(date));
    }

    private static int LastTopLevelSemicolon(string value)
    {
        int depth = 0;
        int angle = 0;
        bool quoted = false;
        int found = -1;

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            // RFC 5322 §3.2.1: a quoted-pair is a backslash and the character after it, which is
            // therefore never a delimiter whatever it happens to be.
            if (c == '\\')
            {
                i++;
                continue;
            }

            if (quoted)
            {
                if (c == '"')
                {
                    quoted = false;
                }

                continue;
            }

            switch (c)
            {
                case '"':
                    quoted = true;
                    break;

                // RFC 5322 §3.2.2: ccontent includes comment, so they nest.
                case '(':
                    depth++;
                    break;

                case ')' when depth > 0:
                    depth--;
                    break;

                case '<':
                    angle++;
                    break;

                case '>' when angle > 0:
                    angle--;
                    break;

                case ';' when depth == 0 && angle == 0:
                    found = i;
                    break;

                default:
                    break;
            }
        }

        return found;
    }

    /// <summary>
    /// Reads an RFC 5322 §3.3 date-time, including the obsolete zone names §4.3 still allows.
    /// </summary>
    private static DateTimeOffset? ParseDate(string date)
    {
        if (date.Length == 0)
        {
            return null;
        }

        // A trailing parenthesised comment is legal after the zone - "(UTC)" and "(PST)" are
        // both common - and would otherwise make the whole date unreadable.
        int comment = date.IndexOf('(', StringComparison.Ordinal);

        string trimmed = (comment >= 0 ? date[..comment] : date).Trim();

        if (DateTimeOffset.TryParse(
                trimmed,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces,
                out DateTimeOffset parsed))
        {
            return parsed;
        }

        int lastSpace = trimmed.LastIndexOf(' ');

        if (lastSpace > 0 &&
            ObsoleteZones.TryGetValue(trimmed[(lastSpace + 1)..], out TimeSpan offset) &&
            DateTime.TryParse(
                trimmed[..lastSpace],
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.NoCurrentDateDefault,
                out DateTime naive))
        {
            return new DateTimeOffset(DateTime.SpecifyKind(naive, DateTimeKind.Unspecified), offset);
        }

        return null;
    }

    /// <summary>Removes comments, collecting them, so clause scanning sees only clause text.</summary>
    private static string StripComments(string value, List<string> comments)
    {
        System.Text.StringBuilder outside = new(value.Length);
        System.Text.StringBuilder inside = new();

        int depth = 0;
        bool quoted = false;

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            if (c == '\\' && i + 1 < value.Length)
            {
                (depth > 0 ? inside : outside).Append(value[i + 1]);
                i++;
                continue;
            }

            if (quoted)
            {
                (depth > 0 ? inside : outside).Append(c);

                if (c == '"')
                {
                    quoted = false;
                }

                continue;
            }

            switch (c)
            {
                case '"':
                    quoted = true;
                    (depth > 0 ? inside : outside).Append(c);
                    break;

                case '(':
                    depth++;

                    if (depth > 1)
                    {
                        inside.Append(c);
                    }

                    break;

                case ')' when depth > 0:
                    depth--;

                    if (depth == 0)
                    {
                        comments.Add(inside.ToString());
                        inside.Clear();
                    }
                    else
                    {
                        inside.Append(c);
                    }

                    break;

                default:
                    (depth > 0 ? inside : outside).Append(c);
                    break;
            }
        }

        // An unterminated comment is a malformed header, and what it opened is still worth
        // reporting: a hop that wrote "(unknown [1.2.3.4]" has told the operator the address.
        if (inside.Length > 0)
        {
            comments.Add(inside.ToString());
        }

        return outside.ToString();
    }

    /// <summary>
    /// Splits the clause text at its keywords.
    /// </summary>
    /// <remarks>
    /// Keyword-driven rather than positional, because RFC 5321 §4.4's <c>Opt-info</c> makes every
    /// clause but FROM and BY optional and real headers omit and reorder them freely. A repeated
    /// keyword keeps the first: a header with two BY clauses is malformed, and the first is the
    /// one the ABNF's position agrees with.
    /// </remarks>
    private static (Dictionary<string, string> Clauses, bool Ambiguous) ReadClauses(string text)
    {
        Dictionary<string, string> clauses = new(StringComparer.OrdinalIgnoreCase);

        List<(int Start, int End, string Name)> found = [];

        foreach (string clause in Clauses)
        {
            int at = 0;

            while (at < text.Length)
            {
                int index = text.IndexOf(clause, at, StringComparison.OrdinalIgnoreCase);

                if (index < 0)
                {
                    break;
                }

                if (IsWholeToken(text, index, clause.Length))
                {
                    found.Add((index, index + clause.Length, clause));
                }

                at = index + 1;
            }
        }

        found.Sort((a, b) => a.Start.CompareTo(b.Start));

        for (int i = 0; i < found.Count; i++)
        {
            int valueStart = found[i].End;
            int valueEnd = i + 1 < found.Count ? found[i + 1].Start : text.Length;

            string value = text[valueStart..valueEnd].Trim();

            if (value.Length > 0 && !clauses.ContainsKey(found[i].Name))
            {
                clauses[found[i].Name] = value;
            }
        }

        // RFC 5321 §4.4's Stamp carries exactly one of each clause, so a repeat means the text
        // contains a keyword nobody following the grammar put there - which in practice means a
        // greeting name chosen to look like one. See ReceivedHop.AmbiguousClauses.
        bool ambiguous = found
            .GroupBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            .Any(g => g.Count() > 1);

        return (clauses, ambiguous);
    }

    /// <summary>
    /// Whether a match sits on token boundaries rather than inside a longer word.
    /// </summary>
    /// <remarks>
    /// Without this, the <c>by</c> keyword matches inside <c>mailby.example.com</c> and the
    /// <c>id</c> keyword matches inside almost any hostname containing those two letters — which
    /// would split one clause into several and attribute the pieces to hops that do not exist.
    /// </remarks>
    private static bool IsWholeToken(string text, int start, int length)
    {
        if (start > 0 && !char.IsWhiteSpace(text[start - 1]))
        {
            return false;
        }

        int after = start + length;

        return after >= text.Length || char.IsWhiteSpace(text[after]);
    }

    private static string? Clause(Dictionary<string, string> clauses, string name) =>
        clauses.TryGetValue(name, out string? value) ? value : null;

    /// <summary>
    /// Reads the FROM clause, splitting what the client claimed from what the server observed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 5321 §4.4: <c>Extended-Domain = Domain / (Domain FWS "(" TCP-info ")") /
    /// (address-literal FWS "(" TCP-info ")")</c>, and <c>TCP-info = address-literal / (Domain
    /// FWS address-literal)</c>, annotated "Information derived by server from TCP connection not
    /// client EHLO".
    /// </para>
    /// <para>
    /// <b>That annotation is the whole reason this clause is split into three fields.</b> The
    /// greeted name is whatever the connecting client typed; the address in the brackets is what
    /// the receiving server saw on the socket. An analyser that presented them as one string
    /// would flatten the only distinction in the header that survives a hostile sender.
    /// </para>
    /// </remarks>
    private static ReceivedFrom ReadFrom(string clauseText, string original)
    {
        // The first token only: §4.4's Extended-Domain is one domain, so anything after it was
        // not written by a server following the grammar. Keeping the whole run would put an
        // attacker's injected clause text into the greeted name as though it were a hostname.
        string greeted = clauseText.Trim().Split(
            (char[])[' ', '\t'],
            2,
            StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } parts
            ? parts[0]
            : string.Empty;

        // The TCP-info lives in the comment that follows the greeted name in the ORIGINAL text:
        // clause scanning runs on the comment-stripped copy, so it is not there to be found.
        string? observedName = null;
        string? observedAddress = null;

        int from = original.IndexOf("from", StringComparison.OrdinalIgnoreCase);

        if (from >= 0)
        {
            int open = original.IndexOf('(', from);
            int close = open >= 0 ? MatchingParen(original, open) : -1;

            if (open >= 0 && close > open)
            {
                (observedName, observedAddress) = ReadTcpInfo(original[(open + 1)..close]);
            }
        }

        return new ReceivedFrom(
            greeted.Length == 0 ? null : greeted,
            observedName,
            observedAddress);
    }

    private static int MatchingParen(string text, int open)
    {
        int depth = 0;

        for (int i = open; i < text.Length; i++)
        {
            if (text[i] == '\\')
            {
                i++;
                continue;
            }

            if (text[i] == '(')
            {
                depth++;
            }
            else if (text[i] == ')')
            {
                depth--;

                if (depth == 0)
                {
                    return i;
                }
            }
        }

        return -1;
    }

    /// <summary>
    /// Splits a <c>TCP-info</c> into its optional name and its address literal.
    /// </summary>
    /// <remarks>
    /// The address is recognised by its brackets, which RFC 5321 §4.1.3's <c>address-literal</c>
    /// requires — <c>"[" ( IPv4-address-literal / IPv6-address-literal / … ) "]"</c>. Anything
    /// before them is the name a receiving server resolved. A comment with no brackets is
    /// somebody's free text and yields neither.
    /// </remarks>
    private static (string? Name, string? Address) ReadTcpInfo(string comment)
    {
        int open = comment.IndexOf('[', StringComparison.Ordinal);
        int close = open >= 0 ? comment.IndexOf(']', open) : -1;

        if (open < 0 || close < 0)
        {
            return (null, null);
        }

        string address = comment[(open + 1)..close].Trim();
        string name = comment[..open].Trim();

        // RFC 5321 §4.1.3 tags an IPv6 literal "IPv6:2001:db8::1"; the tag is part of the
        // literal's syntax and not part of the address an operator would look up.
        const string IpV6Tag = "IPv6:";

        if (address.StartsWith(IpV6Tag, StringComparison.OrdinalIgnoreCase))
        {
            address = address[IpV6Tag.Length..];
        }

        return (name.Length == 0 ? null : name, address.Length == 0 ? null : address);
    }

    /// <summary>
    /// Removes folding, keeping the whitespace that followed it.
    /// </summary>
    /// <remarks>
    /// RFC 5322 §2.2.3: "Unfolding is accomplished by simply removing any CRLF that is
    /// immediately followed by WSP" — the same rule <c>ImapHeaderFields</c> follows, and for the
    /// same reason: the WSP is part of the field body and removing it would join two tokens that
    /// were separate.
    /// </remarks>
    private static string Unfold(string value) =>
        value.Replace("\r\n", string.Empty, StringComparison.Ordinal)
             .Replace("\n", string.Empty, StringComparison.Ordinal);
}
