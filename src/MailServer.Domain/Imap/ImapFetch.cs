using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using MailServer.Domain.Enums;

namespace MailServer.Domain.Imap;

/// <summary>
/// One of RFC 3501 §6.4.5's message data items.
/// </summary>
/// <remarks>
/// <para>
/// The whole list, including the items this server cannot answer yet. Parsing a name it will
/// then refuse is deliberate: §6.4.5's result codes distinguish "BAD - command unknown or
/// arguments invalid" from "NO - fetch error: can't fetch that data", and a client told BAD for
/// <c>ENVELOPE</c> would go looking for a syntax error that is not there. The refusal names the
/// item.
/// </para>
/// <para>
/// §6.4.5 divides them a second way, which matters for what a client may cache: "Most data
/// items, identified in the formal syntax under the msg-att-static rule, are static and MUST NOT
/// change for any particular message. Other data items, identified in the formal syntax under
/// the msg-att-dynamic rule, MAY change". Only <c>FLAGS</c> is dynamic — see
/// <see cref="ImapFetchItems.IsDynamic"/>.
/// </para>
/// </remarks>
public enum ImapFetchItem
{
    /// <summary><c>FLAGS</c> — "the flags that are set for this message".</summary>
    Flags = 0,

    /// <summary><c>UID</c> — "the unique identifier for the message".</summary>
    Uid = 1,

    /// <summary><c>INTERNALDATE</c> — "the internal date of the message".</summary>
    InternalDate = 2,

    /// <summary><c>RFC822.SIZE</c> — "the [RFC-2822] size of the message".</summary>
    Rfc822Size = 3,

    /// <summary><c>ENVELOPE</c> — the parsed header. Needs a MIME reader; not answerable yet.</summary>
    Envelope = 4,

    /// <summary><c>BODY</c> — "non-extensible form of BODYSTRUCTURE". Not answerable yet.</summary>
    Body = 5,

    /// <summary><c>BODYSTRUCTURE</c> — the MIME tree. Not answerable yet.</summary>
    BodyStructure = 6,

    /// <summary><c>RFC822</c> — "functionally equivalent to BODY[]". Not answerable yet.</summary>
    Rfc822 = 7,

    /// <summary><c>RFC822.HEADER</c> — equivalent to <c>BODY.PEEK[HEADER]</c>. Not answerable yet.</summary>
    Rfc822Header = 8,

    /// <summary><c>RFC822.TEXT</c> — equivalent to <c>BODY[TEXT]</c>. Not answerable yet.</summary>
    Rfc822Text = 9,

    /// <summary>
    /// <c>BODY[…]</c> or <c>BODY.PEEK[…]</c> — a section of the message.
    /// </summary>
    /// <remarks>
    /// One enum member for a whole family, because this increment does not parse the section
    /// specifier. §6.4.5's section grammar is part numbers, <c>HEADER</c>, <c>HEADER.FIELDS</c>,
    /// <c>HEADER.FIELDS.NOT</c>, <c>MIME</c> and <c>TEXT</c> in combination, and giving it a
    /// shape before there is a MIME reader to serve it would be designing the parser against a
    /// consumer that does not exist. Recognising the form is enough to refuse it by name.
    /// </remarks>
    BodySection = 10,
}

/// <summary>Reading the <c>FETCH</c> data item names and macros.</summary>
public static class ImapFetchItems
{
    /// <summary>Every item, for exhaustiveness tests.</summary>
    public static IReadOnlyList<ImapFetchItem> All { get; } = Enum.GetValues<ImapFetchItem>();

    /// <summary>
    /// The items this server can answer today.
    /// </summary>
    /// <remarks>
    /// Everything that is a column rather than a parse. The rest wait on the MIME reader, and
    /// <c>docs/Standards.md</c> records IMAP's <c>BODY[…]</c> as this product's first real MIME
    /// consumer.
    /// </remarks>
    public static IReadOnlyList<ImapFetchItem> Available { get; } =
    [
        ImapFetchItem.Flags,
        ImapFetchItem.Uid,
        ImapFetchItem.InternalDate,
        ImapFetchItem.Rfc822Size,
    ];

    /// <summary>The longest item list accepted.</summary>
    /// <remarks>
    /// Eleven items exist and repeats are grammatical, so a conformant list is short — but a
    /// client may send one name a thousand times. The same argument
    /// <see cref="ImapStatusItems.MaxItemCount"/> makes for itself.
    /// </remarks>
    public const int MaxItemCount = 64;

    /// <summary>
    /// Whether the item may change for a message, and a client therefore must not cache it.
    /// </summary>
    /// <remarks>
    /// §9 puts exactly one item under <c>msg-att-dynamic</c>: <c>msg-att-dynamic = "FLAGS" SP "("
    /// [flag-fetch *(SP flag-fetch)] ")"</c>, annotated "; MAY change for a message". Everything
    /// else is <c>msg-att-static</c> and "MUST NOT change for any particular message".
    /// </remarks>
    public static bool IsDynamic(ImapFetchItem item) => item == ImapFetchItem.Flags;

    /// <summary>The wire name of one item.</summary>
    public static string NameOf(ImapFetchItem item) => item switch
    {
        ImapFetchItem.Flags => "FLAGS",
        ImapFetchItem.Uid => "UID",
        ImapFetchItem.InternalDate => "INTERNALDATE",
        ImapFetchItem.Rfc822Size => "RFC822.SIZE",
        ImapFetchItem.Envelope => "ENVELOPE",
        ImapFetchItem.Body => "BODY",
        ImapFetchItem.BodyStructure => "BODYSTRUCTURE",
        ImapFetchItem.Rfc822 => "RFC822",
        ImapFetchItem.Rfc822Header => "RFC822.HEADER",
        ImapFetchItem.Rfc822Text => "RFC822.TEXT",
        ImapFetchItem.BodySection => "BODY[]",
        _ => throw new ArgumentOutOfRangeException(nameof(item), item, "Not a FETCH data item."),
    };

    /// <summary>
    /// Recognises one <c>fetch-att</c>.
    /// </summary>
    /// <remarks>
    /// Case-insensitively, per §9's note (1). <c>BODY</c> is the awkward one: §9's
    /// <c>fetch-att</c> lists <c>"BODY" ["STRUCTURE"]</c> and <c>"BODY" section</c> and
    /// <c>"BODY.PEEK" section</c> as three alternatives, so the name alone does not decide which
    /// — a trailing <c>[</c> does. <c>BODY.PEEK</c> without a section is not any of the three
    /// and is refused.
    /// </remarks>
    public static bool TryParse(string name, out ImapFetchItem item)
    {
        ArgumentNullException.ThrowIfNull(name);

        item = default;

        if (name.Length == 0)
        {
            return false;
        }

        // A section specifier makes it the BODY[...] family whatever precedes the bracket, and
        // the closing bracket has to be there: "BODY[" alone is a truncated argument, not an
        // item this server merely cannot answer.
        int bracket = name.IndexOf('[', StringComparison.Ordinal);

        if (bracket >= 0)
        {
            if (!name.EndsWith(']') && !IsPartialSuffix(name))
            {
                return false;
            }

            string head = name[..bracket];

            if (!head.Equals("BODY", StringComparison.OrdinalIgnoreCase) &&
                !head.Equals("BODY.PEEK", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            item = ImapFetchItem.BodySection;
            return true;
        }

        foreach (ImapFetchItem candidate in All)
        {
            if (candidate != ImapFetchItem.BodySection &&
                name.Equals(NameOf(candidate), StringComparison.OrdinalIgnoreCase))
            {
                item = candidate;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Whether a bracketed item carries §9's <c>&lt;number "." nz-number&gt;</c> partial suffix.
    /// </summary>
    /// <remarks>
    /// Only the shape is checked, not the numbers: the whole family is refused by name in this
    /// increment, so validating an argument to a command that will not run would be work whose
    /// only effect is to change which refusal a client gets.
    /// </remarks>
    private static bool IsPartialSuffix(string name) =>
        name.EndsWith('>') && name.Contains("]<", StringComparison.Ordinal);

    /// <summary>
    /// Expands one of §6.4.5's three macros.
    /// </summary>
    /// <remarks>
    /// Quoted from §6.4.5 rather than reconstructed: <c>ALL</c> is "(FLAGS INTERNALDATE
    /// RFC822.SIZE ENVELOPE)", <c>FAST</c> is "(FLAGS INTERNALDATE RFC822.SIZE)" and
    /// <c>FULL</c> is "(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY)". Only <c>FAST</c> is
    /// answerable today, and the other two refuse by naming <c>ENVELOPE</c> — which is a more
    /// useful thing to tell a client than that its macro failed.
    /// </remarks>
    public static bool TryParseMacro(string name, out IReadOnlyList<ImapFetchItem> items)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (name.Equals("FAST", StringComparison.OrdinalIgnoreCase))
        {
            items = [ImapFetchItem.Flags, ImapFetchItem.InternalDate, ImapFetchItem.Rfc822Size];
            return true;
        }

        if (name.Equals("ALL", StringComparison.OrdinalIgnoreCase))
        {
            items =
            [
                ImapFetchItem.Flags,
                ImapFetchItem.InternalDate,
                ImapFetchItem.Rfc822Size,
                ImapFetchItem.Envelope,
            ];

            return true;
        }

        if (name.Equals("FULL", StringComparison.OrdinalIgnoreCase))
        {
            items =
            [
                ImapFetchItem.Flags,
                ImapFetchItem.InternalDate,
                ImapFetchItem.Rfc822Size,
                ImapFetchItem.Envelope,
                ImapFetchItem.Body,
            ];

            return true;
        }

        items = [];
        return false;
    }

    /// <summary>
    /// Parses the whole data-item argument of a <c>FETCH</c> command.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §9: <c>fetch = "FETCH" SP sequence-set SP ("ALL" / "FULL" / "FAST" / fetch-att / "("
    /// fetch-att *(SP fetch-att) ")")</c>. Three shapes, and the grammar is precise about which
    /// may nest: <b>a macro is legal only bare</b>, so <c>FETCH 1 (FAST)</c> is a syntax error
    /// however reasonable it looks. §6.4.5 says the same in prose — "A macro must be used by
    /// itself, and not in conjunction with other macros or data items."
    /// </para>
    /// <para>
    /// An empty list is refused too: <c>msg-att</c> requires one item before the repetition, so
    /// <c>FETCH 1 ()</c> asks for nothing and gets <c>BAD</c> rather than an untagged line
    /// reporting nothing.
    /// </para>
    /// <para>
    /// Repeats are dropped and the requested order kept, as in
    /// <see cref="ImapStatusItems.TryParseList"/> and for the same reason: the response has no
    /// way to say one item twice about one message.
    /// </para>
    /// </remarks>
    public static bool TryParseRequest(string text, out IReadOnlyList<ImapFetchItem> items)
    {
        bool ok = TryParseRequestItems(text, out IReadOnlyList<ImapFetchRequestItem> parsed);

        items = ok ? [.. parsed.Select(r => r.Item)] : [];

        return ok;
    }

    /// <summary>
    /// Parses the data-item argument, keeping each <c>BODY[…]</c>'s section specifier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The form a handler needs, because <c>BODY[HEADER]</c> and <c>BODY[TEXT]</c> are the same
    /// <see cref="ImapFetchItem"/> and different requests: the enum says which family the item
    /// belongs to and the section says what was actually asked for.
    /// </para>
    /// <para>
    /// <b>Duplicates are compared on the whole item, not just the family.</b>
    /// <c>FETCH 1 (BODY[HEADER] BODY[TEXT])</c> asks for two different things and must be
    /// answered twice; collapsing them the way a repeated <c>FLAGS</c> collapses would silently
    /// drop half the request.
    /// </para>
    /// </remarks>
    public static bool TryParseRequestItems(
        string text,
        out IReadOnlyList<ImapFetchRequestItem> items)
    {
        ArgumentNullException.ThrowIfNull(text);

        items = [];

        string trimmed = text.Trim();

        if (trimmed.Length == 0)
        {
            return false;
        }

        if (trimmed[0] != '(')
        {
            // Bare: a macro, or exactly one data item. A space does not settle it - a section
            // specifier may contain one - so the argument is tokenised and must come to exactly
            // one token.
            if (!TryTokenise(trimmed, out List<string> bare) || bare.Count != 1)
            {
                return false;
            }

            trimmed = bare[0];

            if (TryParseMacro(trimmed, out IReadOnlyList<ImapFetchItem> expanded))
            {
                items = [.. expanded.Select(i => new ImapFetchRequestItem(i, null))];
                return true;
            }

            if (!TryParseOne(trimmed, out ImapFetchRequestItem? single))
            {
                return false;
            }

            items = [single];
            return true;
        }

        if (trimmed[^1] != ')')
        {
            return false;
        }

        if (!TryTokenise(trimmed[1..^1], out List<string> names) ||
            names.Count is 0 or > MaxItemCount)
        {
            return false;
        }

        List<ImapFetchRequestItem> parsed = [];
        HashSet<string> seen = new(StringComparer.Ordinal);

        foreach (string name in names)
        {
            // Inside the brackets a macro is not a data item, so it does not parse and is not
            // quietly expanded. Refusing is the grammar's answer, not an interpretation of it.
            if (!TryParseOne(name, out ImapFetchRequestItem? item))
            {
                return false;
            }

            if (seen.Add(item.Key))
            {
                parsed.Add(item);
            }
        }

        items = parsed;
        return true;
    }

    /// <summary>The body section an <c>RFC822</c> item is equivalent to, if it is one.</summary>
    private static ImapSection? Equivalent(ImapFetchItem item) => item switch
    {
        ImapFetchItem.Rfc822 => new ImapSection(
            ImapSectionKind.Full, [], [], Peek: false, null, null),

        ImapFetchItem.Rfc822Header => new ImapSection(
            ImapSectionKind.Header, [], [], Peek: true, null, null),

        ImapFetchItem.Rfc822Text => new ImapSection(
            ImapSectionKind.Text, [], [], Peek: false, null, null),

        _ => null,
    };

    /// <summary>Parses one <c>fetch-att</c> token, section and all.</summary>
    private static bool TryParseOne(
        string name,
        [NotNullWhen(true)] out ImapFetchRequestItem? item)
    {
        item = null;

        if (!TryParse(name, out ImapFetchItem kind))
        {
            return false;
        }

        // §6.4.5 defines the RFC822 family in terms of body sections: "RFC822 - Functionally
        // equivalent to BODY[]", "RFC822.HEADER - Functionally equivalent to BODY.PEEK[HEADER]",
        // "RFC822.TEXT - Functionally equivalent to BODY[TEXT]". Note which one peeks: fetching
        // the header alone does not mark a message read, and fetching its text does.
        if (Equivalent(kind) is { } equivalent)
        {
            item = new ImapFetchRequestItem(
                ImapFetchItem.BodySection,
                equivalent,
                ImapFetchItems.NameOf(kind));

            return true;
        }

        if (kind != ImapFetchItem.BodySection)
        {
            item = new ImapFetchRequestItem(kind, null);
            return true;
        }

        if (!ImapSection.TryParse(name, out ImapSection? section))
        {
            return false;
        }

        item = new ImapFetchRequestItem(kind, section);
        return true;
    }

    /// <summary>
    /// Splits a data-item argument into <c>fetch-att</c> tokens.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A space is not always a separator, which is why this is not a <c>Split</c>.</b> RFC 3501
    /// §9 puts a space inside a single <c>fetch-att</c>: <c>section-msgtext = "HEADER" /
    /// "HEADER.FIELDS" [".NOT"] SP header-list / "TEXT"</c>, and
    /// <c>header-list = "(" header-fld-name *(SP header-fld-name) ")"</c>. So
    /// <c>BODY[HEADER.FIELDS (DATE FROM)]</c> is one item containing two spaces and a nested
    /// list — and it is the shape a real client sends on every folder open. Splitting on spaces
    /// tears it into fragments that parse as nothing, which turns a request this server merely
    /// cannot serve into a protocol syntax error: §6.4.5 separates "NO - fetch error: can't fetch
    /// that data" from "BAD - command unknown or arguments invalid", and a client told <c>BAD</c>
    /// goes looking for a fault that is not there.
    /// </para>
    /// <para>
    /// Brackets are tracked because only they can contain a separator-space; parentheses are
    /// tracked only inside brackets, because that is the one place §9 nests them within an item.
    /// An unbalanced bracket is a malformed argument rather than an unsupported one, and is
    /// refused.
    /// </para>
    /// </remarks>
    private static bool TryTokenise(string text, out List<string> tokens)
    {
        tokens = [];

        int brackets = 0;
        int parens = 0;
        int start = 0;

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];

            switch (c)
            {
                case '[':
                    brackets++;
                    break;

                case ']':
                    if (--brackets < 0)
                    {
                        return false;
                    }

                    break;

                case '(' when brackets > 0:
                    parens++;
                    break;

                case ')' when brackets > 0:
                    if (--parens < 0)
                    {
                        return false;
                    }

                    break;

                case ' ' when brackets == 0:
                    if (i > start)
                    {
                        tokens.Add(text[start..i]);
                    }

                    start = i + 1;
                    break;

                default:
                    break;
            }
        }

        if (brackets != 0 || parens != 0)
        {
            return false;
        }

        if (start < text.Length)
        {
            tokens.Add(text[start..]);
        }

        return true;
    }
}

/// <summary>
/// One data item a <c>FETCH</c> asked for, with its section when it has one.
/// </summary>
/// <param name="Item">Which family of data item.</param>
/// <param name="Section">
/// The parsed <c>BODY[…]</c> specifier, or null for every other item.
/// </param>
public sealed record ImapFetchRequestItem(
    ImapFetchItem Item,
    ImapSection? Section,
    string? ResponseNameOverride = null)
{
    /// <summary>
    /// What makes two requested items the same request.
    /// </summary>
    /// <remarks>
    /// The rendered item name, so <c>BODY[HEADER]</c> and <c>BODY[TEXT]</c> are distinct while a
    /// repeated <c>FLAGS</c> still collapses. <c>BODY[X]</c> and <c>BODY.PEEK[X]</c> share a key
    /// deliberately: they ask for the same octets and differ only in a side effect, so answering
    /// twice would put the same data item on one line twice.
    /// </remarks>
    public string Key => Section?.Format() ?? ImapFetchItems.NameOf(Item);

    /// <summary>
    /// The data item name to write in the response.
    /// </summary>
    /// <remarks>
    /// The <c>RFC822</c> family is served through a body section but must not be answered as
    /// one. RFC 3501 §6.4.5 defines each as "Functionally equivalent to" a <c>BODY</c> form,
    /// "differing in the syntax of the resulting untagged FETCH data (RFC822 is returned)" — so
    /// the octets are found the same way and the name on the wire is the one the client used.
    /// </remarks>
    public string ResponseName =>
        ResponseNameOverride ?? Section?.Format() ?? ImapFetchItems.NameOf(Item);
}

/// <summary>
/// What this server can report about one message without parsing it.
/// </summary>
/// <remarks>
/// <para>
/// Every field is a stored column, which is what makes the whole type answerable from one query
/// over <c>IX_Deliveries_Folder_Uid</c>. <c>ENVELOPE</c> and <c>BODY[…]</c> are absent because
/// they are not columns — they are a parse of the message, and the type that carries them will
/// arrive with the reader that can produce them.
/// </para>
/// <para>
/// <b>The sequence number is carried rather than recomputed.</b> RFC 3501 §2.3.1.2 makes it
/// "the relative position from 1 to the number of messages in the mailbox", ordered by UID, so
/// it is a property of the read that produced this summary and not of the message. A caller that
/// recomputed it from a UID would be assuming the folder had not changed in between.
/// </para>
/// </remarks>
/// <param name="SequenceNumber">The message's position in the folder, from 1.</param>
/// <param name="Uid">The message's UID, unique in the folder and never reused.</param>
/// <param name="Flags">The flags set on it.</param>
/// <param name="InternalDate">When this server took delivery of it.</param>
/// <param name="SizeBytes">Its RFC 2822 size in octets.</param>
public sealed record ImapMessageSummary(
    long SequenceNumber,
    long Uid,
    MessageFlags Flags,
    DateTimeOffset InternalDate,
    long SizeBytes)
{
    /// <summary>The value to report for one requested item, already formatted.</summary>
    /// <remarks>
    /// Returns null for an item this server cannot answer, so a caller that has not filtered the
    /// request first gets nothing rather than a plausible wrong value. The handler filters, and
    /// this is the second line of defence.
    /// </remarks>
    public string? ValueOf(ImapFetchItem item) => item switch
    {
        ImapFetchItem.Flags => $"({ImapFlagNames.Format(Flags)})",
        ImapFetchItem.Uid => Uid.ToString(CultureInfo.InvariantCulture),
        ImapFetchItem.InternalDate => ImapInternalDate.Format(InternalDate),
        ImapFetchItem.Rfc822Size => SizeBytes.ToString(CultureInfo.InvariantCulture),
        _ => null,
    };
}

/// <summary>RFC 3501 §9's <c>date-time</c>, which <c>INTERNALDATE</c> is reported in.</summary>
public static class ImapInternalDate
{
    /// <summary>
    /// Formats an instant as a quoted <c>date-time</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §9: <c>date-time = DQUOTE date-day-fixed "-" date-month "-" date-year SP time SP zone
    /// DQUOTE</c>, and the trap is one production down: <c>date-day-fixed = (SP DIGIT) /
    /// 2DIGIT</c>, annotated "Fixed-format version of date-day". <b>A single-digit day is padded
    /// with a space, not a zero</b>, so the first of January is <c>" 1-Jan-2026 …"</c>. Every
    /// field is fixed width, which is the point of the production, and a server that wrote
    /// <c>"01-Jan"</c> would be emitting a string the grammar does not have.
    /// </para>
    /// <para>
    /// The month names are literals from §9's <c>date-month</c> and the whole thing is invariant:
    /// a server whose <c>INTERNALDATE</c> changed with the machine's locale would hand a Turkish
    /// or French host's clients a date-time no client can parse.
    /// </para>
    /// <para>
    /// The offset is preserved rather than normalised to UTC. §9's <c>zone</c> is "Signed
    /// four-digit value of hhmm representing hours and minutes east of Greenwich", so both are
    /// legal and equal — but the stored instant is what this server took delivery at, and
    /// rewriting its offset would discard information for no gain.
    /// </para>
    /// </remarks>
    public static string Format(DateTimeOffset instant)
    {
        string day = instant.Day < 10
            ? $" {instant.Day}"
            : instant.Day.ToString(CultureInfo.InvariantCulture);

        string month = MonthNames[instant.Month - 1];

        string rest = instant.ToString("yyyy HH:mm:ss", CultureInfo.InvariantCulture);

        TimeSpan offset = instant.Offset;
        TimeSpan magnitude = offset.Duration();
        char sign = offset < TimeSpan.Zero ? '-' : '+';

        string zone = string.Create(
            CultureInfo.InvariantCulture,
            $"{sign}{magnitude.Hours:00}{magnitude.Minutes:00}");

        return $"\"{day}-{month}-{rest} {zone}\"";
    }

    /// <summary>
    /// Reads a quoted <c>date-time</c>, as <c>APPEND</c> may carry one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The inverse of <see cref="Format"/>, and deliberately more forgiving in one place: the
    /// day may arrive space-padded as §9's <c>date-day-fixed</c> requires, or zero-padded, or
    /// bare. A server that insisted on the fixed form would refuse an <c>APPEND</c> over a
    /// detail the sending client got cosmetically wrong, losing the message rather than the
    /// formatting.
    /// </para>
    /// <para>
    /// The zone is not forgiving, because it changes the instant. §9: <c>zone = ("+" / "-")
    /// 4DIGIT</c>, "Signed four-digit value of hhmm representing hours and minutes east of
    /// Greenwich" — a missing or malformed zone would make the stored date wrong by hours rather
    /// than merely ugly.
    /// </para>
    /// </remarks>
    public static bool TryParse(string text, out DateTimeOffset value)
    {
        ArgumentNullException.ThrowIfNull(text);

        value = default;

        string trimmed = text.Trim();

        if (trimmed.Length < 2 || trimmed[0] != '"' || trimmed[^1] != '"')
        {
            return false;
        }

        string body = trimmed[1..^1].Trim();

        // "d-MMM-yyyy HH:mm:ss zzz" with the colon the grammar's zone does not have.
        int lastSpace = body.LastIndexOf(' ');

        if (lastSpace < 0 || body.Length - lastSpace != 6)
        {
            return false;
        }

        string zone = body[(lastSpace + 1)..];

        if (zone[0] is not ('+' or '-'))
        {
            return false;
        }

        string rebuilt = body[..(lastSpace + 1)] + zone[..3] + ":" + zone[3..];

        return DateTimeOffset.TryParseExact(
            rebuilt,
            ["d-MMM-yyyy HH:mm:ss zzz", "dd-MMM-yyyy HH:mm:ss zzz"],
            CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out value);
    }

    private static readonly string[] MonthNames =
    [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
}
