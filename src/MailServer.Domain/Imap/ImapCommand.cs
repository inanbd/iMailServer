using System.Diagnostics.CodeAnalysis;

namespace MailServer.Domain.Imap;

/// <summary>The IMAP commands this server understands.</summary>
/// <remarks>
/// RFC 3501 §6 groups commands by the state they are legal in; that grouping lives in
/// <see cref="ImapStateMachine"/> rather than here, because a verb is a fact about the grammar
/// and its legality is a fact about the session.
/// </remarks>
public enum ImapVerb
{
    /// <summary>Not a command this server implements.</summary>
    Unknown = 0,

    // ---- RFC 3501 §6.1 — any state ------------------------------------------------------------

    Capability,
    Noop,
    Logout,

    // ---- RFC 3501 §6.2 — not authenticated ----------------------------------------------------

    StartTls,
    Authenticate,
    Login,

    // ---- RFC 3501 §6.3 — authenticated --------------------------------------------------------

    Select,
    Examine,
    Create,
    Delete,
    Rename,
    Subscribe,
    Unsubscribe,
    List,
    Lsub,
    Status,
    Append,

    // ---- RFC 3501 §6.4 — selected -------------------------------------------------------------

    Check,
    Close,
    Expunge,
    Search,
    Fetch,
    Store,
    Copy,

    // ---- Extensions ---------------------------------------------------------------------------

    /// <summary><c>IDLE</c> — RFC 2177.</summary>
    Idle,

    /// <summary><c>NAMESPACE</c> — RFC 2342.</summary>
    Namespace,

    /// <summary><c>UNSELECT</c> — RFC 3691.</summary>
    Unselect,

    /// <summary><c>MOVE</c> — RFC 6851.</summary>
    Move,
}

/// <summary>Why a command line could not be attributed to a tag.</summary>
/// <remarks>
/// Only ever produced for a failure of the <i>tag</i>, never of the command. A line with a
/// usable tag and an unrecognised command word parses successfully as
/// <see cref="ImapVerb.Unknown"/> — the server can still answer it tagged, which is what lets a
/// client match the refusal to the command it sent. See <see cref="ImapCommand.TryParse"/>.
/// </remarks>
public enum ImapTagFailure
{
    /// <summary>The tag was usable.</summary>
    None = 0,

    /// <summary>The line was empty, or began with a space.</summary>
    Missing = 1,

    /// <summary>The tag was longer than <see cref="ImapCommand.MaxTagLength"/>.</summary>
    TooLong = 2,

    /// <summary>The tag contained a character RFC 3501 §9's <c>tag</c> production forbids.</summary>
    IllegalCharacter = 3,
}

/// <summary>A parsed IMAP command line.</summary>
/// <param name="Tag">
/// The client's tag, exactly as received. Validated by <see cref="TryParse"/>, never rewritten.
/// </param>
/// <param name="Verb">The command. <see cref="ImapVerb.Unknown"/> for one this server does not implement.</param>
/// <param name="IsUid">
/// True when the command arrived behind RFC 3501 §6.4.8's <c>UID</c> prefix, so
/// <paramref name="Verb"/> names what to do and this flag names what the numbers in
/// <paramref name="Argument"/> mean.
/// </param>
/// <param name="Argument">Everything after the command word. Empty when there was none.</param>
/// <param name="Raw">The line as received, minus its terminator, for logging.</param>
/// <remarks>
/// <para>
/// Shaped like <see cref="Smtp.SmtpCommand"/>: the line is split into a verb and the text that
/// follows it, and interpreting that text is the job of whatever handles the specific command —
/// the same division that leaves <c>MAIL FROM</c>'s parameters to <see cref="Smtp.SmtpPath"/>
/// rather than to <see cref="Smtp.SmtpCommand.Parse"/>. A single parser that also understood
/// every command's arguments would have to know about mailbox names, sequence sets, fetch
/// attributes and search keys at once, and would be the one place a bug in any of them lands.
/// </para>
/// <para>
/// <b>The <c>UID</c> prefix is a flag, not a verb.</b> RFC 3501 §6.4.8 defines <c>UID</c> as a
/// command taking <c>COPY</c>, <c>FETCH</c>, <c>STORE</c> or <c>SEARCH</c> as its first argument,
/// and the effect is to reinterpret every number in the rest of the command as a UID rather than
/// a message sequence number. Modelling it as six more verbs would duplicate every argument rule
/// and invite the two copies to drift; modelling it as a flag keeps one <c>FETCH</c> whose
/// numbers mean one of two things, which is what the RFC actually describes.
/// </para>
/// </remarks>
public sealed record ImapCommand(string Tag, ImapVerb Verb, bool IsUid, string Argument, string Raw)
{
    /// <summary>
    /// The values of the literals that arrived with this command, in the order their specifiers
    /// appear in <see cref="Argument"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Empty for the ordinary single-line command, which is most of them. RFC 3501 §4.3 admits a
    /// literal wherever the grammar has an <c>astring</c>, so a mailbox name outside ASCII, a
    /// userid or a <c>SEARCH</c> term may arrive as octets after the line rather than on it; the
    /// connection reads them and puts them here, and <see cref="ImapAstringReader"/> hands each
    /// one back in place of the <c>{n}</c> that stands for it.
    /// </para>
    /// <para>
    /// <b><c>APPEND</c>'s message literal is deliberately not here.</b> It is the one literal
    /// this server never holds in memory — it streams to the message store as it arrives — so
    /// its specifier stays unresolved in <see cref="Argument"/> for <see cref="ImapAppend"/> to
    /// read. A message is the one argument large enough for the difference to matter.
    /// </para>
    /// <para>
    /// <b>Like <see cref="Argument"/> and <see cref="Raw"/>, this can hold a password</b> — a
    /// client may send <c>LOGIN</c>'s userid and password as literals — which is why
    /// <see cref="PrintMembers"/> does not print it. See that method's remarks.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> Literals { get; init; } = [];

    /// <summary>
    /// The longest tag accepted.
    /// </summary>
    /// <remarks>
    /// RFC 3501 imposes no bound, so this server imposes one. Real clients send counters and
    /// short alphanumerics — <c>A001</c>, <c>1</c>, <c>a17</c> — so thirty-two characters is
    /// generous by a wide margin while bounding the amplification a long tag would otherwise
    /// buy: every tagged response repeats the tag back, and a pipelining client can have many
    /// commands in flight at once. The same argument <see cref="ImapSequenceSet.MaxSegments"/>
    /// makes for itself, and more sharply, because no tag has a legitimate reason to be long.
    /// </remarks>
    public const int MaxTagLength = 32;

    /// <summary>
    /// Prints the tag and the verb, and deliberately never the argument or the raw line.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A record's generated <c>ToString</c> prints every property, and one of these
    /// properties is a password.</b> RFC 3501 §6.2.3's <c>LOGIN</c> is
    /// <c>a1 LOGIN alice hunter2</c> — the credential sits in
    /// <see cref="Argument"/> and again in <see cref="Raw"/>, in the clear, with none of the
    /// base64 obfuscation SMTP's <c>AUTH PLAIN</c> at least applies. Left generated, this type
    /// would render as
    /// <c>ImapCommand { Tag = a1, Verb = Login, IsUid = False, Argument = alice hunter2, … }</c>,
    /// so any future <c>logger.LogWarning("Unexpected command {Command}", command)</c> — or a
    /// bare string interpolation, or an exception message, or a debugger-attached crash dump —
    /// writes a customer's password down.
    /// </para>
    /// <para>
    /// Overridden here rather than left to a rule that every call site must remember, because
    /// the failure is silent and the call site that forgets will not be the one anybody reviews.
    /// <c>ImapProtocolSecurityTests</c>'s scan for a logged <c>Raw</c> or <c>Argument</c> cannot
    /// catch this shape at all: the offending line mentions neither property by name.
    /// </para>
    /// <para>
    /// <b><see cref="Literals"/> is a third way the same credential can arrive</b>, and is
    /// excluded here for the same reason: RFC 3501 §4.3 lets a client send
    /// <c>LOGIN {5}</c>/<c>alice</c>/<c>{8}</c>/<c>hunter2</c>, which puts the password in that
    /// list rather than on the line. Every property that can hold one is left unprinted, so the
    /// rule is "print the three that are safe" rather than "remember to exclude the unsafe
    /// ones", and a property added later is excluded by default.
    /// </para>
    /// <para>
    /// The tag is safe to print: <see cref="TryParse"/> refuses anything outside RFC 3501 §9's
    /// <c>tag</c> production, so by the time one exists on this type it carries no control
    /// character and nothing a log parser could be confused by.
    /// </para>
    /// </remarks>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Append("Tag = ").Append(Tag)
            .Append(", Verb = ").Append(Verb)
            .Append(", IsUid = ").Append(IsUid);

        return true;
    }

    /// <summary>Whether RFC 3501 §6.4.8's <c>UID</c> prefix may precede <paramref name="verb"/>.</summary>
    /// <remarks>
    /// <c>UID</c> takes <c>COPY</c>, <c>FETCH</c>, <c>STORE</c> and <c>SEARCH</c> (§6.4.8), and
    /// RFC 6851 adds <c>MOVE</c>. <c>UID EXPUNGE</c> is RFC 4315 UIDPLUS and is deliberately
    /// absent: this server does not implement UIDPLUS yet, and accepting the prefix for a
    /// command whose UID form is not implemented would answer a client's capability probe with
    /// something other than the truth.
    /// </remarks>
    public static bool SupportsUidPrefix(ImapVerb verb) =>
        verb is ImapVerb.Copy or ImapVerb.Fetch or ImapVerb.Store or ImapVerb.Search or ImapVerb.Move;

    /// <summary>Whether <paramref name="tag"/> is one this server will accept and echo.</summary>
    /// <remarks>
    /// Public so that composing a response can assert the same rule the parser enforced, rather
    /// than trusting that every tag reaching the writer came through <see cref="TryParse"/>. See
    /// <see cref="ImapResponse.Tagged"/>, which refuses rather than sanitises: the hostile bytes
    /// then never enter the output stream at all, not even in reduced form.
    /// </remarks>
    public static bool IsValidTag(string tag)
    {
        ArgumentNullException.ThrowIfNull(tag);

        return ValidateTag(tag) == ImapTagFailure.None;
    }

    /// <summary>Parses a command line.</summary>
    /// <remarks>
    /// <para>
    /// <b>Failure here means the tag is unusable, and nothing else.</b> An unrecognised command
    /// word is not a failure: it parses as <see cref="ImapVerb.Unknown"/> so the caller can
    /// answer <c>&lt;tag&gt; BAD</c>, which the client matches to the command it sent. A caller
    /// that gets <c>false</c> has no tag to answer with and must send an <i>untagged</i>
    /// <c>* BAD</c> — RFC 3501 §7.1.3's "protocol-level error for which the associated command
    /// can not be determined" is written for exactly this case.
    /// </para>
    /// <para>
    /// <b>An invalid tag is refused, never repaired.</b> Stripping an offending character and
    /// echoing what is left would be the wrong repair, because unlike SMTP reply text — which
    /// <see cref="Smtp.SmtpReply.Format"/> sanitises precisely because it is decorative — an
    /// IMAP tag is load-bearing: the client byte-matches the tagged completion against the
    /// command it issued. A completion carrying a tag the client never sent is a completion the
    /// client cannot match, and it waits for one that will never come until its own timeout
    /// fires. Echo it exactly or refuse it; there is no third option.
    /// </para>
    /// <para>
    /// <b>The character rules are the injection defence, not a formality.</b> RFC 3501 §9's
    /// <c>tag</c> production excludes CTL, which is what keeps a CR out of text this server is
    /// about to write back. That matters concretely here:
    /// <c>ImapLineReader</c> strips only the CR that sits immediately before a line's
    /// terminating LF, so a line of <c>A&lt;CR&gt;BBB NOOP</c>
    /// reaches this parser with the CR intact in the middle. Echoing that tag would put an
    /// attacker-chosen line break into the response stream, and any reader that treats a bare CR
    /// as a line ending then sees a response the server never sent — the IMAP form of the
    /// response splitting <see cref="Smtp.SmtpReply.Format"/>'s own remarks describe. Enforcing
    /// the grammar at the door is what prevents it.
    /// </para>
    /// </remarks>
    /// <param name="line">One command line, without its terminator.</param>
    /// <param name="command">The parsed command, when the tag was usable.</param>
    /// <param name="failure">Why the tag was refused, when it was.</param>
    public static bool TryParse(
        string line,
        [NotNullWhen(true)] out ImapCommand? command,
        out ImapTagFailure failure)
    {
        ArgumentNullException.ThrowIfNull(line);

        command = null;

        string trimmed = line.TrimEnd('\r', '\n');

        (string tag, string afterTag) = SplitWord(trimmed);

        failure = ValidateTag(tag);

        if (failure != ImapTagFailure.None)
        {
            return false;
        }

        (string word, string afterWord) = SplitWord(afterTag);

        bool isUid = word.Equals("UID", StringComparison.OrdinalIgnoreCase);

        if (isUid)
        {
            (word, afterWord) = SplitWord(afterWord);
        }

        ImapVerb verb = MapVerb(word);

        // 'UID SELECT' is not a command. Reporting it as an unknown verb that happens to carry
        // the prefix would invite a handler to act on the inner verb and ignore the flag; there
        // is no such command, so there is no such verb.
        if (isUid && !SupportsUidPrefix(verb))
        {
            verb = ImapVerb.Unknown;
        }

        command = new ImapCommand(tag, verb, isUid, afterWord, trimmed);
        return true;
    }

    /// <summary>Splits the first space-delimited word from the rest.</summary>
    /// <remarks>
    /// The remainder is left-trimmed only. RFC 3501 §9 separates tokens with a single SP, and a
    /// client that sent two has produced a difference no command's meaning depends on — but
    /// trailing text is never trimmed, because a trailing space inside a quoted mailbox name is
    /// part of the name.
    /// </remarks>
    private static (string Word, string Remainder) SplitWord(string text)
    {
        int space = text.IndexOf(' ', StringComparison.Ordinal);

        return space < 0
            ? (text, string.Empty)
            : (text[..space], text[(space + 1)..].TrimStart(' '));
    }

    private static ImapTagFailure ValidateTag(string tag)
    {
        if (tag.Length == 0)
        {
            return ImapTagFailure.Missing;
        }

        if (tag.Length > MaxTagLength)
        {
            return ImapTagFailure.TooLong;
        }

        foreach (char c in tag)
        {
            if (!IsTagChar(c))
            {
                return ImapTagFailure.IllegalCharacter;
            }
        }

        return ImapTagFailure.None;
    }

    /// <summary>
    /// RFC 3501 §9's <c>tag = 1*&lt;any ASTRING-CHAR except "+"&gt;</c>, resolved.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ASTRING-CHAR = ATOM-CHAR / resp-specials</c>, and <c>atom-specials</c> — which
    /// <c>ATOM-CHAR</c> excludes — itself lists <c>resp-specials</c>. The double negative is not
    /// a typo in the RFC: <c>]</c> is removed and then added back, so <b><c>]</c> is legal in a
    /// tag and illegal in an atom</b>. A single shared "is this an atom character" predicate
    /// used for both would be wrong in one direction or the other, which is why this predicate
    /// is named for the tag and is not reused.
    /// </para>
    /// <para>
    /// <c>*</c> and <c>+</c> are excluded for one reason rather than two. Every line this server
    /// writes is classified by its first token — <c>*</c> is untagged (§7), <c>+</c> is a
    /// continuation request (§7.5), and anything else is a tag. <c>*</c> is already gone as a
    /// list-wildcard; excluding <c>+</c> completes the invariant. A client permitted to tag a
    /// command <c>+</c> would be answered <c>+ OK NOOP completed</c>, read that as a request for
    /// a literal, and send one the server never asked for — after which the connection is
    /// permanently out of step.
    /// </para>
    /// </remarks>
    private static bool IsTagChar(char c)
    {
        // CTL (0x00-0x1F and 0x7F), SP (0x20) and everything outside CHAR (above 0x7F) in one
        // range test. The CTL half is the response-splitting defence; see TryParse's remarks.
        if (c is < (char)0x21 or > (char)0x7E)
        {
            return false;
        }

        return c is not ('(' or ')' or '{' or '%' or '*' or '"' or '\\' or '+');
    }

    private static ImapVerb MapVerb(string word) => word.ToUpperInvariant() switch
    {
        "CAPABILITY" => ImapVerb.Capability,
        "NOOP" => ImapVerb.Noop,
        "LOGOUT" => ImapVerb.Logout,
        "STARTTLS" => ImapVerb.StartTls,
        "AUTHENTICATE" => ImapVerb.Authenticate,
        "LOGIN" => ImapVerb.Login,
        "SELECT" => ImapVerb.Select,
        "EXAMINE" => ImapVerb.Examine,
        "CREATE" => ImapVerb.Create,
        "DELETE" => ImapVerb.Delete,
        "RENAME" => ImapVerb.Rename,
        "SUBSCRIBE" => ImapVerb.Subscribe,
        "UNSUBSCRIBE" => ImapVerb.Unsubscribe,
        "LIST" => ImapVerb.List,
        "LSUB" => ImapVerb.Lsub,
        "STATUS" => ImapVerb.Status,
        "APPEND" => ImapVerb.Append,
        "CHECK" => ImapVerb.Check,
        "CLOSE" => ImapVerb.Close,
        "EXPUNGE" => ImapVerb.Expunge,
        "SEARCH" => ImapVerb.Search,
        "FETCH" => ImapVerb.Fetch,
        "STORE" => ImapVerb.Store,
        "COPY" => ImapVerb.Copy,
        "IDLE" => ImapVerb.Idle,
        "NAMESPACE" => ImapVerb.Namespace,
        "UNSELECT" => ImapVerb.Unselect,
        "MOVE" => ImapVerb.Move,
        _ => ImapVerb.Unknown,
    };
}
