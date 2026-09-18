using System.Globalization;
using System.Text;
using MailServer.Domain.Enums;

namespace MailServer.Domain.Imap;

/// <summary>Which of RFC 3501 §7's three line shapes a response is.</summary>
public enum ImapResponseKind
{
    /// <summary>
    /// <c>&lt;tag&gt; OK|NO|BAD &lt;text&gt;</c> — the completion result of one command.
    /// </summary>
    /// <remarks>
    /// Exactly one per command, and always the last line that command produces. Clients pipeline
    /// and match completions to commands by tag, which is what makes the tag load-bearing rather
    /// than decorative.
    /// </remarks>
    Tagged = 0,

    /// <summary><c>* …</c> — server data, or a status response not tied to a command.</summary>
    Untagged = 1,

    /// <summary><c>+ &lt;text&gt;</c> — a command continuation request. RFC 3501 §7.5.</summary>
    Continuation = 2,
}

/// <summary>The status word of an IMAP status response. RFC 3501 §7.1.</summary>
public enum ImapResponseStatus
{
    /// <summary>The command succeeded, or the untagged form carries information.</summary>
    Ok = 0,

    /// <summary>
    /// The server understood the command and declined to perform it.
    /// </summary>
    /// <remarks>
    /// Never the answer to a malformed or out-of-sequence command. <c>NO</c> tells a client the
    /// request was well-formed and invites a retry, so a client answered <c>NO</c> for a command
    /// it sent in the wrong state retries it in the wrong state. That is
    /// <see cref="Bad"/>'s job.
    /// </remarks>
    No = 1,

    /// <summary>A protocol error: the command was unrecognised, malformed, or out of sequence.</summary>
    Bad = 2,

    /// <summary>
    /// The connection is already authenticated by external means. RFC 3501 §7.1.4.
    /// </summary>
    /// <remarks>
    /// Untagged only — there is no tagged <c>PREAUTH</c>. This server never sends one: it has no
    /// external authentication path, and a greeting that claimed pre-authentication would hand a
    /// mailbox to whoever opened the socket.
    /// </remarks>
    PreAuth = 3,

    /// <summary>The server is closing the connection. RFC 3501 §7.1.5. Untagged only.</summary>
    Bye = 4,
}

/// <summary>
/// An RFC 3501 §7.1 response code — the <c>[NAME]</c> or <c>[NAME argument]</c> that may precede
/// a status response's text.
/// </summary>
/// <remarks>
/// <para>
/// A type rather than text spliced into a message, so that a code cannot be assembled at a call
/// site with an argument that does not match its name, and so the one place a <c>]</c> could
/// terminate the code early is written once. RFC 3501 §9's production is
/// <c>resp-text-code = atom [SP 1*&lt;any TEXT-CHAR except "]"&gt;]</c>: the closing bracket is
/// excluded from the argument precisely because it would otherwise end the code, and everything
/// after it would be read by the client as ordinary text.
/// </para>
/// <para>
/// Only the codes this server actually sends have factories. A code is a promise about the
/// response it decorates — <c>[TRYCREATE]</c> tells a client to create the mailbox and retry,
/// <c>[UIDVALIDITY n]</c> tells it whether its entire cache is still valid — so inventing one
/// ad hoc is not a formatting shortcut, it is an instruction the client will follow.
/// </para>
/// </remarks>
/// <param name="Name">The code's atom, e.g. <c>UIDVALIDITY</c>.</param>
/// <param name="Argument">Its argument, or null for a code that takes none.</param>
public sealed record ImapResponseCode(string Name, string? Argument)
{
    /// <summary>
    /// <c>[ALERT]</c> — text the client must show its user. RFC 3501 §7.1.
    /// </summary>
    /// <remarks>
    /// Clients display this verbatim, so it is the one response code whose text reaches a human
    /// unfiltered. Never attach it to text derived from anything a peer sent.
    /// </remarks>
    public static ImapResponseCode Alert { get; } = new("ALERT", null);

    /// <summary><c>[PARSE]</c> — this server could not parse a stored message's headers.</summary>
    public static ImapResponseCode Parse { get; } = new("PARSE", null);

    /// <summary><c>[READ-ONLY]</c> — the mailbox was opened read-only. RFC 3501 §6.3.2.</summary>
    public static ImapResponseCode ReadOnly { get; } = new("READ-ONLY", null);

    /// <summary><c>[READ-WRITE]</c> — the mailbox was opened for modification.</summary>
    public static ImapResponseCode ReadWrite { get; } = new("READ-WRITE", null);

    /// <summary>
    /// <c>[TRYCREATE]</c> — the destination mailbox does not exist, but creating it would help.
    /// </summary>
    /// <remarks>
    /// RFC 3501 §6.3.11 and §6.4.7: sent on a <c>NO</c> to <c>APPEND</c> or <c>COPY</c>. It is
    /// the difference between a client showing "failed" and a client offering to create the
    /// folder, so omitting it turns a recoverable situation into a dead end.
    /// </remarks>
    public static ImapResponseCode TryCreate { get; } = new("TRYCREATE", null);

    /// <summary><c>[UIDVALIDITY n]</c> — the selected folder's UID validity. RFC 3501 §6.3.1.</summary>
    /// <remarks>
    /// Always the folder's stored value, never a fresh timestamp. A UIDVALIDITY that changes
    /// when it should not makes every client discard its cache and re-download the mailbox; one
    /// that changes on every restart does that forever. See <see cref="Entities.MailboxFolder"/>.
    /// </remarks>
    public static ImapResponseCode UidValidity(long value) => Numeric("UIDVALIDITY", value);

    /// <summary><c>[UIDNEXT n]</c> — the UID that will probably be assigned next.</summary>
    public static ImapResponseCode UidNext(long value) => Numeric("UIDNEXT", value);

    /// <summary>
    /// <c>[UNSEEN n]</c> — the sequence number of the first message without <c>\Seen</c>.
    /// </summary>
    /// <remarks>
    /// A message sequence number, not a count of unseen messages. RFC 3501 §9 types it as an
    /// <c>nz-number</c>, so there is no way to say "none": a mailbox with nothing unseen omits
    /// the whole <c>* OK [UNSEEN …]</c> line rather than sending <c>[UNSEEN 0]</c>, which is
    /// ungrammatical.
    /// </remarks>
    public static ImapResponseCode Unseen(long sequenceNumber) => Numeric("UNSEEN", sequenceNumber);

    /// <summary>
    /// <c>[PERMANENTFLAGS (…)]</c> — the flags a client may change and have persist.
    /// </summary>
    /// <remarks>
    /// An empty list is meaningful and correct for a mailbox opened by <c>EXAMINE</c>: nothing
    /// may be changed, so nothing persists. <c>\Recent</c> never appears here — RFC 3501 §2.3.2
    /// does not permit a client to set it via <c>STORE</c> at all.
    /// </remarks>
    public static ImapResponseCode PermanentFlags(MessageFlags flags) =>
        new("PERMANENTFLAGS", $"({ImapFlagNames.Format(flags)})");

    /// <summary><c>[CAPABILITY …]</c> — the capability listing, inline. RFC 3501 §7.2.1.</summary>
    /// <remarks>
    /// Carried in the greeting and in the tagged <c>OK</c> of a successful <c>LOGIN</c> or
    /// <c>AUTHENTICATE</c>, which saves the client a round trip it would otherwise spend on
    /// <c>CAPABILITY</c> — and, after authentication, tells it the list has changed.
    /// </remarks>
    public static ImapResponseCode Capability(IEnumerable<string> capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);

        return new ImapResponseCode("CAPABILITY", string.Join(' ', capabilities));
    }

    private static ImapResponseCode Numeric(string name, long value)
    {
        // nz-number, and RFC 3501 §9 bounds it at 32 bits: "(0 < n < 4,294,967,296)".
        ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 4_294_967_295);

        return new ImapResponseCode(name, value.ToString(CultureInfo.InvariantCulture));
    }
}

/// <summary>
/// One line this server writes.
/// </summary>
/// <remarks>
/// <para>
/// A type rather than a formatted string, for the reason <see cref="Smtp.SmtpReply"/> is one and
/// then a sharper one. In SMTP, injected text buys an attacker a forged reply code. In IMAP it
/// buys forged <i>server data</i>, and untagged responses are unsolicited by design (RFC 3501
/// §7), so a client has no grounds to reject one as arriving out of place.
/// </para>
/// <para>
/// <b>The attack this type exists to make impossible.</b> Response text routinely quotes
/// something the client sent — a mailbox name that would not decode, an unrecognised command, a
/// malformed sequence set — and several of those arrive before <c>LOGIN</c>, from a peer that
/// has proven nothing. If a CRLF in that text reached the wire, everything after it would be a
/// line the attacker wrote and the client could not tell from the server's own. A forged
/// <c>* n EXPUNGE</c> makes a caching client delete messages from its local store; a forged
/// <c>* 0 EXISTS</c> makes the mailbox look empty; a forged <c>* OK [UIDVALIDITY x]</c> makes
/// every client discard its cache. That is exactly the silent, client-side mail loss
/// <c>docs/IMAP.md</c> opens by naming as the reason this subsystem is the riskiest one. Worse
/// still, a forged <i>tagged</i> completion carrying the tag of a different in-flight command
/// tells the client that command succeeded when it did not.
/// </para>
/// <para>
/// <b>Text is reduced to printable US-ASCII, which is stricter than the SMTP rule and stricter
/// than the grammar.</b> <see cref="Smtp.SmtpReply.Format"/> strips control characters and lets
/// 8-bit octets through, legitimately, because SMTPUTF8 exists. RFC 3501 §9 gives no such
/// licence: <c>TEXT-CHAR</c> is <c>CHAR</c> minus CR and LF, and <c>CHAR</c> is <c>%x01-7F</c>,
/// so anything above 0x7F is ungrammatical until RFC 6855 <c>UTF8=ACCEPT</c> is advertised,
/// which this server does not do. Between 0x7E and 0x7F the grammar and this filter disagree on
/// purpose: DEL is a legal <c>TEXT-CHAR</c> and is dropped anyway, along with every other
/// non-printable below SP that the grammar would also permit. A filter defined as "what can be
/// displayed" needs no argument about which control characters are harmless in which client;
/// one defined as "what the grammar allows" would have to make that argument for every one of
/// them.
/// </para>
/// <para>
/// <b>Stripping can empty a string, and an empty one is ungrammatical too.</b> RFC 3501 §9's
/// <c>text</c> is <c>1*TEXT-CHAR</c>, so a mailbox name made entirely of control characters
/// would reduce to nothing and produce a line ending in a bare space. The fallback is therefore
/// required rather than tidy.
/// </para>
/// <para>
/// <b>Line structure never comes from text.</b> There is one line per response and no property
/// through which text can add another — the same reason
/// <see cref="Smtp.SmtpReply.ContinuationLines"/> is a separate list. A multi-line answer is
/// several responses, each written separately.
/// </para>
/// </remarks>
public sealed record ImapResponse
{
    /// <summary>Stands in for text that sanitised away to nothing.</summary>
    public const string EmptyTextPlaceholder = "(text omitted)";

    private ImapResponse(
        ImapResponseKind kind,
        string? tag,
        ImapResponseStatus? status,
        ImapResponseCode? code,
        string text)
    {
        Kind = kind;
        Tag = tag;
        Status = status;
        Code = code;
        Text = text;
    }

    /// <summary>Which line shape this is.</summary>
    public ImapResponseKind Kind { get; }

    /// <summary>The client's tag, for <see cref="ImapResponseKind.Tagged"/>. Null otherwise.</summary>
    public string? Tag { get; }

    /// <summary>The status word, or null for untagged server data and continuations.</summary>
    public ImapResponseStatus? Status { get; }

    /// <summary>The response code, when there is one.</summary>
    public ImapResponseCode? Code { get; }

    /// <summary>The text, before sanitisation. <see cref="Format"/> is what makes it safe.</summary>
    public string Text { get; }

    /// <summary>A command's completion result.</summary>
    /// <remarks>
    /// <b>Refuses an invalid tag rather than repairing one.</b> RFC 3501 §7.1.3 provides the
    /// untagged <c>* BAD</c> for "a protocol-level error for which the associated command can not
    /// be determined", which is the right answer when the tag itself did not parse — and taking
    /// it means the hostile bytes never enter the output stream at all, not even reduced. A tag
    /// reaching here that <see cref="ImapCommand.IsValidTag"/> rejects did not come from
    /// <see cref="ImapCommand.TryParse"/>, so it is a caller bug, not a client one.
    /// </remarks>
    /// <exception cref="ArgumentException">The tag is not one this server would have accepted.</exception>
    public static ImapResponse Tagged(
        string tag,
        ImapResponseStatus status,
        string text,
        ImapResponseCode? code = null)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(text);

        if (!ImapCommand.IsValidTag(tag))
        {
            throw new ArgumentException(
                "A tagged response can only carry a tag this server accepted; answer untagged instead.",
                nameof(tag));
        }

        if (status is ImapResponseStatus.PreAuth or ImapResponseStatus.Bye)
        {
            // RFC 3501 §7.1.4 and §7.1.5 define both as untagged. There is no "a1 BYE".
            throw new ArgumentException(
                $"{status} is an untagged-only status.",
                nameof(status));
        }

        return new ImapResponse(ImapResponseKind.Tagged, tag, status, code, text);
    }

    /// <summary>An untagged status response: <c>* OK …</c>, <c>* BYE …</c>, and the rest.</summary>
    public static ImapResponse Untagged(
        ImapResponseStatus status,
        string text,
        ImapResponseCode? code = null)
    {
        ArgumentNullException.ThrowIfNull(text);

        return new ImapResponse(ImapResponseKind.Untagged, null, status, code, text);
    }

    /// <summary>
    /// Untagged server data: <c>* CAPABILITY …</c>, <c>* 172 EXISTS</c>, <c>* FLAGS (…)</c>.
    /// </summary>
    /// <remarks>
    /// No status word and no response code — a different production from the status responses
    /// above, which is why it is a different factory rather than a null status. Compose the text
    /// through <see cref="ImapResponses"/> rather than here: the numeric data responses put the
    /// number before the keyword, and a factory that cannot be called the wrong way round is
    /// worth more than a comment saying so.
    /// </remarks>
    public static ImapResponse Data(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return new ImapResponse(ImapResponseKind.Untagged, null, null, null, text);
    }

    /// <summary>A command continuation request: <c>+ …</c>. RFC 3501 §7.5.</summary>
    /// <remarks>
    /// Sent to ask for a synchronising literal's octets, or for the next step of a SASL exchange.
    /// It is the server's one chance to refuse a literal before any of it is transmitted, which
    /// is the whole reason the synchronising form exists.
    /// </remarks>
    public static ImapResponse Continuation(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return new ImapResponse(ImapResponseKind.Continuation, null, null, null, text);
    }

    /// <summary>
    /// Prints the response as it would actually go on the wire, never as it was constructed.
    /// </summary>
    /// <remarks>
    /// The same defect <see cref="ImapCommand"/> carries, in the opposite direction. A record's
    /// generated <c>ToString</c> prints every property, and <see cref="Text"/> is the property
    /// holding whatever the client sent — unsanitised, because sanitisation happens in
    /// <see cref="Format"/>. Left generated, <c>$"{response}"</c> on a refusal quoting a hostile
    /// mailbox name would render that name's CRLF intact into a log file or an exception
    /// message, which is the injection this type exists to prevent, arriving by the one route
    /// that does not go through <see cref="Format"/>.
    /// </remarks>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Format() is the definition of what is safe to emit, so rendering through it means
        // this can never be less safe than the wire form. The terminator is dropped because a
        // rendered object is not a line.
        builder.Append(Kind).Append(": ").Append(Format().TrimEnd('\r', '\n'));

        return true;
    }

    /// <summary>Renders the response in wire format, with a CRLF terminator.</summary>
    /// <remarks>
    /// The only place a response becomes bytes, and therefore the only place the sanitisation
    /// described in this type's remarks has to hold. Nothing that reaches here can produce more
    /// than one line.
    /// </remarks>
    public string Format()
    {
        StringBuilder builder = new();

        builder.Append(Kind switch
        {
            ImapResponseKind.Tagged => Tag,
            ImapResponseKind.Continuation => "+",
            _ => "*",
        });

        if (Status is not null)
        {
            builder.Append(' ').Append(StatusWord(Status.Value));
        }

        if (Code is not null)
        {
            builder.Append(" [").Append(SanitizeCodeName(Code.Name));

            if (Code.Argument is not null)
            {
                builder.Append(' ').Append(SanitizeCodeArgument(Code.Argument));
            }

            builder.Append(']');
        }

        builder.Append(' ').Append(Sanitize(Text, EmptyTextPlaceholder));

        return builder.Append("\r\n").ToString();
    }

    private static string StatusWord(ImapResponseStatus status) => status switch
    {
        ImapResponseStatus.Ok => "OK",
        ImapResponseStatus.No => "NO",
        ImapResponseStatus.Bad => "BAD",
        ImapResponseStatus.PreAuth => "PREAUTH",
        ImapResponseStatus.Bye => "BYE",
        _ => "BAD",
    };

    /// <summary>
    /// Reduces text to RFC 3501 §9's <c>TEXT-CHAR</c>, minus the rest of the non-printables.
    /// </summary>
    /// <remarks>
    /// Stripped, not escaped, for the reason <see cref="Smtp.SmtpReply.Format"/> gives: an escape
    /// sequence is still a sequence the receiver has to decode correctly, and a defence that
    /// depends on the other end's decoder being right is not a defence. Removing the octet
    /// removes the question.
    /// </remarks>
    private static string Sanitize(string text, string fallback)
    {
        StringBuilder builder = new(text.Length);

        foreach (char c in text)
        {
            if (c is >= (char)0x20 and <= (char)0x7E)
            {
                builder.Append(c);
            }
        }

        // Trimmed, then checked for emptiness rather than the other way round. RFC 3501 §9's
        // text is 1*TEXT-CHAR and SP *is* a TEXT-CHAR, so " " survives the filter above and
        // would render as "A001 OK  " - two spaces and no text, ending in the bare space this
        // type promises never to emit. A name made entirely of control characters reduces to
        // nothing and a name made entirely of spaces reduces to spaces; both are reachable from
        // client input and both need the fallback.
        string reduced = builder.ToString().Trim();

        return reduced.Length == 0 ? fallback : reduced;
    }

    /// <summary>A code's name is an atom, so it carries no space and no bracket.</summary>
    private static string SanitizeCodeName(string name)
    {
        StringBuilder builder = new(name.Length);

        foreach (char c in name)
        {
            if (c is >= (char)0x21 and <= (char)0x7E && c is not (']' or '[' or '(' or ')' or '{'))
            {
                builder.Append(c);
            }
        }

        return builder.Length == 0 ? "BAD" : builder.ToString();
    }

    /// <summary>
    /// A code's argument is <c>1*&lt;any TEXT-CHAR except "]"&gt;</c>.
    /// </summary>
    /// <remarks>
    /// The bracket is excluded by the grammar because it would close the code early, after which
    /// the client reads the remainder as ordinary text — the same class of confusion as a CRLF
    /// in the text, one nesting level down.
    /// </remarks>
    private static string SanitizeCodeArgument(string argument)
    {
        StringBuilder builder = new(argument.Length);

        foreach (char c in argument)
        {
            if (c is >= (char)0x20 and <= (char)0x7E && c != ']')
            {
                builder.Append(c);
            }
        }

        return builder.Length == 0 ? EmptyTextPlaceholder : builder.ToString();
    }
}

/// <summary>The wire names of RFC 3501 §2.3.2's system flags.</summary>
/// <remarks>
/// A backslash is a <c>quoted-special</c>, so <c>\Seen</c> is a <c>flag</c> in RFC 3501 §9's
/// grammar and never an atom — which is why these are written once here rather than assembled
/// wherever a flag list is needed.
/// </remarks>
public static class ImapFlagNames
{
    /// <summary>
    /// The flags this server stores, in the order they are listed.
    /// </summary>
    /// <remarks>
    /// <c>\Recent</c> is absent. It is reserved and never set — see
    /// <see cref="MessageFlags.Recent"/> — and RFC 3501 §2.3.2 does not permit a client to set it
    /// via <c>STORE</c> in any case, so listing it as available would be wrong twice over.
    /// </remarks>
    public static IReadOnlyList<MessageFlags> Ordered { get; } =
    [
        MessageFlags.Seen,
        MessageFlags.Answered,
        MessageFlags.Flagged,
        MessageFlags.Deleted,
        MessageFlags.Draft,
    ];

    /// <summary>Every flag a client may set on a message in this server.</summary>
    public static MessageFlags Settable =>
        MessageFlags.Seen | MessageFlags.Answered | MessageFlags.Flagged |
        MessageFlags.Deleted | MessageFlags.Draft;

    /// <summary>The wire name of one system flag.</summary>
    public static string NameOf(MessageFlags flag) => flag switch
    {
        MessageFlags.Seen => @"\Seen",
        MessageFlags.Answered => @"\Answered",
        MessageFlags.Flagged => @"\Flagged",
        MessageFlags.Deleted => @"\Deleted",
        MessageFlags.Draft => @"\Draft",
        MessageFlags.Recent => @"\Recent",
        _ => throw new ArgumentOutOfRangeException(nameof(flag), flag, "Not a single system flag."),
    };

    /// <summary>
    /// Recognises one system flag a client may set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only the five in <see cref="Ordered"/>. <c>\Recent</c> is deliberately not recognised
    /// here even though <see cref="NameOf"/> can write it: §9's <c>flag</c> production is
    /// annotated "; Does not include <c>\Recent</c>" and §2.3.2 says "This flag can not be
    /// altered by the client", so a <c>STORE</c> naming it must not be able to reach the flag
    /// through this method. Writing it and reading it are different permissions, and this is the
    /// read side.
    /// </para>
    /// <para>
    /// Case-insensitively, per §9's note (1): "all alphabetic characters are case-insensitive
    /// […] Implementations MUST accept these strings in a case-insensitive fashion." Clients do
    /// vary — <c>\seen</c> and <c>\SEEN</c> both occur in the wild.
    /// </para>
    /// </remarks>
    public static bool TryParse(string name, out MessageFlags flag)
    {
        ArgumentNullException.ThrowIfNull(name);

        foreach (MessageFlags candidate in Ordered)
        {
            if (name.Equals(NameOf(candidate), StringComparison.OrdinalIgnoreCase))
            {
                flag = candidate;
                return true;
            }
        }

        flag = MessageFlags.None;
        return false;
    }

    /// <summary>Formats a set of flags as the space-separated body of a parenthesised list.</summary>
    /// <remarks>
    /// Without the parentheses, because the surrounding syntax differs by response — <c>FLAGS</c>
    /// and <c>PERMANENTFLAGS</c> wrap the list themselves — and an empty result is correct and
    /// expected for a read-only mailbox's <c>PERMANENTFLAGS</c>.
    /// </remarks>
    public static string Format(MessageFlags flags)
    {
        List<string> names = [];

        foreach (MessageFlags flag in Ordered)
        {
            if (flags.HasFlag(flag))
            {
                names.Add(NameOf(flag));
            }
        }

        return string.Join(' ', names);
    }
}

/// <summary>The responses this server sends, written once each.</summary>
/// <remarks>
/// The numeric data responses are the reason this class exists rather than a handful of call
/// sites composing strings. RFC 3501 §7.3 puts the <b>number before the keyword</b> —
/// <c>* 172 EXISTS</c>, not <c>* EXISTS 172</c> — and getting that backwards is the single most
/// common defect in a hand-rolled IMAP server. A factory that cannot be called the wrong way
/// round settles it once.
/// </remarks>
public static class ImapResponses
{
    /// <summary>The greeting sent when a connection opens. RFC 3501 §7.1.1.</summary>
    public static ImapResponse Greeting(string product, IEnumerable<string> capabilities) =>
        ImapResponse.Untagged(
            ImapResponseStatus.Ok,
            $"{product} IMAP4rev1 ready",
            ImapResponseCode.Capability(capabilities));

    /// <summary>The farewell that precedes closing the connection. RFC 3501 §7.1.5.</summary>
    /// <remarks>
    /// Untagged, always, and sent before the tagged completion of <c>LOGOUT</c> — and also
    /// unilaterally when the server closes a connection for its own reasons, which is the case
    /// that makes it untagged-only: there is no command to tag it against.
    /// </remarks>
    public static ImapResponse Bye(string reason) =>
        ImapResponse.Untagged(ImapResponseStatus.Bye, reason);

    /// <summary>The untagged capability listing. RFC 3501 §7.2.1.</summary>
    public static ImapResponse Capability(IEnumerable<string> capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);

        return ImapResponse.Data($"CAPABILITY {string.Join(' ', capabilities)}");
    }

    /// <summary><c>* n EXISTS</c> — how many messages the mailbox holds. RFC 3501 §7.3.1.</summary>
    public static ImapResponse Exists(long count) => Count(count, "EXISTS");

    /// <summary>
    /// <c>* n RECENT</c> — how many messages are "recently arrived". RFC 3501 §7.3.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Always zero from this server, and required all the same. <c>\Recent</c> is reserved and
    /// never set — see <see cref="MessageFlags.Recent"/> — so zero is what this server's own
    /// state says, and <c>docs/IMAP.md</c>'s "reporting conservatively beats reporting
    /// incorrectly" is the decision behind it.
    /// </para>
    /// <para>
    /// <b>This is a deliberate deviation from a SHOULD, not conformance.</b> RFC 3501 §2.3.2
    /// says that "if it is not possible to determine whether or not this session is the first
    /// session to be notified about a message, then that message SHOULD be considered recent" —
    /// which points at reporting <i>more</i> messages as recent, not none. Reporting zero is
    /// therefore a choice this product makes against that SHOULD, on the grounds that correct
    /// <c>\Recent</c> semantics need cross-connection bookkeeping nothing here has and that
    /// modern clients rely on <c>EXISTS</c> growing instead. Worth stating plainly rather than
    /// dressing up as the conformant answer.
    /// </para>
    /// </remarks>
    public static ImapResponse Recent(long count) => Count(count, "RECENT");

    /// <summary>
    /// <c>* n EXPUNGE</c> — the message at sequence number <paramref name="sequenceNumber"/> is gone.
    /// </summary>
    /// <remarks>
    /// The most dangerous line this server can write. Every following message renumbers, so a
    /// batch must be emitted in <b>descending</b> order, and RFC 3501 §7.4.1 forbids sending one
    /// during <c>FETCH</c>, <c>STORE</c> or <c>SEARCH</c> at all — a client that renumbers
    /// mid-command acts on the wrong messages. Ordering and timing are the caller's to get right;
    /// this only makes the line.
    /// </remarks>
    public static ImapResponse Expunge(long sequenceNumber) =>
        SequenceNumber(sequenceNumber, "EXPUNGE");

    /// <summary>
    /// <c>* LIST (…) "/" name</c> — one mailbox. RFC 3501 §7.2.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 3501 §9's production is
    /// <c>mailbox-list = "(" [mbx-list-flags] ")" SP (DQUOTE QUOTED-CHAR DQUOTE / nil) SP
    /// mailbox</c> — so the delimiter is a <i>quoted single character</i> and never a bare one,
    /// and the name is an <c>astring</c> rather than raw text.
    /// </para>
    /// <para>
    /// <b>The name is encoded to modified UTF-7 first and quoted second, and that order is not
    /// interchangeable.</b> <see cref="ImapMailboxName.Encode"/> turns a name into printable
    /// US-ASCII; <see cref="ImapAstring.Format"/> then quotes that if the grammar requires it.
    /// Reversing the two would quote the Unicode name and then run the modified-UTF-7 encoder
    /// over the quotation marks it had just added, producing a name no client can decode back to
    /// what the user called their folder.
    /// </para>
    /// <para>
    /// The delimiter is always present for this server. §7.2.2: "A NIL hierarchy delimiter means
    /// that no hierarchy exists; the name is a 'flat' name" — and folder names here are
    /// <c>/</c>-separated paths, so <c>NIL</c> would be a false claim about the namespace.
    /// </para>
    /// </remarks>
    public static ImapResponse List(ImapMailboxAttribute attributes, string name) =>
        MailboxListing("LIST", attributes, name);

    /// <summary>
    /// <c>* LSUB (…) "/" name</c> — one subscribed mailbox. RFC 3501 §7.2.3.
    /// </summary>
    /// <remarks>
    /// The same shape as <see cref="List"/>, differing only in the keyword, which is why they
    /// share one formatter: two would be one grammar written twice with two places to get the
    /// quoting wrong.
    /// </remarks>
    public static ImapResponse Lsub(ImapMailboxAttribute attributes, string name) =>
        MailboxListing("LSUB", attributes, name);

    /// <summary>
    /// The answer to <c>LIST reference ""</c> — the hierarchy-delimiter probe.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 3501 §6.3.8: "An empty ("" string) mailbox name argument is a special request to
    /// return the hierarchy delimiter and the root name of the name given in the reference […]
    /// This permits a client to get the hierarchy delimiter (or find out that the mailbox names
    /// are flat) even when no mailboxes by that name currently exist."
    /// </para>
    /// <para>
    /// It is the first thing most clients send, and §6.3.8's own example fixes the wire form
    /// exactly:
    /// </para>
    /// <code>
    /// C: A101 LIST "" ""
    /// S: * LIST (\Noselect) "/" ""
    /// </code>
    /// <para>
    /// <c>\Noselect</c> because the root is not a mailbox anybody can open, and the empty name
    /// as <c>""</c> because <c>astring</c>'s unquoted branch is <c>1*ASTRING-CHAR</c> and an
    /// empty argument has no unquoted form — emitting nothing at all there would shift every
    /// following token in the response.
    /// </para>
    /// </remarks>
    public static ImapResponse HierarchyDelimiter(string root) =>
        MailboxListing("LIST", ImapMailboxAttribute.NoSelect, root);

    /// <summary>
    /// The hierarchy-delimiter probe answered as an <c>LSUB</c> line.
    /// </summary>
    /// <remarks>
    /// The same information under the other keyword. RFC 3501 §6.3.9 does not restate §6.3.8's
    /// empty-name special case, but it does say the arguments take the same form, so a client
    /// that probes with <c>LSUB</c> gets the same answer rather than a bare <c>OK</c> it cannot
    /// use.
    /// </remarks>
    public static ImapResponse LsubHierarchyDelimiter(string root) =>
        MailboxListing("LSUB", ImapMailboxAttribute.NoSelect, root);

    private static ImapResponse MailboxListing(
        string keyword,
        ImapMailboxAttribute attributes,
        string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        string encoded = ImapAstring.Format(ImapMailboxName.Encode(name));

        return ImapResponse.Data(
            $"{keyword} ({ImapMailboxAttributes.Format(attributes)}) " +
            $"\"{Entities.MailboxFolder.PathSeparator}\" {encoded}");
    }

    /// <summary>
    /// <c>* STATUS mailbox (…)</c> — the answer to <c>STATUS</c>. RFC 3501 §7.2.4.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The items and their values are paired here rather than by the caller.</b> §9's
    /// <c>status-att-list</c> is a flat run of alternating names and numbers, which is exactly
    /// the shape in which a name can end up next to another item's number — and a client reading
    /// <c>UNSEEN</c> where the server meant <c>MESSAGES</c> would show the user an unread badge
    /// on every message in the folder. Taking the requested items and the folder's status and
    /// doing the pairing in one place makes that mismatch unexpressible.
    /// </para>
    /// <para>
    /// Only the items asked for are reported, and in the order asked — which is this server's
    /// choice rather than a requirement, because §9's <c>status-att-list</c> imposes no order.
    /// <b>§6.3.10's own example in fact reorders</b>: <c>C: A042 STATUS blurdybloop (UIDNEXT
    /// MESSAGES)</c> is answered <c>S: * STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292)</c>, the
    /// other way round. So reordering is plainly permitted; echoing the requested order is done
    /// because it makes a packet capture legible beside the command that prompted it, and for no
    /// other reason.
    /// </para>
    /// </remarks>
    /// <param name="name">The mailbox, as the client named it. Encoded and quoted here.</param>
    /// <param name="items">The requested items, already parsed and de-duplicated.</param>
    /// <param name="status">The folder's numbers.</param>
    public static ImapResponse Status(
        string name,
        IReadOnlyList<ImapStatusItem> items,
        ImapFolderStatus status)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(status);

        List<string> pairs = new(items.Count);

        foreach (ImapStatusItem item in items)
        {
            pairs.Add($"{ImapStatusItems.NameOf(item)} {status.ValueOf(item)}");
        }

        string encoded = ImapAstring.Format(ImapMailboxName.Encode(name));

        return ImapResponse.Data($"STATUS {encoded} ({string.Join(' ', pairs)})");
    }

    /// <summary>
    /// <c>* n FETCH (…)</c> — one message's data. RFC 3501 §7.4.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The number is always a message sequence number, even for <c>UID FETCH</c>.</b> §6.4.8
    /// is explicit: "The number after the "*" in an untagged FETCH response is always a message
    /// sequence number, not a unique identifier, even for a UID command response." A server that
    /// echoed the UID there would have clients renumbering their caches against positions that do
    /// not exist.
    /// </para>
    /// <para>
    /// <b>The items and their values are paired here</b>, for the reason
    /// <see cref="Status"/> gives about its own list: §9's <c>msg-att</c> is a flat run of
    /// alternating names and values, which is the shape in which one item's value can end up
    /// under another item's name.
    /// </para>
    /// <para>
    /// An item this server cannot answer is skipped rather than guessed at — see
    /// <see cref="ImapMessageSummary.ValueOf"/> — so a caller that failed to filter the request
    /// emits a shorter response rather than a wrong one. The handler filters first, and a
    /// response with nothing in it would be ungrammatical, so this refuses to build one.
    /// </para>
    /// </remarks>
    /// <param name="sequenceNumber">The message's position in the folder, from 1.</param>
    /// <param name="items">The requested items, in the order asked.</param>
    /// <param name="summary">The message's stored values.</param>
    public static ImapResponse Fetch(
        long sequenceNumber,
        IReadOnlyList<ImapFetchItem> items,
        ImapMessageSummary summary)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(summary);

        List<string> pairs = new(items.Count);

        foreach (ImapFetchItem item in items)
        {
            if (summary.ValueOf(item) is { } value)
            {
                pairs.Add($"{ImapFetchItems.NameOf(item)} {value}");
            }
        }

        if (pairs.Count == 0)
        {
            throw new ArgumentException(
                "A FETCH response must carry at least one data item; RFC 3501 §9's msg-att has " +
                "no empty form.",
                nameof(items));
        }

        return SequenceNumber(sequenceNumber, $"FETCH ({string.Join(' ', pairs)})");
    }

    /// <summary><c>* FLAGS (…)</c> — the flags defined in the selected mailbox. RFC 3501 §7.2.6.</summary>
    public static ImapResponse Flags(MessageFlags flags) =>
        ImapResponse.Data($"FLAGS ({ImapFlagNames.Format(flags)})");

    /// <summary>The tagged completion of a command that succeeded.</summary>
    public static ImapResponse Ok(string tag, string text, ImapResponseCode? code = null) =>
        ImapResponse.Tagged(tag, ImapResponseStatus.Ok, text, code);

    /// <summary>The tagged refusal of a command this server understood and declined.</summary>
    public static ImapResponse No(string tag, string text, ImapResponseCode? code = null) =>
        ImapResponse.Tagged(tag, ImapResponseStatus.No, text, code);

    /// <summary>The tagged refusal of a command that was malformed or out of sequence.</summary>
    public static ImapResponse Bad(string tag, string text, ImapResponseCode? code = null) =>
        ImapResponse.Tagged(tag, ImapResponseStatus.Bad, text, code);

    /// <summary>
    /// The untagged refusal, for when the command cannot be determined. RFC 3501 §7.1.3.
    /// </summary>
    /// <remarks>
    /// What a tag that would not parse earns: there is nothing to tag the answer with, and
    /// echoing the offending tag back is exactly what must not happen. See
    /// <see cref="ImapCommand.TryParse"/>.
    /// </remarks>
    public static ImapResponse UntaggedBad(string text) =>
        ImapResponse.Untagged(ImapResponseStatus.Bad, text);

    /// <summary>The continuation request that asks for a synchronising literal's octets.</summary>
    public static ImapResponse ReadyForLiteral() => ImapResponse.Continuation("Ready for literal data");

    /// <summary>The largest value RFC 3501 §9's <c>number</c> can carry.</summary>
    /// <remarks>
    /// "Unsigned 32-bit integer (0 &lt;= n &lt; 4,294,967,296)", and <c>nz-number</c> is the same
    /// range without zero. These are <see cref="long"/> here because a UID counter is stored as
    /// one, so the ceiling has to be checked rather than assumed: a folder whose <c>UIDNEXT</c>
    /// has genuinely run past 2^32 cannot be described to a client in this protocol at all, and
    /// silently emitting a number no client can parse would be the worse of the two failures.
    /// </remarks>
    private const long MaxProtocolNumber = 4_294_967_295;

    /// <summary>A count: <c>number</c>, so zero is legal.</summary>
    /// <remarks>
    /// RFC 3501 §9: <c>mailbox-data = … number SP "EXISTS" / number SP "RECENT"</c>. An empty
    /// mailbox reports <c>* 0 EXISTS</c>, which is both grammatical and the truth.
    /// </remarks>
    private static ImapResponse Count(long number, string keyword)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(number);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(number, MaxProtocolNumber);

        return ImapResponse.Data(
            string.Create(CultureInfo.InvariantCulture, $"{number} {keyword}"));
    }

    /// <summary>A message sequence number: <c>nz-number</c>, so zero is not.</summary>
    /// <remarks>
    /// RFC 3501 §9: <c>message-data = nz-number SP ("EXPUNGE" / ("FETCH" SP msg-att))</c>. The
    /// distinction from <see cref="Count"/> is not pedantry — sequence numbers are one-based, so
    /// <c>* 0 EXPUNGE</c> names no message. A client that renumbers its cache from it either
    /// rejects the line or acts on the wrong message, and this is the one response where acting
    /// on the wrong message means deleting the wrong mail.
    /// </remarks>
    private static ImapResponse SequenceNumber(long number, string text)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(number, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(number, MaxProtocolNumber);

        return ImapResponse.Data(
            string.Create(CultureInfo.InvariantCulture, $"{number} {text}"));
    }
}
