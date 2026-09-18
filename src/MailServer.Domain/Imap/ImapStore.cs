using System.Diagnostics.CodeAnalysis;
using MailServer.Domain.Enums;

namespace MailServer.Domain.Imap;

/// <summary>
/// Which of RFC 3501 §6.4.6's three flag operations a <c>STORE</c> asked for.
/// </summary>
/// <remarks>
/// §9: <c>store-att-flags = (["+" / "-"] "FLAGS" [".SILENT"]) SP (flag-list / (flag *(SP
/// flag)))</c>. The sign is the whole of the distinction, and its absence is the third case
/// rather than a default — <c>FLAGS</c> replaces, <c>+FLAGS</c> adds, <c>-FLAGS</c> removes.
/// </remarks>
public enum ImapStoreMode
{
    /// <summary>
    /// <c>FLAGS</c> — §6.4.6: "Replace the flags for the message (other than <c>\Recent</c>)
    /// with the argument."
    /// </summary>
    Replace = 0,

    /// <summary><c>+FLAGS</c> — "Add the argument to the flags for the message."</summary>
    Add = 1,

    /// <summary><c>-FLAGS</c> — "Remove the argument from the flags for the message."</summary>
    Remove = 2,
}

/// <summary>
/// A parsed <c>STORE</c> data item: what to do, to which flags, and whether to say so.
/// </summary>
/// <remarks>
/// <para>
/// <b><c>\Recent</c> can never be among <see cref="Flags"/>, and the grammar is why.</b> §9's
/// <c>flag</c> production is annotated "; Does not include <c>\Recent</c>", and §2.3.2 says of
/// it: "This flag can not be altered by the client." So a client cannot even write it, and
/// <see cref="Apply"/> preserves whatever the server has set rather than taking the client's
/// word for it.
/// </para>
/// <para>
/// <b>A flag this server cannot store is dropped rather than refused, which the RFC
/// sanctions in as many words.</b> §7.1 on <c>PERMANENTFLAGS</c>: "If the client attempts to
/// STORE a flag that is not in the PERMANENTFLAGS list, the server will either ignore the change
/// or store the state change for the remainder of the current session only." This server ignores
/// it, and the untagged <c>FETCH</c> that follows shows the client exactly what it got — which
/// is the RFC's own stated intent for that response, "that the status of the flags is
/// determinate". Refusing instead would be within the letter of §6.4.6's "NO - store error" and
/// would break real clients: Thunderbird and Apple Mail both send keywords like <c>$Junk</c> and
/// <c>$MDNSent</c> without asking, and a mailbox that answered <c>NO</c> to those would appear
/// broken for an operation the user never requested.
/// </para>
/// </remarks>
/// <param name="Mode">Replace, add or remove.</param>
/// <param name="Silent">
/// Whether <c>.SILENT</c> was given. §6.4.6: it "prevents the untagged FETCH, and the server
/// SHOULD assume that the client has determined the updated value itself".
/// </param>
/// <param name="Flags">The storable flags the client named. Never includes <c>\Recent</c>.</param>
/// <param name="HadUnstorableFlags">
/// Whether anything was dropped — a keyword, or a flag extension this server has no column for.
/// Carried so a handler can log it; it never changes the answer.
/// </param>
public sealed record ImapStoreRequest(
    ImapStoreMode Mode,
    bool Silent,
    MessageFlags Flags,
    bool HadUnstorableFlags)
{
    /// <summary>
    /// The flags a message ends up with.
    /// </summary>
    /// <remarks>
    /// <c>\Recent</c> survives every mode, including <c>Replace</c>. §6.4.6 puts the exception in
    /// the sentence itself — "Replace the flags for the message (other than <c>\Recent</c>) with
    /// the argument" — so a replace that cleared it would be altering a flag the client is not
    /// permitted to alter, by means of a command that does not mention it.
    /// </remarks>
    public MessageFlags Apply(MessageFlags current) => Mode switch
    {
        ImapStoreMode.Replace => (current & MessageFlags.Recent) | Flags,
        ImapStoreMode.Add => current | Flags,
        ImapStoreMode.Remove => current & ~Flags,
        _ => current,
    };
}

/// <summary>Reading a <c>STORE</c> command's data item and its value.</summary>
public static class ImapStore
{
    /// <summary>The most flags one <c>STORE</c> may name.</summary>
    /// <remarks>
    /// Five are storable and repeats are grammatical, so a real list is short. The cap bounds the
    /// work a single line can force before any of it reaches a mailbox, as
    /// <see cref="ImapStatusItems.MaxItemCount"/> does for its own list.
    /// </remarks>
    public const int MaxFlagCount = 64;

    /// <summary>
    /// Parses <c>store-att-flags</c> and its value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The flag list may arrive without brackets.</b> §9: <c>… SP (flag-list / (flag *(SP
    /// flag)))</c> — two alternatives, so <c>STORE 1 +FLAGS \Deleted</c> and
    /// <c>STORE 1 +FLAGS (\Deleted)</c> are both conformant. A parser that required the brackets
    /// would reject clients that are in the right.
    /// </para>
    /// <para>
    /// <b>An empty bracketed list is legal and means something.</b> <c>flag-list = "(" [flag
    /// *(SP flag)] ")"</c> makes the contents optional, so <c>STORE 1 FLAGS ()</c> clears every
    /// flag — which is how a client marks a message unread, undeleted and unflagged in one go.
    /// The bare alternative has no empty form, so <c>STORE 1 FLAGS</c> with nothing after it is
    /// a syntax error rather than the same request.
    /// </para>
    /// </remarks>
    /// <param name="text">Everything after the sequence set.</param>
    public static bool TryParse(
        string text,
        [NotNullWhen(true)] out ImapStoreRequest? request)
    {
        ArgumentNullException.ThrowIfNull(text);

        request = null;

        string trimmed = text.Trim();

        int space = trimmed.IndexOf(' ', StringComparison.Ordinal);

        if (space <= 0)
        {
            return false;
        }

        if (!TryParseItem(trimmed[..space], out ImapStoreMode mode, out bool silent))
        {
            return false;
        }

        string value = trimmed[(space + 1)..].Trim();

        if (!TryParseFlags(value, out MessageFlags flags, out bool dropped))
        {
            return false;
        }

        request = new ImapStoreRequest(mode, silent, flags, dropped);
        return true;
    }

    /// <summary>Reads the <c>["+" / "-"] "FLAGS" [".SILENT"]</c> item name.</summary>
    /// <remarks>
    /// Case-insensitively for the words, per §9's note (1) — but the sign is punctuation and has
    /// no case, so it is compared as itself. <c>FLAGS</c> is the only data item §6.4.6 defines
    /// for <c>STORE</c>, so anything else is a syntax error and not an unimplemented feature.
    /// </remarks>
    private static bool TryParseItem(string name, out ImapStoreMode mode, out bool silent)
    {
        mode = ImapStoreMode.Replace;
        silent = false;

        string rest = name;

        if (rest.StartsWith('+'))
        {
            mode = ImapStoreMode.Add;
            rest = rest[1..];
        }
        else if (rest.StartsWith('-'))
        {
            mode = ImapStoreMode.Remove;
            rest = rest[1..];
        }

        if (rest.EndsWith(".SILENT", StringComparison.OrdinalIgnoreCase))
        {
            silent = true;
            rest = rest[..^".SILENT".Length];
        }

        return rest.Equals("FLAGS", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Reads either alternative of the value, and drops what cannot be stored.</summary>
    private static bool TryParseFlags(string value, out MessageFlags flags, out bool dropped)
    {
        flags = MessageFlags.None;
        dropped = false;

        string body;

        if (value.StartsWith('('))
        {
            if (!value.EndsWith(')'))
            {
                return false;
            }

            body = value[1..^1];
        }
        else
        {
            // The bare alternative is 'flag *(SP flag)', which has no empty form.
            if (value.Length == 0)
            {
                return false;
            }

            body = value;
        }

        if (body.Contains('(') || body.Contains(')'))
        {
            return false;
        }

        string[] names = body.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (names.Length > MaxFlagCount)
        {
            return false;
        }

        foreach (string name in names)
        {
            if (ImapFlagNames.TryParse(name, out MessageFlags flag))
            {
                flags |= flag;
            }
            else if (IsWellFormedFlag(name))
            {
                // Grammatical, and this server has nowhere to put it. Ignored rather than
                // refused - see ImapStoreRequest's remarks for the RFC text that permits it.
                dropped = true;
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Whether a name is a <c>flag</c> the grammar admits, even if this server cannot store it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §9: <c>flag-keyword = atom</c> and <c>flag-extension = "\" atom</c>. So a keyword is a
    /// bare atom and an extension is a backslash and an atom — and something that is neither,
    /// such as a bare <c>\</c> or a name carrying a space or a bracket, is malformed rather than
    /// merely unsupported. The difference decides <c>BAD</c> against a silent drop.
    /// </para>
    /// <para>
    /// <c>\Recent</c> is deliberately not special-cased here. §9 annotates <c>flag</c> with
    /// "; Does not include <c>\Recent</c>", so a client that sends it is outside the grammar —
    /// but it is a well-formed <c>flag-extension</c> by shape, and dropping it silently reaches
    /// the same place as refusing it would: the flag is not altered. Treating it as a drop keeps
    /// the one rule that matters — <see cref="ImapStoreRequest.Apply"/> never changes it —
    /// without inventing a refusal the RFC does not ask for.
    /// </para>
    /// </remarks>
    private static bool IsWellFormedFlag(string name)
    {
        string atom = name.StartsWith('\\') ? name[1..] : name;

        if (atom.Length == 0)
        {
            return false;
        }

        foreach (char c in atom)
        {
            // atom = 1*ATOM-CHAR, and ATOM-CHAR excludes the specials and everything outside
            // printable ASCII.
            if (c is < (char)0x21 or > (char)0x7E)
            {
                return false;
            }

            if (c is '(' or ')' or '{' or '%' or '*' or '"' or '\\' or ']')
            {
                return false;
            }
        }

        return true;
    }
}
