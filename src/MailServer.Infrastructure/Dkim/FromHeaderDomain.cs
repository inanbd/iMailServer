using System.Text;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Dkim;

/// <summary>
/// Extracts the domain of a message's <c>From:</c> header — what both DKIM signing (which key to
/// sign with) and DMARC alignment (a later step) key off.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not a full RFC 5322 mailbox parser: comments and non-ASCII display names are not
/// handled. For a single mailbox, this looks for the last <c>&lt;...&gt;</c> pair and falls back
/// to treating the whole value as an addr-spec, which is the same pragmatic extraction most MTAs
/// use for this specific purpose.
/// </para>
/// <para>
/// <b>This is a security boundary, and a multi-address <c>From:</c> is refused rather than
/// picked from.</b> RFC 7489 §6.6.1 calls out exactly this ambiguity: more than one address in a
/// single <c>From:</c> field, or more than one <c>From:</c> field, has "no meaningful" single
/// author domain and receivers typically reject such mail outright. Silently picking one
/// address (the earlier last-<c>&lt;...&gt;</c>-pair heuristic did, with no mailbox count check)
/// lets an attacker put their own domain — with valid SPF/DKIM/DMARC of its own — anywhere in a
/// crafted multi-address <c>From:</c> alongside a spoofed, displayed address, and have DMARC
/// pass against the attacker's domain while a recipient's mail client shows the spoofed one.
/// Refusing to extract a domain at all here means <see cref="Dmarc.DmarcEvaluator"/> treats the
/// message as "DMARC does not apply" (never as a pass), which is the safe direction: it can
/// under-protect a message DMARC does not get to evaluate, but it can never turn an attacker's
/// address of their own choosing into a false alignment pass.
/// </para>
/// </remarks>
internal static class FromHeaderDomain
{
    public static bool TryExtract(RawMessageHeaders headers, out DomainName? domain)
    {
        domain = null;

        List<RawHeaderField> fromFields = [.. headers.GetAll("From")];

        // RFC 5322 forbids more than one From: field; RFC 7489 section 6.6.1 says such mail (and
        // a single From: field naming more than one mailbox) has no unambiguous author domain.
        if (fromFields.Count != 1)
        {
            return false;
        }

        string value = ExtractHeaderValueText(fromFields[0]);

        if (HasMoreThanOneMailbox(value))
        {
            return false;
        }

        string addrSpec = ExtractAddrSpec(value);

        if (!EmailAddress.TryParse(addrSpec, out EmailAddress? address))
        {
            return false;
        }

        domain = address.Domain;
        return true;
    }

    /// <summary>
    /// A conservative, cheap signal that a <c>From:</c> value names more than one mailbox: more
    /// than one <c>&lt;...&gt;</c> pair, or a comma outside of any such pair (a mailbox-list
    /// separator between a bracketed and a bare addr-spec, or between two bare ones).
    /// </summary>
    /// <remarks>
    /// A quoted display name containing a comma (<c>"Smith, John" &lt;john@example.com&gt;</c>)
    /// is a single mailbox this flags as ambiguous anyway, since quoted strings are not tracked —
    /// consistent with this type's existing "not a full RFC 5322 parser" scope, and safe for the
    /// same reason a misparse always is here: the result is a skipped alignment opportunity for
    /// an unusual but legitimate message, never a bypassed check.
    /// </remarks>
    private static bool HasMoreThanOneMailbox(string headerValue)
    {
        int bracketPairs = 0;
        bool insideBrackets = false;

        foreach (char c in headerValue)
        {
            switch (c)
            {
                case '<':
                    insideBrackets = true;
                    bracketPairs++;
                    break;
                case '>':
                    insideBrackets = false;
                    break;
                case ',' when !insideBrackets:
                    return true;
            }
        }

        return bracketPairs > 1;
    }

    private static string ExtractHeaderValueText(RawHeaderField field)
    {
        ReadOnlySpan<byte> raw = field.RawBytes.Span;
        int colon = raw.IndexOf((byte)':');
        string value = Encoding.ASCII.GetString(raw[(colon + 1)..^2]);

        // Folding inserts CRLF before a WSP run; removing it leaves the WSP as an ordinary
        // separator, which is all bracket/address extraction needs.
        return value.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal);
    }

    private static string ExtractAddrSpec(string headerValue)
    {
        int close = headerValue.LastIndexOf('>');

        if (close < 0)
        {
            return headerValue.Trim();
        }

        int open = headerValue.LastIndexOf('<', close);

        return open < 0 ? headerValue.Trim() : headerValue[(open + 1)..close].Trim();
    }
}
