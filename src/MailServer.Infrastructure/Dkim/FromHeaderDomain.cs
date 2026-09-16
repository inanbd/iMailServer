using System.Text;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Dkim;

/// <summary>
/// Extracts the domain of a message's <c>From:</c> header — what both DKIM signing (which key to
/// sign with) and DMARC alignment (a later step) key off.
/// </summary>
/// <remarks>
/// Deliberately not a full RFC 5322 mailbox parser: comments and non-ASCII display names are not
/// handled. This looks for the last <c>&lt;...&gt;</c> pair and falls back to treating the whole
/// value as an addr-spec, which is the same pragmatic extraction most MTAs use for this specific
/// purpose. Nothing here is a security boundary — the worst case of a misparse is that signing
/// or alignment is skipped for a message that could otherwise have had it, never that a check is
/// bypassed.
/// </remarks>
internal static class FromHeaderDomain
{
    public static bool TryExtract(RawMessageHeaders headers, out DomainName? domain)
    {
        domain = null;

        List<RawHeaderField> fromFields = [.. headers.GetAll("From")];

        if (fromFields.Count == 0)
        {
            return false;
        }

        string value = ExtractHeaderValueText(fromFields[0]);
        string addrSpec = ExtractAddrSpec(value);

        if (!EmailAddress.TryParse(addrSpec, out EmailAddress? address))
        {
            return false;
        }

        domain = address.Domain;
        return true;
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
