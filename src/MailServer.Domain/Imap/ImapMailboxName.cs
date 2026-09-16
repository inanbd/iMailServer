using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace MailServer.Domain.Imap;

/// <summary>
/// RFC 3501 §5.1.3's modified UTF-7 — how a mailbox name carrying characters outside printable
/// US-ASCII is represented on the wire.
/// </summary>
/// <remarks>
/// <para>
/// A variant of UTF-7 (RFC 2152) with three changes: <c>&amp;</c> is the shift character instead
/// of <c>+</c> (mailbox names use <c>+</c> constantly; they essentially never use <c>&amp;</c>),
/// <c>,</c> replaces <c>/</c> in the base64 alphabet (<c>/</c> is IMAP's own hierarchy separator
/// in this product — see <see cref="Entities.MailboxFolder.PathSeparator"/>, though that
/// separator is a domain-model choice, not something this RFC depends on — and <c>/</c>
/// appearing inside an encoded run would be needlessly confusing either way), and there is no
/// <c>=</c> padding: a partial trailing group of fewer than 6 bits is padded with zero
/// <i>bits</i>, not padding characters.
/// </para>
/// <para>
/// Operates on UTF-16 code units, not Unicode code points — <see cref="string"/> already is a
/// sequence of UTF-16 code units in .NET, so a surrogate pair (anything outside the Basic
/// Multilingual Plane) is handled correctly as an unremarkable side effect of encoding/decoding
/// char by char, never as a special case.
/// </para>
/// </remarks>
public static class ImapMailboxName
{
    private const string ModifiedBase64Alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

    /// <summary>Encodes a mailbox name for the wire.</summary>
    public static string Encode(string mailboxName)
    {
        ArgumentNullException.ThrowIfNull(mailboxName);

        StringBuilder result = new();
        int i = 0;

        while (i < mailboxName.Length)
        {
            char c = mailboxName[i];

            if (c == '&')
            {
                result.Append("&-");
                i++;
                continue;
            }

            if (IsDirectlyRepresentable(c))
            {
                result.Append(c);
                i++;
                continue;
            }

            int start = i;

            while (i < mailboxName.Length && !IsDirectlyRepresentable(mailboxName[i]) && mailboxName[i] != '&')
            {
                i++;
            }

            result.Append('&');
            AppendModifiedBase64(result, mailboxName, start, i - start);
            result.Append('-');
        }

        return result.ToString();
    }

    /// <summary>Decodes a mailbox name from the wire.</summary>
    /// <remarks>
    /// The wire text is client-controlled — arriving in a <c>SELECT</c>, <c>CREATE</c> or
    /// <c>RENAME</c> argument before that client has necessarily proven anything about itself —
    /// so every malformed shape (an unrecognised base64 character, non-zero padding bits left
    /// over from a partial group, a raw byte outside printable ASCII sitting unescaped) is
    /// refused rather than guessed at.
    /// </remarks>
    public static bool TryDecode(string wireText, [NotNullWhen(true)] out string? mailboxName)
    {
        ArgumentNullException.ThrowIfNull(wireText);

        StringBuilder result = new();
        int i = 0;

        while (i < wireText.Length)
        {
            char c = wireText[i];

            if (c != '&')
            {
                if (!IsDirectlyRepresentable(c))
                {
                    // A raw non-ASCII or control byte outside any shift sequence never
                    // legitimately appears in modified UTF-7 - it must have been encoded.
                    mailboxName = null;
                    return false;
                }

                result.Append(c);
                i++;
                continue;
            }

            // c == '&'.
            if (i + 1 < wireText.Length && wireText[i + 1] == '-')
            {
                result.Append('&');
                i += 2;
                continue;
            }

            int start = i + 1;
            int end = start;

            while (end < wireText.Length && ModifiedBase64Alphabet.Contains(wireText[end], StringComparison.Ordinal))
            {
                end++;
            }

            if (!TryDecodeModifiedBase64(wireText, start, end - start, out string? decoded))
            {
                mailboxName = null;
                return false;
            }

            result.Append(decoded);

            // The closing '-' is consumed when present; a shift may also end at end-of-string or
            // at any other non-alphabet character, which the outer loop picks up from here.
            i = end < wireText.Length && wireText[end] == '-' ? end + 1 : end;
        }

        mailboxName = result.ToString();
        return true;
    }

    /// <summary>Printable US-ASCII, per RFC 3501 §5.1.3 — the range that never needs a shift.</summary>
    private static bool IsDirectlyRepresentable(char c) => c is >= (char)0x20 and <= (char)0x7E;

    private static void AppendModifiedBase64(StringBuilder sb, string s, int start, int count)
    {
        int bitBuffer = 0;
        int bitCount = 0;

        for (int j = 0; j < count; j++)
        {
            bitBuffer = (bitBuffer << 16) | s[start + j];
            bitCount += 16;

            while (bitCount >= 6)
            {
                bitCount -= 6;
                sb.Append(ModifiedBase64Alphabet[(bitBuffer >> bitCount) & 0x3F]);
            }
        }

        if (bitCount > 0)
        {
            sb.Append(ModifiedBase64Alphabet[(bitBuffer << (6 - bitCount)) & 0x3F]);
        }
    }

    private static bool TryDecodeModifiedBase64(string s, int start, int count, out string? decoded)
    {
        List<char> chars = [];
        int bitBuffer = 0;
        int bitCount = 0;

        for (int j = 0; j < count; j++)
        {
            int value = ModifiedBase64Alphabet.IndexOf(s[start + j]);

            if (value < 0)
            {
                decoded = null;
                return false;
            }

            bitBuffer = (bitBuffer << 6) | value;
            bitCount += 6;

            if (bitCount >= 16)
            {
                bitCount -= 16;
                chars.Add((char)((bitBuffer >> bitCount) & 0xFFFF));
            }
        }

        // Whatever bits are left over must be zero-padding, never real content: a correct
        // encoder pads a partial trailing group with zero bits, so anything else means this text
        // was not produced by one.
        if (bitCount > 0 && (bitBuffer & ((1 << bitCount) - 1)) != 0)
        {
            decoded = null;
            return false;
        }

        decoded = new string([.. chars]);
        return true;
    }
}
