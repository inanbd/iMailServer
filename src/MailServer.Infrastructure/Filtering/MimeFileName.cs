using System.Text;
using MailServer.Domain.Filtering;
using MailServer.Domain.Imap;

namespace MailServer.Infrastructure.Filtering;

/// <summary>
/// Works out what a MIME part calls itself, through the encodings a sender may have used.
/// </summary>
/// <remarks>
/// <para>
/// <b>Without this, the attachment policy is trivially bypassed.</b> A name check that reads
/// <c>filename</c> literally is defeated by writing <c>filename*=utf-8''payload%2Eexe</c>
/// instead — the recipient's client decodes it and saves <c>payload.exe</c>, and the check saw
/// a parameter it did not recognise. Every form a real client honours has to be understood
/// here, or the policy only stops senders who were not trying.
/// </para>
/// <para>
/// <b>Three forms, in the order a client prefers them.</b> RFC 2231's extended parameter
/// (<c>filename*</c>), RFC 2231's continuations (<c>filename*0*</c>, <c>filename*1*</c>), and
/// the plain parameter — which real senders fill with RFC 2047 encoded-words even though RFC
/// 2047 §5 forbids it in a parameter, so that is decoded too.
/// </para>
/// <para>
/// <b><c>Content-Disposition</c> wins over <c>Content-Type</c>.</b> RFC 2183 §2.3's
/// <c>filename</c> is what a client saves the file as; <c>Content-Type</c>'s <c>name</c> is
/// the older convention it falls back to. Reading the wrong one first means checking a name
/// the recipient will never see.
/// </para>
/// <para>
/// <b>Decoding never fails loudly.</b> A name that cannot be decoded is returned as written:
/// the check that follows is about what a desktop would do with it, and a desktop that cannot
/// decode a name does the same thing.
/// </para>
/// </remarks>
public static class MimeFileName
{
    /// <summary>The longest name this will decode.</summary>
    /// <remarks>
    /// A sender chooses this, and a decoded name goes into a finding an operator reads and a
    /// row this server stores. Real filenames are far below it; a megabyte-long one is an
    /// attempt at something.
    /// </remarks>
    public const int MaxLength = 1024;

    /// <summary>Everything about a part that the attachment policy needs.</summary>
    /// <remarks>
    /// <b>A part with no name is still described.</b> Its media type is what is left to judge
    /// it by, and a part that declined to name itself is not thereby exempt.
    /// </remarks>
    public static AttachmentDescriptor Describe(ImapBodyPart part)
    {
        ArgumentNullException.ThrowIfNull(part);

        string? name =
            Read(part.DispositionParameters, "FILENAME") ??
            Read(part.Parameters, "NAME");

        string mediaType = $"{part.Type}/{part.Subtype}".ToLowerInvariant();

        return new AttachmentDescriptor(name, mediaType, part.Content.Length);
    }

    /// <summary>
    /// Whether a part is an attachment rather than the message a person reads.
    /// </summary>
    /// <remarks>
    /// <b>A named part is an attachment whatever its disposition says.</b> A sender who marks
    /// an executable <c>inline</c> has not made it safe, and several clients save an inline
    /// part with a filename exactly as they would an attached one. The disposition is a hint
    /// about rendering, not a statement about what the file is.
    /// </remarks>
    public static bool IsAttachment(ImapBodyPart part)
    {
        ArgumentNullException.ThrowIfNull(part);

        if (part.IsMultipart)
        {
            return false;
        }

        if (string.Equals(part.DispositionType, "ATTACHMENT", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return Read(part.DispositionParameters, "FILENAME") is not null ||
               Read(part.Parameters, "NAME") is not null;
    }

    /// <summary>
    /// Reads one parameter out of a flattened name/value list, decoding whatever form it is in.
    /// </summary>
    /// <param name="parameters">
    /// Name, value, name, value — <c>ImapBodyPart.Parameters</c>'s shape. Names arrive
    /// upper-cased; values arrive exactly as written.
    /// </param>
    /// <param name="wanted">The parameter name, upper-cased.</param>
    public static string? Read(IReadOnlyList<string> parameters, string wanted)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentException.ThrowIfNullOrEmpty(wanted);

        string? extended = null;
        string? plain = null;
        SortedDictionary<int, (string Value, bool Encoded)>? continuations = null;

        for (int i = 0; i + 1 < parameters.Count; i += 2)
        {
            string name = parameters[i];
            string value = parameters[i + 1];

            if (!name.StartsWith(wanted, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string suffix = name[wanted.Length..];

            if (suffix.Length == 0)
            {
                plain ??= value;
            }
            else if (suffix == "*")
            {
                extended ??= DecodeExtended(value);
            }
            else if (suffix.StartsWith('*'))
            {
                // RFC 2231 §3: filename*0*="utf-8''a", filename*1="b". The section number
                // decides the order, not the order the parameters happened to be written in,
                // and each section says for itself whether it is percent-encoded.
                bool encoded = suffix.EndsWith('*');
                ReadOnlySpan<char> digits = suffix.AsSpan(1, suffix.Length - 1 - (encoded ? 1 : 0));

                if (int.TryParse(digits, out int section))
                {
                    continuations ??= [];
                    continuations.TryAdd(section, (value, encoded));
                }
            }
        }

        if (continuations is { Count: > 0 })
        {
            string joined = Assemble(continuations);

            if (joined.Length > 0)
            {
                return Clamp(joined);
            }
        }

        if (extended is not null)
        {
            return Clamp(extended);
        }

        return plain is null ? null : Clamp(DecodeEncodedWords(plain));
    }

    /// <summary>
    /// Joins RFC 2231 §3 continuation sections.
    /// </summary>
    /// <remarks>
    /// The charset is declared on section 0 alone and applies to the whole value, so the
    /// percent-decoding of later sections is deferred until it is known. A run with no
    /// section 0 has no declared charset and is read as UTF-8, which is what every client
    /// does with it.
    /// </remarks>
    private static string Assemble(SortedDictionary<int, (string Value, bool Encoded)> sections)
    {
        Encoding charset = Encoding.UTF8;
        List<byte> bytes = [];

        foreach ((int section, (string value, bool encoded)) in sections)
        {
            string text = value;

            if (encoded && section == sections.Keys.First())
            {
                // Only the first section carries charset'language'text.
                int firstQuote = text.IndexOf('\'');
                int secondQuote = firstQuote < 0 ? -1 : text.IndexOf('\'', firstQuote + 1);

                if (secondQuote >= 0)
                {
                    charset = CharsetOrUtf8(text[..firstQuote]);
                    text = text[(secondQuote + 1)..];
                }
            }

            if (encoded)
            {
                PercentDecodeInto(text, bytes);
            }
            else
            {
                bytes.AddRange(Encoding.Latin1.GetBytes(text));
            }
        }

        try
        {
            return charset.GetString([.. bytes]);
        }
        catch (ArgumentException)
        {
            return Encoding.UTF8.GetString([.. bytes]);
        }
    }

    /// <summary>Decodes RFC 2231 §4's <c>charset'language'percent-encoded</c>.</summary>
    private static string DecodeExtended(string value)
    {
        int firstQuote = value.IndexOf('\'');
        int secondQuote = firstQuote < 0 ? -1 : value.IndexOf('\'', firstQuote + 1);

        if (secondQuote < 0)
        {
            // No charset prefix. Malformed, and every client falls back to reading it as-is
            // rather than discarding the name.
            return value;
        }

        Encoding charset = CharsetOrUtf8(value[..firstQuote]);
        List<byte> bytes = [];
        PercentDecodeInto(value[(secondQuote + 1)..], bytes);

        try
        {
            return charset.GetString([.. bytes]);
        }
        catch (ArgumentException)
        {
            return Encoding.UTF8.GetString([.. bytes]);
        }
    }

    /// <summary>
    /// Decodes RFC 2047 encoded-words embedded in a parameter value.
    /// </summary>
    /// <remarks>
    /// RFC 2047 §5 forbids this in a parameter and senders do it anyway, so clients honour it.
    /// A check that did not would miss the most common way an executable name is disguised.
    /// </remarks>
    private static string DecodeEncodedWords(string value)
    {
        if (!value.Contains("=?", StringComparison.Ordinal))
        {
            return value;
        }

        StringBuilder result = new(value.Length);
        int pos = 0;

        while (pos < value.Length)
        {
            int start = value.IndexOf("=?", pos, StringComparison.Ordinal);

            if (start < 0)
            {
                result.Append(value, pos, value.Length - pos);
                break;
            }

            result.Append(value, pos, start - pos);

            int end = value.IndexOf("?=", start + 2, StringComparison.Ordinal);

            if (end < 0 || !TryDecodeWord(value.AsSpan(start, end - start + 2), out string? decoded))
            {
                // Not a well-formed encoded-word. Emit the marker literally and carry on from
                // just after it, so a value containing "=?" in ordinary text survives intact.
                result.Append("=?");
                pos = start + 2;
                continue;
            }

            result.Append(decoded);
            pos = end + 2;
        }

        return result.ToString();
    }

    /// <summary>Decodes one <c>=?charset?B|Q?text?=</c>.</summary>
    private static bool TryDecodeWord(ReadOnlySpan<char> word, out string? decoded)
    {
        decoded = null;

        // =?charset?encoding?text?=
        ReadOnlySpan<char> inner = word[2..^2];

        int firstQuestion = inner.IndexOf('?');

        if (firstQuestion < 0)
        {
            return false;
        }

        ReadOnlySpan<char> afterCharset = inner[(firstQuestion + 1)..];
        int secondQuestion = afterCharset.IndexOf('?');

        if (secondQuestion != 1)
        {
            return false;
        }

        Encoding charset = CharsetOrUtf8(inner[..firstQuestion].ToString());
        char encoding = char.ToUpperInvariant(afterCharset[0]);
        ReadOnlySpan<char> text = afterCharset[(secondQuestion + 1)..];

        try
        {
            byte[] bytes = encoding switch
            {
                'B' => Convert.FromBase64String(text.ToString()),
                'Q' => DecodeQuotedPrintableWord(text),
                _ => [],
            };

            if (encoding is not ('B' or 'Q'))
            {
                return false;
            }

            decoded = charset.GetString(bytes);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or DecoderFallbackException)
        {
            return false;
        }
    }

    /// <summary>RFC 2047 §4.2's Q encoding, which is quoted-printable with <c>_</c> for space.</summary>
    private static byte[] DecodeQuotedPrintableWord(ReadOnlySpan<char> text)
    {
        List<byte> bytes = new(text.Length);

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];

            if (c == '_')
            {
                bytes.Add((byte)' ');
            }
            else if (c == '=' && i + 2 < text.Length &&
                     byte.TryParse(text.Slice(i + 1, 2), System.Globalization.NumberStyles.HexNumber, null, out byte b))
            {
                bytes.Add(b);
                i += 2;
            }
            else
            {
                bytes.Add((byte)c);
            }
        }

        return [.. bytes];
    }

    private static void PercentDecodeInto(string text, List<byte> bytes)
    {
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '%' && i + 2 < text.Length &&
                byte.TryParse(text.AsSpan(i + 1, 2), System.Globalization.NumberStyles.HexNumber, null, out byte b))
            {
                bytes.Add(b);
                i += 2;
            }
            else
            {
                bytes.Add((byte)text[i]);
            }
        }
    }

    /// <summary>
    /// The named encoding, or UTF-8.
    /// </summary>
    /// <remarks>
    /// Only the encodings the base class library carries without a code-pages provider are
    /// resolvable, which is UTF-8, UTF-16, ASCII and Latin-1. Anything else falls back to
    /// UTF-8 rather than throwing: mis-decoding a name produces mojibake, and the extension
    /// this is all for is ASCII in every case that matters.
    /// </remarks>
    private static Encoding CharsetOrUtf8(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return Encoding.UTF8;
        }

        try
        {
            return Encoding.GetEncoding(name.Trim());
        }
        catch (ArgumentException)
        {
            return Encoding.UTF8;
        }
    }

    private static string Clamp(string value) =>
        value.Length <= MaxLength ? value : value[..MaxLength];
}
