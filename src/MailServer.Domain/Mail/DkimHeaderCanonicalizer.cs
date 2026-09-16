namespace MailServer.Domain.Mail;

/// <summary>
/// RFC 6376 §3.4.2 "relaxed" header canonicalization.
/// </summary>
/// <remarks>
/// <para>
/// This product implements <c>relaxed</c> canonicalization only — never <c>simple</c>. Relaxed
/// tolerates the whitespace and line-folding changes that mailing-list software, forwarding
/// agents and mail gateways routinely make in transit; <c>simple</c> breaks on the first byte
/// any of them touch, which in practice makes it the less interoperable choice for signing, not
/// the more rigorous one. See the addendum recording this scope decision.
/// </para>
/// <para>
/// Header fields are small and bounded (the receive pipeline enforces a header-size limit), so
/// unlike <see cref="DkimBodyCanonicalizer"/> this does not need to be streaming — it operates
/// on one already-parsed <see cref="RawHeaderField"/> at a time and returns the canonical bytes
/// directly.
/// </para>
/// <para>
/// <b>Relies on an invariant of <see cref="RawMessageHeaders"/>:</b> a field's raw bytes contain
/// a CRLF only at a fold boundary (a continuation line, which by definition starts with SP or
/// TAB) or as the field's own final terminator. <see cref="RawMessageHeaders.TryParse"/> would
/// not have produced a field any other way — a CRLF not followed by WSP ends the field there.
/// That is what lets <see cref="Unfold"/> below treat every CRLF it finds as a fold to remove,
/// without first re-checking what follows it.
/// </para>
/// </remarks>
public static class DkimHeaderCanonicalizer
{
    private const byte Cr = (byte)'\r';
    private const byte Lf = (byte)'\n';
    private const byte Colon = (byte)':';
    private const byte Space = (byte)' ';

    /// <summary>
    /// Produces the relaxed-canonical form of one header field, ending in a single CRLF.
    /// </summary>
    /// <remarks>
    /// RFC 6376 §3.4.2, all four rules: unfold; collapse whitespace runs to a single SP; drop
    /// whitespace at the very start and end of the value (which is what "delete WSP immediately
    /// after the colon" and "delete WSP at the end of the header value" amount to once the value
    /// is considered as a whole); drop whitespace immediately before the colon; lowercase the
    /// field name. The colon itself is always retained.
    /// </remarks>
    public static byte[] Canonicalize(RawHeaderField field)
    {
        ReadOnlySpan<byte> raw = field.RawBytes.Span;

        if (raw.Length < 2 || raw[^2] != Cr || raw[^1] != Lf)
        {
            throw new ArgumentException(
                "A raw header field produced by RawMessageHeaders always ends in CRLF.",
                nameof(field));
        }

        byte[] unfolded = Unfold(raw[..^2]);
        int colonIndex = Array.IndexOf(unfolded, Colon);

        if (colonIndex < 0)
        {
            throw new ArgumentException(
                "A raw header field produced by RawMessageHeaders always contains a colon.",
                nameof(field));
        }

        byte[] name = LowercaseAndTrimEnd(unfolded.AsSpan(0, colonIndex));
        byte[] value = CollapseAndTrimWhitespace(unfolded.AsSpan(colonIndex + 1));

        byte[] result = new byte[name.Length + 1 + value.Length + 2];
        int o = 0;
        name.CopyTo(result, o);
        o += name.Length;
        result[o++] = Colon;
        value.CopyTo(result, o);
        o += value.Length;
        result[o++] = Cr;
        result[o] = Lf;
        return result;
    }

    /// <summary>Removes every fold CRLF, leaving the WSP that followed it in place.</summary>
    private static byte[] Unfold(ReadOnlySpan<byte> withoutTerminator)
    {
        byte[] output = new byte[withoutTerminator.Length];
        int o = 0;
        int i = 0;

        while (i < withoutTerminator.Length)
        {
            if (withoutTerminator[i] == Cr && i + 1 < withoutTerminator.Length && withoutTerminator[i + 1] == Lf)
            {
                i += 2;
                continue;
            }

            output[o++] = withoutTerminator[i];
            i++;
        }

        return output[..o];
    }

    private static byte[] LowercaseAndTrimEnd(ReadOnlySpan<byte> name)
    {
        int end = name.Length;
        while (end > 0 && IsWsp(name[end - 1]))
        {
            end--;
        }

        byte[] result = new byte[end];
        for (int i = 0; i < end; i++)
        {
            result[i] = ToLowerAscii(name[i]);
        }

        return result;
    }

    private static byte[] CollapseAndTrimWhitespace(ReadOnlySpan<byte> value)
    {
        byte[] output = new byte[value.Length];
        int o = 0;
        bool pendingWsp = false;
        bool anyContent = false;

        foreach (byte b in value)
        {
            if (IsWsp(b))
            {
                if (anyContent)
                {
                    pendingWsp = true;
                }

                continue;
            }

            if (pendingWsp)
            {
                output[o++] = Space;
                pendingWsp = false;
            }

            output[o++] = b;
            anyContent = true;
        }

        return output[..o];
    }

    private static bool IsWsp(byte b) => b is (byte)' ' or (byte)'\t';

    private static byte ToLowerAscii(byte b) => b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
}
