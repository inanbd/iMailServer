namespace MailServer.Domain.Smtp;

/// <summary>
/// The transmitting half of SMTP transparency: inserts the dot that
/// <see cref="SmtpDataDecoder"/> removes.
/// </summary>
/// <remarks>
/// <para>
/// RFC 5321 §4.5.2. Any body line that begins with <c>.</c> gets a second one prepended before
/// it goes on the wire, so that the receiver — which removes exactly one — sees the original
/// line, and so that a line consisting solely of <c>.</c> cannot be mistaken for the
/// end-of-data marker.
/// </para>
/// <para>
/// This is what makes the round trip safe. A message whose body genuinely contains the octets
/// <c>CRLF "." CRLF</c> is stored verbatim by the decoder and is re-stuffed here on the way
/// out, so relaying it truncates nothing and injects nothing. Stuffing on send and unstuffing
/// on receipt are two halves of one guarantee and neither is optional.
/// </para>
/// <para>
/// Streaming, like the decoder: one octet of state, no line buffering.
/// </para>
/// </remarks>
public sealed class SmtpDotStuffing
{
    private const byte Cr = (byte)'\r';
    private const byte Lf = (byte)'\n';
    private const byte Dot = (byte)'.';

    private bool _atLineStart = true;
    private byte _lastEmitted;
    private bool _anyEmitted;

    /// <summary>The largest output <see cref="Stuff"/> can produce for a given input length.</summary>
    /// <remarks>
    /// Worst case is a body of nothing but <c>".\r\n"</c> lines, where one octet in three is
    /// doubled. Bounding it exactly lets callers size a buffer once instead of growing one.
    /// </remarks>
    public static int MaxOutputFor(int inputLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(inputLength);
        return checked((inputLength * 2) + 2);
    }

    /// <summary>Stuffs one chunk of body octets.</summary>
    /// <param name="input">Body octets as stored.</param>
    /// <param name="output">
    /// Receives wire octets. Must be at least <see cref="MaxOutputFor"/> octets long.
    /// </param>
    /// <returns>Octets written to <paramref name="output"/>.</returns>
    public int Stuff(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length < MaxOutputFor(input.Length))
        {
            throw new ArgumentException(
                $"Output buffer must be at least {MaxOutputFor(input.Length)} octets for " +
                $"{input.Length} input octets; see {nameof(MaxOutputFor)}.",
                nameof(output));
        }

        int written = 0;

        foreach (byte b in input)
        {
            if (_atLineStart && b == Dot)
            {
                output[written++] = Dot;
            }

            output[written++] = b;
            _atLineStart = b == Lf;
            _lastEmitted = b;
            _anyEmitted = true;
        }

        return written;
    }

    /// <summary>
    /// Writes the end-of-data marker, first completing the final line if the body did not end
    /// with one.
    /// </summary>
    /// <remarks>
    /// A body that does not end in <c>CRLF</c> must not have <c>".CRLF"</c> appended directly:
    /// the dot would land mid-line and the receiver would never see a terminator, so the
    /// message would hang until the peer's session timeout. Completing the line first is not
    /// cosmetic.
    /// </remarks>
    /// <param name="output">Receives the marker. Must be at least 5 octets long.</param>
    /// <returns>Octets written.</returns>
    public int WriteTerminator(Span<byte> output)
    {
        if (output.Length < 5)
        {
            throw new ArgumentException(
                "Output buffer must be at least 5 octets for the end-of-data marker.",
                nameof(output));
        }

        int written = 0;

        if (_anyEmitted && _lastEmitted != Lf)
        {
            output[written++] = Cr;
            output[written++] = Lf;
        }

        output[written++] = Dot;
        output[written++] = Cr;
        output[written++] = Lf;

        _atLineStart = true;
        return written;
    }

    /// <summary>Stuffs a whole body and appends the marker. For tests and small messages.</summary>
    /// <remarks>
    /// Deliberately not used on the delivery path. Materialising a message as a single array is
    /// exactly the habit the streaming API exists to prevent, so the one method that does it
    /// says so in its name and its documentation.
    /// </remarks>
    public static byte[] StuffEntireBodyForTesting(ReadOnlySpan<byte> body)
    {
        SmtpDotStuffing stuffing = new();
        byte[] buffer = new byte[MaxOutputFor(body.Length) + 5];

        int written = stuffing.Stuff(body, buffer);
        written += stuffing.WriteTerminator(buffer.AsSpan(written));

        return buffer[..written];
    }
}
