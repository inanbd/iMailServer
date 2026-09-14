namespace MailServer.Domain.Smtp;

/// <summary>
/// Decodes the body of an SMTP <c>DATA</c> command from the bytes on the wire.
/// </summary>
/// <remarks>
/// <para>
/// Three jobs, performed in a fixed order that is itself the security property:
/// </para>
/// <list type="number">
///   <item>
///     <description>
///     <b>Find the end of the message</b> — and only at the exact octet sequence
///     <c>CRLF "." CRLF</c>, scanned on the <b>raw</b> bytes before any other transformation
///     has touched them.
///     </description>
///   </item>
///   <item>
///     <description>
///     <b>Normalise line endings</b> — a bare <c>LF</c> or a lone <c>CR</c> from a sloppy
///     client becomes <c>CRLF</c>, so that what is stored is a well-formed RFC 5322 message.
///     </description>
///   </item>
///   <item>
///     <description>
///     <b>Unstuff the transparency dot</b> — RFC 5321 §4.5.2: a line that begins with
///     <c>.</c> had that dot inserted by the sender and it is removed here.
///     </description>
///   </item>
/// </list>
/// <para>
/// <b>Why the order matters.</b> If normalisation ran first, a body containing
/// <c>"\n.\n"</c> would be rewritten to <c>"\r\n.\r\n"</c> and the end-of-data scan would then
/// find a terminator that the sending server never sent. The message would be truncated at
/// that point and the remainder — attacker-chosen bytes, including a fresh <c>MAIL FROM</c>
/// — would be interpreted as commands. That is the SMTP smuggling class of bug (2023), and
/// the defence is exactly this: <b>the terminator is decided on raw octets, and only the
/// five-octet sequence CRLF "." CRLF ends the message.</b> <c>"\n.\n"</c>, <c>"\r.\r\n"</c>
/// and every other near-miss are content.
/// </para>
/// <para>
/// <b>Why unstuffing cannot reintroduce the problem.</b> Unstuffing only ever <i>removes</i> a
/// dot; it can never manufacture a terminator. A body that legitimately contains the octets
/// <c>CRLF "." CRLF</c> — because the sender stuffed them to <c>CRLF ".." CRLF</c> — is
/// decoded back to its true content and does not truncate. Sending it on again is safe
/// because <see cref="SmtpDotStuffing"/> re-stuffs on the way out.
/// </para>
/// <para>
/// The decoder is a streaming state machine: it holds back at most four octets and never
/// buffers a line, a header or a message. Nothing here grows with the size of the input, which
/// is what lets <c>DATA</c> be written straight to disk in bounded chunks.
/// </para>
/// <para>Not thread-safe. One instance belongs to one session's one message.</para>
/// </remarks>
public sealed class SmtpDataDecoder
{
    /// <summary>The one and only sequence that ends a message.</summary>
    private static ReadOnlySpan<byte> Terminator => "\r\n.\r\n"u8;

    private const byte Cr = (byte)'\r';
    private const byte Lf = (byte)'\n';
    private const byte Dot = (byte)'.';

    // --- Stage one: end-of-data detection over raw octets. -------------------------------
    //
    // _held is always exactly Terminator[0.._heldCount], i.e. a proper prefix of the
    // terminator that has been consumed but not yet released to stage two, because it might
    // still turn out to be the terminator.
    private readonly byte[] _held = new byte[5];
    private int _heldCount;

    // The message begins at a line start, so the decoder starts out as though a CRLF had just
    // arrived - that is what makes a message whose entire content is ".CRLF" an empty message
    // rather than a body of ".". Those two octets are synthetic and must never be emitted;
    // _suppress counts how many of the held octets are synthetic.
    private int _suppress;

    // --- Stage two: normalisation and unstuffing over body octets. ------------------------
    private bool _atLineStart = true;
    private bool _pendingCr;

    /// <summary>Creates a decoder positioned at the start of a message.</summary>
    public SmtpDataDecoder()
    {
        _held[0] = Cr;
        _held[1] = Lf;
        _heldCount = 2;
        _suppress = 2;
    }

    /// <summary>Raw octets fed in, including the terminator. This is the size the sender is charged.</summary>
    /// <remarks>
    /// Size limits are enforced against this, not against <see cref="BodyByteCount"/>. A sender
    /// must not be able to exceed a limit by sending octets that the decoder happens to discard.
    /// </remarks>
    public long RawByteCount { get; private set; }

    /// <summary>Decoded body octets produced so far.</summary>
    public long BodyByteCount { get; private set; }

    /// <summary>True once the terminator has been consumed.</summary>
    public bool IsComplete { get; private set; }

    /// <summary>
    /// The largest number of output octets <see cref="Decode"/> can produce from
    /// <paramref name="inputLength"/> input octets.
    /// </summary>
    /// <remarks>
    /// Worst case is a run of bare <c>LF</c>, each becoming <c>CRLF</c>, plus the four octets
    /// that may have been held back from an earlier call and are released by this one.
    /// Callers size their output buffer with this rather than guessing.
    /// </remarks>
    public static int MaxOutputFor(int inputLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(inputLength);
        return checked((inputLength * 2) + 8);
    }

    /// <summary>
    /// Decodes one chunk.
    /// </summary>
    /// <param name="input">Raw octets from the wire.</param>
    /// <param name="output">
    /// Receives decoded body octets. Must be at least <see cref="MaxOutputFor"/> octets long.
    /// </param>
    /// <param name="consumed">
    /// How much of <paramref name="input"/> was consumed. Less than the whole chunk only when
    /// the terminator was found part-way through; the remainder is the next command and belongs
    /// to the session, not to the message.
    /// </param>
    /// <param name="written">Decoded octets written to <paramref name="output"/>.</param>
    /// <returns>True when this chunk completed the message.</returns>
    public bool Decode(ReadOnlySpan<byte> input, Span<byte> output, out int consumed, out int written)
    {
        if (IsComplete)
        {
            throw new InvalidOperationException(
                "The message is already complete. Decoding further octets would fold the next " +
                "command into the message body.");
        }

        if (output.Length < MaxOutputFor(input.Length))
        {
            throw new ArgumentException(
                $"Output buffer must be at least {MaxOutputFor(input.Length)} octets for " +
                $"{input.Length} input octets; see {nameof(MaxOutputFor)}.",
                nameof(output));
        }

        consumed = 0;
        written = 0;

        for (int i = 0; i < input.Length; i++)
        {
            consumed++;
            RawByteCount++;

            if (FeedRaw(input[i], output, ref written))
            {
                IsComplete = true;
                BodyByteCount += written;
                return true;
            }
        }

        BodyByteCount += written;
        return false;
    }

    /// <summary>
    /// Feeds one raw octet through stage one. Returns true when it completed the terminator.
    /// </summary>
    private bool FeedRaw(byte b, Span<byte> output, ref int written)
    {
        if (b == Terminator[_heldCount])
        {
            _held[_heldCount] = b;
            _heldCount++;

            if (_heldCount == Terminator.Length)
            {
                // The message ended. The CRLF that opens the terminator is also the line
                // ending of the message's last line, so it belongs to the body - unless it is
                // the synthetic pair, in which case the message is empty.
                Release(_held.AsSpan(0, 2), output, ref written);
                _heldCount = 0;
                return true;
            }

            return false;
        }

        // Not the terminator after all. Release octets from the front until what remains -
        // the unreleased held octets followed by this one - is again a prefix of the
        // terminator. The candidate is at most five octets, so the scan is a fixed, tiny cost
        // and its correctness is easy to read off.
        Span<byte> candidate = stackalloc byte[6];
        _held.AsSpan(0, _heldCount).CopyTo(candidate);
        candidate[_heldCount] = b;
        int candidateLength = _heldCount + 1;

        for (int start = 1; start <= candidateLength; start++)
        {
            ReadOnlySpan<byte> remainder = candidate[start..candidateLength];

            if (remainder.Length <= Terminator.Length &&
                Terminator[..remainder.Length].SequenceEqual(remainder))
            {
                Release(candidate[..start], output, ref written);
                remainder.CopyTo(_held);
                _heldCount = remainder.Length;
                return false;
            }
        }

        // Unreachable: start == candidateLength always leaves an empty remainder, and the
        // empty span is a prefix of everything.
        throw new InvalidOperationException("End-of-data scan failed to resynchronise.");
    }

    /// <summary>
    /// Releases octets ruled out as part of a terminator into stage two, skipping any that are
    /// the synthetic start-of-message CRLF.
    /// </summary>
    private void Release(ReadOnlySpan<byte> octets, Span<byte> output, ref int written)
    {
        foreach (byte octet in octets)
        {
            if (_suppress > 0)
            {
                _suppress--;
                continue;
            }

            FeedBody(octet, output, ref written);
        }
    }

    /// <summary>
    /// Stage two: normalise the line ending and remove the transparency dot.
    /// </summary>
    /// <remarks>
    /// This runs only on octets stage one has already ruled out as part of a terminator, which
    /// is why rewriting a line ending here cannot create one.
    /// </remarks>
    private void FeedBody(byte b, Span<byte> output, ref int written)
    {
        if (_pendingCr)
        {
            _pendingCr = false;

            if (b == Lf)
            {
                EmitLineBreak(output, ref written);
                return;
            }

            // A lone CR. Old-Mac line endings and mangled transport both produce these; either
            // way the octet is a line ending, not content, and leaving it in the store would
            // hand a malformed message to IMAP clients and to the DKIM verifier alike.
            EmitLineBreak(output, ref written);
        }

        switch (b)
        {
            case Cr:
                _pendingCr = true;
                return;

            case Lf:
                // A bare LF. Normalised, and - critically - normalised here, where it can no
                // longer be mistaken for part of a terminator.
                EmitLineBreak(output, ref written);
                return;
        }

        if (_atLineStart && b == Dot)
        {
            // RFC 5321 §4.5.2: exactly one dot is removed. A line of "..." becomes "..".
            _atLineStart = false;
            return;
        }

        _atLineStart = false;
        output[written++] = b;
    }

    private void EmitLineBreak(Span<byte> output, ref int written)
    {
        output[written++] = Cr;
        output[written++] = Lf;
        _atLineStart = true;
    }

    /// <summary>
    /// Flushes a line ending left pending when a session ends without a terminator.
    /// </summary>
    /// <remarks>
    /// Only reachable on an aborted message. A message that ended properly has already had its
    /// final CRLF released as part of the terminator. Callers that abandon a message discard
    /// the partial content anyway; this exists so that a caller which chooses to keep it
    /// (a diagnostic capture, say) does not silently lose the last octet.
    /// </remarks>
    public int Flush(Span<byte> output)
    {
        int written = 0;

        if (_pendingCr)
        {
            _pendingCr = false;
            EmitLineBreak(output, ref written);
            BodyByteCount += written;
        }

        return written;
    }
}
