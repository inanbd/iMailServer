namespace MailServer.Domain.Pop3;

/// <summary>
/// Frames a multi-line response body: byte-stuffing, and the terminator.
/// </summary>
/// <remarks>
/// <para>
/// RFC 1939 §3: "after sending the first line of the response and a CRLF, any additional lines
/// are sent, each terminated by a CRLF pair. When all lines of the response have been sent, a
/// final line is sent, consisting of a termination octet (decimal code 046, ".") and a CRLF pair.
/// If any line of the multi-line response begins with the termination octet, the line is
/// "byte-stuffed" by pre-pending the termination octet to that line of the response. Hence a
/// multi-line response is terminated with the five octets "CRLF.CRLF"."
/// </para>
/// <para>
/// <b>This is the single most dangerous piece of POP3 to get wrong.</b> A message body line
/// beginning with a full stop is ordinary — a wrapped sentence, a signature, a quoted diff — and
/// a server that failed to stuff it would end the response there, hand the rest of the message
/// to the client as if it were a sequence of commands' worth of responses, and desynchronise the
/// connection for good. In the other direction, a client removes one leading stop from every
/// line, so a server that stuffed a line that did not need it corrupts the message silently.
/// </para>
/// <para>
/// <b>Everything here works in bytes.</b> A stored message may be in any charset or none. The
/// only octets this has to recognise — LF, CR and the full stop — are the same byte in every
/// encoding it could meet.
/// </para>
/// </remarks>
public static class Pop3DotStuffing
{
    private const byte Dot = (byte)'.';
    private const byte Cr = (byte)'\r';
    private const byte Lf = (byte)'\n';

    /// <summary>
    /// Stuffs a body and appends the terminator.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The result is everything that follows the status line, ready to be written as it is. A
    /// caller cannot forget the terminator, and cannot append it to an unstuffed body, because
    /// the two are produced together.
    /// </para>
    /// <para>
    /// <b>A body that does not end with a line ending gets one.</b> §3's terminator is the five
    /// octets <c>CRLF.CRLF</c>, so the stop has to begin a line; a message whose last line was
    /// never terminated — which local delivery and a truncated file both produce — would
    /// otherwise have the terminator appended to it, and the client would read the stop as part
    /// of the message and then wait for an end that never comes.
    /// </para>
    /// </remarks>
    public static ReadOnlyMemory<byte> Frame(ReadOnlyMemory<byte> body)
    {
        ReadOnlySpan<byte> span = body.Span;

        // The worst case is a body of nothing but "." lines, which doubles. Sized for the common
        // case instead, plus the terminator: the list grows if it has to.
        List<byte> framed = new(span.Length + 8);

        bool atLineStart = true;

        foreach (byte octet in span)
        {
            if (atLineStart && octet == Dot)
            {
                framed.Add(Dot);
            }

            framed.Add(octet);

            // A line starts after a line feed. Recognising a bare LF as well as CRLF is
            // deliberate: a message written by local delivery may use one, and a scan that only
            // knew CRLF would leave a "." line in the middle of such a message unstuffed.
            atLineStart = octet == Lf;
        }

        if (!atLineStart)
        {
            framed.Add(Cr);
            framed.Add(Lf);
        }

        framed.Add(Dot);
        framed.Add(Cr);
        framed.Add(Lf);

        return framed.ToArray();
    }

    /// <summary>
    /// Cuts a message down to its header and the first lines of its body, for <c>TOP</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §7: "the POP3 server sends the headers of the message, the blank line separating the
    /// headers from the body, and then the number of lines of the indicated message's body […]
    /// Note that if the number of lines requested by the POP3 client is greater than than the
    /// number of lines in the body, then the POP3 server sends the entire message."
    /// </para>
    /// <para>
    /// <b>Zero lines is a request for the header alone, not an error.</b> §7 makes the count "a
    /// non-negative number of lines", so <c>TOP 1 0</c> is how a client asks for headers only —
    /// which is what most clients do first, and what makes <c>TOP</c> worth having.
    /// </para>
    /// </remarks>
    /// <param name="message">The whole stored message.</param>
    /// <param name="bodyLines">How many lines of the body to keep. Must not be negative.</param>
    public static ReadOnlyMemory<byte> Top(ReadOnlyMemory<byte> message, int bodyLines)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bodyLines);

        ReadOnlySpan<byte> span = message.Span;
        int headerEnd = HeaderLength(span);

        if (headerEnd >= span.Length)
        {
            return message;
        }

        int index = headerEnd;
        int taken = 0;

        while (index < span.Length && taken < bodyLines)
        {
            int feed = span[index..].IndexOf(Lf);

            if (feed < 0)
            {
                // A final line with no terminator still counts as a line.
                return message;
            }

            index += feed + 1;
            taken++;
        }

        return message[..index];
    }

    /// <summary>
    /// Where the header ends: the offset just past the blank line that terminates it.
    /// </summary>
    /// <remarks>
    /// The same scan <c>ImapBodySection</c> performs, and deliberately a copy rather than a
    /// reference: that type belongs to IMAP's section specifiers and this one to POP3's framing,
    /// and a shared helper would tie a change made for one protocol's grammar to the other's
    /// wire format. Both accept a bare LF as a line ending, because a message written by local
    /// delivery may use one and a scan that knew only CRLF would treat such a message as all
    /// header and no body — which for <c>TOP</c> means sending the whole thing every time.
    /// </remarks>
    private static int HeaderLength(ReadOnlySpan<byte> message)
    {
        if (message.Length > 0 && message[0] == Lf)
        {
            return 1;
        }

        if (message.Length > 1 && message[0] == Cr && message[1] == Lf)
        {
            return 2;
        }

        for (int i = 0; i < message.Length; i++)
        {
            if (message[i] != Lf)
            {
                continue;
            }

            int next = i + 1;

            if (next >= message.Length)
            {
                return message.Length;
            }

            if (message[next] == Lf)
            {
                return next + 1;
            }

            if (message[next] == Cr && next + 1 < message.Length && message[next + 1] == Lf)
            {
                return next + 2;
            }
        }

        return message.Length;
    }
}
