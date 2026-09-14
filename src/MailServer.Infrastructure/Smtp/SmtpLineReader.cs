using System.Text;

namespace MailServer.Infrastructure.Smtp;

/// <summary>How a line read ended.</summary>
public enum SmtpLineStatus
{
    /// <summary>A complete line was read.</summary>
    Line = 0,

    /// <summary>The peer exceeded the line limit. The session is no longer synchronised.</summary>
    LineTooLong = 1,

    /// <summary>The peer closed the connection.</summary>
    EndOfStream = 2,

    /// <summary>Nothing arrived within the command timeout.</summary>
    Timeout = 3,
}

/// <summary>The outcome of reading one command line.</summary>
/// <param name="Status">How the read ended.</param>
/// <param name="Text">The line without its terminator. Empty unless <paramref name="Status"/> is <see cref="SmtpLineStatus.Line"/>.</param>
/// <param name="OctetCount">Octets the line occupied on the wire, terminator included.</param>
public readonly record struct SmtpLineResult(SmtpLineStatus Status, string Text, int OctetCount)
{
    /// <summary>True when a line was actually read.</summary>
    public bool IsLine => Status == SmtpLineStatus.Line;
}

/// <summary>How a raw read ended.</summary>
public enum SmtpReadStatus
{
    /// <summary>Octets were read.</summary>
    Data = 0,

    /// <summary>The peer closed the connection.</summary>
    EndOfStream = 1,

    /// <summary>Nothing arrived within the timeout.</summary>
    Timeout = 2,
}

/// <summary>The outcome of a raw read.</summary>
public readonly record struct SmtpReadResult(SmtpReadStatus Status, int OctetCount);

/// <summary>
/// Reads SMTP command lines from a connection under a hard, fixed octet budget.
/// </summary>
/// <remarks>
/// <para>
/// This type exists to make brief rule 105 — <i>no unbounded network reads</i> — structural
/// rather than aspirational. The buffer is allocated once at construction and <b>never grows</b>.
/// There is no <c>MemoryStream</c>, no <c>StringBuilder</c>, no list of chunks: a peer that
/// sends four gigabytes without a line ending causes this reader to allocate exactly
/// <see cref="MaxLineOctets"/> + 2 octets and then refuse.
/// </para>
/// <para>
/// <b>An over-long line poisons the session.</b> Once the limit is hit the reader latches into
/// <see cref="SmtpLineStatus.LineTooLong"/> and stays there. It deliberately does <b>not</b>
/// skip forward to the next line ending and carry on, because the tail of an over-long line is
/// attacker-chosen text that would then be parsed as a fresh command — the same
/// command-injection shape as the STARTTLS bug, arrived at from a different direction. The
/// only correct recovery is 500 and close.
/// </para>
/// <para>
/// <b>Buffered input is visible.</b> <see cref="BufferedOctetCount"/> and
/// <see cref="DiscardBufferedInput"/> exist for STARTTLS: RFC 3207 §4 requires everything
/// received before the handshake to be discarded, and a session cannot honour that unless it
/// can see and drop what the reader has read ahead.
/// </para>
/// <para>Not thread-safe. One reader belongs to one connection, read by one loop.</para>
/// </remarks>
public sealed class SmtpLineReader
{
    private const byte Cr = (byte)'\r';
    private const byte Lf = (byte)'\n';

    /// <summary>
    /// Replacement rather than exception on malformed input.
    /// </summary>
    /// <remarks>
    /// SMTPUTF8 puts UTF-8 in command lines, so the decoder must be UTF-8. Invalid sequences
    /// become replacement characters, which then fail address parsing and earn a 501 — the
    /// ordinary path for a malformed command. Throwing would turn a bad byte into an exception
    /// on the hot path, and a peer can send bad bytes at will.
    /// </remarks>
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

    private readonly Stream _stream;
    private readonly byte[] _buffer;

    private int _start;
    private int _end;

    /// <summary>How far into the buffered octets the LF scan has already reached.</summary>
    /// <remarks>
    /// Without this, each top-up rescans everything already buffered, which is quadratic in
    /// the line length — a peer could burn CPU by dripping a long line one octet per packet.
    /// </remarks>
    private int _scanned;

    private bool _tooLongLatched;

    /// <summary>Creates a reader over a connection.</summary>
    /// <param name="stream">The connection. Replaced, not reconfigured, when TLS starts.</param>
    /// <param name="maxLineOctets">
    /// Longest command line accepted, excluding the CRLF. From <c>MailServer:Limits:MaxSmtpLineBytes</c>.
    /// </param>
    public SmtpLineReader(Stream stream, int maxLineOctets)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLineOctets, 512);

        _stream = stream;
        MaxLineOctets = maxLineOctets;

        // Exactly enough for the longest legal line and its terminator, and not one octet more.
        // The capacity is the limit; there is no separate check that could be forgotten.
        _buffer = new byte[maxLineOctets + 2];
    }

    /// <summary>Longest command line accepted, excluding the terminator.</summary>
    public int MaxLineOctets { get; }

    /// <summary>Octets read from the connection but not yet consumed.</summary>
    public int BufferedOctetCount => _end - _start;

    /// <summary>True when the reader has read ahead of the caller.</summary>
    public bool HasBufferedInput => _end > _start;

    /// <summary>
    /// Drops everything read ahead and reports how much was dropped.
    /// </summary>
    /// <remarks>
    /// Called by the session immediately before a TLS handshake. A non-zero return is not a
    /// housekeeping detail — it means the peer pipelined octets across STARTTLS, which no
    /// legitimate client does, and the session treats it as an injection attempt.
    /// </remarks>
    public int DiscardBufferedInput()
    {
        int discarded = _end - _start;

        _start = 0;
        _end = 0;
        _scanned = 0;

        return discarded;
    }

    /// <summary>Reads one command line, or explains why it could not.</summary>
    /// <param name="timeout">Longest wait for the line to complete. Bounds slowloris.</param>
    /// <param name="cancellationToken">Host shutdown.</param>
    public async ValueTask<SmtpLineResult> ReadLineAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);

        if (_tooLongLatched)
        {
            // Latched on purpose. See the class remarks: resynchronising would execute the
            // tail of an over-long line as a command.
            return new SmtpLineResult(SmtpLineStatus.LineTooLong, string.Empty, 0);
        }

        using CancellationTokenSource timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        timeoutSource.CancelAfter(timeout);

        while (true)
        {
            if (TryTakeLine(out SmtpLineResult line))
            {
                return line;
            }

            if (_end - _start >= _buffer.Length)
            {
                // The whole budget is buffered and there is still no line ending.
                _tooLongLatched = true;
                DiscardBufferedInput();
                return new SmtpLineResult(SmtpLineStatus.LineTooLong, string.Empty, _buffer.Length);
            }

            Compact();

            int read;

            try
            {
                read = await _stream
                    .ReadAsync(_buffer.AsMemory(_end), timeoutSource.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new SmtpLineResult(SmtpLineStatus.Timeout, string.Empty, 0);
            }

            if (read == 0)
            {
                // A partial command at end of stream is not a command. Dropping it is the
                // point: acting on half a line is how a truncated RCPT TO becomes a delivery
                // to the wrong address.
                DiscardBufferedInput();
                return new SmtpLineResult(SmtpLineStatus.EndOfStream, string.Empty, 0);
            }

            _end += read;
        }
    }

    /// <summary>Octets read from the connection and not yet consumed.</summary>
    /// <remarks>
    /// The window a raw reader works from. It is a view into the reader's own buffer rather than
    /// a copy, so the octets a caller does not consume stay exactly where they were.
    /// </remarks>
    public ReadOnlyMemory<byte> BufferedInput => _buffer.AsMemory(_start, _end - _start);

    /// <summary>
    /// Ensures at least one unconsumed octet is buffered, reading from the connection if needed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is how <c>DATA</c> is read: fill, look at <see cref="BufferedInput"/>, then
    /// <see cref="Consume"/> exactly what belonged to the message. The leftover — with PIPELINING
    /// that is the next command, which arrives in the same packet as the end-of-data marker —
    /// stays buffered for the command loop to read.
    /// </para>
    /// <para>
    /// A caller that copied octets out into its own buffer instead would have to hand back
    /// whatever it did not use, and a reader with a push-back path is a reader that can be made
    /// to hold more than its budget. Returning a window avoids the question.
    /// </para>
    /// </remarks>
    public async ValueTask<SmtpReadResult> FillAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);

        if (_end > _start)
        {
            return new SmtpReadResult(SmtpReadStatus.Data, _end - _start);
        }

        _start = 0;
        _end = 0;
        _scanned = 0;

        using CancellationTokenSource timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        timeoutSource.CancelAfter(timeout);

        int read;

        try
        {
            read = await _stream.ReadAsync(_buffer.AsMemory(0), timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new SmtpReadResult(SmtpReadStatus.Timeout, 0);
        }

        if (read == 0)
        {
            return new SmtpReadResult(SmtpReadStatus.EndOfStream, 0);
        }

        _end = read;

        return new SmtpReadResult(SmtpReadStatus.Data, read);
    }

    /// <summary>Marks the first <paramref name="octets"/> buffered octets as used.</summary>
    public void Consume(int octets)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(octets);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(octets, _end - _start);

        _start += octets;
        _scanned = Math.Max(0, _scanned - octets);

        if (_start == _end)
        {
            _start = 0;
            _end = 0;
            _scanned = 0;
        }
    }

    private bool TryTakeLine(out SmtpLineResult line)
    {
        int searchFrom = _start + _scanned;
        int index = Array.IndexOf(_buffer, Lf, searchFrom, _end - searchFrom);

        if (index < 0)
        {
            _scanned = _end - _start;
            line = default;
            return false;
        }

        int octets = index - _start + 1;
        int contentLength = octets - 1;

        // A bare LF terminator is tolerated on command lines - plenty of clients emit them and
        // refusing would reject mail over a line ending. It is tolerated ONLY here: the
        // end-of-DATA marker requires a true CRLF, because there a bare LF is the SMTP
        // smuggling vector. See SmtpDataDecoder.
        if (contentLength > 0 && _buffer[index - 1] == Cr)
        {
            contentLength--;
        }

        string text = Utf8.GetString(_buffer, _start, contentLength);

        _start = index + 1;
        _scanned = 0;

        if (_start == _end)
        {
            _start = 0;
            _end = 0;
        }

        line = new SmtpLineResult(SmtpLineStatus.Line, text, octets);
        return true;
    }

    private void Compact()
    {
        if (_start == 0)
        {
            return;
        }

        Buffer.BlockCopy(_buffer, _start, _buffer, 0, _end - _start);
        _end -= _start;
        _start = 0;
    }
}
