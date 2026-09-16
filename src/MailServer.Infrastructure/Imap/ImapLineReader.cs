using System.Text;

namespace MailServer.Infrastructure.Imap;

/// <summary>How a line read ended.</summary>
public enum ImapLineStatus
{
    /// <summary>A complete line was read.</summary>
    Line = 0,

    /// <summary>The peer exceeded the line limit. The session is no longer synchronised.</summary>
    LineTooLong = 1,

    /// <summary>The peer closed the connection.</summary>
    EndOfStream = 2,

    /// <summary>Nothing arrived within the timeout.</summary>
    Timeout = 3,
}

/// <summary>The outcome of reading one line.</summary>
/// <param name="Status">How the read ended.</param>
/// <param name="Text">The line without its terminator. Empty unless <paramref name="Status"/> is <see cref="ImapLineStatus.Line"/>.</param>
/// <param name="OctetCount">Octets the line occupied on the wire, terminator included.</param>
public readonly record struct ImapLineResult(ImapLineStatus Status, string Text, int OctetCount)
{
    public bool IsLine => Status == ImapLineStatus.Line;
}

/// <summary>How a raw read ended.</summary>
public enum ImapReadStatus
{
    Data = 0,
    EndOfStream = 1,
    Timeout = 2,
}

/// <summary>The outcome of a raw read.</summary>
public readonly record struct ImapReadResult(ImapReadStatus Status, int OctetCount);

/// <summary>
/// Reads IMAP command lines and literal octets from a connection under a hard, fixed buffer.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="Smtp.SmtpLineReader"/>'s design deliberately, for the same reason brief
/// rule 76 (resource-exhaustion protection) applies here too: the buffer is allocated once and
/// <b>never grows</b>, so a peer that never sends a line ending causes exactly one bounded
/// allocation and a refusal, never an unbounded one.
/// </para>
/// <para>
/// <b>A literal is read through the same <see cref="FillAsync"/>/<see cref="Consume"/> pair
/// <see cref="Smtp.SmtpDataReceiver"/> uses for a message body</b> — fill whatever the buffer
/// received, hand the caller a window over it, let the caller decide how much of that window is
/// literal content and consume exactly that much. A caller wanting the bytes on disk rather than
/// in memory (a large <c>APPEND</c>) copies straight out of <see cref="BufferedInput"/> into a
/// file one <see cref="FillAsync"/> at a time; this reader never needs to hold a whole literal at
/// once regardless of how large the client declared it, which is the actual answer to
/// <c>docs/IMAP.md</c>'s "trivial memory exhaustion" warning about an uncapped LITERAL+.
/// </para>
/// <para>
/// <b>An over-long line poisons the session</b>, exactly as it does for SMTP: latched into
/// <see cref="ImapLineStatus.LineTooLong"/> rather than resynchronised past, because the tail of
/// an over-long line is attacker-chosen text that a resync would then parse as a fresh command.
/// </para>
/// <para>Not thread-safe. One reader belongs to one connection.</para>
/// </remarks>
public sealed class ImapLineReader
{
    private const byte Cr = (byte)'\r';
    private const byte Lf = (byte)'\n';

    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

    private readonly Stream _stream;
    private readonly byte[] _buffer;

    private int _start;
    private int _end;
    private int _scanned;
    private bool _tooLongLatched;

    /// <summary>Creates a reader over a connection.</summary>
    /// <param name="stream">The connection. Replaced, not reconfigured, when TLS starts.</param>
    /// <param name="maxLineOctets">
    /// Longest command line accepted, excluding the CRLF. From <c>MailServer:Limits:MaxImapLineBytes</c>.
    /// Bounds tag/command/argument text; a literal's own declared byte count is a separate,
    /// larger limit the caller checks before ever asking this reader to fill that many octets.
    /// </param>
    public ImapLineReader(Stream stream, int maxLineOctets)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLineOctets, 512);

        _stream = stream;
        MaxLineOctets = maxLineOctets;
        _buffer = new byte[maxLineOctets + 2];
    }

    /// <summary>Longest command line accepted, excluding the terminator.</summary>
    public int MaxLineOctets { get; }

    /// <summary>Octets read from the connection but not yet consumed.</summary>
    public int BufferedOctetCount => _end - _start;

    /// <summary>True when the reader has read ahead of the caller.</summary>
    public bool HasBufferedInput => _end > _start;

    /// <summary>Drops everything read ahead and reports how much was dropped.</summary>
    /// <remarks>
    /// Called before a <c>STARTTLS</c> handshake, for the identical reason
    /// <see cref="Smtp.SmtpLineReader.DiscardBufferedInput"/> is: RFC 3501 §6.2.1 requires
    /// discarding anything obtained from the client before the TLS negotiation, and a non-zero
    /// return means the peer pipelined octets across it, which no legitimate client does.
    /// </remarks>
    public int DiscardBufferedInput()
    {
        int discarded = _end - _start;

        _start = 0;
        _end = 0;
        _scanned = 0;

        return discarded;
    }

    /// <summary>Reads one line, or explains why it could not.</summary>
    /// <param name="timeout">Longest wait for the line to complete. Bounds slowloris.</param>
    /// <param name="cancellationToken">Host shutdown.</param>
    public async ValueTask<ImapLineResult> ReadLineAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);

        if (_tooLongLatched)
        {
            return new ImapLineResult(ImapLineStatus.LineTooLong, string.Empty, 0);
        }

        using CancellationTokenSource timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        timeoutSource.CancelAfter(timeout);

        while (true)
        {
            if (TryTakeLine(out ImapLineResult line))
            {
                return line;
            }

            if (_end - _start >= _buffer.Length)
            {
                _tooLongLatched = true;
                DiscardBufferedInput();
                return new ImapLineResult(ImapLineStatus.LineTooLong, string.Empty, _buffer.Length);
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
                return new ImapLineResult(ImapLineStatus.Timeout, string.Empty, 0);
            }

            if (read == 0)
            {
                DiscardBufferedInput();
                return new ImapLineResult(ImapLineStatus.EndOfStream, string.Empty, 0);
            }

            _end += read;
        }
    }

    /// <summary>Octets read from the connection and not yet consumed.</summary>
    public ReadOnlyMemory<byte> BufferedInput => _buffer.AsMemory(_start, _end - _start);

    /// <summary>Ensures at least one unconsumed octet is buffered, reading from the connection if needed.</summary>
    public async ValueTask<ImapReadResult> FillAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);

        if (_end > _start)
        {
            return new ImapReadResult(ImapReadStatus.Data, _end - _start);
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
            return new ImapReadResult(ImapReadStatus.Timeout, 0);
        }

        if (read == 0)
        {
            return new ImapReadResult(ImapReadStatus.EndOfStream, 0);
        }

        _end = read;

        return new ImapReadResult(ImapReadStatus.Data, read);
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

    private bool TryTakeLine(out ImapLineResult line)
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

        // A bare LF is tolerated on a line the same way SmtpLineReader tolerates one on a
        // command line: plenty of clients emit it, and a literal's own byte count - never a
        // line ending - is what actually delimits literal content, so tolerating it here creates
        // no smuggling vector the way it would on SMTP's end-of-DATA marker.
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

        line = new ImapLineResult(ImapLineStatus.Line, text, octets);
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
