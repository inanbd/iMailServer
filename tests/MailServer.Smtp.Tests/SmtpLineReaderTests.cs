using System.Text;
using MailServer.Infrastructure.Smtp;

namespace MailServer.Smtp.Tests;

/// <summary>
/// A stream that hands out its content in fixed-size pieces, so that a test can put the
/// packet boundary anywhere it likes.
/// </summary>
/// <remarks>
/// Real connections fragment. A reader tested only against a <see cref="MemoryStream"/> that
/// answers every request in full has not been tested against anything a peer can do.
/// </remarks>
internal sealed class ChunkedStream(byte[] content, int chunkSize) : Stream
{
    private int _position;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => content.Length;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int available = Math.Min(Math.Min(chunkSize, buffer.Length), content.Length - _position);

        if (available <= 0)
        {
            return 0;
        }

        content.AsSpan(_position, available).CopyTo(buffer);
        _position += available;

        return available;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>A stream that never produces a line ending, and never ends.</summary>
/// <remarks>
/// This is the attack the line limit exists for: a peer sends octets forever without a CRLF. A
/// reader that accumulated into a growing buffer would consume memory until the process died,
/// which is why the test stream is unbounded rather than merely large - a bounded fake would
/// let a broken implementation pass.
/// </remarks>
internal sealed class EndlessStream(byte fill) : Stream
{
    public long OctetsServed { get; private set; }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (OctetsServed > 64 * 1024 * 1024)
        {
            throw new InvalidOperationException(
                "The reader accepted more than 64 MiB without a line ending. The read is unbounded.");
        }

        buffer.Fill(fill);
        OctetsServed += buffer.Length;

        return buffer.Length;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>A stream that blocks until cancelled. Models a peer that stops sending.</summary>
internal sealed class SilentStream : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        return 0;
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

public sealed class SmtpLineReaderTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    private static SmtpLineReader Reader(string wire, int chunkSize = 4096, int maxLine = 4096) =>
        new(new ChunkedStream(Encoding.UTF8.GetBytes(wire), chunkSize), maxLine);

    [Fact]
    public async Task Lines_are_returned_one_at_a_time()
    {
        SmtpLineReader reader = Reader("EHLO mail.example\r\nMAIL FROM:<a@b.example>\r\nQUIT\r\n");

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("EHLO mail.example");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("MAIL FROM:<a@b.example>");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("QUIT");

        (await reader.ReadLineAsync(Generous, default)).Status.ShouldBe(SmtpLineStatus.EndOfStream);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(17)]
    public async Task Fragmentation_does_not_change_the_lines(int chunkSize)
    {
        SmtpLineReader reader = Reader("EHLO one\r\nNOOP\r\nQUIT\r\n", chunkSize);

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("EHLO one");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("NOOP");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("QUIT");
    }

    [Fact]
    public async Task A_bare_line_feed_terminates_a_command_line()
    {
        // Tolerated for commands only. The end-of-DATA marker is strict; see SmtpDataDecoderTests.
        SmtpLineReader reader = Reader("NOOP\nQUIT\n");

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("NOOP");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("QUIT");
    }

    [Fact]
    public async Task An_empty_line_is_a_line_not_end_of_stream()
    {
        SmtpLineReader reader = Reader("\r\nNOOP\r\n");

        SmtpLineResult first = await reader.ReadLineAsync(Generous, default);

        first.Status.ShouldBe(SmtpLineStatus.Line);
        first.Text.ShouldBe(string.Empty);
    }

    [Fact]
    public async Task The_octet_count_includes_the_terminator()
    {
        SmtpLineReader reader = Reader("NOOP\r\n");

        (await reader.ReadLineAsync(Generous, default)).OctetCount.ShouldBe(6);
    }

    [Fact]
    public async Task A_line_of_exactly_the_limit_is_accepted()
    {
        // The boundary in the accepting direction. An off-by-one here rejects legitimate mail
        // with long ESMTP parameter lists.
        const int MaxLine = 512;
        string content = new('x', MaxLine);

        SmtpLineReader reader = Reader($"{content}\r\n", maxLine: MaxLine);
        SmtpLineResult result = await reader.ReadLineAsync(Generous, default);

        result.Status.ShouldBe(SmtpLineStatus.Line);
        result.Text.Length.ShouldBe(MaxLine);
    }

    [Fact]
    public async Task A_line_one_octet_over_the_limit_is_refused()
    {
        const int MaxLine = 512;
        string content = new('x', MaxLine + 1);

        SmtpLineReader reader = Reader($"{content}\r\n", maxLine: MaxLine);

        (await reader.ReadLineAsync(Generous, default)).Status.ShouldBe(SmtpLineStatus.LineTooLong);
    }

    [Fact]
    public async Task An_endless_line_is_refused_without_unbounded_buffering()
    {
        // Brief rule 105: no unbounded network reads. The stream will keep producing octets
        // forever; the reader must stop at its budget.
        EndlessStream endless = new((byte)'A');
        SmtpLineReader reader = new(endless, 4096);

        SmtpLineResult result = await reader.ReadLineAsync(Generous, default);

        result.Status.ShouldBe(SmtpLineStatus.LineTooLong);
        endless.OctetsServed.ShouldBeLessThanOrEqualTo(4098L);
    }

    [Fact]
    public async Task An_over_long_line_latches_and_never_resynchronises()
    {
        // The tail of an over-long line is attacker-chosen text. A reader that skipped to the
        // next CRLF and carried on would hand that text to the command parser, which is
        // command injection by another route.
        const int MaxLine = 512;
        string wire = new string('x', MaxLine + 10) + "\r\nMAIL FROM:<attacker@evil.example>\r\n";

        SmtpLineReader reader = Reader(wire, maxLine: MaxLine);

        (await reader.ReadLineAsync(Generous, default)).Status.ShouldBe(SmtpLineStatus.LineTooLong);

        SmtpLineResult next = await reader.ReadLineAsync(Generous, default);

        next.Status.ShouldBe(SmtpLineStatus.LineTooLong);
        next.Text.ShouldBe(
            string.Empty,
            customMessage: "The reader must never surface the tail of an over-long line as a command.");
    }

    [Fact]
    public async Task A_partial_command_at_end_of_stream_is_discarded()
    {
        // "RCPT TO:<victim@example.com" without a terminator must not become a recipient.
        SmtpLineReader reader = Reader("RCPT TO:<victim@example.com");

        SmtpLineResult result = await reader.ReadLineAsync(Generous, default);

        result.Status.ShouldBe(SmtpLineStatus.EndOfStream);
        result.Text.ShouldBe(string.Empty);
    }

    [Fact]
    public async Task A_silent_peer_times_out_rather_than_holding_the_connection()
    {
        // Slowloris. The read must end on the command timeout, not on the peer's goodwill.
        SmtpLineReader reader = new(new SilentStream(), 4096);

        SmtpLineResult result = await reader.ReadLineAsync(TimeSpan.FromMilliseconds(150), default);

        result.Status.ShouldBe(SmtpLineStatus.Timeout);
    }

    [Fact]
    public async Task Host_shutdown_is_distinguishable_from_a_timeout()
    {
        // A timeout means "refuse this peer"; a shutdown means "stop the server". Collapsing
        // them would have the shutdown path emit a 421 timeout to every open session, and the
        // session loop would treat cancellation as an ordinary protocol event.
        using CancellationTokenSource shutdown = new();
        SmtpLineReader reader = new(new SilentStream(), 4096);

        ValueTask<SmtpLineResult> pending = reader.ReadLineAsync(Generous, shutdown.Token);
        await shutdown.CancelAsync();

        await Should.ThrowAsync<OperationCanceledException>(async () => await pending);
    }

    // ---------------------------------------------------------------------------------------
    // Read-ahead, which is what STARTTLS has to be able to see and drop.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Pipelined_input_is_visible_as_buffered()
    {
        SmtpLineReader reader = Reader("STARTTLS\r\nRSET\r\n");

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("STARTTLS");

        reader.HasBufferedInput.ShouldBeTrue();
        reader.BufferedOctetCount.ShouldBe(Encoding.UTF8.GetByteCount("RSET\r\n"));
    }

    [Fact]
    public async Task Discarding_reports_how_much_it_dropped()
    {
        SmtpLineReader reader = Reader("STARTTLS\r\nRSET\r\n");

        await reader.ReadLineAsync(Generous, default);

        reader.DiscardBufferedInput().ShouldBe(6);
        reader.HasBufferedInput.ShouldBeFalse();
        reader.BufferedOctetCount.ShouldBe(0);
    }

    [Fact]
    public async Task Discarding_when_nothing_is_buffered_reports_zero()
    {
        // The session uses a non-zero return as evidence of an injection attempt, so a false
        // positive here would abort every legitimate STARTTLS.
        SmtpLineReader reader = Reader("STARTTLS\r\n", chunkSize: 1);

        await reader.ReadLineAsync(Generous, default);

        reader.DiscardBufferedInput().ShouldBe(0);
    }

    // ---------------------------------------------------------------------------------------
    // Raw reads, which is how DATA is consumed.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Filling_surfaces_buffered_octets_before_touching_the_connection()
    {
        // With PIPELINING the body arrives in the same packet as DATA. Going straight to the
        // socket would lose the first octets of every pipelined message.
        SmtpLineReader reader = Reader("DATA\r\nhello\r\n.\r\n");

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("DATA");

        SmtpReadResult result = await reader.FillAsync(Generous, default);

        result.Status.ShouldBe(SmtpReadStatus.Data);
        Encoding.UTF8.GetString(reader.BufferedInput.Span).ShouldBe("hello\r\n.\r\n");
    }

    [Fact]
    public async Task Octets_the_caller_does_not_consume_stay_buffered()
    {
        // The reason the raw read hands back a window rather than copying into the caller's
        // buffer. A DATA pump consumes up to the end-of-data marker; whatever follows is the
        // next command and must still be there for the command loop to read.
        SmtpLineReader reader = Reader("DATA\r\nhi\r\n.\r\nQUIT\r\n");

        await reader.ReadLineAsync(Generous, default);
        await reader.FillAsync(Generous, default);

        reader.Consume("hi\r\n.\r\n".Length);

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("QUIT");
    }

    [Fact]
    public async Task Consuming_more_than_is_buffered_is_refused()
    {
        // A caller that over-consumed would silently skip octets of the next command, which is
        // how a partial command becomes a command nobody sent.
        SmtpLineReader reader = Reader("DATA\r\nhi\r\n.\r\n");

        await reader.ReadLineAsync(Generous, default);

        SmtpReadResult result = await reader.FillAsync(Generous, default);

        Should.Throw<ArgumentOutOfRangeException>(() => reader.Consume(result.OctetCount + 1));
    }

    [Fact]
    public async Task Filling_continues_past_the_buffer_into_the_connection()
    {
        SmtpLineReader reader = Reader("DATA\r\nbody\r\n.\r\n", chunkSize: 3);

        await reader.ReadLineAsync(Generous, default);

        StringBuilder collected = new();

        while (collected.Length < "body\r\n.\r\n".Length)
        {
            SmtpReadResult result = await reader.FillAsync(Generous, default);

            result.Status.ShouldBe(SmtpReadStatus.Data);
            collected.Append(Encoding.UTF8.GetString(reader.BufferedInput.Span));
            reader.Consume(result.OctetCount);
        }

        collected.ToString().ShouldBe("body\r\n.\r\n");
    }

    [Fact]
    public async Task Filling_at_end_of_stream_says_so()
    {
        SmtpLineReader reader = Reader("NOOP\r\n");

        await reader.ReadLineAsync(Generous, default);

        SmtpReadResult result = await reader.FillAsync(Generous, default);

        result.Status.ShouldBe(SmtpReadStatus.EndOfStream);
        result.OctetCount.ShouldBe(0);
    }

    [Fact]
    public async Task A_fill_never_returns_more_than_the_line_budget()
    {
        // The window is the reader's own buffer, so the DATA pump inherits the same bound the
        // command reader has. Nothing on either path grows with what the peer sends.
        EndlessStream endless = new((byte)'A');
        SmtpLineReader reader = new(endless, 4096);

        SmtpReadResult result = await reader.FillAsync(Generous, default);

        result.OctetCount.ShouldBeLessThanOrEqualTo(4098);
        reader.BufferedInput.Length.ShouldBeLessThanOrEqualTo(4098);
    }

    [Fact]
    public void The_buffer_is_sized_from_the_limit_and_the_limit_has_a_floor()
    {
        // RFC 5321 §4.5.3.1.4 requires at least 512 octets for a command line. A configuration
        // below that would reject conforming clients, so it is refused at construction rather
        // than producing mysterious 500s in production.
        Should.Throw<ArgumentOutOfRangeException>(
            () => new SmtpLineReader(new MemoryStream(), 511));
    }
}
