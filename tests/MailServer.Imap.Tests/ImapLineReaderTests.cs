using System.Text;
using MailServer.Infrastructure.Imap;

namespace MailServer.Imap.Tests;

/// <summary>
/// A stream that hands out its content in fixed-size pieces, so a test can put the packet
/// boundary anywhere it likes.
/// </summary>
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

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

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

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

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

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
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

public sealed class ImapLineReaderTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    private static ImapLineReader Reader(string wire, int chunkSize = 4096, int maxLine = 4096) =>
        new(new ChunkedStream(Encoding.UTF8.GetBytes(wire), chunkSize), maxLine);

    [Fact]
    public async Task Lines_are_returned_one_at_a_time()
    {
        ImapLineReader reader = Reader("a001 NOOP\r\na002 SELECT INBOX\r\na003 LOGOUT\r\n");

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a001 NOOP");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a002 SELECT INBOX");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a003 LOGOUT");

        (await reader.ReadLineAsync(Generous, default)).Status.ShouldBe(ImapLineStatus.EndOfStream);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(17)]
    public async Task Fragmentation_does_not_change_the_lines(int chunkSize)
    {
        ImapLineReader reader = Reader("a1 CAPABILITY\r\na2 NOOP\r\na3 LOGOUT\r\n", chunkSize);

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a1 CAPABILITY");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a2 NOOP");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a3 LOGOUT");
    }

    [Fact]
    public async Task A_bare_line_feed_terminates_a_line()
    {
        ImapLineReader reader = Reader("a1 NOOP\na2 LOGOUT\n");

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a1 NOOP");
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a2 LOGOUT");
    }

    [Fact]
    public async Task An_empty_line_is_a_line_not_end_of_stream()
    {
        ImapLineReader reader = Reader("\r\na1 NOOP\r\n");

        ImapLineResult first = await reader.ReadLineAsync(Generous, default);

        first.Status.ShouldBe(ImapLineStatus.Line);
        first.Text.ShouldBe(string.Empty);
    }

    [Fact]
    public async Task The_octet_count_includes_the_terminator()
    {
        ImapLineReader reader = Reader("a1 NOOP\r\n");

        (await reader.ReadLineAsync(Generous, default)).OctetCount.ShouldBe(9);
    }

    [Fact]
    public async Task A_line_of_exactly_the_limit_is_accepted()
    {
        const int MaxLine = 512;
        string content = new('x', MaxLine);

        ImapLineReader reader = Reader($"{content}\r\n", maxLine: MaxLine);
        ImapLineResult result = await reader.ReadLineAsync(Generous, default);

        result.Status.ShouldBe(ImapLineStatus.Line);
        result.Text.Length.ShouldBe(MaxLine);
    }

    [Fact]
    public async Task A_line_one_octet_over_the_limit_is_refused()
    {
        const int MaxLine = 512;
        string content = new('x', MaxLine + 1);

        ImapLineReader reader = Reader($"{content}\r\n", maxLine: MaxLine);

        (await reader.ReadLineAsync(Generous, default)).Status.ShouldBe(ImapLineStatus.LineTooLong);
    }

    [Fact]
    public async Task An_endless_line_is_refused_without_unbounded_buffering()
    {
        EndlessStream endless = new((byte)'A');
        ImapLineReader reader = new(endless, 4096);

        ImapLineResult result = await reader.ReadLineAsync(Generous, default);

        result.Status.ShouldBe(ImapLineStatus.LineTooLong);
        endless.OctetsServed.ShouldBeLessThanOrEqualTo(4098L);
    }

    [Fact]
    public async Task An_over_long_line_latches_and_never_resynchronises()
    {
        const int MaxLine = 512;
        string wire = new string('x', MaxLine + 10) + "\r\na1 LOGIN attacker evil\r\n";

        ImapLineReader reader = Reader(wire, maxLine: MaxLine);

        (await reader.ReadLineAsync(Generous, default)).Status.ShouldBe(ImapLineStatus.LineTooLong);

        ImapLineResult next = await reader.ReadLineAsync(Generous, default);

        next.Status.ShouldBe(ImapLineStatus.LineTooLong);
        next.Text.ShouldBe(
            string.Empty,
            customMessage: "The reader must never surface the tail of an over-long line as a command.");
    }

    [Fact]
    public async Task A_partial_command_at_end_of_stream_is_discarded()
    {
        ImapLineReader reader = Reader("a1 SELECT INB");

        ImapLineResult result = await reader.ReadLineAsync(Generous, default);

        result.Status.ShouldBe(ImapLineStatus.EndOfStream);
        result.Text.ShouldBe(string.Empty);
    }

    [Fact]
    public async Task A_silent_peer_times_out_rather_than_holding_the_connection()
    {
        ImapLineReader reader = new(new SilentStream(), 4096);

        ImapLineResult result = await reader.ReadLineAsync(TimeSpan.FromMilliseconds(150), default);

        result.Status.ShouldBe(ImapLineStatus.Timeout);
    }

    [Fact]
    public async Task Host_shutdown_is_distinguishable_from_a_timeout()
    {
        using CancellationTokenSource shutdown = new();
        ImapLineReader reader = new(new SilentStream(), 4096);

        ValueTask<ImapLineResult> pending = reader.ReadLineAsync(Generous, shutdown.Token);
        await shutdown.CancelAsync();

        await Should.ThrowAsync<OperationCanceledException>(async () => await pending);
    }

    // ---------------------------------------------------------------------------------------
    // Read-ahead, which is what STARTTLS has to be able to see and drop.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Pipelined_input_is_visible_as_buffered()
    {
        ImapLineReader reader = Reader("a1 STARTTLS\r\na2 NOOP\r\n");

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a1 STARTTLS");

        reader.HasBufferedInput.ShouldBeTrue();
        reader.BufferedOctetCount.ShouldBe(Encoding.UTF8.GetByteCount("a2 NOOP\r\n"));
    }

    [Fact]
    public async Task Discarding_reports_how_much_it_dropped()
    {
        ImapLineReader reader = Reader("a1 STARTTLS\r\na2 NOOP\r\n");

        await reader.ReadLineAsync(Generous, default);

        reader.DiscardBufferedInput().ShouldBe(Encoding.UTF8.GetByteCount("a2 NOOP\r\n"));
        reader.HasBufferedInput.ShouldBeFalse();
        reader.BufferedOctetCount.ShouldBe(0);
    }

    [Fact]
    public async Task Discarding_when_nothing_is_buffered_reports_zero()
    {
        ImapLineReader reader = Reader("a1 STARTTLS\r\n", chunkSize: 1);

        await reader.ReadLineAsync(Generous, default);

        reader.DiscardBufferedInput().ShouldBe(0);
    }

    // ---------------------------------------------------------------------------------------
    // Raw reads, which is how a literal's octets are consumed.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Filling_surfaces_buffered_octets_before_touching_the_connection()
    {
        // With a literal's bytes pipelined right after its specifier's line, going straight to
        // the socket would lose the first octets of every one.
        ImapLineReader reader = Reader("a1 LOGIN {5}\r\nalice\r\n");

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("a1 LOGIN {5}");

        ImapReadResult result = await reader.FillAsync(Generous, default);

        result.Status.ShouldBe(ImapReadStatus.Data);
        Encoding.UTF8.GetString(reader.BufferedInput.Span).ShouldBe("alice\r\n");
    }

    [Fact]
    public async Task Octets_the_caller_does_not_consume_stay_buffered()
    {
        // A literal names an exact byte count. Whatever follows it - more of the same command,
        // or the next one entirely - must still be there for the command reader to see.
        ImapLineReader reader = Reader("a1 LOGIN {5}\r\nalice a2 NOOP\r\n");

        await reader.ReadLineAsync(Generous, default);
        await reader.FillAsync(Generous, default);

        reader.Consume("alice".Length);

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe(" a2 NOOP");
    }

    [Fact]
    public async Task Consuming_more_than_is_buffered_is_refused()
    {
        ImapLineReader reader = Reader("a1 LOGIN {5}\r\nalice\r\n");

        await reader.ReadLineAsync(Generous, default);

        ImapReadResult result = await reader.FillAsync(Generous, default);

        Should.Throw<ArgumentOutOfRangeException>(() => reader.Consume(result.OctetCount + 1));
    }

    [Fact]
    public async Task Filling_continues_past_the_buffer_into_the_connection()
    {
        ImapLineReader reader = Reader("a1 LOGIN {8}\r\npassword\r\n", chunkSize: 3);

        await reader.ReadLineAsync(Generous, default);

        StringBuilder collected = new();

        while (collected.Length < "password".Length)
        {
            ImapReadResult result = await reader.FillAsync(Generous, default);

            result.Status.ShouldBe(ImapReadStatus.Data);

            int take = Math.Min(result.OctetCount, "password".Length - collected.Length);
            collected.Append(Encoding.UTF8.GetString(reader.BufferedInput.Span[..take]));
            reader.Consume(take);
        }

        collected.ToString().ShouldBe("password");
    }

    [Fact]
    public async Task Filling_at_end_of_stream_says_so()
    {
        ImapLineReader reader = Reader("a1 NOOP\r\n");

        await reader.ReadLineAsync(Generous, default);

        ImapReadResult result = await reader.FillAsync(Generous, default);

        result.Status.ShouldBe(ImapReadStatus.EndOfStream);
        result.OctetCount.ShouldBe(0);
    }

    [Fact]
    public async Task A_fill_never_returns_more_than_the_line_budget()
    {
        EndlessStream endless = new((byte)'A');
        ImapLineReader reader = new(endless, 4096);

        ImapReadResult result = await reader.FillAsync(Generous, default);

        result.OctetCount.ShouldBeLessThanOrEqualTo(4098);
        reader.BufferedInput.Length.ShouldBeLessThanOrEqualTo(4098);
    }

    [Fact]
    public void The_buffer_is_sized_from_the_limit_and_the_limit_has_a_floor()
    {
        Should.Throw<ArgumentOutOfRangeException>(() => new ImapLineReader(new MemoryStream(), 511));
    }
}
