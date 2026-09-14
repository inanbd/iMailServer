using System.Text;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

public sealed class SmtpDataReceiverTests : IDisposable
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "aethermail-receiver-" + Guid.NewGuid().ToString("N"));

    private readonly TestClock _clock = new();

    private FileSystemMessageStore _store = null!;

    private FileSystemMessageStore Store =>
        _store ??= new FileSystemMessageStore(_root, _clock, NullLogger<FileSystemMessageStore>.Instance);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private SmtpDataReceiver Receiver() => new(Store, NullLogger<SmtpDataReceiver>.Instance);

    private static SmtpLineReader Reader(string wire, int chunkSize = 4096, int maxLine = 4096) =>
        new(new ChunkedStream(Encoding.UTF8.GetBytes(wire), chunkSize), maxLine);

    private async Task<string> ReadStoredAsync(StoredMessage message)
    {
        await using Stream stream = await Store.OpenReadAsync(message.Id, default);

        using StreamReader reader = new(stream, Encoding.UTF8);

        return await reader.ReadToEndAsync();
    }

    // ---------------------------------------------------------------------------------------
    // The ordinary path.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_message_is_stored_with_the_trace_header_ahead_of_it()
    {
        SmtpLineReader reader = Reader("Subject: hello\r\n\r\nBody text.\r\n.\r\n");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, "Received: from test\r\n", 1_000_000, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Accepted);
        result.Message.ShouldNotBeNull();

        (await ReadStoredAsync(result.Message)).ShouldBe(
            "Received: from test\r\nSubject: hello\r\n\r\nBody text.\r\n");
    }

    [Fact]
    public async Task Dot_stuffing_is_undone_on_the_way_into_the_store()
    {
        SmtpLineReader reader = Reader("head\r\n..\r\ntail\r\n.\r\n");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, 1_000_000, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Accepted);
        (await ReadStoredAsync(result.Message!)).ShouldBe("head\r\n.\r\ntail\r\n");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(64)]
    [InlineData(4096)]
    public async Task The_stored_message_does_not_depend_on_packet_boundaries(int chunkSize)
    {
        const string Wire = "A: 1\r\nB: 2\r\n\r\nline\nline two\r\n..dotted\r\n.\r\n";

        SmtpLineReader reader = Reader(Wire, chunkSize);

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, 1_000_000, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Accepted);
        (await ReadStoredAsync(result.Message!)).ShouldBe("A: 1\r\nB: 2\r\n\r\nline\r\nline two\r\n.dotted\r\n");
    }

    [Fact]
    public async Task A_message_larger_than_one_read_is_stored_whole()
    {
        // Streams across many reads through fixed buffers. If any of the carry-over state were
        // wrong this is where it shows, because the body is far bigger than the reader's window.
        string body = string.Concat(Enumerable.Range(0, 5000).Select(i => $"line {i}\r\n"));

        SmtpLineReader reader = Reader(body + ".\r\n", chunkSize: 1500);

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, 10_000_000, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Accepted);
        (await ReadStoredAsync(result.Message!)).ShouldBe(body);
    }

    [Fact]
    public async Task Octets_after_the_marker_are_left_for_the_command_loop()
    {
        // PIPELINING puts the next command in the same packet as the end of the message.
        // Consuming it here would leave the session waiting for a command already sent.
        SmtpLineReader reader = Reader("body\r\n.\r\nQUIT\r\n");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, 1_000_000, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Accepted);

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("QUIT");
    }

    // ---------------------------------------------------------------------------------------
    // Size limits.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_over_size_message_is_refused_but_the_session_survives()
    {
        // RFC 5321 §4.5.3.1.9: read on to the marker so the sender gets a proper 552 rather than
        // a dropped connection it has to interpret.
        string body = new('x', 2000);

        SmtpLineReader reader = Reader($"{body}\r\n.\r\nQUIT\r\n");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, maxSizeBytes: 500, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.TooLarge);
        result.Reply!.Code.ShouldBe(552);
        result.Message.ShouldBeNull();
        result.ShouldCloseConnection.ShouldBeFalse();

        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("QUIT");
    }

    [Fact]
    public async Task An_over_size_message_leaves_nothing_in_the_store()
    {
        SmtpLineReader reader = Reader(new string('x', 2000) + "\r\n.\r\n");

        await Receiver().ReceiveAsync(reader, "Received: from test\r\n", 500, Generous, default);

        Directory.EnumerateFiles(_root, "*.eml", SearchOption.AllDirectories).ShouldBeEmpty();
        Directory.EnumerateFiles(_root, "*.tmp", SearchOption.AllDirectories).ShouldBeEmpty();
    }

    [Fact]
    public async Task The_size_is_charged_against_what_the_peer_sent_not_what_was_stored()
    {
        // A sender must not be able to exceed the limit by padding with octets the decoder
        // discards - stuffed dots, for instance, which shrink on the way in.
        string stuffed = string.Concat(Enumerable.Repeat("..\r\n", 200));   // 800 raw, 600 stored

        SmtpLineReader reader = Reader(stuffed + ".\r\n");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, maxSizeBytes: 700, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.TooLarge);
        result.RawByteCount.ShouldBeGreaterThan(700);
    }

    [Fact]
    public async Task A_message_of_exactly_the_limit_is_accepted()
    {
        // 16 body octets plus the five-octet marker. The limit is charged against what the peer
        // sent, and the marker is part of that.
        const string Body = "0123456789abcdef";

        SmtpLineReader reader = Reader($"{Body}\r\n.\r\n");

        long raw = Encoding.UTF8.GetByteCount($"{Body}\r\n.\r\n");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, maxSizeBytes: raw, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Accepted);
    }

    [Fact]
    public async Task The_trace_header_is_not_charged_to_the_peer()
    {
        // The peer did not send it. A message exactly at the limit must not be refused because
        // of a header this server added to it.
        const string Body = "0123456789";

        string preamble = "Received: from " + new string('h', 400) + "\r\n";

        SmtpLineReader reader = Reader($"{Body}\r\n.\r\n");

        long raw = Encoding.UTF8.GetByteCount($"{Body}\r\n.\r\n");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, preamble, maxSizeBytes: raw, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Accepted);
        result.Message!.SizeBytes.ShouldBeGreaterThan(raw);
    }

    [Fact]
    public async Task A_peer_that_runs_far_past_the_limit_is_disconnected()
    {
        // Reading to the marker is a courtesy with a budget. Past it the peer has stopped trying
        // to deliver mail, and continuing would be the unbounded read rule 105 forbids.
        long overrun = SmtpDataReceiver.MaxOverrunBytes;

        // Never terminates, so the only way out is the overrun budget.
        EndlessStream endless = new((byte)'x');
        SmtpLineReader reader = new(endless, 4096);

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, maxSizeBytes: 1000, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.TooLargeAndUnrecoverable);
        result.ShouldCloseConnection.ShouldBeTrue();
        result.RawByteCount.ShouldBeLessThanOrEqualTo(1000 + overrun + 4098);
    }

    // ---------------------------------------------------------------------------------------
    // Failures.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_message_cut_off_mid_body_is_not_delivered()
    {
        // No marker, so no message. The sender will retry, and a truncated copy delivered now
        // becomes a duplicate of the complete one that follows.
        SmtpLineReader reader = Reader("Subject: interrupted\r\n\r\nhalf a bo");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, 1_000_000, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.ConnectionClosed);
        result.Message.ShouldBeNull();
        result.ShouldCloseConnection.ShouldBeTrue();

        Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories).ShouldBeEmpty();
    }

    [Fact]
    public async Task A_peer_that_stops_sending_mid_message_times_out()
    {
        SmtpLineReader reader = new(new SilentStream(), 4096);

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, 1_000_000, TimeSpan.FromMilliseconds(150), default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Timeout);
        result.Reply!.Code.ShouldBe(421);
        result.ShouldCloseConnection.ShouldBeTrue();
    }

    [Fact]
    public async Task Smuggled_commands_are_stored_as_body_not_executed()
    {
        // The whole SMTP smuggling defence, end to end through the real reader and the real
        // store: "\n.\n" is not a marker, so what follows is content.
        SmtpLineReader reader = Reader(
            "legitimate\n.\nMAIL FROM:<attacker@evil.example>\r\nRCPT TO:<victim@example.com>\r\n.\r\nQUIT\r\n");

        SmtpDataResult result = await Receiver()
            .ReceiveAsync(reader, string.Empty, 1_000_000, Generous, default);

        result.Outcome.ShouldBe(SmtpDataOutcome.Accepted);

        string stored = await ReadStoredAsync(result.Message!);

        stored.ShouldContain("MAIL FROM:<attacker@evil.example>");
        stored.ShouldContain("RCPT TO:<victim@example.com>");

        // And the only thing left for the command loop is the one command the peer really sent.
        (await reader.ReadLineAsync(Generous, default)).Text.ShouldBe("QUIT");
    }
}
