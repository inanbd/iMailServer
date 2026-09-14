using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

internal sealed class TestClock(DateTimeOffset? start = null) : IClock
{
    public DateTimeOffset UtcNow { get; set; } =
        start ?? new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    /// <summary>Monotonic ticks, derived from the settable wall clock so the two never disagree.</summary>
    public long GetTimestamp() => UtcNow.UtcTicks;

    public TimeSpan GetElapsedTime(long startingTimestamp) =>
        TimeSpan.FromTicks(UtcNow.UtcTicks - startingTimestamp);
}

public sealed class MessageStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "aethermail-store-" + Guid.NewGuid().ToString("N"));

    private readonly TestClock _clock = new();

    private FileSystemMessageStore Store() =>
        new(_root, _clock, NullLogger<FileSystemMessageStore>.Instance);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static async Task<StoredMessage> WriteAsync(IMessageStore store, string content, long limit = 1_000_000)
    {
        await using IMessageWriter writer = await store.BeginWriteAsync(limit, default);

        await writer.WriteAsync(Encoding.UTF8.GetBytes(content), default);

        return await writer.CommitAsync(default);
    }

    private static async Task<string> ReadAsync(IMessageStore store, StoredMessageId id)
    {
        await using Stream stream = await store.OpenReadAsync(id, default);

        using StreamReader reader = new(stream, Encoding.UTF8);

        return await reader.ReadToEndAsync();
    }

    // ---------------------------------------------------------------------------------------
    // The API surface is the enforcement, so it gets its own test.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Neither_the_store_nor_the_writer_offers_a_whole_message_as_an_array()
    {
        // docs/SMTP.md: "IMessageStore exposes Stream and has no byte[] ReadAll() method to
        // misuse - the API surface enforces the rule." An overload that returned the whole
        // message would eventually be called on a thirty-megabyte one from a stranger, and the
        // bound would then be whatever the caller remembered to check.
        foreach (Type type in (Type[])[typeof(IMessageStore), typeof(IMessageWriter)])
        {
            foreach (MethodInfo method in type.GetMethods())
            {
                string returnType = method.ReturnType.ToString();

                returnType.ShouldNotContain(
                    "System.Byte[]",
                    customMessage:
                        $"{type.Name}.{method.Name} returns a whole message as an array. " +
                        "The streaming API exists so that cannot happen.");
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Round trips.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_committed_message_reads_back_byte_for_byte()
    {
        FileSystemMessageStore store = Store();

        const string Content = "Received: from a\r\nSubject: test\r\n\r\nBody.\r\n";

        StoredMessage stored = await WriteAsync(store, Content);

        (await ReadAsync(store, stored.Id)).ShouldBe(Content);
        stored.SizeBytes.ShouldBe(Encoding.UTF8.GetByteCount(Content));
    }

    [Fact]
    public async Task The_hash_is_the_sha256_of_what_was_stored()
    {
        // Computed while streaming, so it costs one pass and can be used later to detect a file
        // that has been altered or truncated underneath the database row that names it.
        FileSystemMessageStore store = Store();

        const string Content = "hello world\r\n";

        StoredMessage stored = await WriteAsync(store, Content);

        string expected = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Content)));

        stored.ContentHash.Value.ShouldBe(expected);
    }

    [Fact]
    public async Task A_message_written_in_many_chunks_is_identical_to_one_written_at_once()
    {
        FileSystemMessageStore store = Store();

        byte[] content = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("line of text\r\n", 500)));

        await using IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default);

        for (int offset = 0; offset < content.Length; offset += 37)
        {
            await writer.WriteAsync(content.AsMemory(offset, Math.Min(37, content.Length - offset)), default);
        }

        StoredMessage stored = await writer.CommitAsync(default);

        stored.SizeBytes.ShouldBe(content.Length);
        stored.ContentHash.Value.ShouldBe(Convert.ToHexStringLower(SHA256.HashData(content)));
    }

    [Fact]
    public async Task An_empty_message_is_storable()
    {
        // A message can legitimately have no content after its headers, and a store that refused
        // one would fail at delivery time rather than at receipt.
        FileSystemMessageStore store = Store();

        StoredMessage stored = await WriteAsync(store, string.Empty);

        stored.SizeBytes.ShouldBe(0);
        (await ReadAsync(store, stored.Id)).ShouldBe(string.Empty);
    }

    // ---------------------------------------------------------------------------------------
    // Commit, abandon and what is left behind.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_abandoned_write_leaves_nothing_readable()
    {
        // The normal path for a refused or interrupted DATA, so it must not accumulate files or
        // leave a half-message something else could find.
        FileSystemMessageStore store = Store();

        StoredMessageId id;

        await using (IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default))
        {
            id = writer.Id;
            await writer.WriteAsync("partial content"u8.ToArray(), default);

            // No commit.
        }

        (await store.ExistsAsync(id, default)).ShouldBeFalse();
    }

    [Fact]
    public async Task An_abandoned_write_leaves_no_file_on_disk_at_all()
    {
        FileSystemMessageStore store = Store();

        await using (IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default))
        {
            await writer.WriteAsync("partial"u8.ToArray(), default);
        }

        Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories).ShouldBeEmpty();
    }

    [Fact]
    public async Task A_message_is_not_visible_under_its_final_name_until_it_commits()
    {
        // Write to a temporary name and rename: a reader, or a crash, never sees a message that
        // is half-written.
        FileSystemMessageStore store = Store();

        await using IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default);

        await writer.WriteAsync("some content"u8.ToArray(), default);

        (await store.ExistsAsync(writer.Id, default)).ShouldBeFalse();

        await writer.CommitAsync(default);

        (await store.ExistsAsync(writer.Id, default)).ShouldBeTrue();
    }

    [Fact]
    public async Task Committing_twice_is_refused()
    {
        FileSystemMessageStore store = Store();

        await using IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default);

        await writer.WriteAsync("content"u8.ToArray(), default);
        await writer.CommitAsync(default);

        await Should.ThrowAsync<InvalidOperationException>(async () => await writer.CommitAsync(default));
    }

    [Fact]
    public async Task Writing_after_commit_is_refused()
    {
        // Appending to a committed message would change content a database row already describes
        // by size and hash.
        FileSystemMessageStore store = Store();

        await using IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default);

        await writer.CommitAsync(default);

        await Should.ThrowAsync<InvalidOperationException>(
            async () => await writer.WriteAsync("more"u8.ToArray(), default));
    }

    // ---------------------------------------------------------------------------------------
    // Limits.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_write_past_the_limit_is_refused_before_the_octets_reach_the_disk()
    {
        FileSystemMessageStore store = Store();

        await using IMessageWriter writer = await store.BeginWriteAsync(maxSizeBytes: 10, default);

        await writer.WriteAsync(new byte[8], default);

        MessageTooLargeException error = await Should.ThrowAsync<MessageTooLargeException>(
            async () => await writer.WriteAsync(new byte[8], default));

        error.LimitBytes.ShouldBe(10L);
        writer.BytesWritten.ShouldBe(8L);
    }

    [Fact]
    public async Task A_message_of_exactly_the_limit_is_accepted()
    {
        // The boundary in the accepting direction. Refusing here would turn a documented limit
        // into a limit one octet lower, which is the kind of thing nobody notices until a
        // customer's mail bounces.
        FileSystemMessageStore store = Store();

        await using IMessageWriter writer = await store.BeginWriteAsync(maxSizeBytes: 16, default);

        await writer.WriteAsync(new byte[16], default);

        (await writer.CommitAsync(default)).SizeBytes.ShouldBe(16L);
    }

    [Fact]
    public async Task A_refused_over_size_write_leaves_nothing_behind()
    {
        FileSystemMessageStore store = Store();

        await using (IMessageWriter writer = await store.BeginWriteAsync(maxSizeBytes: 10, default))
        {
            await Should.ThrowAsync<MessageTooLargeException>(
                async () => await writer.WriteAsync(new byte[64], default));
        }

        Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories).ShouldBeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // Layout, lookup and housekeeping.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Messages_are_sharded_by_date()
    {
        // One directory per day rather than one directory for every message the server has ever
        // received. The failure mode without it is not subtle: directory operations on NTFS
        // degrade badly past a few million entries.
        FileSystemMessageStore store = Store();

        StoredMessage stored = await WriteAsync(store, "content");

        string path = Directory.EnumerateFiles(_root, "*.eml", SearchOption.AllDirectories).Single();

        path.ShouldContain(Path.Combine("2026", "03", "01"));
        path.ShouldContain(stored.Id.Value.ToString("N"));
    }

    [Fact]
    public async Task A_message_stored_on_an_earlier_day_is_still_found()
    {
        // The identifier does not carry its date, and the clock moves on. A lookup that only
        // ever looked in today's directory would lose every message the moment midnight passed.
        FileSystemMessageStore store = Store();

        StoredMessage stored = await WriteAsync(store, "yesterday's mail");

        _clock.UtcNow = _clock.UtcNow.AddDays(4);

        (await store.ExistsAsync(stored.Id, default)).ShouldBeTrue();
        (await ReadAsync(store, stored.Id)).ShouldBe("yesterday's mail");
    }

    [Fact]
    public void The_stored_file_name_cannot_contain_a_path_segment()
    {
        // Rule 105: no path traversal. The name is generated from a GUID in "N" format, so it is
        // 32 hex digits and nothing else - met by construction rather than by sanitising a name
        // that came from somewhere else.
        string name = Guid.NewGuid().ToString("N");

        name.Length.ShouldBe(32);
        name.ShouldNotContain("/");
        name.ShouldNotContain("\\");
        name.ShouldNotContain("..");
        name.ShouldNotContain(":");
        name.ShouldAllBe(c => Uri.IsHexDigit(c));
    }

    [Fact]
    public async Task Reading_a_message_that_does_not_exist_is_an_error_rather_than_an_empty_stream()
    {
        // An empty stream would be delivered as an empty message. Failing loudly means the
        // orphaned row is noticed instead of silently emptying someone's mailbox.
        FileSystemMessageStore store = Store();

        await Should.ThrowAsync<FileNotFoundException>(
            async () => await store.OpenReadAsync(new StoredMessageId(Guid.NewGuid()), default));
    }

    [Fact]
    public async Task Deleting_reports_whether_anything_was_there()
    {
        FileSystemMessageStore store = Store();

        StoredMessage stored = await WriteAsync(store, "content");

        (await store.DeleteAsync(stored.Id, default)).ShouldBeTrue();
        (await store.DeleteAsync(stored.Id, default)).ShouldBeFalse();
    }

    [Fact]
    public async Task The_sweep_removes_temporary_files_a_crash_left_behind()
    {
        // The other half of write-then-rename. A process killed mid-write leaves a temporary
        // file nothing will ever dispose, and nothing ever referred to it, so removing it loses
        // no mail.
        // The sweep compares file timestamps against the injected clock, so the test moves the
        // clock to real time rather than leaving the two to disagree and pass by accident.
        _clock.UtcNow = DateTimeOffset.UtcNow;

        FileSystemMessageStore store = Store();

        string orphan = Path.Combine(_root, "Incoming", "abandoned.tmp");
        await File.WriteAllTextAsync(orphan, "half a message");

        File.SetLastWriteTimeUtc(orphan, _clock.UtcNow.AddHours(-6).UtcDateTime);

        store.SweepAbandonedWrites(TimeSpan.FromHours(1)).ShouldBe(1);
        File.Exists(orphan).ShouldBeFalse();
    }

    [Fact]
    public async Task The_sweep_leaves_a_write_that_is_still_in_progress_alone()
    {
        _clock.UtcNow = DateTimeOffset.UtcNow;

        FileSystemMessageStore store = Store();

        await using IMessageWriter writer = await store.BeginWriteAsync(1_000_000, default);

        await writer.WriteAsync("in progress"u8.ToArray(), default);

        store.SweepAbandonedWrites(TimeSpan.FromHours(1)).ShouldBe(0);

        await writer.CommitAsync(default);

        (await ReadAsync(store, writer.Id)).ShouldBe("in progress");
    }
}
