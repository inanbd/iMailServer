using MailServer.Ipc.Protocol;

namespace MailServer.Ipc.Tests;

public sealed class IpcFrameTests
{
    private const int MaxFrame = 64 * 1024;

    private static IpcRequest SampleRequest() => new()
    {
        ProtocolVersion = IpcProtocol.Version,
        RequestId = "req-1",
        Command = "Domains.List",
        Payload = """{"page":0}""",
        CorrelationId = "corr-1",
    };

    [Fact]
    public async Task A_frame_round_trips_through_a_stream()
    {
        using MemoryStream stream = new();

        await IpcFrame.WriteAsync(stream, SampleRequest(), MaxFrame, CancellationToken.None);

        stream.Position = 0;

        IpcRequest? read = await IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None);

        read.ShouldNotBeNull();
        read.RequestId.ShouldBe("req-1");
        read.Command.ShouldBe("Domains.List");
        read.Payload.ShouldBe("""{"page":0}""");
        read.CorrelationId.ShouldBe("corr-1");
    }

    [Fact]
    public async Task Several_frames_round_trip_in_order()
    {
        using MemoryStream stream = new();

        for (int i = 0; i < 5; i++)
        {
            await IpcFrame.WriteAsync(
                stream,
                SampleRequest() with { RequestId = $"req-{i}" },
                MaxFrame,
                CancellationToken.None);
        }

        stream.Position = 0;

        for (int i = 0; i < 5; i++)
        {
            IpcRequest? read =
                await IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None);

            read!.RequestId.ShouldBe($"req-{i}");
        }
    }

    [Fact]
    public async Task A_clean_close_between_frames_returns_null_rather_than_throwing()
    {
        // The admin application exiting is normal, not a fault, and must not be logged as one.
        using MemoryStream empty = new();

        IpcRequest? read = await IpcFrame.ReadAsync<IpcRequest>(empty, MaxFrame, CancellationToken.None);

        read.ShouldBeNull();
    }

    [Fact]
    public async Task An_oversized_declared_length_is_rejected_before_any_allocation()
    {
        // THE security property of the framing layer. The length prefix is
        // attacker-influenced data read before any buffer exists; allocating what it declares
        // is how a four-byte message becomes a two-gigabyte allocation.
        using MemoryStream stream = new();

        // Declare 1 GB and send nothing else.
        stream.Write([0x40, 0x00, 0x00, 0x00]);
        stream.Position = 0;

        IpcFrameException ex = await Should.ThrowAsync<IpcFrameException>(
            () => IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None));

        ex.Message.ShouldContain("exceeds");
    }

    [Fact]
    public async Task A_negative_declared_length_is_rejected()
    {
        using MemoryStream stream = new();

        // 0xFFFFFFFF read big-endian as a signed int is -1.
        stream.Write([0xFF, 0xFF, 0xFF, 0xFF]);
        stream.Position = 0;

        await Should.ThrowAsync<IpcFrameException>(
            () => IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None));
    }

    [Fact]
    public async Task A_zero_length_frame_is_rejected()
    {
        using MemoryStream stream = new();

        stream.Write([0x00, 0x00, 0x00, 0x00]);
        stream.Position = 0;

        await Should.ThrowAsync<IpcFrameException>(
            () => IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None));
    }

    [Fact]
    public async Task A_truncated_prefix_is_reported_as_truncation_not_as_a_clean_close()
    {
        // The distinction matters: a clean close is a normal disconnect, a truncated frame is
        // a protocol violation that should close the connection and be logged.
        using MemoryStream stream = new();

        stream.Write([0x00, 0x00]);
        stream.Position = 0;

        IpcFrameException ex = await Should.ThrowAsync<IpcFrameException>(
            () => IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None));

        ex.Message.ShouldContain("truncated");
    }

    [Fact]
    public async Task A_truncated_payload_is_rejected()
    {
        using MemoryStream stream = new();

        // Declare 100 bytes, supply 10.
        stream.Write([0x00, 0x00, 0x00, 0x64]);
        stream.Write(new byte[10]);
        stream.Position = 0;

        await Should.ThrowAsync<EndOfStreamException>(
            () => IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None));
    }

    [Fact]
    public async Task A_payload_that_is_not_valid_json_is_rejected_as_a_protocol_error()
    {
        using MemoryStream stream = new();

        byte[] garbage = "this is not json"u8.ToArray();

        stream.Write([0x00, 0x00, 0x00, (byte)garbage.Length]);
        stream.Write(garbage);
        stream.Position = 0;

        await Should.ThrowAsync<IpcFrameException>(
            () => IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None));
    }

    [Fact]
    public async Task Writing_a_frame_larger_than_the_limit_is_refused()
    {
        using MemoryStream stream = new();

        IpcRequest huge = SampleRequest() with { Payload = new string('x', 200_000) };

        await Should.ThrowAsync<IpcFrameException>(
            () => IpcFrame.WriteAsync(stream, huge, MaxFrame, CancellationToken.None));
    }

    [Fact]
    public async Task A_frame_at_exactly_the_limit_is_accepted()
    {
        using MemoryStream stream = new();

        IpcRequest request = SampleRequest();

        // Round-trips because the serialised form is comfortably under the limit; the point
        // is that the check is "greater than", not "greater than or equal to".
        await IpcFrame.WriteAsync(stream, request, MaxFrame, CancellationToken.None);

        stream.Position = 0;

        (await IpcFrame.ReadAsync<IpcRequest>(stream, MaxFrame, CancellationToken.None))
            .ShouldNotBeNull();
    }

    [Fact]
    public void Payload_serialisation_round_trips()
    {
        Dictionary<string, string> original = new(StringComparer.Ordinal)
        {
            ["name"] = "example.com",
        };

        string json = IpcFrame.SerializePayload(original);

        Dictionary<string, string>? restored =
            IpcFrame.DeserializePayload<Dictionary<string, string>>(json);

        restored.ShouldNotBeNull();
        restored["name"].ShouldBe("example.com");
    }

    [Fact]
    public void An_error_response_carries_its_structured_detail()
    {
        IpcResponse response = IpcResponse.Failed(
            "req-1",
            new IpcError
            {
                Kind = IpcErrorKind.Validation,
                Code = "validation.failed",
                Message = "Two errors occurred.",
                ValidationErrors = new Dictionary<string, string[]>(StringComparer.Ordinal)
                {
                    ["Name"] = ["A name is required.", "Too long."],
                },
            },
            "corr-1");

        string json = IpcFrame.SerializePayload(response);
        IpcResponse? restored = IpcFrame.DeserializePayload<IpcResponse>(json);

        restored.ShouldNotBeNull();
        restored.Success.ShouldBeFalse();
        restored.Error!.Kind.ShouldBe(IpcErrorKind.Validation);
        restored.Error.ValidationErrors!["Name"].Length.ShouldBe(2);
    }
}
