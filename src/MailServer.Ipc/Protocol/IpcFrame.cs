using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MailServer.Ipc.Protocol;

/// <summary>
/// Length-prefixed framing over a duplex stream.
/// </summary>
/// <remarks>
/// <para>
/// A pipe is a byte stream with no message boundaries, so the protocol supplies its own:
/// a 4-byte big-endian length followed by that many bytes of UTF-8 JSON.
/// </para>
/// <para>
/// <b>The length prefix is attacker-influenced data that is read before any allocation.</b>
/// It is therefore validated against a caller-supplied maximum <i>and</i> an absolute
/// ceiling before a single byte is allocated. Reading the prefix and calling
/// <c>new byte[length]</c> is how a four-byte message becomes a two-gigabyte allocation and
/// takes the mail server down with it.
/// </para>
/// <para>
/// Big-endian because it is the conventional network byte order and makes a packet capture
/// readable; both ends are .NET, so there is no interop reason to prefer either.
/// </para>
/// </remarks>
public static class IpcFrame
{
    /// <summary>Size of the length prefix in bytes.</summary>
    public const int PrefixBytes = 4;

    /// <summary>
    /// JSON options shared by both ends.
    /// </summary>
    /// <remarks>
    /// Cached and immutable: constructing <see cref="JsonSerializerOptions"/> per call is
    /// expensive because it rebuilds the serialiser's metadata cache each time.
    /// </remarks>
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.General)
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,

        // No custom converters beyond the enum one declared on the enums themselves, and
        // no polymorphic type handling. Type discriminators in a payload from a lower-trust
        // process are a deserialisation gadget waiting to be used.
        WriteIndented = false,
    };

    /// <summary>Serialises a value and writes it as one frame.</summary>
    public static async Task WriteAsync<T>(
        Stream stream,
        T value,
        int maxFrameBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);

        if (json.Length > maxFrameBytes)
        {
            throw new IpcFrameException(
                $"The outgoing frame is {json.Length} bytes, which exceeds the {maxFrameBytes}-byte limit.");
        }

        byte[] prefix = new byte[PrefixBytes];
        BinaryPrimitives.WriteInt32BigEndian(prefix, json.Length);

        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(json, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one frame and deserialises it. Returns <c>default</c> when the peer closed the
    /// stream cleanly between frames.
    /// </summary>
    public static async Task<T?> ReadAsync<T>(
        Stream stream,
        int maxFrameBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[] prefix = new byte[PrefixBytes];

        int read = await ReadExactlyOrZeroAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            // Clean close between frames. Not an error: the admin application exited.
            return default;
        }

        int length = BinaryPrimitives.ReadInt32BigEndian(prefix);

        // Validate BEFORE allocating. This is the whole point of the framing layer.
        if (length < 0)
        {
            throw new IpcFrameException(
                $"The frame length prefix is negative ({length}). The stream is corrupt or the " +
                "peer is not speaking this protocol.");
        }

        if (length == 0)
        {
            throw new IpcFrameException("The frame length prefix is zero; an empty frame is not valid.");
        }

        if (length > maxFrameBytes || length > IpcProtocol.AbsoluteMaxFrameBytes)
        {
            throw new IpcFrameException(
                $"The peer declared a {length}-byte frame, which exceeds the " +
                $"{Math.Min(maxFrameBytes, IpcProtocol.AbsoluteMaxFrameBytes)}-byte limit. " +
                "The connection will be closed without allocating the buffer.");
        }

        byte[] payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);

        try
        {
            return JsonSerializer.Deserialize<T>(payload, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new IpcFrameException("The frame payload is not valid JSON for this protocol.", ex);
        }
    }

    /// <summary>
    /// Fills <paramref name="buffer"/>, or returns 0 if the stream ended before any byte
    /// arrived.
    /// </summary>
    /// <remarks>
    /// Distinguishing "clean close between frames" from "closed mid-frame" matters: the
    /// first is normal shutdown and must not be logged as an error, while the second is a
    /// truncated frame and must be.
    /// </remarks>
    private static async Task<int> ReadExactlyOrZeroAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        int total = 0;

        while (total < buffer.Length)
        {
            int read = await stream
                .ReadAsync(buffer.AsMemory(total), cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                if (total == 0)
                {
                    return 0;
                }

                throw new IpcFrameException(
                    $"The stream ended after {total} of {buffer.Length} prefix bytes. The frame " +
                    "was truncated.");
            }

            total += read;
        }

        return total;
    }

    /// <summary>Encodes a value as a JSON string for an envelope payload.</summary>
    public static string SerializePayload<T>(T value) =>
        JsonSerializer.Serialize(value, JsonOptions);

    /// <summary>Decodes an envelope payload.</summary>
    public static T? DeserializePayload<T>(string? payload) =>
        string.IsNullOrEmpty(payload) ? default : JsonSerializer.Deserialize<T>(payload, JsonOptions);

    /// <summary>Decodes an envelope payload into a known type.</summary>
    public static object? DeserializePayload(string? payload, Type type)
    {
        ArgumentNullException.ThrowIfNull(type);

        return string.IsNullOrEmpty(payload)
            ? null
            : JsonSerializer.Deserialize(payload, type, JsonOptions);
    }

    /// <summary>Encoding used for every frame payload.</summary>
    public static Encoding PayloadEncoding => Encoding.UTF8;
}

/// <summary>A framing or protocol-level failure. Always closes the connection.</summary>
public sealed class IpcFrameException : Exception
{
    public IpcFrameException(string message) : base(message)
    {
    }

    public IpcFrameException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
