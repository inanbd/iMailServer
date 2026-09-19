using System.Net.Sockets;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Time;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Measures this server's clock against an SNTP server. RFC 4330.
/// </summary>
/// <remarks>
/// <para>
/// <b>Read-only, and deliberately so.</b> Nothing here sets the clock or feeds anything that
/// does — the result reaches one check in the deliverability report and stops. A mail server
/// that took its time from an unauthenticated UDP packet would hand whoever can answer it the
/// ability to expire its own certificates and invalidate its own signatures.
/// </para>
/// <para>
/// An implementation rather than a dependency because SNTP's client half is small: RFC 4330 §4
/// is a 48-octet request whose only required content is the mode, and the answer this needs is
/// the transmit timestamp at octet 40. The alternative is a package, a supply-chain surface and
/// a configuration surface, for thirty lines.
/// </para>
/// </remarks>
public sealed class SntpTimeReference(IClock clock, string server, int port = 123) : ITimeReference
{
    /// <summary>The size of an SNTP packet. RFC 4330 §4's header is the whole of it.</summary>
    public const int PacketBytes = 48;

    /// <summary>The offset of the transmit timestamp within that packet.</summary>
    public const int TransmitTimestampOffset = 40;

    /// <summary>
    /// The NTP epoch: 1 January 1900. RFC 4330 §3.
    /// </summary>
    /// <remarks>
    /// Seventy years before the Unix epoch, which is the entire difficulty of reading one of
    /// these timestamps and the reason it is named rather than written inline.
    /// </remarks>
    public static readonly DateTimeOffset NtpEpoch = new(1900, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>How long to wait for an answer before giving up.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    /// <inheritdoc />
    public async Task<TimeSpan?> GetSkewAsync(CancellationToken cancellationToken)
    {
        try
        {
            using UdpClient client = new();

            client.Client.ReceiveTimeout = (int)Timeout.TotalMilliseconds;

            byte[] request = new byte[PacketBytes];

            // RFC 4330 §4: the first octet carries Leap Indicator, Version Number and Mode.
            // 0x1B is LI=0 (no warning), VN=3, Mode=3 (client) - the packet every SNTP client
            // sends and the only field a server requires to be set.
            request[0] = 0x1B;

            await client.SendAsync(request, server, port, cancellationToken).ConfigureAwait(false);

            using CancellationTokenSource timeout = CancellationTokenSource
                .CreateLinkedTokenSource(cancellationToken);

            timeout.CancelAfter(Timeout);

            UdpReceiveResult result = await client.ReceiveAsync(timeout.Token).ConfigureAwait(false);

            // Measured after the answer arrives rather than before it was sent, so the round
            // trip is charged against the server rather than silently added to the skew. A
            // report is not a time sync: being a few milliseconds pessimistic costs nothing,
            // and the thresholds it feeds are measured in seconds.
            DateTimeOffset local = clock.UtcNow;

            return ReadTransmitTimestamp(result.Buffer) is { } reference
                ? local - reference
                : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // An unreachable reference is null, never zero. See ITimeReference.GetSkewAsync: a
            // report that could not measure the skew must not report the clock as correct.
            return null;
        }
    }

    /// <summary>
    /// The transmit timestamp from an SNTP answer, or null when the packet is not one.
    /// </summary>
    /// <remarks>
    /// RFC 4330 §3: a timestamp is "a 64-bit unsigned fixed-point number, in seconds relative to
    /// 0h on 1 January 1900. The integer part is in the first 32 bits and the fraction part in
    /// the last 32 bits." Both halves are big-endian on the wire, which is why they are read a
    /// byte at a time rather than cast.
    /// </remarks>
    public static DateTimeOffset? ReadTransmitTimestamp(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < PacketBytes)
        {
            return null;
        }

        ReadOnlySpan<byte> stamp = packet.Slice(TransmitTimestampOffset, 8);

        ulong seconds = ((ulong)stamp[0] << 24) | ((ulong)stamp[1] << 16) |
                        ((ulong)stamp[2] << 8) | stamp[3];

        ulong fraction = ((ulong)stamp[4] << 24) | ((ulong)stamp[5] << 16) |
                         ((ulong)stamp[6] << 8) | stamp[7];

        // All zeroes is RFC 4330 §4's "unknown or unsynchronized" value, not 1900.
        if (seconds == 0 && fraction == 0)
        {
            return null;
        }

        double milliseconds = (seconds * 1000d) + (fraction * 1000d / 0x1_0000_0000L);

        return NtpEpoch.AddMilliseconds(milliseconds);
    }
}
