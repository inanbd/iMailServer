using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// Reading an SNTP answer's transmit timestamp. RFC 4330 §3.
/// </summary>
/// <remarks>
/// The conversation itself is a UDP round trip and is not tested here; the arithmetic is, because
/// it is where this can be wrong in a way that looks plausible — a timestamp read against the
/// Unix epoch rather than the NTP one is out by seventy years and would report every clock as
/// catastrophically skewed.
/// </remarks>
public sealed class SntpTimeReferenceTests
{
    /// <summary>Builds a 48-octet answer carrying a transmit timestamp.</summary>
    private static byte[] Packet(uint seconds, uint fraction = 0)
    {
        byte[] packet = new byte[SntpTimeReference.PacketBytes];

        int at = SntpTimeReference.TransmitTimestampOffset;

        packet[at] = (byte)(seconds >> 24);
        packet[at + 1] = (byte)(seconds >> 16);
        packet[at + 2] = (byte)(seconds >> 8);
        packet[at + 3] = (byte)seconds;
        packet[at + 4] = (byte)(fraction >> 24);
        packet[at + 5] = (byte)(fraction >> 16);
        packet[at + 6] = (byte)(fraction >> 8);
        packet[at + 7] = (byte)fraction;

        return packet;
    }

    /// <summary>
    /// The timestamp is seconds since 1900, not since 1970.
    /// </summary>
    /// <remarks>
    /// RFC 4330 §3: a timestamp is "in seconds relative to 0h on 1 January 1900". The two epochs
    /// are 2,208,988,800 seconds apart, so reading against the wrong one puts every answer
    /// seventy years out — and the check it feeds would report every clock in the world as
    /// broken.
    /// </remarks>
    [Fact]
    public void The_timestamp_is_read_against_the_ntp_epoch()
    {
        SntpTimeReference.ReadTransmitTimestamp(Packet(0x8000_0000))
            .ShouldBe(SntpTimeReference.NtpEpoch.AddSeconds(0x8000_0000));

        SntpTimeReference.NtpEpoch.ShouldBe(new DateTimeOffset(1900, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }

    /// <summary>
    /// The seconds are big-endian, as everything on the wire is.
    /// </summary>
    /// <remarks>
    /// Reading them little-endian would produce a date that parses perfectly and is wrong by
    /// centuries — a failure with no symptom other than an absurd number in one finding.
    /// </remarks>
    [Fact]
    public void The_seconds_are_read_big_endian()
    {
        SntpTimeReference.ReadTransmitTimestamp(Packet(1))
            .ShouldBe(SntpTimeReference.NtpEpoch.AddSeconds(1));
    }

    /// <summary>
    /// The fraction is the low 32 bits of a fixed-point second.
    /// </summary>
    /// <remarks>
    /// §3: "The integer part is in the first 32 bits and the fraction part in the last 32 bits."
    /// So 0x80000000 is exactly half a second, and treating the fraction as milliseconds — a
    /// natural mistake — would add two million seconds instead.
    /// </remarks>
    [Fact]
    public void The_fraction_is_a_fixed_point_second()
    {
        DateTimeOffset half = SntpTimeReference.ReadTransmitTimestamp(Packet(1, 0x8000_0000))
            .ShouldNotBeNull();

        (half - SntpTimeReference.NtpEpoch.AddSeconds(1)).TotalMilliseconds.ShouldBe(500, 1);
    }

    /// <summary>
    /// An all-zero timestamp means unsynchronised, not 1900.
    /// </summary>
    /// <remarks>
    /// RFC 4330 §4 gives zero that meaning. Taking it literally would report a skew of a century
    /// from a server that was politely saying it does not know the time.
    /// </remarks>
    [Fact]
    public void An_all_zero_timestamp_is_not_a_time()
    {
        SntpTimeReference.ReadTransmitTimestamp(Packet(0)).ShouldBeNull();
    }

    /// <summary>A packet too short to hold a timestamp yields none.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(40)]
    [InlineData(47)]
    public void A_short_packet_yields_no_timestamp(int length)
    {
        SntpTimeReference.ReadTransmitTimestamp(new byte[length]).ShouldBeNull();
    }
}
