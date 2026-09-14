using System.Buffers.Binary;
using System.Text;
using MailServer.Infrastructure.Dns;

namespace MailServer.Acme.Tests;

/// <summary>
/// The DNS response parser, exercised against hand-built packets.
/// </summary>
/// <remarks>
/// <para>
/// This parses bytes that arrive from the network, so the tests weight malformed input as
/// heavily as well-formed input. An unchecked length or a compression-pointer loop in a DNS
/// parser is a crash or a hang triggered by anyone who can answer a query.
/// </para>
/// <para>
/// Packets are built here rather than captured, so each test states exactly which byte it is
/// about.
/// </para>
/// </remarks>
public sealed class DnsTxtParsingTests
{
    private const ushort TransactionId = 0x1234;

    /// <summary>Builds a response carrying the given TXT strings.</summary>
    private static byte[] BuildResponse(
        string name,
        IReadOnlyList<string> txtValues,
        ushort id = TransactionId,
        int rcode = 0)
    {
        List<byte> packet = [];

        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(id)));

        // Response, recursion desired and available, with the requested rcode.
        packet.Add(0x81);
        packet.Add((byte)(0x80 | rcode));

        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)1)));
        packet.AddRange(BitConverter.GetBytes(
            BinaryPrimitives.ReverseEndianness((ushort)txtValues.Count)));
        packet.AddRange([0x00, 0x00, 0x00, 0x00]);

        WriteName(packet, name);
        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)16)));
        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)1)));

        foreach (string value in txtValues)
        {
            // A compression pointer back to the question's name at offset 12, which is what a
            // real resolver emits and what the parser must be able to step over.
            packet.Add(0xC0);
            packet.Add(0x0C);

            packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)16)));
            packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)1)));
            packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(300u)));

            byte[] encoded = Encoding.ASCII.GetBytes(value);

            // TXT rdata is length-prefixed strings of at most 255 bytes each.
            List<byte> rdata = [];
            int offset = 0;

            while (offset < encoded.Length)
            {
                int chunk = Math.Min(255, encoded.Length - offset);
                rdata.Add((byte)chunk);
                rdata.AddRange(encoded.AsSpan(offset, chunk).ToArray());
                offset += chunk;
            }

            packet.AddRange(BitConverter.GetBytes(
                BinaryPrimitives.ReverseEndianness((ushort)rdata.Count)));
            packet.AddRange(rdata);
        }

        return [.. packet];
    }

    private static void WriteName(List<byte> packet, string name)
    {
        foreach (string label in name.Split('.'))
        {
            byte[] encoded = Encoding.ASCII.GetBytes(label);
            packet.Add((byte)encoded.Length);
            packet.AddRange(encoded);
        }

        packet.Add(0x00);
    }

    [Fact]
    public void A_single_txt_record_is_read()
    {
        byte[] response = BuildResponse("_acme-challenge.example.com", ["token-value"]);

        DnsTxtResolver.ParseTxtAnswers(response, TransactionId)
            .ShouldHaveSingleItem()
            .ShouldBe("token-value");
    }

    [Fact]
    public void Several_txt_records_are_all_read()
    {
        byte[] response = BuildResponse("_acme-challenge.example.com", ["first", "second"]);

        DnsTxtResolver.ParseTxtAnswers(response, TransactionId)
            .ShouldBe(["first", "second"]);
    }

    /// <summary>
    /// A value longer than 255 bytes arrives split across several strings and must be
    /// concatenated — which is how a long DNS-01 digest would arrive.
    /// </summary>
    [Fact]
    public void A_value_split_across_several_strings_is_concatenated()
    {
        string long_ = new('x', 400);

        byte[] response = BuildResponse("_acme-challenge.example.com", [long_]);

        DnsTxtResolver.ParseTxtAnswers(response, TransactionId)
            .ShouldHaveSingleItem()
            .ShouldBe(long_);
    }

    /// <summary>
    /// A response whose transaction id does not match is not an answer to our query, whether
    /// that is a stale datagram or an attempt at poisoning.
    /// </summary>
    [Fact]
    public void A_response_with_the_wrong_transaction_id_is_discarded()
    {
        byte[] response = BuildResponse("example.com", ["value"], id: 0x9999);

        DnsTxtResolver.ParseTxtAnswers(response, TransactionId).ShouldBeEmpty();
    }

    [Theory]
    [InlineData(3)]  // NXDOMAIN
    [InlineData(2)]  // SERVFAIL
    [InlineData(5)]  // REFUSED
    public void An_error_response_yields_nothing(int rcode)
    {
        byte[] response = BuildResponse("example.com", ["value"], rcode: rcode);

        DnsTxtResolver.ParseTxtAnswers(response, TransactionId).ShouldBeEmpty();
    }

    [Fact]
    public void A_truncated_packet_does_not_throw()
    {
        byte[] full = BuildResponse("_acme-challenge.example.com", ["token-value"]);

        // Every truncation point, because the interesting failures are mid-header, mid-name
        // and mid-rdata, and asserting one of them would miss the other two.
        for (int length = 0; length < full.Length; length++)
        {
            byte[] truncated = full[..length];

            Should.NotThrow(() => DnsTxtResolver.ParseTxtAnswers(truncated, TransactionId));
        }
    }

    /// <summary>
    /// A compression pointer that points at itself is an infinite loop in a naive parser.
    /// </summary>
    [Fact]
    public async Task A_self_referential_compression_pointer_does_not_hang()
    {
        List<byte> packet = [];

        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(TransactionId)));
        packet.AddRange([0x81, 0x80]);
        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)1)));
        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)1)));
        packet.AddRange([0x00, 0x00, 0x00, 0x00]);

        // A pointer at offset 12 pointing back to offset 12.
        packet.Add(0xC0);
        packet.Add(0x0C);
        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)16)));
        packet.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)1)));

        byte[] response = [.. packet];

        // The bound on compression jumps is what makes this terminate at all.
        Task<IReadOnlyList<string>> parse =
            Task.Run(() => DnsTxtResolver.ParseTxtAnswers(response, TransactionId));

        Task finished = await Task.WhenAny(parse, Task.Delay(TimeSpan.FromSeconds(5)));

        finished.ShouldBe(
            parse,
            "parsing a self-referential compression pointer must terminate, not loop");
    }

    [Fact]
    public void An_rdata_length_beyond_the_buffer_is_ignored()
    {
        byte[] response = BuildResponse("example.com", ["value"]);

        // Overstate the last record's rdata length so it claims to run past the packet.
        response[^7] = 0xFF;
        response[^6] = 0xFF;

        Should.NotThrow(() => DnsTxtResolver.ParseTxtAnswers(response, TransactionId));
    }

    [Fact]
    public void An_empty_buffer_yields_nothing()
    {
        DnsTxtResolver.ParseTxtAnswers([], TransactionId).ShouldBeEmpty();
    }
}
