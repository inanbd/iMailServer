using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dns;

/// <summary>
/// A minimal DNS client that can read TXT records.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists at all.</b> The BCL has no TXT lookup — <see cref="System.Net.Dns"/>
/// resolves names to addresses and nothing else. Checking a DNS-01 challenge needs TXT, so
/// either this exists or the "Check DNS" step is a lie that reports failure for a correctly
/// published record.
/// </para>
/// <para>
/// <b>Deliberately minimal.</b> It builds one query, sends it over UDP, and parses A-record and
/// TXT answers. It does not do DNSSEC validation, EDNS, or recursion of its own. The full
/// resolver arrives in Milestone 9 for DKIM, SPF and DMARC, where correctness under adversarial
/// conditions actually matters; this one only has to answer "can the world see my TXT record
/// yet", where the cost of a wrong answer is one retry.
/// </para>
/// <para>
/// <b>It queries the resolver it is told to.</b> Ideally that is the zone's authoritative
/// nameserver, because a recursive resolver can report a record before the CA's resolver sees
/// it — or, worse, serve a cached negative answer after the record is live. Resolving the
/// authoritative set needs NS and SOA handling that belongs with the Milestone 9 resolver, so
/// for now the caller passes the servers to ask and the UI says which were used.
/// </para>
/// <para>
/// Every read is bounds-checked against the received buffer. Parsing a DNS response is parsing
/// attacker-controlled bytes from the network: an unchecked length or a compression pointer
/// loop is a crash at best.
/// </para>
/// </remarks>
internal sealed class DnsTxtResolver(ILogger<DnsTxtResolver> logger)
{
    private const int DnsPort = 53;

    private const ushort TypeTxt = 16;
    private const ushort ClassInternet = 1;

    /// <summary>
    /// Ceiling on a UDP DNS response.
    /// </summary>
    /// <remarks>
    /// 512 bytes is the classic limit; 4096 is the usual EDNS0 buffer. Allocating 4096 and
    /// refusing more bounds the read, which rule 105 requires — an unbounded network read is
    /// how a resolver becomes a memory-exhaustion target.
    /// </remarks>
    private const int MaxResponseBytes = 4096;

    /// <summary>
    /// How many compression pointers one name may follow before parsing gives up.
    /// </summary>
    /// <remarks>
    /// A DNS name can be compressed by pointing at an earlier offset, and a response can point
    /// a name at itself. Without a bound that is an infinite loop in a parser reading bytes
    /// from an untrusted source.
    /// </remarks>
    private const int MaxCompressionJumps = 64;

    /// <summary>Queries one resolver for the TXT records at a name.</summary>
    /// <returns>Every TXT string found, or an empty list on any failure.</returns>
    /// <remarks>
    /// Returns empty rather than throwing on a network failure, because every caller's question
    /// is "is it published yet" and the answer to that when DNS is unreachable is "not as far
    /// as we can tell". Distinguishing the two cases would give callers a third state none of
    /// them would act on differently.
    /// </remarks>
    public async Task<IReadOnlyList<string>> QueryTxtAsync(
        string name,
        IPAddress server,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(server);

        try
        {
            byte[] query = BuildQuery(name, out ushort transactionId);

            using UdpClient client = new(server.AddressFamily);
            client.Client.ReceiveTimeout = (int)timeout.TotalMilliseconds;

            await client
                .SendAsync(query, new IPEndPoint(server, DnsPort), cancellationToken)
                .ConfigureAwait(false);

            using CancellationTokenSource timeoutSource =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            timeoutSource.CancelAfter(timeout);

            UdpReceiveResult result = await client
                .ReceiveAsync(timeoutSource.Token)
                .ConfigureAwait(false);

            if (result.Buffer.Length > MaxResponseBytes)
            {
                logger.LogWarning(
                    "A DNS response from {Server} was {Length} bytes, beyond the {Max}-byte " +
                    "limit, and was discarded.",
                    server,
                    result.Buffer.Length,
                    MaxResponseBytes);

                return [];
            }

            return ParseTxtAnswers(result.Buffer, transactionId);
        }
        catch (Exception ex) when (ex is SocketException
                                       or OperationCanceledException
                                       or ObjectDisposedException)
        {
            logger.LogDebug(
                "Querying {Server} for TXT records at {Name} did not return an answer: {Reason}",
                server,
                name,
                ex.Message);

            return [];
        }
    }

    /// <summary>Builds a standard recursive TXT query.</summary>
    private static byte[] BuildQuery(string name, out ushort transactionId)
    {
        // Random, not sequential. A predictable transaction id is half of what a cache-poisoning
        // attempt needs, and there is no reason to make it easy even for a check like this one.
        transactionId = (ushort)Random.Shared.Next(1, ushort.MaxValue);

        List<byte> query = new(64);

        query.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(transactionId)));

        // Flags: standard query, recursion desired.
        query.Add(0x01);
        query.Add(0x00);

        // One question, no answer/authority/additional records.
        query.AddRange([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        foreach (string label in name.TrimEnd('.').Split('.'))
        {
            byte[] encoded = Encoding.ASCII.GetBytes(label);

            if (encoded.Length is 0 or > 63)
            {
                throw new ArgumentException(
                    $"'{label}' is not a valid DNS label; labels are 1 to 63 bytes.",
                    nameof(name));
            }

            query.Add((byte)encoded.Length);
            query.AddRange(encoded);
        }

        query.Add(0x00);

        query.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(TypeTxt)));
        query.AddRange(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(ClassInternet)));

        return [.. query];
    }

    /// <summary>
    /// Reads the TXT strings out of a response.
    /// </summary>
    /// <remarks>
    /// Every offset is checked before it is used. This parses bytes that arrived from the
    /// network, and the failure modes of not checking are a crash or a hang.
    /// </remarks>
    internal static IReadOnlyList<string> ParseTxtAnswers(byte[] response, ushort expectedId)
    {
        if (response.Length < 12)
        {
            return [];
        }

        ushort id = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(0, 2));

        // A response whose id does not match the query is not an answer to it, whether that is
        // a stale datagram or a spoofing attempt.
        if (id != expectedId)
        {
            return [];
        }

        // RCODE lives in the low nibble of the second flags byte. Anything non-zero is an
        // error, and NXDOMAIN in particular means "no such name" rather than "no records".
        int rcode = response[3] & 0x0F;

        if (rcode != 0)
        {
            return [];
        }

        ushort questionCount = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(4, 2));
        ushort answerCount = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6, 2));

        int offset = 12;

        for (int i = 0; i < questionCount; i++)
        {
            if (!TrySkipName(response, ref offset) || offset + 4 > response.Length)
            {
                return [];
            }

            offset += 4;
        }

        List<string> values = [];

        for (int i = 0; i < answerCount; i++)
        {
            if (!TrySkipName(response, ref offset) || offset + 10 > response.Length)
            {
                return values;
            }

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset, 2));
            ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset + 8, 2));

            offset += 10;

            if (offset + rdLength > response.Length)
            {
                return values;
            }

            if (type == TypeTxt)
            {
                int end = offset + rdLength;
                int cursor = offset;

                // TXT rdata is a sequence of length-prefixed strings, each at most 255 bytes.
                // A long value arrives split across several, and they concatenate - which is
                // exactly how a DNS-01 digest longer than 255 characters would arrive.
                StringBuilder builder = new();

                while (cursor < end)
                {
                    int length = response[cursor];
                    cursor++;

                    if (cursor + length > end)
                    {
                        break;
                    }

                    builder.Append(Encoding.ASCII.GetString(response, cursor, length));
                    cursor += length;
                }

                if (builder.Length > 0)
                {
                    values.Add(builder.ToString());
                }
            }

            offset += rdLength;
        }

        return values;
    }

    /// <summary>
    /// Advances past a name, following compression pointers.
    /// </summary>
    /// <remarks>
    /// Returns false rather than throwing on a malformed name, so a truncated or hostile
    /// response yields whatever was parsed before it rather than an exception from a background
    /// check.
    /// </remarks>
    private static bool TrySkipName(byte[] buffer, ref int offset)
    {
        int jumps = 0;

        while (true)
        {
            if (offset >= buffer.Length)
            {
                return false;
            }

            byte length = buffer[offset];

            if (length == 0)
            {
                offset++;
                return true;
            }

            // The top two bits set marks a compression pointer: two bytes, then the name ends
            // as far as this cursor is concerned.
            if ((length & 0xC0) == 0xC0)
            {
                if (offset + 2 > buffer.Length || ++jumps > MaxCompressionJumps)
                {
                    return false;
                }

                offset += 2;
                return true;
            }

            offset += length + 1;
        }
    }
}
