using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>What the open-relay self-test found.</summary>
/// <param name="Ran">Whether the conversation got far enough to learn anything.</param>
/// <param name="Relayed">Whether the server accepted the outside recipient.</param>
/// <param name="Source">The address the test connected from.</param>
/// <param name="Transcript">The conversation, for the report to show.</param>
public sealed record OpenRelayResult(
    bool Ran,
    bool Relayed,
    string? Source,
    IReadOnlyList<string> Transcript);

/// <summary>
/// Asks this server, over SMTP, whether it will relay for a stranger.
/// </summary>
/// <remarks>
/// <para>
/// <b>The conversation stops at <c>RCPT TO</c> and never reaches <c>DATA</c>.</b> The answer to
/// that one command is the entire finding, and a test that went on to submit a message would be
/// a test that sends mail — from a server whose whole problem, if the test fails, is that it
/// sends mail for strangers.
/// </para>
/// <para>
/// Both addresses use RFC 2606's reserved <c>.invalid</c> top-level domain, which "is intended
/// for use in online construction of domain names that will surely fail". So even a server that
/// accepted the recipient has accepted something with nowhere to go, and even a bug that sent
/// the message could not deliver it.
/// </para>
/// <para>
/// <b>What an acceptance means here is specific to this server.</b> <c>RelayPolicy</c> has no
/// implicit trust for any address: local domains, authenticated submission, and a list an
/// operator typed are the only three ways through. So an acceptance from loopback is not the
/// usual "many servers trust localhost" false positive — it means that address is on the
/// authorised relay list, which the finding says.
/// </para>
/// </remarks>
public sealed class OpenRelaySelfTest
{
    /// <summary>
    /// The sender the test claims to be. RFC 2606 §2 reserves <c>.invalid</c>.
    /// </summary>
    public const string ProbeSender = "deliverability-probe@relay-test.invalid";

    /// <summary>The outside recipient the test asks the server to accept.</summary>
    public const string ProbeRecipient = "deliverability-probe@relay-target.invalid";

    /// <summary>How long the whole conversation may take.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    /// <summary>Runs the test against a listener.</summary>
    /// <param name="host">The host to connect to.</param>
    /// <param name="port">Its SMTP port.</param>
    /// <param name="ehloName">The name to greet with.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public static async Task<OpenRelayResult> RunAsync(
        string host,
        int port,
        string ehloName,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(ehloName);

        List<string> transcript = [];

        try
        {
            using CancellationTokenSource timeout = CancellationTokenSource
                .CreateLinkedTokenSource(cancellationToken);

            timeout.CancelAfter(Timeout);

            using TcpClient tcp = new();

            await tcp.ConnectAsync(host, port, timeout.Token).ConfigureAwait(false);

            string source = (tcp.Client.LocalEndPoint as System.Net.IPEndPoint)?.Address.ToString() ?? host;

            await using NetworkStream stream = tcp.GetStream();
            using StreamReader reader = new(stream, Encoding.ASCII, false, 1024, leaveOpen: true);

            string? greeting = await ReadReplyAsync(reader, transcript, timeout.Token).ConfigureAwait(false);

            if (greeting is null || !greeting.StartsWith("220", StringComparison.Ordinal))
            {
                return new OpenRelayResult(false, false, source, transcript);
            }

            await SendAsync(stream, $"EHLO {ehloName}", transcript, timeout.Token).ConfigureAwait(false);
            await ReadReplyAsync(reader, transcript, timeout.Token).ConfigureAwait(false);

            await SendAsync(stream, $"MAIL FROM:<{ProbeSender}>", transcript, timeout.Token).ConfigureAwait(false);

            string? mail = await ReadReplyAsync(reader, transcript, timeout.Token).ConfigureAwait(false);

            // A server that refuses the sender never gets asked about the recipient, and a test
            // that reported "not a relay" from that would be reporting the wrong thing: the
            // question was never put.
            if (mail is null || !mail.StartsWith('2'))
            {
                await SendAsync(stream, "QUIT", transcript, timeout.Token).ConfigureAwait(false);
                await ReadReplyAsync(reader, transcript, timeout.Token).ConfigureAwait(false);

                return new OpenRelayResult(false, false, source, transcript);
            }

            await SendAsync(stream, $"RCPT TO:<{ProbeRecipient}>", transcript, timeout.Token).ConfigureAwait(false);

            string? rcpt = await ReadReplyAsync(reader, transcript, timeout.Token).ConfigureAwait(false);

            bool relayed = rcpt is not null && rcpt.StartsWith('2');

            // RSET before QUIT: the transaction is abandoned explicitly rather than left for the
            // server to discard, so a server that did accept the recipient is not left holding
            // one.
            await SendAsync(stream, "RSET", transcript, timeout.Token).ConfigureAwait(false);
            await ReadReplyAsync(reader, transcript, timeout.Token).ConfigureAwait(false);
            await SendAsync(stream, "QUIT", transcript, timeout.Token).ConfigureAwait(false);

            // RFC 5321 §4.1.1.10: the receiver "MUST send an OK reply" to QUIT "and then close
            // the transmission channel". Waiting for it means this end closes second, and it
            // completes the transcript the report shows - a conversation that ends mid-command
            // reads like a fault rather than a clean exit.
            await ReadReplyAsync(reader, transcript, timeout.Token).ConfigureAwait(false);

            return new OpenRelayResult(rcpt is not null, relayed, source, transcript);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
        {
            transcript.Add(string.Create(CultureInfo.InvariantCulture, $"[the test could not complete: {ex.Message}]"));

            // Ran: false, so the check reports "not tested" rather than "not a relay". A
            // listener that refused the connection has told us nothing about what it does with
            // one it accepts.
            return new OpenRelayResult(false, false, null, transcript);
        }
    }

    private static async Task SendAsync(
        Stream stream,
        string line,
        List<string> transcript,
        CancellationToken cancellationToken)
    {
        transcript.Add($"C: {line}");

        byte[] bytes = Encoding.ASCII.GetBytes(line + "\r\n");

        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one reply, following RFC 5321 §4.2's multiline form.
    /// </summary>
    /// <remarks>
    /// §4.2.1: "the format for multiline replies requires that every line, except the last,
    /// begin with the reply code, followed immediately by a hyphen[…] The last line begins with
    /// the reply code, followed immediately by &lt;SP&gt;". An EHLO answer is always multiline,
    /// so a reader that took the first line would leave the rest in the buffer and read them as
    /// the answers to everything after.
    /// </remarks>
    private static async Task<string?> ReadReplyAsync(
        StreamReader reader,
        List<string> transcript,
        CancellationToken cancellationToken)
    {
        string? last = null;

        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            transcript.Add($"S: {line}");
            last = line;

            if (line.Length < 4 || line[3] != '-')
            {
                break;
            }
        }

        return last;
    }
}
