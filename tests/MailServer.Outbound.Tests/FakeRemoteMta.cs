using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MailServer.Outbound.Tests;

/// <summary>What the fake server says at each step of one conversation.</summary>
internal sealed class FakeMtaScript
{
    public bool OfferStartTls { get; init; } = true;

    public string MailFromReply { get; init; } = "250 2.1.0 OK";

    public string RcptToReply { get; init; } = "250 2.1.5 OK";

    public string DataReply { get; init; } = "250 2.0.0 Queued as ABC123";

    public static FakeMtaScript AcceptEverything() => new();

    public static FakeMtaScript RejectRecipient(string reply) => new() { RcptToReply = reply };

    public static FakeMtaScript RejectAtData(string reply) => new() { DataReply = reply };

    public static FakeMtaScript WithoutStartTls() => new() { OfferStartTls = false };
}

/// <summary>
/// A minimal SMTP server, playing the remote MX so <see cref="OutboundSmtpClient"/> can be
/// driven end to end over a real loopback socket.
/// </summary>
/// <remarks>
/// Deliberately simple: one connection at a time, one script per connection, and the DATA
/// reader looks only for a line that is exactly <c>.</c> rather than implementing RFC 5321
/// dot-unstuffing - the tests that use it choose message bodies with no line starting with a
/// dot, so nothing here needs to undo the client's stuffing to read the body back correctly.
/// </remarks>
internal sealed class FakeRemoteMta : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;
    private readonly X509Certificate2 _certificate;

    public FakeRemoteMta()
    {
        _certificate = CreateSelfSignedCertificate();

        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    public int Port { get; }

    public FakeMtaScript Script { get; set; } = FakeMtaScript.AcceptEverything();

    public List<string> ReceivedCommands { get; } = [];

    public string? ReceivedBody { get; private set; }

    public bool TlsWasNegotiated { get; private set; }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                using TcpClient client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
                await HandleConnectionAsync(client).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
        {
            // Shutdown. Nothing to report.
        }
    }

    private async Task HandleConnectionAsync(TcpClient client)
    {
        Stream stream = client.GetStream();

        try
        {
            await WriteLineAsync(stream, "220 fake-mx.example.test ESMTP ready");

            while (true)
            {
                string? line = await ReadLineAsync(stream).ConfigureAwait(false);

                if (line is null)
                {
                    return;
                }

                ReceivedCommands.Add(line);
                string verb = line.Split(' ', 2)[0].ToUpperInvariant();

                switch (verb)
                {
                    case "EHLO":
                    case "HELO":
                        await WriteLineAsync(stream, "250-fake-mx.example.test greets you").ConfigureAwait(false);

                        if (Script.OfferStartTls && !TlsWasNegotiated)
                        {
                            await WriteLineAsync(stream, "250-STARTTLS").ConfigureAwait(false);
                        }

                        await WriteLineAsync(stream, "250 8BITMIME").ConfigureAwait(false);
                        break;

                    case "STARTTLS":
                        await WriteLineAsync(stream, "220 2.0.0 Ready to start TLS").ConfigureAwait(false);

                        SslStream tls = new(stream, leaveInnerStreamOpen: false);

                        await tls.AuthenticateAsServerAsync(
                            new SslServerAuthenticationOptions
                            {
                                ServerCertificate = _certificate,
                                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                                ClientCertificateRequired = false,
                            },
                            CancellationToken.None).ConfigureAwait(false);

                        stream = tls;
                        TlsWasNegotiated = true;
                        break;

                    case "MAIL":
                        await WriteLineAsync(stream, Script.MailFromReply).ConfigureAwait(false);
                        break;

                    case "RCPT":
                        await WriteLineAsync(stream, Script.RcptToReply).ConfigureAwait(false);
                        break;

                    case "DATA":
                        await WriteLineAsync(stream, "354 Start mail input; end with <CRLF>.<CRLF>")
                            .ConfigureAwait(false);

                        ReceivedBody = await ReadDataAsync(stream).ConfigureAwait(false);

                        await WriteLineAsync(stream, Script.DataReply).ConfigureAwait(false);
                        break;

                    case "QUIT":
                        await WriteLineAsync(stream, "221 2.0.0 closing connection").ConfigureAwait(false);
                        return;

                    default:
                        await WriteLineAsync(stream, "502 5.5.1 command not implemented").ConfigureAwait(false);
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException)
        {
            // The client hung up or a deliberately-broken-TLS test closed early; nothing to
            // report, the test asserts on the client's own observed result.
        }
    }

    private static async Task<string?> ReadLineAsync(Stream stream)
    {
        List<byte> buffer = [];
        byte[] one = new byte[1];
        byte previous = 0;

        while (true)
        {
            int read = await stream.ReadAsync(one, CancellationToken.None).ConfigureAwait(false);

            if (read == 0)
            {
                return buffer.Count == 0 ? null : Encoding.UTF8.GetString([.. buffer]);
            }

            if (previous == (byte)'\r' && one[0] == (byte)'\n')
            {
                buffer.RemoveAt(buffer.Count - 1);
                return Encoding.UTF8.GetString([.. buffer]);
            }

            buffer.Add(one[0]);
            previous = one[0];
        }
    }

    private static async Task<string> ReadDataAsync(Stream stream)
    {
        List<string> lines = [];

        while (true)
        {
            string? line = await ReadLineAsync(stream).ConfigureAwait(false);

            if (line is null || line == ".")
            {
                break;
            }

            lines.Add(line);
        }

        return string.Join("\r\n", lines);
    }

    private static async Task WriteLineAsync(Stream stream, string line)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(line + "\r\n");
        await stream.WriteAsync(bytes, CancellationToken.None).ConfigureAwait(false);
        await stream.FlushAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private static X509Certificate2 CreateSelfSignedCertificate()
    {
        using RSA key = RSA.Create(2048);

        CertificateRequest request = new(
            "CN=fake-mx.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder sans = new();
        sans.AddDnsName("fake-mx.example.test");
        request.CertificateExtensions.Add(sans.Build());

        using X509Certificate2 generated = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        // Round-tripped through PKCS#12 so the private key is usable by SslStream on every
        // platform - a certificate created in memory is not always bound to its key otherwise.
        return X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pkcs12), password: null);
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        _listener.Stop();

        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best-effort shutdown.
        }

        _certificate.Dispose();
        _cts.Dispose();
    }
}
