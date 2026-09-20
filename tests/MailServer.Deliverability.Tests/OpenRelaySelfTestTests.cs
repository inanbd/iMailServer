using System.Net;
using System.Net.Sockets;
using System.Text;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// A listener that reads one line at a time and answers from a script.
/// </summary>
/// <remarks>
/// A real socket rather than a stream fake, because what is being tested is a conversation: the
/// multiline EHLO answer, the order of the commands, and that <c>DATA</c> is never sent. None of
/// that is observable without something on the other end reading lines.
/// </remarks>
internal sealed class ScriptedSmtpListener : IDisposable
{
    private readonly TcpListener _listener;
    private readonly Func<string, string?> _answer;
    private readonly CancellationTokenSource _stopping = new();

    public ScriptedSmtpListener(string greeting, Func<string, string?> answer)
    {
        _answer = answer;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();

        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Accepted = Task.Run(() => ServeAsync(greeting, _stopping.Token));
    }

    public int Port { get; }

    /// <summary>Every command the client sent, in order.</summary>
    public List<string> Received { get; } = [];

    private Task Accepted { get; }

    private async Task ServeAsync(string greeting, CancellationToken cancellationToken)
    {
        try
        {
            using TcpClient client = await _listener.AcceptTcpClientAsync(cancellationToken)
                .ConfigureAwait(false);

            await using NetworkStream stream = client.GetStream();
            using StreamReader reader = new(stream, Encoding.ASCII, false, 1024, leaveOpen: true);

            await WriteAsync(stream, greeting, cancellationToken).ConfigureAwait(false);

            while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
            {
                lock (Received)
                {
                    Received.Add(line);
                }

                if (_answer(line) is { } reply)
                {
                    await WriteAsync(stream, reply, cancellationToken).ConfigureAwait(false);
                }

                if (line.StartsWith("QUIT", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException)
        {
            // The client hung up, or the test finished. Neither is a failure of the listener.
        }
    }

    private static async Task WriteAsync(Stream stream, string text, CancellationToken cancellationToken)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text.Replace("\n", "\r\n", StringComparison.Ordinal));

        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public IReadOnlyList<string> Commands()
    {
        lock (Received)
        {
            return [.. Received];
        }
    }

    public void Dispose()
    {
        _stopping.Cancel();
        _listener.Dispose();
        _stopping.Dispose();
    }
}

public sealed class OpenRelaySelfTestTests
{
    /// <summary>The answers a correctly configured server gives.</summary>
    private static string? Refusing(string command) => command switch
    {
        _ when command.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase) =>
            "250-mail.example.com\n250-SIZE 10240000\n250 STARTTLS\n",
        _ when command.StartsWith("MAIL", StringComparison.OrdinalIgnoreCase) => "250 2.1.0 OK\n",
        _ when command.StartsWith("RCPT", StringComparison.OrdinalIgnoreCase) =>
            "554 5.7.1 Relay access denied\n",
        _ when command.StartsWith("RSET", StringComparison.OrdinalIgnoreCase) => "250 2.0.0 OK\n",
        _ when command.StartsWith("QUIT", StringComparison.OrdinalIgnoreCase) => "221 2.0.0 Bye\n",
        _ => "502 5.5.2 Not recognised\n",
    };

    /// <summary>The answers an open relay gives.</summary>
    private static string? Relaying(string command) =>
        command.StartsWith("RCPT", StringComparison.OrdinalIgnoreCase)
            ? "250 2.1.5 OK\n"
            : Refusing(command);

    private static Task<OpenRelayResult> RunAsync(ScriptedSmtpListener listener) =>
        OpenRelaySelfTest.RunAsync(
            "127.0.0.1",
            listener.Port,
            "probe.example.com",
            CancellationToken.None);

    /// <summary>A server that refuses the outside recipient is not an open relay.</summary>
    [Fact]
    public async Task A_server_that_refuses_the_recipient_is_not_a_relay()
    {
        using ScriptedSmtpListener listener = new("220 mail.example.com ESMTP\n", Refusing);

        OpenRelayResult result = await RunAsync(listener);

        result.Ran.ShouldBeTrue();
        result.Relayed.ShouldBeFalse();
    }

    /// <summary>A server that accepts it is.</summary>
    [Fact]
    public async Task A_server_that_accepts_the_recipient_is_a_relay()
    {
        using ScriptedSmtpListener listener = new("220 mail.example.com ESMTP\n", Relaying);

        OpenRelayResult result = await RunAsync(listener);

        result.Ran.ShouldBeTrue();
        result.Relayed.ShouldBeTrue();
    }

    /// <summary>
    /// The conversation never sends DATA.
    /// </summary>
    /// <remarks>
    /// The answer to <c>RCPT TO</c> is the entire finding. A test that went on to submit a
    /// message would be a test that sends mail — from a server whose whole problem, if the test
    /// fails, is that it sends mail for strangers. It is also the difference between a
    /// diagnostic and an abuse of somebody's inbox if this is ever pointed elsewhere.
    /// </remarks>
    [Fact]
    public async Task The_conversation_never_sends_data()
    {
        using ScriptedSmtpListener listener = new("220 mail.example.com ESMTP\n", Relaying);

        await RunAsync(listener);

        listener.Commands().ShouldNotContain(c => c.StartsWith("DATA", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The transaction is abandoned with RSET before QUIT.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A server that did accept the recipient is not left holding a transaction for the sake of
    /// a diagnostic.
    /// </para>
    /// <para>
    /// This test is only sound because the client waits for the reply to <c>QUIT</c>, per RFC
    /// 5321 §4.1.1.10. Without that it returns with the command still in flight, and asserting
    /// on what the listener has recorded is a race that passes almost every time.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_transaction_is_reset_before_quitting()
    {
        using ScriptedSmtpListener listener = new("220 mail.example.com ESMTP\n", Relaying);

        await RunAsync(listener);

        IReadOnlyList<string> commands = listener.Commands();

        int rset = commands.ToList().FindIndex(c => c.StartsWith("RSET", StringComparison.OrdinalIgnoreCase));
        int quit = commands.ToList().FindIndex(c => c.StartsWith("QUIT", StringComparison.OrdinalIgnoreCase));

        rset.ShouldBeGreaterThan(-1);
        quit.ShouldBeGreaterThan(rset);
    }

    /// <summary>
    /// Both addresses are in RFC 2606's reserved .invalid domain.
    /// </summary>
    /// <remarks>
    /// §2 reserves it for "online construction of domain names that will surely fail". So a
    /// server that accepted the recipient accepted something with nowhere to go, and even a bug
    /// that submitted the message could not deliver it.
    /// </remarks>
    [Fact]
    public async Task Both_addresses_are_in_the_reserved_invalid_domain()
    {
        using ScriptedSmtpListener listener = new("220 mail.example.com ESMTP\n", Relaying);

        await RunAsync(listener);

        IReadOnlyList<string> commands = listener.Commands();

        commands.ShouldContain(c => c.Contains(".invalid>", StringComparison.Ordinal) &&
                                    c.StartsWith("MAIL", StringComparison.OrdinalIgnoreCase));

        commands.ShouldContain(c => c.Contains(".invalid>", StringComparison.Ordinal) &&
                                    c.StartsWith("RCPT", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A multiline EHLO answer is read whole.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §4.2.1: every line but the last "begin[s] with the reply code, followed
    /// immediately by a hyphen". A reader that stopped at the first line would leave the rest in
    /// the buffer and read "250 STARTTLS" as the answer to MAIL FROM — which happens to start
    /// with a 2, so the test would carry on and misreport the RCPT answer as whatever came next.
    /// </remarks>
    [Fact]
    public async Task A_multiline_ehlo_answer_does_not_desynchronise_the_conversation()
    {
        using ScriptedSmtpListener listener = new(
            "220 mail.example.com ESMTP\n",
            c => c.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase)
                ? "250-mail.example.com\n250-SIZE 10240000\n250-8BITMIME\n250-PIPELINING\n250 STARTTLS\n"
                : Refusing(c));

        OpenRelayResult result = await RunAsync(listener);

        result.Ran.ShouldBeTrue();
        result.Relayed.ShouldBeFalse();
    }

    /// <summary>
    /// A server that refuses the sender has not answered the question.
    /// </summary>
    /// <remarks>
    /// The recipient was never asked about, so "not a relay" would be a conclusion drawn from a
    /// question nobody put. <c>Ran</c> is false and the check reports "not tested".
    /// </remarks>
    [Fact]
    public async Task A_refused_sender_means_the_question_was_never_put()
    {
        using ScriptedSmtpListener listener = new(
            "220 mail.example.com ESMTP\n",
            c => c.StartsWith("MAIL", StringComparison.OrdinalIgnoreCase)
                ? "550 5.7.1 Sender rejected\n"
                : Refusing(c));

        OpenRelayResult result = await RunAsync(listener);

        result.Ran.ShouldBeFalse();
        result.Relayed.ShouldBeFalse();
        listener.Commands().ShouldNotContain(c => c.StartsWith("RCPT", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>A greeting that is not a 220 means there is no conversation to have.</summary>
    [Fact]
    public async Task A_refused_greeting_means_the_test_did_not_run()
    {
        using ScriptedSmtpListener listener = new("554 No service here\n", Refusing);

        OpenRelayResult result = await RunAsync(listener);

        result.Ran.ShouldBeFalse();
        listener.Commands().ShouldBeEmpty();
    }

    /// <summary>
    /// A listener that is not there means the test did not run, not that it passed.
    /// </summary>
    /// <remarks>
    /// The most dangerous false pass in the report: a refused connection says nothing about what
    /// the server does with one it accepts.
    /// </remarks>
    [Fact]
    public async Task An_unreachable_listener_means_the_test_did_not_run()
    {
        // Port 1 on loopback, which nothing listens on.
        OpenRelayResult result = await OpenRelaySelfTest.RunAsync(
            "127.0.0.1",
            1,
            "probe.example.com",
            CancellationToken.None);

        result.Ran.ShouldBeFalse();
        result.Relayed.ShouldBeFalse();
        result.Transcript.ShouldNotBeEmpty();
    }

    /// <summary>
    /// STARTTLS is read out of the same EHLO answer.
    /// </summary>
    /// <remarks>
    /// RFC 3207 §2 gives the keyword; RFC 5321 §4.1.1.1 puts it on its own line of the EHLO
    /// answer. The relay test has to send EHLO to get anywhere, so a separate probe would open a
    /// second connection to learn something this one already has on the wire.
    /// </remarks>
    [Fact]
    public async Task Starttls_is_read_from_the_same_ehlo_answer()
    {
        using ScriptedSmtpListener offering = new("220 mail.example.com ESMTP\n", Refusing);

        (await RunAsync(offering)).StartTlsOffered.ShouldBe(true);

        using ScriptedSmtpListener silent = new(
            "220 mail.example.com ESMTP\n",
            c => c.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase)
                ? "250-mail.example.com\n250 SIZE 10240000\n"
                : Refusing(c));

        (await RunAsync(silent)).StartTlsOffered.ShouldBe(false);
    }

    /// <summary>
    /// A keyword that merely begins with STARTTLS is not STARTTLS.
    /// </summary>
    /// <remarks>
    /// A prefix match would read a hypothetical extension named STARTTLSNG as the real thing and
    /// report a server offering no TLS at all as offering it — a false pass on the one check
    /// MTA-STS's enforce mode turns on.
    /// </remarks>
    [Fact]
    public async Task A_keyword_beginning_with_starttls_is_not_starttls()
    {
        using ScriptedSmtpListener listener = new(
            "220 mail.example.com ESMTP\n",
            c => c.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase)
                ? "250-mail.example.com\n250 STARTTLSNG\n"
                : Refusing(c));

        (await RunAsync(listener)).StartTlsOffered.ShouldBe(false);
    }

    /// <summary>
    /// The greeting line is not one of the extensions.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §4.1.1.1 makes the first line of an EHLO answer the server's greeting, not a
    /// keyword. A server whose hostname happened to be "starttls" would otherwise be read as
    /// offering it.
    /// </remarks>
    [Fact]
    public async Task The_ehlo_greeting_line_is_not_an_extension()
    {
        using ScriptedSmtpListener listener = new(
            "220 mail.example.com ESMTP\n",
            c => c.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase)
                ? "250 STARTTLS\n"
                : Refusing(c));

        (await RunAsync(listener)).StartTlsOffered.ShouldBe(false);
    }

    /// <summary>The transcript records both sides, for the report to show.</summary>
    [Fact]
    public async Task The_transcript_records_both_sides()
    {
        using ScriptedSmtpListener listener = new("220 mail.example.com ESMTP\n", Refusing);

        OpenRelayResult result = await RunAsync(listener);

        result.Transcript.ShouldContain(l => l.StartsWith("C: EHLO", StringComparison.Ordinal));
        result.Transcript.ShouldContain(l => l.StartsWith("S: 220", StringComparison.Ordinal));
        result.Transcript.ShouldContain(l => l.Contains("Relay access denied", StringComparison.Ordinal));
    }
}
