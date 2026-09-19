using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Pop3;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Imap;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Pop3;

/// <summary>Everything one POP3 connection needs that does not come from the socket.</summary>
/// <param name="Role">Fixed by the listener the peer reached.</param>
/// <param name="Processor">Command options for this listener.</param>
/// <param name="MaxLineOctets">
/// Longest command line accepted. RFC 2449 §4 makes 255 a floor for a server implementing
/// <c>CAPA</c>: "Servers which support the CAPA command MUST support commands up to 255 octets."
/// </param>
/// <param name="PreAuthenticationTimeout">
/// Longest the connection may sit idle before it has authenticated. Bounds slowloris.
/// </param>
/// <param name="InactivityTimeout">
/// Longest an authenticated connection may sit idle. RFC 1939 §3: "A POP3 server MAY have an
/// inactivity autologout timer. Such a timer MUST be of at least 10 minutes' duration."
/// </param>
/// <param name="CertificatePurpose">Which certificate this listener presents.</param>
public sealed record Pop3ConnectionOptions(
    Pop3ListenerRole Role,
    Pop3ProcessorOptions Processor,
    int MaxLineOctets,
    TimeSpan PreAuthenticationTimeout,
    TimeSpan InactivityTimeout,
    CertificatePurpose CertificatePurpose);

/// <summary>
/// Drives one POP3 connection from greeting to close.
/// </summary>
/// <remarks>
/// <para>
/// The same split <see cref="ImapConnectionHandler"/> makes: this owns the socket, the reader and
/// the TLS upgrade, and <see cref="Pop3CommandProcessor"/> owns the decisions and never sees a
/// stream.
/// </para>
/// <para>
/// <b>An abandoned connection removes nothing.</b> RFC 1939 §6: "If a session terminates for some
/// reason other than a client-issued QUIT command, the POP3 session does NOT enter the UPDATE
/// state and MUST not remove any messages from the maildrop." Every exit path here except the one
/// through <c>QUIT</c> simply drops the session, and the deletions live in memory, so honouring
/// that MUST costs nothing and cannot be forgotten.
/// </para>
/// <para>
/// <b>The autologout is silent.</b> §3: "When the timer expires, the session does NOT enter the
/// UPDATE state--the server should close the TCP connection without removing any messages or
/// sending any response to the client." Unlike IMAP, which has an untagged <c>BYE</c> for this,
/// POP3 asks for no response at all.
/// </para>
/// </remarks>
public sealed class Pop3ConnectionHandler(
    ITlsCertificateProvider certificates,
    IMailboxAuthenticator authenticator,
    IImapMailboxReader mailboxes,
    IImapMailboxWriter writer,
    IMessageStore messageStore,
    IPop3MaildropLocks locks,
    ILogger<Pop3ConnectionHandler> logger)
{
    /// <summary>Serves one connection to its end.</summary>
    /// <param name="transport">The accepted socket's stream.</param>
    /// <param name="remoteAddress">The peer, from the transport.</param>
    /// <param name="options">This listener's options.</param>
    /// <param name="startedAt">When the connection was accepted.</param>
    /// <param name="cancellationToken">Host shutdown.</param>
    public async Task HandleAsync(
        Stream transport,
        IpAddressValue remoteAddress,
        Pop3ConnectionOptions options,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(remoteAddress);
        ArgumentNullException.ThrowIfNull(options);

        bool implicitTls = options.Role == Pop3ListenerRole.ImplicitTls;

        Stream stream = transport;
        SslStream? tls = null;
        Pop3CommandProcessor? processor = null;

        try
        {
            if (implicitTls)
            {
                // Port 995: RFC 8314 §3.1 has the handshake begin immediately, so there is no
                // cleartext phase for a stripping attacker to interfere with.
                tls = await UpgradeAsync(stream, options, cancellationToken).ConfigureAwait(false);

                if (tls is null)
                {
                    return;
                }

                stream = tls;
            }

            Pop3SessionContext session = new(remoteAddress, startedAt, implicitTls);

            processor = new Pop3CommandProcessor(
                session,
                options.Processor,
                logger,
                authenticator,
                mailboxes,
                writer,
                messageStore,
                locks);

            ImapLineReader reader = new(stream, options.MaxLineOctets);

            await WriteAsync(stream, processor.Greeting(), cancellationToken).ConfigureAwait(false);

            await RunCommandLoopAsync(stream, reader, processor, options, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            logger.LogDebug("POP3 session from {RemoteAddress} ended by cancellation.", remoteAddress.Value);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException)
        {
            logger.LogDebug(
                ex,
                "POP3 session from {RemoteAddress} ended: {Reason}",
                remoteAddress.Value,
                ex.Message);
        }
        catch (Exception ex)
        {
            // One poisoned session must never take the listener with it.
            logger.LogError(ex, "POP3 session from {RemoteAddress} failed.", remoteAddress.Value);
        }
        finally
        {
            // Every exit path, not only the tidy one. A maildrop left locked by a dropped
            // connection would refuse the user's next attempt until the process restarted.
            processor?.ReleaseMaildrop();

            if (tls is not null)
            {
                await tls.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task RunCommandLoopAsync(
        Stream stream,
        ImapLineReader reader,
        Pop3CommandProcessor processor,
        Pop3ConnectionOptions options,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            // Recomputed each iteration, which is what makes it an inactivity timer rather than
            // a deadline. RFC 1939 §3: "The receipt of any command from the client during that
            // interval should suffice to reset the autologout timer."
            TimeSpan timeout = CurrentTimeout(processor.Session, options);

            ImapLineResult line = await reader
                .ReadLineAsync(timeout, cancellationToken)
                .ConfigureAwait(false);

            switch (line.Status)
            {
                case ImapLineStatus.EndOfStream:
                    return;

                case ImapLineStatus.Timeout:
                    // §3 asks for silence here, not a farewell: "the server should close the TCP
                    // connection without removing any messages or sending any response to the
                    // client."
                    return;

                case ImapLineStatus.LineTooLong:
                    // The reader has latched and will not resynchronise: the tail of an over-long
                    // line is attacker-chosen text that would parse as a fresh command. §3's
                    // negative status indicator goes out and the connection ends.
                    await WriteAsync(
                        stream,
                        Pop3Response.Error("Command line too long"),
                        cancellationToken).ConfigureAwait(false);

                    return;
            }

            Pop3CommandResult result = Pop3Command.TryParse(line.Text, out Pop3Command? command)
                ? await processor.ExecuteAsync(command, cancellationToken).ConfigureAwait(false)
                : Pop3CommandProcessor.Malformed();

            await WriteAsync(stream, result.Response, cancellationToken).ConfigureAwait(false);

            switch (result.Action)
            {
                case Pop3SessionAction.CloseAfterResponse:
                    return;

                case Pop3SessionAction.StartTlsHandshake:
                    (Stream? upgraded, ImapLineReader? replacement) = await PerformStartTlsAsync(
                        stream,
                        reader,
                        processor,
                        options,
                        cancellationToken).ConfigureAwait(false);

                    if (upgraded is null || replacement is null)
                    {
                        return;
                    }

                    stream = upgraded;
                    reader = replacement;
                    continue;
            }
        }
    }

    /// <summary>
    /// Which idle timeout applies right now.
    /// </summary>
    /// <remarks>
    /// The short one until the client has authenticated and the long one afterwards. The boundary
    /// is the session's own state rather than a flag this handler keeps, so the two cannot
    /// disagree.
    /// </remarks>
    private static TimeSpan CurrentTimeout(Pop3SessionContext session, Pop3ConnectionOptions options) =>
        session.State == Pop3SessionState.Authorization
            ? options.PreAuthenticationTimeout
            : options.InactivityTimeout;

    /// <summary>
    /// Upgrades the connection to TLS and forgets everything that came before it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 2595 §4: "Once TLS has been started, the client MUST discard cached information about
    /// server capabilities and SHOULD re-issue the CAPA command. This is necessary to protect
    /// against man-in-the-middle attacks which alter the capabilities list prior to STLS." The
    /// server's side of the same problem is its own two carriers of pre-TLS knowledge — the
    /// session's pending user name and the reader's buffer — and both are dropped here.
    /// </para>
    /// <para>
    /// <b>Buffered input is treated as an attack, not as noise.</b> §4 forbids it outright: "Once
    /// a client issues a STLS command, it MUST NOT issue further commands until a server response
    /// is seen and the TLS negotiation is complete." Those octets would otherwise be executed
    /// inside the tunnel with the authority the real client goes on to establish, which is the
    /// command-injection pattern of CVE-2011-0411.
    /// </para>
    /// </remarks>
    private async Task<(Stream? Stream, ImapLineReader? Reader)> PerformStartTlsAsync(
        Stream stream,
        ImapLineReader reader,
        Pop3CommandProcessor processor,
        Pop3ConnectionOptions options,
        CancellationToken cancellationToken)
    {
        // The +OK has already been written and flushed by the caller. It has to be: §4 has the
        // negotiation begin "immediately after the CRLF at the end of the +OK response", and a
        // reply still sitting in a buffer behind a TLS record deadlocks the connection.
        int pipelined = reader.DiscardBufferedInput();

        if (pipelined > 0)
        {
            logger.LogWarning(
                "Peer {RemoteAddress} sent {Octets} octets after STLS and before the handshake; " +
                "the connection is being closed. This is the STARTTLS command-injection pattern.",
                processor.Session.RemoteAddress.Value,
                pipelined);

            return (null, null);
        }

        SslStream? tls = await UpgradeAsync(stream, options, cancellationToken).ConfigureAwait(false);

        if (tls is null)
        {
            return (null, null);
        }

        // After the handshake succeeds, never before: a failed handshake leaves the session where
        // it was, and the peer may legitimately carry on in the clear.
        processor.Session.ActivateTls();

        // A NEW reader over the new stream. Reusing the old one would carry its buffer across the
        // boundary, which is the other half of the bug the discard above addresses.
        return (tls, new ImapLineReader(tls, options.MaxLineOctets));
    }

    private async Task<SslStream?> UpgradeAsync(
        Stream stream,
        Pop3ConnectionOptions options,
        CancellationToken cancellationToken)
    {
        X509Certificate2? certificate = certificates.Select(hostname: null, options.CertificatePurpose);

        if (certificate is null)
        {
            logger.LogError(
                "No certificate is configured for {Purpose}; the TLS handshake cannot proceed.",
                options.CertificatePurpose);

            return null;
        }

        SslStream tls = new(stream, leaveInnerStreamOpen: true);

        try
        {
            await tls.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,

                    // TLS 1.2 is the floor. 1.0 and 1.1 are withdrawn, and on port 995 the whole
                    // session - the password and every message read - is inside this tunnel.
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,

                    // No client certificate is requested. Mail clients do not present one, and
                    // asking makes some of them prompt or fail.
                    ClientCertificateRequired = false,
                },
                cancellationToken).ConfigureAwait(false);

            return tls;
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException)
        {
            // An ordinary event: a client with no shared cipher, a probe, a port scan. Logged at
            // Debug so a scan does not fill an operator's log.
            logger.LogDebug(ex, "POP3 TLS handshake failed: {Reason}", ex.Message);

            await tls.DisposeAsync().ConfigureAwait(false);

            return null;
        }
    }

    /// <summary>
    /// Writes one response — status line, body if there is one — and flushes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Pop3Response.Format"/> is the only thing that turns a status line into octets,
    /// so it is the only place the sanitisation that keeps a client's bytes out of the response
    /// stream has to hold. Nothing here composes text.
    /// </para>
    /// <para>
    /// <b>A message's octets are written as they are.</b> They have already been byte-stuffed and
    /// terminated by <see cref="Pop3DotStuffing.Frame"/>; encoding them would corrupt every
    /// message that is not ASCII, and re-stuffing them would corrupt every line that begins with
    /// a full stop.
    /// </para>
    /// </remarks>
    private static async Task WriteAsync(
        Stream stream,
        Pop3Response response,
        CancellationToken cancellationToken)
    {
        StringBuilder builder = new(response.Format());

        if (response.Lines is { } lines)
        {
            foreach (string line in lines)
            {
                // §3's byte-stuffing applies to every line of every multi-line response, not
                // only to a message's: a capability or a scan listing that began with a full
                // stop would end the response early.
                if (line.StartsWith('.'))
                {
                    builder.Append('.');
                }

                builder.Append(line).Append("\r\n");
            }

            builder.Append(".\r\n");
        }

        await stream
            .WriteAsync(Encoding.ASCII.GetBytes(builder.ToString()), cancellationToken)
            .ConfigureAwait(false);

        if (response.Octets is { } octets)
        {
            await stream.WriteAsync(octets, cancellationToken).ConfigureAwait(false);
        }

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
