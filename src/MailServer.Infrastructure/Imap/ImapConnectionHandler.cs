using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Imap;

/// <summary>Everything one IMAP connection needs that does not come from the socket.</summary>
/// <param name="Role">Fixed by the listener the peer reached.</param>
/// <param name="Processor">Command options for this listener.</param>
/// <param name="MaxLineOctets">Longest command line accepted.</param>
/// <param name="PreAuthenticationTimeout">
/// Longest the connection may sit idle before it has authenticated. Bounds slowloris.
/// </param>
/// <param name="InactivityTimeout">
/// Longest an authenticated connection may sit idle. RFC 3501 §5.4 requires at least thirty
/// minutes; see <c>LimitsOptions.ImapInactivityTimeoutSeconds</c>.
/// </param>
/// <param name="CertificatePurpose">Which certificate this listener presents.</param>
public sealed record ImapConnectionOptions(
    ImapListenerRole Role,
    ImapProcessorOptions Processor,
    int MaxLineOctets,
    TimeSpan PreAuthenticationTimeout,
    TimeSpan InactivityTimeout,
    CertificatePurpose CertificatePurpose);

/// <summary>
/// Drives one IMAP connection from greeting to close.
/// </summary>
/// <remarks>
/// <para>
/// The handler owns the socket, the reader and the TLS upgrade; the decisions belong to
/// <see cref="ImapCommandProcessor"/>, which never sees a stream. That split is why the whole
/// command surface is testable without a network, and why this class can be read for the two
/// things it is uniquely responsible for: the <c>STARTTLS</c> upgrade and the timeouts.
/// </para>
/// <para>
/// <b>The STARTTLS upgrade is the highest-risk sequence here, exactly as it is for SMTP.</b>
/// Three things happen in this order and no other: the tagged <c>OK</c> is written and flushed;
/// the reader's buffered input is discarded and a non-empty discard is treated as an attack; the
/// handshake runs and only then is the session marked encrypted. Getting the order wrong
/// deadlocks the connection — a client will not begin its handshake until it has read the
/// <c>OK</c> — and skipping the discard is the command-injection pattern of CVE-2011-0411 and
/// its relatives, which RFC 3501 §6.2.1 forbids in the same words RFC 3207 §4 uses for SMTP.
/// </para>
/// <para>
/// <b>The timeouts are where IMAP genuinely differs from SMTP, rather than merely differing in
/// scale.</b> An SMTP connection has both a per-command timeout and an absolute session
/// lifetime, and both are short, because a transaction is short by nature. RFC 3501 §5.4
/// forbids the same shape here: "If a server has an inactivity autologout timer, the duration of
/// that timer MUST be at least 30 minutes. The receipt of ANY command from the client during
/// that interval SHOULD suffice to reset the autologout timer." So this handler has an
/// inactivity timer reset by every command and <b>no session-lifetime cap at all</b> — a cap
/// would drop a client in the middle of a working session, which is the thing §5.4 exists to
/// prevent. The short timer applies only before the client has authenticated, where §5.4's
/// protection does not yet apply and slowloris does.
/// </para>
/// </remarks>
public sealed class ImapConnectionHandler(
    ITlsCertificateProvider certificates,
    IMailboxAuthenticator authenticator,
    IImapMailboxReader mailboxes,
    IImapMailboxWriter writer,
    ILogger<ImapConnectionHandler> logger)
{
    /// <summary>Handles one connection to completion.</summary>
    /// <param name="transport">The accepted socket's stream. Not disposed here; the caller owns it.</param>
    /// <param name="remoteAddress">The peer, from the transport.</param>
    /// <param name="options">Listener configuration.</param>
    /// <param name="startedAt">When the connection was accepted.</param>
    /// <param name="cancellationToken">Host shutdown.</param>
    public async Task HandleAsync(
        Stream transport,
        IpAddressValue remoteAddress,
        ImapConnectionOptions options,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(remoteAddress);
        ArgumentNullException.ThrowIfNull(options);

        bool implicitTls = options.Role == ImapListenerRole.ImplicitTls;

        Stream stream = transport;
        SslStream? tls = null;

        try
        {
            if (implicitTls)
            {
                // Port 993: the handshake precedes the greeting, so there is no cleartext phase
                // and nothing for a STARTTLS injection to inject into. RFC 8314 §3 prefers this
                // for exactly that reason.
                tls = await UpgradeAsync(stream, options, cancellationToken).ConfigureAwait(false);

                if (tls is null)
                {
                    return;
                }

                stream = tls;
            }

            ImapSessionContext session = new(remoteAddress, startedAt, implicitTls);

            ImapCommandProcessor processor =
                new(session, options.Processor, logger, authenticator, mailboxes, writer);

            ImapLineReader reader = new(stream, options.MaxLineOctets);

            await WriteAsync(stream, [processor.Greeting()], cancellationToken).ConfigureAwait(false);

            await RunCommandLoopAsync(stream, reader, processor, options, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutdown. The peer gets nothing further; a client treats a dropped connection as
            // something to reconnect from, and nothing has been acknowledged that was not done.
            logger.LogDebug("IMAP session from {RemoteAddress} ended by cancellation.", remoteAddress.Value);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException)
        {
            logger.LogDebug(
                ex,
                "IMAP session from {RemoteAddress} ended: {Reason}",
                remoteAddress.Value,
                ex.Message);
        }
        catch (Exception ex)
        {
            // One poisoned session must never take the listener with it.
            logger.LogError(ex, "IMAP session from {RemoteAddress} failed.", remoteAddress.Value);
        }
        finally
        {
            if (tls is not null)
            {
                await tls.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task RunCommandLoopAsync(
        Stream stream,
        ImapLineReader reader,
        ImapCommandProcessor processor,
        ImapConnectionOptions options,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            // Recomputed every iteration rather than captured once, which is what makes this an
            // inactivity timer rather than a deadline: RFC 3501 §5.4's "receipt of ANY command
            // ... SHOULD suffice to reset" is satisfied by the read simply starting again.
            TimeSpan timeout = CurrentTimeout(processor.Session, options);

            ImapLineResult line = await reader
                .ReadLineAsync(timeout, cancellationToken)
                .ConfigureAwait(false);

            switch (line.Status)
            {
                case ImapLineStatus.EndOfStream:
                    return;

                case ImapLineStatus.Timeout:
                    // RFC 3501 §7.1.5: the untagged BYE is how a server says it is closing of
                    // its own accord. There is no command in flight to tag it against.
                    await WriteAsync(
                        stream,
                        [ImapResponses.Bye("Autologout; idle for too long")],
                        cancellationToken).ConfigureAwait(false);

                    return;

                case ImapLineStatus.LineTooLong:
                    // RFC 2683 §3.2.1.5 asks for a BAD, and it must be untagged: the tag is
                    // somewhere in the text that was discarded, so the command cannot be
                    // determined - RFC 3501 §7.1.3's case exactly. The reader has latched and
                    // will not resynchronise, because the tail of an over-long line is
                    // attacker-chosen text that would parse as a fresh command, so the
                    // connection ends here.
                    await WriteAsync(
                        stream,
                        [
                            ImapResponses.UntaggedBad("Command line too long"),
                            ImapResponses.Bye("Command line too long"),
                        ],
                        cancellationToken).ConfigureAwait(false);

                    return;
            }

            ImapCommandResult result = ImapCommand.TryParse(
                line.Text,
                out ImapCommand? command,
                out ImapTagFailure failure)
                ? await processor.ExecuteAsync(command, cancellationToken).ConfigureAwait(false)
                : processor.MalformedLine(failure);

            await WriteAsync(stream, result.Responses, cancellationToken).ConfigureAwait(false);

            switch (result.Action)
            {
                case ImapSessionAction.CloseAfterResponse:
                    return;

                case ImapSessionAction.StartTlsHandshake:
                    // Returns a new stream and a new reader, because the old ones are exactly
                    // what must not survive the upgrade.
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

                case ImapSessionAction.ReadAuthenticationResponse:
                    if (!await RunAuthenticationExchangeAsync(
                            stream,
                            reader,
                            processor,
                            options,
                            cancellationToken).ConfigureAwait(false))
                    {
                        return;
                    }

                    continue;
            }
        }
    }

    /// <summary>
    /// Which idle timeout applies right now.
    /// </summary>
    /// <remarks>
    /// The short one until the client has authenticated and the long one afterwards. The
    /// boundary is the session's own state rather than a flag this handler keeps, so the two
    /// cannot disagree.
    /// </remarks>
    private static TimeSpan CurrentTimeout(ImapSessionContext session, ImapConnectionOptions options) =>
        session.State == ImapSessionState.NotAuthenticated
            ? options.PreAuthenticationTimeout
            : options.InactivityTimeout;

    /// <summary>
    /// Runs a SASL exchange to its end, one continuation line at a time.
    /// </summary>
    /// <remarks>
    /// <b>The lines read here are credentials and never reach the command parser.</b> A session
    /// mid-<c>AUTHENTICATE</c> has no command grammar, so a line treated as a command would both
    /// be misparsed and be echoed into the <c>BAD</c> it earned — putting a password into the
    /// response stream and, from there, into any log or capture of it. The exchange therefore
    /// has its own read loop rather than borrowing the ordinary one.
    /// </remarks>
    /// <returns>False when the connection should close.</returns>
    private async Task<bool> RunAuthenticationExchangeAsync(
        Stream stream,
        ImapLineReader reader,
        ImapCommandProcessor processor,
        ImapConnectionOptions options,
        CancellationToken cancellationToken)
    {
        while (processor.IsAuthenticationInFlight)
        {
            ImapLineResult line = await reader
                .ReadLineAsync(CurrentTimeout(processor.Session, options), cancellationToken)
                .ConfigureAwait(false);

            if (!line.IsLine)
            {
                // Abandoned mid-exchange. Nothing is written back: whatever went wrong, the one
                // thing that must not happen is a response quoting the line.
                return false;
            }

            ImapCommandResult result = await processor
                .ContinueAuthenticationAsync(line.Text, cancellationToken)
                .ConfigureAwait(false);

            await WriteAsync(stream, result.Responses, cancellationToken).ConfigureAwait(false);

            if (result.Action == ImapSessionAction.CloseAfterResponse)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Upgrades the connection to TLS and forgets everything that came before it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 3501 §6.2.1 requires the client to "discard cached information about server
    /// capabilities" and to re-issue <c>CAPABILITY</c>, because a machine-in-the-middle may have
    /// altered the listing before the upgrade. The server's side of the same problem is its own
    /// two carriers of pre-TLS knowledge — the session state and the reader's buffer — and both
    /// are dropped here.
    /// </para>
    /// <para>
    /// <b>Buffered input is treated as an attack, not as noise.</b> No legitimate client
    /// pipelines across <c>STARTTLS</c>; the prohibition exists precisely because those octets
    /// would otherwise be executed inside the tunnel with the authority the real client goes on
    /// to establish. Discarding them silently would be correct and invisible. This refuses the
    /// connection and says so, because a peer doing it is either broken in a way its operator
    /// needs to know about or attacking.
    /// </para>
    /// </remarks>
    private async Task<(Stream? Stream, ImapLineReader? Reader)> PerformStartTlsAsync(
        Stream stream,
        ImapLineReader reader,
        ImapCommandProcessor processor,
        ImapConnectionOptions options,
        CancellationToken cancellationToken)
    {
        // The tagged OK has already been written and flushed by the caller. It has to be: the
        // client waits for it before starting its handshake, and an OK still sitting in a buffer
        // behind a TLS record the client cannot yet read deadlocks the connection.
        int pipelined = reader.DiscardBufferedInput();

        if (pipelined > 0)
        {
            logger.LogWarning(
                "Peer {RemoteAddress} sent {Octets} octets after STARTTLS and before the handshake; " +
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

        // After the handshake succeeds, never before: a failed handshake leaves the session
        // where it was, and the peer may legitimately carry on in the clear.
        processor.Session.CompleteTlsHandshake();

        // A NEW reader over the new stream. Reusing the old one would carry its buffer across
        // the boundary, which is the other half of the bug the discard above addresses.
        return (tls, new ImapLineReader(tls, options.MaxLineOctets));
    }

    private async Task<SslStream?> UpgradeAsync(
        Stream stream,
        ImapConnectionOptions options,
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

                    // TLS 1.2 is the floor. 1.0 and 1.1 are withdrawn, and on port 993 the whole
                    // session - credentials and every message read - is inside this tunnel.
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,

                    // No client certificate is requested. Mail clients do not present one, and
                    // asking makes some of them prompt or fail.
                    ClientCertificateRequired = false,

                    // Rule 105: no certificate validation bypass. There is deliberately no
                    // validation callback here - this is the server side of the handshake, it
                    // validates nothing, and a callback would be the place someone later added
                    // "return true" while debugging and never took it out.
                },
                cancellationToken).ConfigureAwait(false);

            return tls;
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException)
        {
            // An ordinary event: a client with no shared cipher, a probe, a port scan. Logged at
            // Debug so a scan does not fill an operator's log.
            logger.LogDebug(ex, "IMAP TLS handshake failed: {Reason}", ex.Message);

            await tls.DisposeAsync().ConfigureAwait(false);

            return null;
        }
    }

    /// <summary>Writes responses and flushes.</summary>
    /// <remarks>
    /// <para>
    /// Every response of a command goes out in one write where it can, and the flush happens
    /// once at the end. A client will not send its next command until it has read the tagged
    /// completion of this one, so a completion left in a buffer is a deadlock rather than a
    /// delay — but the untagged responses ahead of it are part of the same answer, and splitting
    /// the flush between them buys nothing.
    /// </para>
    /// <para>
    /// <see cref="ImapResponse.Format"/> is the only thing that turns a response into octets, so
    /// it is the only place the sanitisation that keeps a client's bytes out of the response
    /// stream has to hold. Nothing here composes text.
    /// </para>
    /// </remarks>
    private static async Task WriteAsync(
        Stream stream,
        IReadOnlyList<ImapResponse> responses,
        CancellationToken cancellationToken)
    {
        StringBuilder builder = new();

        foreach (ImapResponse response in responses)
        {
            builder.Append(response.Format());
        }

        byte[] octets = Encoding.UTF8.GetBytes(builder.ToString());

        await stream.WriteAsync(octets, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
