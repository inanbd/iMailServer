using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Smtp;

/// <summary>Everything one connection needs that does not come from the socket.</summary>
/// <param name="Role">Fixed by the listener the peer reached.</param>
/// <param name="Processor">Command options for this listener.</param>
/// <param name="MaxLineOctets">Longest command line accepted.</param>
/// <param name="CommandTimeout">Longest wait for one command. Bounds slowloris.</param>
/// <param name="SessionTimeout">Longest a connection may live.</param>
/// <param name="CertificatePurpose">Which certificate this listener presents.</param>
public sealed record SmtpConnectionOptions(
    SmtpListenerRole Role,
    SmtpProcessorOptions Processor,
    int MaxLineOctets,
    TimeSpan CommandTimeout,
    TimeSpan SessionTimeout,
    CertificatePurpose CertificatePurpose);

/// <summary>
/// Drives one SMTP connection from banner to close.
/// </summary>
/// <remarks>
/// <para>
/// The handler owns the socket, the reader and the TLS upgrade; the decisions belong to
/// <see cref="SmtpCommandProcessor"/>, which never sees a stream. That split is why the entire
/// command surface is testable without a network, and why this class can be read for the one
/// thing it is uniquely responsible for: the STARTTLS upgrade.
/// </para>
/// <para>
/// <b>The STARTTLS upgrade is the highest-risk sequence in the product.</b> Three things must
/// happen in this order and no other: the 220 is written and flushed; the reader's buffered
/// input is discarded and a non-empty discard is treated as an attack; the handshake runs and
/// the session state is reset. Getting the order wrong deadlocks the connection; skipping the
/// discard is the command-injection bug of CVE-2011-0411 and its relatives.
/// </para>
/// </remarks>
public sealed class SmtpConnectionHandler(
    ISmtpDirectory directory,
    ITlsCertificateProvider certificates,
    ILocalDeliveryService delivery,
    SmtpDataReceiver receiver,
    RelayPolicy relayPolicy,
    ILogger<SmtpConnectionHandler> logger)
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
        SmtpConnectionOptions options,
        DateTimeOffset startedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(remoteAddress);
        ArgumentNullException.ThrowIfNull(options);

        bool implicitTls = options.Role == SmtpListenerRole.ImplicitTlsSubmission;

        Stream stream = transport;
        SslStream? tls = null;

        try
        {
            if (implicitTls)
            {
                // Port 465: the handshake precedes the banner, so there is no plaintext phase
                // and nothing for a STARTTLS injection to inject into.
                tls = await UpgradeAsync(transport, options, cancellationToken).ConfigureAwait(false);

                if (tls is null)
                {
                    return;
                }

                stream = tls;
            }

            SmtpSessionContext session = new(options.Role, remoteAddress, startedAt, implicitTls);

            SmtpCommandProcessor processor = new(
                session,
                options.Processor,
                directory,
                relayPolicy,
                logger);

            SmtpLineReader reader = new(stream, options.MaxLineOctets);

            // The session deadline is separate from the per-command timeout. Without it a peer
            // that sends NOOP just inside the command timeout holds a connection for ever.
            using CancellationTokenSource sessionCts =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            sessionCts.CancelAfter(options.SessionTimeout);

            await WriteAsync(stream, processor.Banner(), sessionCts.Token).ConfigureAwait(false);

            await RunCommandLoopAsync(
                stream,
                reader,
                processor,
                options,
                sessionCts.Token,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutdown or the session deadline. Either way the peer gets nothing further; a
            // sender treats a dropped connection as a temporary failure and retries.
            logger.LogDebug("SMTP session from {RemoteAddress} ended by cancellation.", remoteAddress.Value);
        }
        catch (Exception ex) when (ex is IOException or AuthenticationException)
        {
            logger.LogDebug(ex, "SMTP session from {RemoteAddress} ended: {Reason}", remoteAddress.Value, ex.Message);
        }
        catch (Exception ex)
        {
            // One poisoned session must never take the listener with it.
            logger.LogError(ex, "SMTP session from {RemoteAddress} failed.", remoteAddress.Value);
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
        SmtpLineReader reader,
        SmtpCommandProcessor processor,
        SmtpConnectionOptions options,
        CancellationToken sessionToken,
        CancellationToken shutdownToken)
    {
        while (true)
        {
            SmtpLineResult line = await reader
                .ReadLineAsync(options.CommandTimeout, sessionToken)
                .ConfigureAwait(false);

            switch (line.Status)
            {
                case SmtpLineStatus.EndOfStream:
                    return;

                case SmtpLineStatus.Timeout:
                    await WriteAsync(stream, SmtpReplies.Timeout(), sessionToken).ConfigureAwait(false);
                    return;

                case SmtpLineStatus.LineTooLong:
                    // The reader has latched; it will not resynchronise, because the tail of an
                    // over-long line is attacker-chosen text that would parse as a command.
                    await WriteAsync(
                        stream,
                        SmtpReplies.LineTooLong(reader.MaxLineOctets),
                        sessionToken).ConfigureAwait(false);

                    return;
            }

            SmtpCommandResult result = await processor
                .ExecuteAsync(SmtpCommand.Parse(line.Text), sessionToken)
                .ConfigureAwait(false);

            await WriteAsync(stream, result.Reply, sessionToken).ConfigureAwait(false);

            switch (result.Action)
            {
                case SmtpSessionAction.CloseAfterReply:
                    return;

                case SmtpSessionAction.StartTlsHandshake:
                    // Returns a new stream and a new reader, because the old ones are exactly
                    // what must not survive.
                    (Stream? upgraded, SmtpLineReader? newReader) = await PerformStartTlsAsync(
                        stream,
                        reader,
                        processor,
                        options,
                        sessionToken).ConfigureAwait(false);

                    if (upgraded is null || newReader is null)
                    {
                        return;
                    }

                    stream = upgraded;
                    reader = newReader;
                    continue;

                case SmtpSessionAction.ReceiveMessageData:
                    if (!await ReceiveMessageAsync(stream, reader, processor, options, shutdownToken)
                        .ConfigureAwait(false))
                    {
                        return;
                    }

                    continue;
            }
        }
    }

    /// <summary>
    /// Upgrades the connection to TLS and forgets everything that came before it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 3207 §4: after the handshake the server MUST discard all knowledge obtained from the
    /// client that was not transmitted inside the TLS negotiation itself. Two things carry that
    /// knowledge — the session state and the reader's buffer — and both are dropped here.
    /// </para>
    /// <para>
    /// <b>Buffered input is treated as an attack, not as noise.</b> No legitimate client pipelines
    /// across STARTTLS: the RFC forbids it precisely because the octets would be executed inside
    /// the tunnel with the authority the real client later establishes. Discarding them silently
    /// would be correct and invisible; this refuses the connection and says so, because a peer
    /// doing it is either broken in a way its operator needs to know about or attacking.
    /// </para>
    /// </remarks>
    private async Task<(Stream? Stream, SmtpLineReader? Reader)> PerformStartTlsAsync(
        Stream stream,
        SmtpLineReader reader,
        SmtpCommandProcessor processor,
        SmtpConnectionOptions options,
        CancellationToken cancellationToken)
    {
        // The 220 has already been written and flushed by the caller. It has to be: the client
        // waits for it before starting its handshake, and a 220 still sitting in a buffer behind
        // a TLS record the client cannot yet read deadlocks the connection.
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

        // Session state goes after the handshake succeeds, not before: a failed handshake leaves
        // the session where it was, and the peer may legitimately carry on in the clear.
        processor.Session.CompleteTlsHandshake();

        // A NEW reader over the new stream. Reusing the old one would carry its buffer across
        // the boundary, which is the other half of the bug the discard above addresses.
        return (tls, new SmtpLineReader(tls, options.MaxLineOctets));
    }

    private async Task<SslStream?> UpgradeAsync(
        Stream stream,
        SmtpConnectionOptions options,
        CancellationToken cancellationToken)
    {
        X509Certificate2? certificate = certificates.Select(
            hostname: null,
            options.CertificatePurpose);

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

                    // TLS 1.2 is the floor. 1.0 and 1.1 are withdrawn, and a mail server that
                    // still offers them lets an attacker downgrade a session that would
                    // otherwise have been fine.
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,

                    // No client certificate is requested. SMTP peers do not present one, and
                    // asking makes some clients prompt or fail.
                    ClientCertificateRequired = false,

                    // Rule 105: no certificate validation bypass. There is deliberately no
                    // RemoteCertificateValidationCallback here - this is the server side, it
                    // validates nothing, and a callback would be the place someone later added
                    // "return true".
                },
                cancellationToken).ConfigureAwait(false);

            return tls;
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException)
        {
            // A failed handshake is ordinary: an old client, a protocol mismatch, a scanner.
            logger.LogDebug(ex, "TLS handshake failed.");

            await tls.DisposeAsync().ConfigureAwait(false);

            return null;
        }
    }

    /// <summary>Receives a message and delivers it. Returns false when the session must end.</summary>
    private async Task<bool> ReceiveMessageAsync(
        Stream stream,
        SmtpLineReader reader,
        SmtpCommandProcessor processor,
        SmtpConnectionOptions options,
        CancellationToken shutdownToken)
    {
        SmtpSessionContext session = processor.Session;

        string BuildPreamble(StoredMessageId messageId) => ReceivedHeader.Build(new ReceivedHeaderContext(
            session.RemoteAddress,
            session.GreetedName,
            ReverseDnsName: null,
            options.Processor.Hostname,

            // Named only when there is exactly one, so the header does not disclose the other
            // recipients of a message to each of them.
            session.Recipients.Count == 1 ? session.Recipients[0].Address : null,
            ReceivedHeader.DescribeProtocol(
                session.UsedExtendedGreeting,
                session.IsTlsActive,
                session.IsAuthenticated),
            session.IsTlsActive ? DescribeTls(stream) : null,
            messageId,
            DateTimeOffset.UtcNow));

        // Deliberately NOT the session token. docs/SMTP.md: abandoning a delivery mid-DATA risks
        // a duplicate at the sending server, which saw no reply and will retry, so an in-flight
        // message is allowed to finish even as the host shuts down.
        SmtpDataResult result = await receiver.ReceiveAsync(
            reader,
            BuildPreamble,
            options.Processor.MaxMessageSizeBytes,
            options.CommandTimeout,
            shutdownToken).ConfigureAwait(false);

        if (result.Outcome != SmtpDataOutcome.Accepted)
        {
            if (result.Reply is not null)
            {
                await WriteAsync(stream, result.Reply, CancellationToken.None).ConfigureAwait(false);
            }

            session.CompleteMessage();

            return !result.ShouldCloseConnection;
        }

        DeliveryRequest request = new(
            result.Message!,
            session.ReversePath,
            session.Recipients,
            session.RemoteAddress,
            session.GreetedName,
            session.Role,
            session.IsTlsActive,
            session.AuthenticatedMailbox);

        try
        {
            await delivery.DeliverAsync(request, shutdownToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // The content is stored; only the delivery rows failed. A 4xx keeps the message in
            // the sender's queue, and a retry is far better than accepting a message this server
            // cannot account for.
            logger.LogError(
                ex,
                "Delivering message {MessageId} failed; the sender will be asked to retry.",
                result.Message!.Id.Value);

            await WriteAsync(
                stream,
                SmtpReplies.LocalError("the message could not be delivered"),
                CancellationToken.None).ConfigureAwait(false);

            session.CompleteMessage();

            return true;
        }

        await WriteAsync(
            stream,
            SmtpReplies.MessageAccepted(result.Message!.Id.Value.ToString("N")),
            CancellationToken.None).ConfigureAwait(false);

        session.CompleteMessage();

        return true;
    }

    /// <summary>Describes the negotiated TLS for the trace header.</summary>
    /// <remarks>
    /// Cipher suite and version only. Never the certificate's private key material, never a
    /// session ticket, never anything a reader of the stored message could use.
    /// </remarks>
    private static string? DescribeTls(Stream stream) => stream is SslStream tls
        ? $"{tls.SslProtocol} with {tls.NegotiatedCipherSuite}"
        : null;

    private static async Task WriteAsync(Stream stream, SmtpReply reply, CancellationToken cancellationToken)
    {
        byte[] octets = Encoding.UTF8.GetBytes(reply.Format());

        await stream.WriteAsync(octets, cancellationToken).ConfigureAwait(false);

        // Flushed on every reply. SMTP is lock-step: the peer will not send its next command
        // until it has read this one, so a reply left in a buffer is a deadlock, not a delay.
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
