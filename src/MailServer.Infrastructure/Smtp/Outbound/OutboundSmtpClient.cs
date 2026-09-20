using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Certificates;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Dkim;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Smtp.Outbound;

/// <summary>
/// Speaks the client side of one SMTP conversation to a remote mail exchanger.
/// </summary>
/// <remarks>
/// <para>
/// The mirror image of <c>SmtpConnectionHandler</c>: where that class answers <c>EHLO</c>,
/// <c>STARTTLS</c>, <c>MAIL FROM</c>, <c>RCPT TO</c> and <c>DATA</c>, this issues them. Reused
/// from the domain layer: <see cref="SmtpReply"/>'s 2xx/4xx/5xx classification (the receiving
/// half of what <see cref="SmtpReplyParser"/> constructs), and <see cref="SmtpDotStuffing"/>'s
/// outgoing dot-stuffing (the sending half of what <c>SmtpDataDecoder</c> undoes on receipt).
/// </para>
/// <para>
/// <b>Outbound TLS policy</b> (<c>docs/TLS.md</c>): opportunistic by default - encrypt when the
/// remote offers STARTTLS, proceed in plaintext otherwise. When
/// <see cref="OutboundDeliveryRequest.RequireTls"/> is set, anything short of a trusted,
/// matching certificate is a failure, not a plaintext fallback: "a security policy that
/// downgrades itself when inconvenient is not a security policy." In the opportunistic case, an
/// untrusted or mismatched certificate is still used to encrypt the session - encryption without
/// authentication is exactly what "opportunistic" means - and the certificate's subject, issuer
/// and trust outcome are always recorded on the result so a genuine problem is diagnosable
/// rather than invisible.
/// </para>
/// <para>
/// One call delivers to exactly one recipient over one connection; see
/// <see cref="IOutboundDeliveryClient"/>'s remarks for why recipients are not batched onto a
/// shared <c>RCPT TO</c> sequence in this milestone.
/// </para>
/// </remarks>
internal sealed class OutboundSmtpClient(
    IServerIdentityProvider serverIdentity,
    IMessageStore messageStore,
    CertificateChainValidator chainValidator,
    IDomainRepository domainRepository,
    IDkimKeyRepository dkimKeyRepository,
    DkimMessageSigner dkimSigner,
    IClock clock,
    IOptions<MailServerOptions> options,
    ILogger<OutboundSmtpClient> logger) : IOutboundDeliveryClient
{
    /// <summary>
    /// Bound on one reply line. Generous next to the inbound command-line bound: a remote MTA's
    /// banner or EHLO capability line is not attacker-controlled input from this server's own
    /// threat model in the way an inbound command is, but it is still bounded rather than
    /// unbounded, per rule 105.
    /// </summary>
    private const int MaxReplyLineOctets = 8_192;

    private const int BodyChunkBytes = 64 * 1024;

    private OutboundOptions Options => options.Value.Outbound;

    public async Task<OutboundDeliveryResult> DeliverAsync(
        OutboundDeliveryRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Only the delivery test asks for one. Ordinary queue delivery runs thousands of these
        // and has DeliveryAttempt rows for its evidence; holding a transcript for each would be
        // memory spent on something nothing reads.
        SmtpTranscript? transcript = request.RecordTranscript ? new SmtpTranscript() : null;

        OutboundDeliveryResult result = await DeliverCoreAsync(request, transcript, cancellationToken)
            .ConfigureAwait(false);

        // Attached at the one exit rather than at each of the dozen returns inside, so a path
        // added later cannot forget it.
        return transcript is null ? result : result with { Transcript = transcript.Lines };
    }

    private async Task<OutboundDeliveryResult> DeliverCoreAsync(
        OutboundDeliveryRequest request,
        SmtpTranscript? transcript,
        CancellationToken cancellationToken)
    {
        using TcpClient tcp = new();
        IpAddressValue? remoteAddress = null;

        try
        {
            using CancellationTokenSource connectCts =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(TimeSpan.FromSeconds(Options.ConnectTimeoutSeconds));

            await tcp.ConnectAsync(request.TargetHost, request.Port, connectCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsConnectFailure(ex, cancellationToken))
        {
            return Result.Temporary(
                null, errorDetail: $"Could not connect to {request.TargetHost}:{request.Port}: {ex.Message}");
        }

        if (tcp.Client.RemoteEndPoint is IPEndPoint remoteEndPoint)
        {
            remoteAddress = IpAddressValue.From(remoteEndPoint.Address);
        }

        Stream stream = tcp.GetStream();
        SslStream? tls = null;

        try
        {
            SmtpLineReader reader = new(stream, MaxReplyLineOctets);
            TimeSpan commandTimeout = TimeSpan.FromSeconds(Options.CommandTimeoutSeconds);

            transcript?.Note(
                $"Connected to {request.TargetHost}:{request.Port} at {remoteAddress?.Value ?? "an unknown address"}.");

            SmtpReply banner = await SmtpReplyParser.ReadAsync(reader, commandTimeout, cancellationToken)
                .ConfigureAwait(false);

            transcript?.Received(banner);

            if (!banner.IsSuccess)
            {
                return Classify(remoteAddress, null, banner, "the banner");
            }

            (SmtpReply ehlo, IReadOnlyList<string> capabilities) = await EhloAsync(
                stream, reader, commandTimeout, transcript, cancellationToken).ConfigureAwait(false);

            if (!ehlo.IsSuccess)
            {
                return Classify(remoteAddress, null, ehlo, "EHLO/HELO");
            }

            bool startTlsOffered = capabilities.Any(
                static c => c.StartsWith("STARTTLS", StringComparison.OrdinalIgnoreCase));

            if (!startTlsOffered && request.RequireTls)
            {
                return Result.TlsRequiredFailure(
                    remoteAddress, $"{request.TargetHost} does not offer STARTTLS.");
            }

            TlsUpgradeOutcome? activeTls = null;

            if (startTlsOffered)
            {
                TlsUpgradeOutcome tlsOutcome = await UpgradeToTlsAsync(
                    stream, reader, request.TargetHost, request.RequireTls, commandTimeout, cancellationToken)
                    .ConfigureAwait(false);

                if (tlsOutcome.Tls is null)
                {
                    // A STARTTLS that was offered but failed to negotiate is treated as a
                    // transient problem rather than a silent plaintext fallback: RFC 3207
                    // expects the connection to be abandoned on a failed handshake, and
                    // continuing on the same connection risks exactly the downgrade attack
                    // STARTTLS exists to prevent.
                    return request.RequireTls
                        ? Result.TlsRequiredFailure(remoteAddress, tlsOutcome.Diagnostic, tlsOutcome)
                        : Result.Temporary(remoteAddress, tlsOutcome.Diagnostic, tlsOutcome);
                }

                tls = tlsOutcome.Tls;
                stream = tls;
                reader = new SmtpLineReader(tls, MaxReplyLineOctets);

                // RFC 3207 §4.2: capabilities learned before the handshake must be discarded
                // and re-learned over the encrypted channel, or a network attacker who stripped
                // an advertised capability before the upgrade would still have succeeded.
                (SmtpReply postTlsEhlo, _) = await EhloAsync(
                    stream, reader, commandTimeout, transcript, cancellationToken)
                    .ConfigureAwait(false);

                if (!postTlsEhlo.IsSuccess)
                {
                    return Classify(remoteAddress, tlsOutcome, postTlsEhlo, "EHLO after STARTTLS");
                }

                transcript?.Note(
                    $"TLS negotiated: {tlsOutcome.Protocol} with {tlsOutcome.Cipher}, " +
                    $"peer certificate {(tlsOutcome.Trusted ? "trusted" : "not trusted")}. " +
                    $"Peer certificate subject {tlsOutcome.PeerSubject ?? "(none)"}, " +
                    $"issuer {tlsOutcome.PeerIssuer ?? "(none)"}.");

                activeTls = tlsOutcome;
            }

            string mailFromArgument = request.ReversePath is null
                ? "MAIL FROM:<>"
                : $"MAIL FROM:<{request.ReversePath.Value}>";

            SmtpReply mailFromReply = await SendCommandAsync(
                stream, reader, mailFromArgument, commandTimeout, cancellationToken, transcript).ConfigureAwait(false);

            if (!mailFromReply.IsSuccess)
            {
                return Classify(remoteAddress, activeTls, mailFromReply, "MAIL FROM");
            }

            SmtpReply rcptReply = await SendCommandAsync(
                stream, reader, $"RCPT TO:<{request.RecipientAddress.Value}>", commandTimeout, cancellationToken, transcript)
                .ConfigureAwait(false);

            if (!rcptReply.IsSuccess)
            {
                return Classify(remoteAddress, activeTls, rcptReply, "RCPT TO");
            }

            SmtpReply dataReply = await SendCommandAsync(
                stream, reader, "DATA", commandTimeout, cancellationToken, transcript).ConfigureAwait(false);

            if (!dataReply.IsIntermediate)
            {
                return Classify(remoteAddress, activeTls, dataReply, "DATA");
            }

            byte[]? dkimSignatureLine = await ComputeDkimSignatureLineAsync(request.MessageId, cancellationToken)
                .ConfigureAwait(false);

            await StreamMessageBodyAsync(stream, request.MessageId, dkimSignatureLine, cancellationToken)
                .ConfigureAwait(false);

            TimeSpan dataTimeout = TimeSpan.FromSeconds(Options.DataTimeoutSeconds);
            SmtpReply finalReply = await SmtpReplyParser.ReadAsync(reader, dataTimeout, cancellationToken)
                .ConfigureAwait(false);

            transcript?.Received(finalReply);

            // QUIT is best-effort: the delivery outcome is already decided by the reply above,
            // and a peer that hangs up first has already told us everything it is going to.
            try
            {
                await SendCommandAsync(stream, reader, "QUIT", commandTimeout, cancellationToken, transcript)
                    .ConfigureAwait(false);
            }
            catch (IOException)
            {
                // Ignored; see remark above.
            }

            return Classify(remoteAddress, activeTls, finalReply, "end of DATA");
        }
        catch (Exception ex) when (IsTransportFailure(ex, cancellationToken))
        {
            return Result.Temporary(remoteAddress, $"The connection failed: {ex.Message}");
        }
        finally
        {
            if (tls is not null)
            {
                await tls.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task<(SmtpReply Reply, IReadOnlyList<string> Capabilities)> EhloAsync(
        Stream stream,
        SmtpLineReader reader,
        TimeSpan timeout,
        SmtpTranscript? transcript,
        CancellationToken cancellationToken)
    {
        SmtpReply ehlo = await SendCommandAsync(
            stream, reader, $"EHLO {serverIdentity.Hostname}", timeout, cancellationToken, transcript)
            .ConfigureAwait(false);

        if (ehlo.IsSuccess)
        {
            // The capabilities are the reply's own continuation lines, which the transcript
            // already holds as part of the reply. Noting them again would duplicate them.
            return (ehlo, ehlo.ContinuationLines);
        }

        // A peer that does not understand EHLO at all - vanishingly rare, but RFC 5321 requires
        // the fallback - simply cannot use any ESMTP extension, STARTTLS included.
        SmtpReply helo = await SendCommandAsync(
            stream, reader, $"HELO {serverIdentity.Hostname}", timeout, cancellationToken, transcript)
            .ConfigureAwait(false);

        return (helo, []);
    }

    private static async Task<SmtpReply> SendCommandAsync(
        Stream stream,
        SmtpLineReader reader,
        string command,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        SmtpTranscript? transcript = null)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(command + "\r\n");
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        transcript?.Sent(command);

        SmtpReply reply = await SmtpReplyParser
            .ReadAsync(reader, timeout, cancellationToken)
            .ConfigureAwait(false);

        transcript?.Received(reply);

        return reply;
    }

    private async Task StreamMessageBodyAsync(
        Stream stream,
        StoredMessageId messageId,
        byte[]? dkimSignatureLine,
        CancellationToken cancellationToken)
    {
        await using Stream content = await messageStore.OpenReadAsync(messageId, cancellationToken)
            .ConfigureAwait(false);

        SmtpDotStuffing stuffing = new();

        // The signature line is fed through the SAME stuffer instance, before the stored
        // content, so dot-stuffing state (which line-start position it thinks it is at) stays
        // continuous across the boundary - a signature line beginning with '.' would otherwise
        // not be stuffed and would be misread as the end-of-data terminator.
        if (dkimSignatureLine is { Length: > 0 })
        {
            byte[] stuffedSignature = new byte[SmtpDotStuffing.MaxOutputFor(dkimSignatureLine.Length)];
            int signatureWritten = stuffing.Stuff(dkimSignatureLine, stuffedSignature);
            await stream.WriteAsync(stuffedSignature.AsMemory(0, signatureWritten), cancellationToken)
                .ConfigureAwait(false);
        }

        byte[] input = new byte[BodyChunkBytes];
        byte[] output = new byte[SmtpDotStuffing.MaxOutputFor(BodyChunkBytes)];

        int read;

        while ((read = await content.ReadAsync(input, cancellationToken).ConfigureAwait(false)) > 0)
        {
            int written = stuffing.Stuff(input.AsSpan(0, read), output);
            await stream.WriteAsync(output.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
        }

        byte[] terminator = new byte[5];
        int terminatorLength = stuffing.WriteTerminator(terminator);
        await stream.WriteAsync(terminator.AsMemory(0, terminatorLength), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes a DKIM-Signature header line for the message, or null when it should be sent
    /// unsigned: the <c>From:</c> header does not parse, its domain is not one this server hosts,
    /// or that domain has no active DKIM key. Never throws — a DKIM subsystem failure must not
    /// block delivery of mail that would otherwise send successfully.
    /// </summary>
    private async Task<byte[]?> ComputeDkimSignatureLineAsync(
        StoredMessageId messageId, CancellationToken cancellationToken)
    {
        try
        {
            await using Stream content = await messageStore.OpenReadAsync(messageId, cancellationToken)
                .ConfigureAwait(false);

            RawMessageHeaders? headers = await MessageHeaderReader.TryReadHeadersAsync(
                content, options.Value.Limits.MaxHeaderBytes, cancellationToken).ConfigureAwait(false);

            if (headers is null)
            {
                logger.LogWarning(
                    "Could not locate the header/body boundary for message {MessageId} while " +
                    "preparing to sign it; sending unsigned.",
                    messageId.Value);

                return null;
            }

            if (!FromHeaderDomain.TryExtract(headers, out DomainName? fromDomain))
            {
                return null;
            }

            MailDomain? domain = await domainRepository.GetByNameAsync(fromDomain!, cancellationToken)
                .ConfigureAwait(false);

            if (domain is null)
            {
                return null;
            }

            DkimKey? activeKey = await dkimKeyRepository
                .GetActiveForDomainAsync(domain.Id, cancellationToken)
                .ConfigureAwait(false);

            if (activeKey is null)
            {
                return null;
            }

            byte[]? privateKey = await dkimKeyRepository
                .GetPrivateKeyAsync(activeKey.Id, cancellationToken)
                .ConfigureAwait(false);

            if (privateKey is null)
            {
                logger.LogWarning(
                    "DKIM key {KeyId} for domain {Domain} has no stored private key; sending " +
                    "{MessageId} unsigned.",
                    activeKey.Id.Value,
                    fromDomain!.Value,
                    messageId.Value);

                return null;
            }

            content.Seek(headers.HeaderBlockLength, SeekOrigin.Begin);

            DkimSignatureTags tags;

            try
            {
                tags = await dkimSigner.SignAsync(
                    headers,
                    content,
                    fromDomain!,
                    activeKey.Selector,
                    privateKey,
                    clock.UtcNow,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                // The decrypted private key came from ISecretProtector.Unprotect purely to be
                // handed to RSA.ImportPkcs8PrivateKey for this one signature; unlike a SASL
                // password (docs/Standards.md's "held in a clearable buffer... overwritten
                // immediately afterwards"), nothing here was clearing this copy afterwards.
                CryptographicOperations.ZeroMemory(privateKey);
            }

            return Encoding.ASCII.GetBytes($"DKIM-Signature: {tags.Compose()}\r\n");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(
                ex, "Failed to compute a DKIM signature for message {MessageId}; sending unsigned.", messageId.Value);

            return null;
        }
    }

    /// <summary>Negotiates STARTTLS, validating the peer's certificate for evidence, not as a gate.</summary>
    /// <remarks>
    /// <para>
    /// The <see cref="SslClientAuthenticationOptions.RemoteCertificateValidationCallback"/> here
    /// always inspects the chain genuinely via <see cref="CertificateChainValidator"/> - there is
    /// no unconditional <c>true</c>. What it does with the answer depends on
    /// <paramref name="requireTls"/>: when TLS is required, an untrusted or mismatched
    /// certificate fails the handshake; otherwise the session proceeds encrypted regardless,
    /// because that is what "opportunistic" means, and the validation outcome is still recorded
    /// for the delivery attempt.
    /// </para>
    /// </remarks>
    private async Task<TlsUpgradeOutcome> UpgradeToTlsAsync(
        Stream stream,
        SmtpLineReader reader,
        string targetHost,
        bool requireTls,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        SmtpReply startTlsReply = await SendCommandAsync(
            stream, reader, "STARTTLS", timeout, cancellationToken).ConfigureAwait(false);

        if (!startTlsReply.IsSuccess)
        {
            return TlsUpgradeOutcome.Failed($"{targetHost} refused STARTTLS: {startTlsReply}");
        }

        SslStream tls = new(stream, leaveInnerStreamOpen: false);

        string? peerSubject = null;
        string? peerIssuer = null;
        bool trusted = false;
        string? validationDiagnostic = null;

        bool ValidateRemoteCertificate(
            object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            if (certificate is null)
            {
                validationDiagnostic = "The remote presented no certificate.";
                return !requireTls;
            }

            bool ownsCopy = certificate is not X509Certificate2;
            X509Certificate2 certificate2 = certificate as X509Certificate2 ?? new X509Certificate2(certificate);

            try
            {
                peerSubject = certificate2.Subject;
                peerIssuer = certificate2.Issuer;

                CertificateChainResult chainResult = chainValidator.Validate(certificate2);
                trusted = chainResult.IsTrusted;
                validationDiagnostic = chainResult.IsTrusted ? null : chainResult.StatusSummary;

                if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                {
                    trusted = false;

                    validationDiagnostic = string.IsNullOrEmpty(validationDiagnostic)
                        ? $"The certificate does not match {targetHost}."
                        : $"{validationDiagnostic} The certificate also does not match {targetHost}.";
                }
            }
            finally
            {
                if (ownsCopy)
                {
                    certificate2.Dispose();
                }
            }

            // Opportunistic TLS encrypts regardless of trust - refusing here would make "may"
            // behave like "must". A required policy accepts nothing less than a trusted, matching
            // certificate.
            return requireTls ? trusted : true;
        }

        try
        {
            using CancellationTokenSource handshakeCts =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(timeout);

            await tls.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = targetHost,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = ValidateRemoteCertificate,
                },
                handshakeCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException)
        {
            await tls.DisposeAsync().ConfigureAwait(false);

            logger.LogDebug(ex, "STARTTLS handshake with {Host} failed.", targetHost);

            return new TlsUpgradeOutcome(
                null,
                null,
                null,
                peerSubject,
                peerIssuer,
                trusted,
                validationDiagnostic ?? $"TLS handshake with {targetHost} failed: {ex.Message}");
        }

        return new TlsUpgradeOutcome(
            tls,
            tls.SslProtocol.ToString(),
            tls.NegotiatedCipherSuite.ToString(),
            peerSubject,
            peerIssuer,
            trusted,
            validationDiagnostic);
    }

    private static bool IsConnectFailure(Exception ex, CancellationToken cancellationToken) =>
        ex is SocketException ||
        (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested);

    private static bool IsTransportFailure(Exception ex, CancellationToken cancellationToken) =>
        ex is IOException or SocketException ||
        (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested);

    /// <summary>Classifies a completed reply into a <see cref="DeliveryOutcome"/>.</summary>
    private static OutboundDeliveryResult Classify(
        IpAddressValue? remoteAddress,
        TlsUpgradeOutcome? tls,
        SmtpReply reply,
        string stage)
    {
        DeliveryOutcome outcome;
        FailureClassification classification;

        if (reply.IsSuccess)
        {
            outcome = DeliveryOutcome.Delivered;
            classification = FailureClassification.None;
        }
        else if (reply.IsPermanentFailure)
        {
            outcome = DeliveryOutcome.Bounced;
            classification = FailureClassification.Permanent;
        }
        else
        {
            outcome = DeliveryOutcome.Deferred;
            classification = FailureClassification.Temporary;
        }

        return new OutboundDeliveryResult(
            outcome,
            classification,
            remoteAddress,
            TlsActive: tls is not null,
            tls?.Protocol,
            tls?.Cipher,
            tls?.PeerSubject,
            tls?.PeerIssuer,
            reply.Code,
            reply.EnhancedStatus,
            reply.Text,
            outcome == DeliveryOutcome.Delivered ? null : $"Rejected at {stage}: {reply}");
    }

    /// <summary>The outcome of one STARTTLS negotiation attempt.</summary>
    private sealed record TlsUpgradeOutcome(
        SslStream? Tls,
        string? Protocol,
        string? Cipher,
        string? PeerSubject,
        string? PeerIssuer,
        bool Trusted,
        string? Diagnostic)
    {
        public static TlsUpgradeOutcome Failed(string diagnostic) =>
            new(null, null, null, null, null, false, diagnostic);
    }

    /// <summary>Builds the two failure shapes that never reach a remote reply.</summary>
    private static class Result
    {
        public static OutboundDeliveryResult Temporary(
            IpAddressValue? remoteAddress, string? errorDetail, TlsUpgradeOutcome? tls = null) =>
            new(
                DeliveryOutcome.Deferred,
                FailureClassification.Temporary,
                remoteAddress,
                tls is not null,
                tls?.Protocol,
                tls?.Cipher,
                tls?.PeerSubject,
                tls?.PeerIssuer,
                ReplyCode: null,
                EnhancedStatus: null,
                ReplyText: null,
                errorDetail ?? "The connection failed.");

        public static OutboundDeliveryResult TlsRequiredFailure(
            IpAddressValue? remoteAddress, string? diagnostic, TlsUpgradeOutcome? tls = null) =>
            new(
                DeliveryOutcome.TlsRequiredFailure,
                FailureClassification.Temporary,
                remoteAddress,
                TlsActive: false,
                tls?.Protocol,
                tls?.Cipher,
                tls?.PeerSubject,
                tls?.PeerIssuer,
                ReplyCode: null,
                EnhancedStatus: null,
                ReplyText: null,
                diagnostic ?? "TLS was required for this destination and could not be established.");
    }
}
