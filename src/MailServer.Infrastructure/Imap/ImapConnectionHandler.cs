using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
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
/// <param name="MaxAppendOctets">
/// The largest message <c>APPEND</c> will accept. Checked against the literal's declared size
/// before a byte is read, so an oversized append costs the connection nothing, and enforced
/// again by the message writer as it fills — a limit checked in one place only is a limit that
/// stops being checked when a second caller appears.
/// </param>
/// <param name="CertificatePurpose">Which certificate this listener presents.</param>
/// <param name="IdlePollInterval">
/// How often an idling connection looks at its folder, or null for the default. Short enough
/// that "immediate mailbox updates" — RFC 2177 §3's own phrase for what <c>IDLE</c> buys a
/// client — is honest, and long enough that a thousand idle connections are a thousand cheap
/// counts a few seconds apart rather than a busy loop.
/// </param>
public sealed record ImapConnectionOptions(
    ImapListenerRole Role,
    ImapProcessorOptions Processor,
    long MaxAppendOctets,
    int MaxLineOctets,
    TimeSpan PreAuthenticationTimeout,
    TimeSpan InactivityTimeout,
    CertificatePurpose CertificatePurpose,
    TimeSpan? IdlePollInterval = null);

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
    IClock clock,
    IMessageStore messageStore,
    ILogger<ImapConnectionHandler> logger)
{
    /// <summary>
    /// The largest literal this server will read into memory as a command argument.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>4096 is RFC 7888's number, and adopting it is what makes advertising <c>LITERAL-</c>
    /// true.</b> §4 defines the capability as the promise that a non-synchronising literal is
    /// "automatically limited to 4096 octets", so a server announcing the atom and then reading
    /// an arbitrarily large <c>{n+}</c> is announcing <c>LITERAL+</c> under another name — the
    /// one thing <c>docs/IMAP.md</c> says this server is not.
    /// </para>
    /// <para>
    /// <b>It applies to the synchronising form too</b>, which RFC 7888 does not require and
    /// which costs nothing: the arguments that arrive as literals are mailbox names, userids and
    /// search text, and four kilobytes is already far past any of them. The one literal that is
    /// legitimately larger is <c>APPEND</c>'s message, which never comes through here —
    /// <see cref="ImapConnectionOptions.MaxAppendOctets"/> bounds it instead, and its octets go
    /// to the message store rather than into memory.
    /// </para>
    /// </remarks>
    public const int MaxInlineLiteralOctets = 4096;

    /// <summary>
    /// The most literals one command may carry.
    /// </summary>
    /// <remarks>
    /// RFC 3501 sets no bound, so this server does. It also bounds the command as a whole: a
    /// literal is the only thing that lets a command span more than one line, so at most this
    /// many lines plus one can be spent on a single command, each already bounded by
    /// <see cref="ImapConnectionOptions.MaxLineOctets"/>. Thirty-two is past anything a real
    /// client sends — a <c>SEARCH</c> with a handful of non-ASCII terms is the busiest case —
    /// while keeping a peer from assembling an unbounded command out of bounded pieces.
    /// </remarks>
    public const int MaxLiteralsPerCommand = 32;

    /// <summary>The most literal content, in total, one command may carry.</summary>
    /// <remarks>
    /// <see cref="MaxLiteralsPerCommand"/> times <see cref="MaxInlineLiteralOctets"/> would be
    /// 128 KiB held for one command; this halves that, because no real command needs even this
    /// much and the two limits together are what bound the memory a single connection can make
    /// this server hold while it is still deciding what the command says.
    /// </remarks>
    public const int MaxTotalInlineLiteralOctets = 64 * 1024;

    /// <summary>
    /// Decodes a literal's octets into the argument they stand for.
    /// </summary>
    /// <remarks>
    /// <b>Never throws on what a client sent.</b> RFC 3501 §4.3 makes a literal a sequence of
    /// octets with no encoding attached, so a client may send bytes that are not UTF-8 at all —
    /// and it is a mailbox name or a search term, not a protocol violation worth dropping a
    /// connection over. Invalid sequences become U+FFFD, which then simply matches no mailbox
    /// and no message, exactly as a wrong name would.
    /// </remarks>
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

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
                new(session, options.Processor, logger, authenticator, mailboxes, writer, clock, messageStore);

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

            // Everything the client owes before the command can be read at all: RFC 3501 §4.3
            // lets any astring argument arrive as octets after the line rather than on it, so a
            // command is a line plus however many literals it announced.
            ImapLiteralRead literals = await ReadLiteralsAsync(
                stream, reader, options, processor, line.Text, cancellationToken)
                .ConfigureAwait(false);

            if (literals.Status == ImapLiteralStatus.Closed)
            {
                return;
            }

            ImapCommandResult result;
            ImapCommand? command = null;

            if (literals.Status == ImapLiteralStatus.Refused)
            {
                result = literals.Refusal!;
            }
            else if (!ImapCommand.TryParse(literals.Text, out ImapCommand? parsed, out ImapTagFailure failure))
            {
                result = processor.MalformedLine(failure);
            }
            else
            {
                command = parsed with { Literals = literals.Values };

                result = command.Verb == ImapVerb.Append

                    // Intercepted before the ordinary dispatch, because APPEND's message literal
                    // is the one this server never holds in memory: RFC 3501 §6.3.11's octets go
                    // straight to the message store, and only the loop owns the stream they
                    // arrive on. ReadLiteralsAsync leaves that specifier unresolved for exactly
                    // this reason; every other literal on the line is already in command.Literals.
                    ? await AppendAsync(
                        stream, reader, processor, options, command, cancellationToken)
                        .ConfigureAwait(false)
                    : await processor.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
            }

            await WriteAsync(stream, result.Responses, cancellationToken).ConfigureAwait(false);

            switch (result.Action)
            {
                case ImapSessionAction.Idle:
                    if (!await IdleAsync(
                        stream, reader, processor, options, command!, cancellationToken)
                        .ConfigureAwait(false))
                    {
                        return;
                    }

                    continue;

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
    /// <summary>How reading a command's literals ended.</summary>
    private enum ImapLiteralStatus
    {
        /// <summary>Every literal arrived; the command is complete.</summary>
        Complete = 0,

        /// <summary>The command was refused before its octets were read.</summary>
        Refused = 1,

        /// <summary>The connection is finished and has already been told so.</summary>
        Closed = 2,
    }

    /// <summary>The outcome of reading a command's literals.</summary>
    /// <param name="Status">How the read ended.</param>
    /// <param name="Text">
    /// The whole command line, with each literal specifier left exactly where the client put it.
    /// </param>
    /// <param name="Values">The literals' values, in the order their specifiers appear.</param>
    /// <param name="Refusal">What to answer, for <see cref="ImapLiteralStatus.Refused"/>.</param>
    private readonly record struct ImapLiteralRead(
        ImapLiteralStatus Status,
        string Text,
        IReadOnlyList<string> Values,
        ImapCommandResult? Refusal);

    /// <summary>
    /// Reads whatever literals a command announced, leaving <c>APPEND</c>'s message alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A literal is always the last thing on the line that announces it</b>, and the command
    /// resumes after the octets — RFC 3501 §4.3. So this is a loop, not a special case: read a
    /// line, and while it ends in a specifier, answer it, take the octets, read the next line
    /// and join it on. <c>LOGIN {5}</c>/<c>alice</c>/<c>{8}</c>/<c>hunter2</c> goes round twice.
    /// </para>
    /// <para>
    /// <b>The specifiers stay in the text.</b> They are the placeholders the values are matched
    /// against, positionally, by <see cref="ImapAstringReader"/>. Substituting the octets into
    /// the line instead would mean re-quoting arbitrary binary into something the parser must
    /// then take apart again — a round trip whose only possible outcomes are "unchanged" and
    /// "wrong".
    /// </para>
    /// <para>
    /// <b>The two refusals differ in kind, and RFC 7888 §4 is why.</b> A synchronising literal
    /// has not been sent yet: withholding the continuation and answering <c>BAD</c> costs the
    /// client one round trip and nothing else, which is the whole point of the handshake. A
    /// non-synchronising one is already in flight, so there is no refusal that does not either
    /// read the octets it was trying not to read or desynchronise the session — §4's own two
    /// exits. This takes the second, with the untagged <c>BYE</c> §4 prescribes, and notes that
    /// advertising <c>LITERAL-</c> is what makes it nearly unreachable: a client that has read
    /// the capability knows the cap and sends a synchronising literal above it.
    /// </para>
    /// <para>
    /// <b><c>APPEND</c>'s message literal is left for <see cref="AppendAsync"/>.</b> The test is
    /// whether the command so far parses as a complete <c>APPEND</c> whose remaining argument is
    /// this literal — which is what <see cref="ImapAppend.TryParse"/> answers — because RFC 3501
    /// §6.3.11 puts the message last and nothing may follow it. A mailbox name earlier on the
    /// same line is an ordinary literal and is read here, so
    /// <c>APPEND {5}</c>/<c>INBOX (\Seen) {310}</c> resolves its name and still streams its
    /// message.
    /// </para>
    /// </remarks>
    private async Task<ImapLiteralRead> ReadLiteralsAsync(
        Stream stream,
        ImapLineReader reader,
        ImapConnectionOptions options,
        ImapCommandProcessor processor,
        string firstLine,
        CancellationToken cancellationToken)
    {
        string text = firstLine;
        List<string> values = [];
        long total = 0;

        // How much of the text has already been answered. The specifiers stay in the text as the
        // placeholders the values are matched against, so "does this line end in a specifier" is
        // true again the moment a literal's own remainder is empty - SELECT {5} is still SELECT
        // {5} after INBOX arrives. Only a specifier beginning at or after this point is a new
        // one; without the mark the loop re-reads the literal it just read, and asks the client
        // for octets it already sent.
        int answered = 0;

        while (true)
        {
            if (!ImapLiteralSpecifier.TryParseTrailing(text, out ImapLiteralSpecifier specifier, out int start) ||
                start < answered)
            {
                return new ImapLiteralRead(ImapLiteralStatus.Complete, text, values, null);
            }

            // The tag has to be usable before anything is answered: a continuation cannot be
            // matched to a command the client cannot identify, so this stops and lets the
            // ordinary parse produce RFC 3501 §7.1.3's untagged BAD.
            if (!ImapCommand.TryParse(text, out ImapCommand? sofar, out _))
            {
                return new ImapLiteralRead(ImapLiteralStatus.Complete, text, values, null);
            }

            if (sofar.Verb == ImapVerb.Append &&
                ImapAppend.TryParse(sofar.Argument, values, out _))
            {
                return new ImapLiteralRead(ImapLiteralStatus.Complete, text, values, null);
            }

            if (specifier.ByteCount > MaxInlineLiteralOctets ||
                values.Count >= MaxLiteralsPerCommand ||
                total + specifier.ByteCount > MaxTotalInlineLiteralOctets)
            {
                if (!specifier.IsSynchronizing)
                {
                    await WriteAsync(
                        stream,
                        [ImapResponses.Bye("Non-synchronising literal is larger than this server accepts")],
                        cancellationToken).ConfigureAwait(false);

                    return new ImapLiteralRead(ImapLiteralStatus.Closed, text, values, null);
                }

                // No continuation, so the octets never leave the client. The command is over.
                return new ImapLiteralRead(
                    ImapLiteralStatus.Refused,
                    text,
                    values,
                    ImapCommandResult.Single(ImapResponses.Bad(
                        sofar.Tag,
                        "Literal is larger than this server accepts")));
            }

            TimeSpan timeout = CurrentTimeout(processor.Session, options);

            if (specifier.IsSynchronizing)
            {
                await WriteAsync(
                    stream,
                    [ImapResponses.ReadyForLiteral()],
                    cancellationToken).ConfigureAwait(false);
            }

            byte[] octets = new byte[(int)specifier.ByteCount];
            int written = 0;

            bool complete = await reader
                .ReadLiteralAsync(
                    specifier.ByteCount,
                    (chunk, _) =>
                    {
                        chunk.Span.CopyTo(octets.AsSpan(written));
                        written += chunk.Length;
                        return ValueTask.CompletedTask;
                    },
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false);

            if (!complete)
            {
                await WriteAsync(
                    stream,
                    [ImapResponses.Bye("Literal was truncated")],
                    cancellationToken).ConfigureAwait(false);

                return new ImapLiteralRead(ImapLiteralStatus.Closed, text, values, null);
            }

            values.Add(Utf8.GetString(octets));
            total += specifier.ByteCount;

            // Everything up to here is answered, so the specifier just satisfied cannot be
            // mistaken for the next one. What follows is the remainder of the command line,
            // which RFC 3501 §4.3 has resume after the octets - and which may announce another.
            answered = text.Length;

            ImapLineResult next = await reader.ReadLineAsync(timeout, cancellationToken).ConfigureAwait(false);

            switch (next.Status)
            {
                case ImapLineStatus.EndOfStream:
                    return new ImapLiteralRead(ImapLiteralStatus.Closed, text, values, null);

                case ImapLineStatus.Timeout:
                    await WriteAsync(
                        stream,
                        [ImapResponses.Bye("Autologout; idle for too long")],
                        cancellationToken).ConfigureAwait(false);

                    return new ImapLiteralRead(ImapLiteralStatus.Closed, text, values, null);

                case ImapLineStatus.LineTooLong:
                    await WriteAsync(
                        stream,
                        [
                            ImapResponses.UntaggedBad("Command line too long"),
                            ImapResponses.Bye("Command line too long"),
                        ],
                        cancellationToken).ConfigureAwait(false);

                    return new ImapLiteralRead(ImapLiteralStatus.Closed, text, values, null);
            }

            text += next.Text;
        }
    }

    /// <summary>
    /// Runs an <c>APPEND</c>: continuation, octets, then the command proper.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The continuation comes first and must be flushed.</b> RFC 3501 §4.3: for a
    /// synchronising literal "the client MUST wait to receive a command continuation request
    /// […] before sending the octets of the literal". A client that never receives it waits
    /// forever, and so does the server.
    /// </para>
    /// <para>
    /// <b>A non-synchronising literal skips it</b>, which is the whole of what RFC 7888's
    /// <c>{n+}</c> buys: the client has already sent the octets, so waiting for permission to
    /// receive what has arrived would deadlock.
    /// </para>
    /// <para>
    /// <b>The octets go straight to the message store.</b> A message may be tens of megabytes;
    /// assembling it in memory to hand it over afterwards would double that for no gain, and the
    /// store enforces the size limit as the writer fills.
    /// </para>
    /// <para>
    /// <b>The trailing line is consumed whether or not the append succeeded.</b> §4.3 has the
    /// command line resume after the literal, so a CRLF follows the octets; leaving it unread
    /// would make the next command parse as the tail of this one.
    /// </para>
    /// </remarks>
    private async Task<ImapCommandResult> AppendAsync(
        Stream stream,
        ImapLineReader reader,
        ImapCommandProcessor processor,
        ImapConnectionOptions options,
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        ImapAppendRequest? request = processor.PlanAppend(command, out ImapCommandResult refusal);

        if (request is null)
        {
            return refusal;
        }

        if (request.Literal.ByteCount > options.MaxAppendOctets)
        {
            // Refused before a byte is read, so an oversized append costs the connection
            // nothing. A plain tagged NO, which is what §6.3.11 provides for - "NO - append
            // error: can't append to that mailbox, error in flags or date/time or message text".
            // No response code: RFC 3501 defines none for this, and inventing one would be a
            // token a client cannot look up.
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "Message is larger than this server accepts"));
        }

        if (request.Literal.IsSynchronizing)
        {
            await WriteAsync(
                stream,
                [ImapResponses.ReadyForLiteral()],
                cancellationToken).ConfigureAwait(false);
        }

        TimeSpan timeout = CurrentTimeout(processor.Session, options);

        await using IMessageWriter writer = await messageStore
            .BeginWriteAsync(options.MaxAppendOctets, cancellationToken)
            .ConfigureAwait(false);

        bool complete;

        try
        {
            complete = await reader
                .ReadLiteralAsync(
                    request.Literal.ByteCount,
                    (chunk, ct) => writer.WriteAsync(chunk, ct),
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (MessageTooLargeException)
        {
            // The store enforces the limit too, and reaching it here means the specifier lied
            // about the size. Nothing is committed, so nothing is left behind.
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "Message is larger than this server accepts"));
        }

        if (!complete)
        {
            return new ImapCommandResult(
                [ImapResponses.Bye("Literal was truncated")],
                ImapSessionAction.CloseAfterResponse);
        }

        // The rest of the command line, which for APPEND is just its CRLF.
        await reader.ReadLineAsync(timeout, cancellationToken).ConfigureAwait(false);

        StoredMessage stored = await writer.CommitAsync(cancellationToken).ConfigureAwait(false);

        return await processor
            .CompleteAppendAsync(command, request, stored, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Holds a connection idle, pushing mailbox updates, until the client sends <c>DONE</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The updates are real, and they come from polling the folder.</b> RFC 2177 §3: "as long
    /// as an IDLE command is active, the server is now free to send untagged EXISTS, EXPUNGE, and
    /// other messages at any time." This server has no cross-session notification bus, so it
    /// watches the folder's message count and its flag-change counter on a short timer instead.
    /// That matters more than it sounds: advertising <c>IDLE</c> and then never pushing would be
    /// actively worse than not advertising it, because §3 tells a client that without the
    /// capability it "must poll for mailbox updates" — so a client given a silent IDLE stops
    /// polling and sees new mail later than it otherwise would.
    /// </para>
    /// <para>
    /// <b>Flag changes are pushed as well as arrivals, which is what discharges RFC 3501
    /// §6.4.6.</b> "Regardless of whether or not the <c>.SILENT</c> suffix was used, the server
    /// SHOULD send an untagged FETCH response if a change to a message's flags from an external
    /// source is observed. The intent is that the status of the flags is determinate without a
    /// race condition." Two clients on one mailbox is the ordinary case, not the exotic one —
    /// a phone and a desktop — and without this a message read on one shows as unread on the
    /// other until something else makes it look. <see cref="ImapFlagWatch"/> holds the
    /// comparison and the reasoning about whose numbering the positions belong to.
    /// </para>
    /// <para>
    /// <b>Nothing selected is a legal idle, not a reason to hang up.</b> RFC 2177 §4 annotates
    /// its <c>command_auth</c> production ";; Valid only in Authenticated or Selected state", so
    /// a client may idle with no mailbox open — there is simply nothing to report to it, and it
    /// waits for its <c>DONE</c> and its inactivity timeout like any other.
    /// </para>
    /// <para>
    /// <b>Only growth is pushed, and the baseline is what the client was told rather than what
    /// the folder held a moment ago.</b> An <c>EXISTS</c> is an absolute count, but a shrink
    /// means another session expunged something, and RFC 2180 §4.1's worked example shows a
    /// falling count being sent as <c>EXPUNGE</c> lines first and the lower <c>EXISTS</c> after
    /// — sequence numbers the poll does not know. So a shrink is absorbed silently and the
    /// client learns of it on its next command, which is late but never wrong.
    /// </para>
    /// <para>
    /// <b>Absorbing it must not move the baseline down.</b> If a folder of ten loses two and
    /// then gains one, the client — which was told ten and nothing since — must not be sent
    /// <c>* 9 EXISTS</c>: that is a decrement without the <c>EXPUNGE</c> lines §7.4.1 pairs it
    /// with, and the client would renumber onto the wrong messages. Tracking
    /// <see cref="ImapSessionContext.ReportedExists"/> instead of a local count is what makes
    /// that impossible, and it also means a message that arrived between <c>SELECT</c> and
    /// <c>IDLE</c> is pushed rather than silently adopted as the starting point.
    /// </para>
    /// <para>
    /// <b>The inactivity timeout still applies.</b> §3 permits it outright: "The server MAY
    /// consider a client inactive if it has an IDLE command running, and if such a server has an
    /// inactivity timeout it MAY log the client off implicitly at the end of its timeout period."
    /// The 29-minute figure in that section is advice to clients about re-issuing IDLE, not a
    /// server-side timer.
    /// </para>
    /// <para>
    /// <b>Anything but <c>DONE</c> ends the idle.</b> §3: "The client MUST NOT send a command
    /// while the server is waiting for the DONE, since the server will not be able to distinguish
    /// a command from a continuation." A client that does so gets a tagged <c>BAD</c> and its
    /// connection back, rather than having its command silently swallowed.
    /// </para>
    /// </remarks>
    /// <returns>False when the connection should close.</returns>
    private async Task<bool> IdleAsync(
        Stream stream,
        ImapLineReader reader,
        ImapCommandProcessor processor,
        ImapConnectionOptions options,
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = clock.UtcNow + CurrentTimeout(processor.Session, options);

        // Before the first read, not after it: a watch seeded on the first poll would take
        // whatever had changed during that poll's interval as its starting point and report
        // none of it.
        await SeedFlagWatchAsync(processor, cancellationToken).ConfigureAwait(false);

        while (true)
        {
            if (clock.UtcNow >= deadline)
            {
                await WriteAsync(
                    stream,
                    [ImapResponses.Bye("Autologout; idle for too long")],
                    cancellationToken).ConfigureAwait(false);

                return false;
            }

            ImapLineResult line = await reader
                .ReadLineAsync(
                    options.IdlePollInterval ?? DefaultIdlePollInterval,
                    cancellationToken)
                .ConfigureAwait(false);

            if (line.Status == ImapLineStatus.EndOfStream)
            {
                return false;
            }

            if (line.Status == ImapLineStatus.Timeout)
            {
                // Nothing from the client: look at the folder instead.
                await PushFolderChangesAsync(stream, processor, cancellationToken)
                    .ConfigureAwait(false);

                continue;
            }

            if (line.Status != ImapLineStatus.Line)
            {
                return false;
            }

            // §3: "The IDLE command is terminated by the receipt of a "DONE" continuation from
            // the client". Case-insensitively, as every other token is.
            if (line.Text.Trim().Equals("DONE", StringComparison.OrdinalIgnoreCase))
            {
                await WriteAsync(
                    stream,
                    [ImapResponses.Ok(command.Tag, "IDLE terminated")],
                    cancellationToken).ConfigureAwait(false);

                return true;
            }

            await WriteAsync(
                stream,
                [ImapResponses.Bad(command.Tag, "Expected DONE to end IDLE")],
                cancellationToken).ConfigureAwait(false);

            return true;
        }
    }

    /// <summary>
    /// Starts a flag watch over the selected folder, unless one is already running.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One already running is the <c>DONE</c>-then-<c>IDLE</c> case, and reusing it is the point
    /// — see <see cref="ImapSessionContext.FlagWatch"/>. Re-seeding there would quietly adopt
    /// whatever changed between the two commands.
    /// </para>
    /// <para>
    /// A session with no mailbox open gets no watch and no error. The next poll finds none and
    /// has nothing to compare, which is the correct amount of work to do for a client that has
    /// not told the server which folder it cares about.
    /// </para>
    /// <para>
    /// <b>The counter is read before the rows, and that order is the safe one.</b> A flag change
    /// landing between the two reads is caught by the rows and not by the counter, so the next
    /// poll sees a counter it has not seen, looks again, and finds nothing new — one wasted
    /// read. Reading the rows first would record a counter that already covered a change the
    /// baseline had silently absorbed, and that change would never be reported at all.
    /// </para>
    /// </remarks>
    private static async Task SeedFlagWatchAsync(
        ImapCommandProcessor processor,
        CancellationToken cancellationToken)
    {
        if (processor.Session.FlagWatch is not null)
        {
            return;
        }

        ImapFolderPoll? poll = await processor
            .PollSelectedAsync(cancellationToken)
            .ConfigureAwait(false);

        if (poll is null)
        {
            return;
        }

        IReadOnlyList<ImapFlagState>? folder = await processor
            .ReadSelectedFlagsAsync(cancellationToken)
            .ConfigureAwait(false);

        if (folder is null)
        {
            return;
        }

        processor.Session.StartFlagWatch(ImapFlagWatch.Start(folder, poll.Value.FlagsModSeq));
    }

    /// <summary>
    /// Looks at the selected folder once and writes whatever the client has not been told.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The <c>EXISTS</c> is written before the flag reports, and that ordering is load-bearing
    /// rather than tidy.</b> A <c>FETCH</c> naming a position the client does not yet believe
    /// exists is a response about a message it cannot identify, so the watch is told how many
    /// messages the client has been told about <i>after</i> any <c>EXISTS</c> in the same look
    /// has moved that number.
    /// </para>
    /// <para>
    /// <b>The folder's rows are read only when the cheap numbers say something happened.</b>
    /// That is the whole reason <c>FlagsModSeq</c> exists; see the 0013 migration. A folder
    /// nothing has touched costs one row per poll however much mail it holds.
    /// </para>
    /// <para>
    /// Everything goes out in one write, so a client cannot observe an arrival and its flags as
    /// two separate events.
    /// </para>
    /// <para>
    /// The counter that is recorded is the one read before the rows, for the reason
    /// <see cref="SeedFlagWatchAsync"/> gives: it errs towards looking again rather than towards
    /// missing a change.
    /// </para>
    /// </remarks>
    private static async Task PushFolderChangesAsync(
        Stream stream,
        ImapCommandProcessor processor,
        CancellationToken cancellationToken)
    {
        ImapFolderPoll? polled = await processor
            .PollSelectedAsync(cancellationToken)
            .ConfigureAwait(false);

        if (polled is null)
        {
            return;
        }

        ImapFolderPoll poll = polled.Value;
        List<ImapResponse> responses = [];

        if (poll.ExistsCount > processor.Session.ReportedExists)
        {
            responses.Add(ImapResponses.Exists(poll.ExistsCount));
            processor.Session.ReportExists(poll.ExistsCount);
        }

        if (processor.Session.FlagWatch is { } watch &&
            watch.NeedsLook(poll.ExistsCount, poll.FlagsModSeq))
        {
            IReadOnlyList<ImapFlagState>? folder = await processor
                .ReadSelectedFlagsAsync(cancellationToken)
                .ConfigureAwait(false);

            if (folder is not null)
            {
                foreach (ImapFlagChange change in watch.Observe(
                    folder,
                    poll.FlagsModSeq,
                    processor.Session.ReportedExists))
                {
                    responses.Add(ImapResponses.FetchFlags(
                        change.SequenceNumber,
                        change.Uid,
                        change.Flags));
                }
            }
        }

        if (responses.Count > 0)
        {
            await WriteAsync(stream, responses, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>How often an idling connection looks at its folder, when nothing says.</summary>
    private static readonly TimeSpan DefaultIdlePollInterval = TimeSpan.FromSeconds(5);

    private static async Task WriteAsync(
        Stream stream,
        IReadOnlyList<ImapResponse> responses,
        CancellationToken cancellationToken)
    {
        // Segment by segment rather than one concatenated string, because a FETCH carrying
        // message content must put those octets on the wire untouched - see ImapResponseSegment.
        // Text is still batched between literals, so an ordinary exchange is one write.
        StringBuilder builder = new();

        foreach (ImapResponse response in responses)
        {
            foreach (ImapResponseSegment segment in response.Segments)
            {
                if (segment.IsText)
                {
                    builder.Append(segment.Text);
                    continue;
                }

                if (builder.Length > 0)
                {
                    await stream
                        .WriteAsync(Encoding.UTF8.GetBytes(builder.ToString()), cancellationToken)
                        .ConfigureAwait(false);

                    builder.Clear();
                }

                await stream.WriteAsync(segment.Octets, cancellationToken).ConfigureAwait(false);
            }
        }

        if (builder.Length > 0)
        {
            await stream
                .WriteAsync(Encoding.UTF8.GetBytes(builder.ToString()), cancellationToken)
                .ConfigureAwait(false);
        }

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
