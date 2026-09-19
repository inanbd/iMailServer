using System.Globalization;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Entities;
using MailServer.Domain.Imap;
using MailServer.Domain.Pop3;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Pop3;

/// <summary>What the connection loop must do after sending the response.</summary>
public enum Pop3SessionAction
{
    /// <summary>Carry on reading commands.</summary>
    Continue = 0,

    /// <summary>
    /// Send the response, perform the TLS handshake, then carry on.
    /// </summary>
    /// <remarks>
    /// RFC 2595 §4: "A TLS negotiation begins immediately after the CRLF at the end of the +OK
    /// response from the server." The loop owns the stream to wrap and the reader to empty, so
    /// this action is how the processor asks for both without holding either.
    /// </remarks>
    StartTlsHandshake = 1,

    /// <summary>Send the response, then close the connection.</summary>
    CloseAfterResponse = 2,
}

/// <summary>A response to send, and what to do next.</summary>
/// <remarks>
/// One response rather than a list, which is the shape difference from
/// <see cref="Imap.ImapCommandResult"/>. RFC 1939 §3 gives every command exactly one response;
/// a multi-line one carries its extra lines inside <see cref="Pop3Response"/> itself, because
/// those lines are part of one response's framing rather than responses in their own right.
/// </remarks>
public sealed record Pop3CommandResult(
    Pop3Response Response,
    Pop3SessionAction Action = Pop3SessionAction.Continue);

/// <summary>Everything the processor needs that comes from configuration.</summary>
/// <param name="ProductName">Product string for the greeting and for <c>IMPLEMENTATION</c>.</param>
/// <param name="Role">The listener this connection arrived on.</param>
/// <param name="AuthenticationAvailable">
/// Whether <c>USER</c> and <c>PASS</c> are offered at all. False advertises no <c>USER</c>
/// capability and refuses both, which is the truthful pairing for a deployment that has not
/// turned mailbox access on.
/// </param>
/// <param name="MaxAuthenticationAttempts">
/// How many credentials one connection may have refused before it is closed.
/// </param>
public sealed record Pop3ProcessorOptions(
    string ProductName,
    Pop3ListenerRole Role,
    bool AuthenticationAvailable,
    int MaxAuthenticationAttempts);

/// <summary>
/// Decides what a POP3 command means. Owns no stream and no socket.
/// </summary>
/// <remarks>
/// <para>
/// The same split <see cref="Imap.ImapCommandProcessor"/> makes: the handler owns the transport
/// and the TLS upgrade, this owns the decisions, and the whole command surface is therefore
/// testable without a network.
/// </para>
/// <para>
/// <b>The maildrop is the mailbox's INBOX, and only its INBOX.</b> RFC 1939 has no concept of a
/// folder — §4 speaks of "the appropriate maildrop", singular — so a POP3 client sees new mail
/// and nothing else. Serving a different folder, or several, would be inventing a protocol.
/// </para>
/// </remarks>
public sealed class Pop3CommandProcessor
{
    private readonly Pop3SessionContext _session;
    private readonly Pop3ProcessorOptions _options;
    private readonly ILogger _logger;
    private readonly IMailboxAuthenticator? _authenticator;
    private readonly IImapMailboxReader? _mailboxes;
    private readonly IImapMailboxWriter? _writer;
    private readonly IMessageStore? _messages;
    private readonly IPop3MaildropLocks? _locks;

    private IDisposable? _lease;

    public Pop3CommandProcessor(
        Pop3SessionContext session,
        Pop3ProcessorOptions options,
        ILogger logger,
        IMailboxAuthenticator? authenticator = null,
        IImapMailboxReader? mailboxes = null,
        IImapMailboxWriter? writer = null,
        IMessageStore? messages = null,
        IPop3MaildropLocks? locks = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _session = session;
        _options = options;
        _logger = logger;
        _authenticator = authenticator;
        _mailboxes = mailboxes;
        _writer = writer;
        _messages = messages;
        _locks = locks;
    }

    /// <summary>The session this processor is deciding for.</summary>
    public Pop3SessionContext Session => _session;

    /// <summary>The greeting, sent before any command is read.</summary>
    public Pop3Response Greeting() => Pop3Responses.Greeting(_options.ProductName);

    /// <summary>Releases the maildrop lock, however the session ended.</summary>
    /// <remarks>
    /// Called by the connection loop on every exit path, not only the tidy one: RFC 1939 §4
    /// requires the lock to be released before a negative reply and §6 requires it "whether the
    /// removal was successful or not", so the only safe rule is that leaving the session releases
    /// it.
    /// </remarks>
    public void ReleaseMaildrop()
    {
        _lease?.Dispose();
        _lease = null;
    }

    /// <summary>
    /// Executes one command.
    /// </summary>
    /// <remarks>
    /// §3: "A server MUST respond to an unrecognized, unimplemented, or syntactically invalid
    /// command by responding with a negative status indicator. A server MUST respond to a command
    /// issued when the session is in an incorrect state by responding with a negative status
    /// indicator."
    /// </remarks>
    public async ValueTask<Pop3CommandResult> ExecuteAsync(
        Pop3Command command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        // QUIT and CAPA are legal in every state; everything else is gated below.
        return command.Verb switch
        {
            Pop3Verb.Quit => await QuitAsync(cancellationToken).ConfigureAwait(false),
            Pop3Verb.Capa => Capa(),
            Pop3Verb.Stls => StartTls(),
            Pop3Verb.User => User(command),
            Pop3Verb.Pass => await PassAsync(command, cancellationToken).ConfigureAwait(false),
            Pop3Verb.Apop => Apop(),
            Pop3Verb.Stat => Stat(),
            Pop3Verb.List => List(command),
            Pop3Verb.Uidl => Uidl(command),
            Pop3Verb.Retr => await RetrAsync(command, cancellationToken).ConfigureAwait(false),
            Pop3Verb.Top => await TopAsync(command, cancellationToken).ConfigureAwait(false),
            Pop3Verb.Dele => Dele(command),
            Pop3Verb.Rset => Rset(),
            Pop3Verb.Noop => Noop(command),
            _ => new Pop3CommandResult(Pop3Responses.Unknown()),
        };
    }

    /// <summary>
    /// The reply to a line that did not parse.
    /// </summary>
    /// <remarks>
    /// The client's own line is never quoted back. A line that failed to parse failed because it
    /// contained something the grammar does not allow, which is exactly the material that must
    /// not be echoed.
    /// </remarks>
    public static Pop3CommandResult Malformed() =>
        new(Pop3Response.Error("Malformed command"));

    // ---------------------------------------------------------------------------------------
    // AUTHORIZATION state.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>CAPA</c> — RFC 2449 §5.
    /// </summary>
    /// <remarks>
    /// §5: "The POP3 CAPA command returns a list of capabilities supported by the POP3 server. It
    /// is available in both the AUTHORIZATION and TRANSACTION states."
    /// </remarks>
    private Pop3CommandResult Capa()
    {
        IReadOnlyList<string> capabilities = _session.State == Pop3SessionState.Transaction
            ? Pop3Capabilities.Transaction(_options.ProductName)
            : Pop3Capabilities.Authorization(
                _options.ProductName,
                _session.IsTlsActive,
                _options.Role == Pop3ListenerRole.Cleartext,
                CanLogIn);

        return new Pop3CommandResult(
            Pop3Response.OkWithLines("Capability list follows", capabilities));
    }

    /// <summary>
    /// Whether a plaintext credential may be accepted on this connection.
    /// </summary>
    /// <remarks>
    /// RFC 2595 §2.2 states the rule this enforces for every protocol in that document: a server
    /// implementing the TLS upgrade must refuse plaintext authentication until it has run. POP3
    /// has no capability name for the refusal — IMAP's <c>LOGINDISABLED</c> has no POP3 twin — so
    /// the absence of RFC 2449 §6.2's <c>USER</c> capability says it instead, and this refuses
    /// the command itself so that a client which ignores the listing gains nothing.
    /// </remarks>
    private bool CanLogIn =>
        _options.AuthenticationAvailable && _authenticator is not null && _session.IsTlsActive;

    /// <summary>
    /// <c>STLS</c> — RFC 2595 §4.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §4: "Only permitted in AUTHORIZATION state. […] A TLS negotiation begins immediately after
    /// the CRLF at the end of the +OK response from the server. A -ERR response MAY result if a
    /// security layer is already active."
    /// </para>
    /// <para>
    /// Refused outright on the implicit-TLS listener: there is no honest moment there when an
    /// upgrade would mean anything, because TLS preceded the greeting.
    /// </para>
    /// </remarks>
    private Pop3CommandResult StartTls()
    {
        if (_options.Role != Pop3ListenerRole.Cleartext)
        {
            return new Pop3CommandResult(Pop3Response.Error("STLS is not available on this port"));
        }

        if (_session.IsTlsActive)
        {
            return new Pop3CommandResult(
                Pop3Response.Error("Command not permitted when TLS active"));
        }

        if (_session.State != Pop3SessionState.Authorization)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState("STLS"));
        }

        return new Pop3CommandResult(
            Pop3Response.Ok("Begin TLS negotiation"),
            Pop3SessionAction.StartTlsHandshake);
    }

    /// <summary>
    /// <c>USER</c> — RFC 1939 §7.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §7: "may only be given in the AUTHORIZATION state after the POP3 greeting or after an
    /// unsuccessful USER or PASS command".
    /// </para>
    /// <para>
    /// <b>The reply is the same whether or not the mailbox exists.</b> §7 permits either — "The
    /// server may return a positive response even though no such mailbox exists" — and permitting
    /// the other would turn this command into an address oracle. Every unknown address is a
    /// credential-stuffing run's first step, and the same reasoning
    /// <c>MailboxAuthenticationOutcome</c> records for SMTP and IMAP applies unchanged.
    /// </para>
    /// </remarks>
    private Pop3CommandResult User(Pop3Command command)
    {
        if (_session.State != Pop3SessionState.Authorization)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState("USER"));
        }

        if (!CanLogIn)
        {
            return new Pop3CommandResult(Pop3Response.Error(RefusalText));
        }

        string name = command.Argument.Trim();

        if (name.Length == 0)
        {
            return new Pop3CommandResult(Pop3Response.Error("USER requires a mailbox name"));
        }

        _session.BeginAuthentication(name);

        return new Pop3CommandResult(Pop3Response.Ok("Name accepted; send PASS"));
    }

    /// <summary>
    /// <c>PASS</c> — RFC 1939 §7.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §7: "may only be given in the AUTHORIZATION state immediately after a successful USER
    /// command. […] When the client issues the PASS command, the POP3 server uses the argument
    /// pair from the USER and PASS commands to determine if the client should be given access to
    /// the appropriate maildrop."
    /// </para>
    /// <para>
    /// <b>The argument is taken whole, spaces and all.</b> §7: "Since the PASS command has
    /// exactly one argument, a POP3 server may treat spaces in the argument as part of the
    /// password, instead of as argument separators." A server that split on spaces would refuse
    /// every passphrase, and the user would see nothing but a wrong-password error.
    /// </para>
    /// </remarks>
    private async ValueTask<Pop3CommandResult> PassAsync(
        Pop3Command command,
        CancellationToken cancellationToken)
    {
        if (_session.State != Pop3SessionState.Authorization)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState("PASS"));
        }

        if (!CanLogIn)
        {
            return new Pop3CommandResult(Pop3Response.Error(RefusalText));
        }

        if (_session.PendingUser is not { } name)
        {
            return new Pop3CommandResult(Pop3Response.Error("Send USER before PASS"));
        }

        // Cleared before anything can fail, so no path leaves a name behind for a second PASS.
        _session.ForgetPendingUser();

        using SaslCredential credential = new(name, string.Empty, command.Argument.ToCharArray());

        MailboxAuthenticationResult result = await _authenticator!
            .AuthenticateAsync(credential, _session.RemoteAddress, cancellationToken)
            .ConfigureAwait(false);

        if (!result.IsSuccess || result.Mailbox is null || result.MailboxId is null)
        {
            _session.RecordFailedAuthentication();

            _logger.LogWarning(
                "POP3 authentication from {RemoteAddress} failed: {Diagnostic}",
                _session.RemoteAddress.Value,
                result.Diagnostic);

            // §3 permits closing after a negative reply: "After returning a negative status
            // indicator, the server may close the connection." A connection is otherwise a free
            // retry budget.
            return new Pop3CommandResult(
                Pop3Response.Error("Authentication failed"),
                _session.FailedAuthenticationAttempts >= _options.MaxAuthenticationAttempts
                    ? Pop3SessionAction.CloseAfterResponse
                    : Pop3SessionAction.Continue);
        }

        return await OpenMaildropAsync(result.Mailbox, result.MailboxId.Value, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Takes the lock, reads the maildrop, and enters the TRANSACTION state.
    /// </summary>
    /// <remarks>
    /// §4, in order: authenticate, "the POP3 server then acquires an exclusive-access lock on the
    /// maildrop", then "After the POP3 server has opened the maildrop, it assigns a message-number
    /// to each message, and notes the size of each message in octets." Taking the lock before the
    /// read is what makes the numbering a snapshot nobody else can move.
    /// </remarks>
    private async ValueTask<Pop3CommandResult> OpenMaildropAsync(
        EmailAddress mailbox,
        MailboxId mailboxId,
        CancellationToken cancellationToken)
    {
        if (_mailboxes is null)
        {
            return new Pop3CommandResult(Pop3Response.Error("Mailbox access is not available"));
        }

        if (_locks is not null)
        {
            _lease = _locks.TryAcquire(mailboxId);

            if (_lease is null)
            {
                // §8.1.2 of RFC 2449: "[IN-USE] […] indicates the authentication was successful,
                // but the user's maildrop is currently in use (probably by another POP3 client)."
                return new Pop3CommandResult(
                    Pop3Response.ErrorWithCode("IN-USE", "Maildrop is locked by another session"));
            }
        }

        ImapFolderSnapshot? snapshot = await _mailboxes
            .OpenFolderAsync(mailboxId, "INBOX", cancellationToken)
            .ConfigureAwait(false);

        if (snapshot is null)
        {
            ReleaseMaildrop();

            return new Pop3CommandResult(Pop3Response.Error("Unable to open maildrop"));
        }

        IReadOnlyList<ImapMessageSummary> summaries = [];

        if (snapshot.ExistsCount > 0 &&
            ImapSequenceSet.TryParse("1:*", out ImapSequenceSet? everything))
        {
            summaries = await _mailboxes
                .ReadSummariesAsync(
                    mailboxId,
                    snapshot.FolderId,
                    everything,
                    byUid: false,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        Pop3Maildrop maildrop = new(
            snapshot.UidValidity,
            summaries.Select(m => (m.Uid, m.SizeBytes)));

        _session.OpenMaildrop(mailbox, mailboxId, snapshot.FolderId, maildrop);

        return new Pop3CommandResult(Pop3Response.Ok(string.Create(
            CultureInfo.InvariantCulture,
            $"maildrop has {maildrop.Count} messages ({maildrop.TotalOctets} octets)")));
    }

    /// <summary>
    /// <c>APOP</c> — recognised, and refused.
    /// </summary>
    /// <remarks>
    /// §7's APOP digest is <c>MD5(timestamp + shared-secret)</c>, which the server can only
    /// compute if it holds the secret. This server stores password verifiers it cannot reverse,
    /// so APOP is not declined but impossible — and <see cref="Pop3Responses.Greeting"/>
    /// guarantees the greeting carries no angle brackets, which RFC 2449 §6 makes the signal that
    /// a client should not try.
    /// </remarks>
    private static Pop3CommandResult Apop() =>
        new(Pop3Response.Error("APOP is not supported; use STLS and USER/PASS"));

    /// <summary>
    /// What a refused login says.
    /// </summary>
    /// <remarks>
    /// Names the remedy rather than merely refusing. A client told only "-ERR" on port 110 will
    /// show its user a password error for what is actually a policy: the password may not cross
    /// the network in the clear.
    /// </remarks>
    private string RefusalText =>
        _options.AuthenticationAvailable && !_session.IsTlsActive
            ? "Plaintext authentication is not permitted without TLS; issue STLS first"
            : "Authentication is not available";

    // ---------------------------------------------------------------------------------------
    // TRANSACTION state.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <c>NOOP</c> — RFC 1939 §5. "The POP3 server does nothing, it merely replies."
    /// </summary>
    private Pop3CommandResult Noop(Pop3Command command) =>
        _session.State == Pop3SessionState.Transaction
            ? new Pop3CommandResult(Pop3Response.Ok(string.Empty))
            : new Pop3CommandResult(Pop3Responses.WrongState(command.Keyword));

    /// <summary><c>STAT</c> — the drop listing. RFC 1939 §5.</summary>
    private Pop3CommandResult Stat()
    {
        if (_session.Maildrop is not { } maildrop)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState("STAT"));
        }

        return new Pop3CommandResult(Pop3Responses.Stat(maildrop.Count, maildrop.TotalOctets));
    }

    /// <summary>
    /// <c>LIST</c> — the scan listing. RFC 1939 §5.
    /// </summary>
    /// <remarks>
    /// §5: with an argument the response is one line; without one it is multi-line, and "If there
    /// are no messages in the maildrop, then the POP3 server responds with no scan listings — it
    /// issues a positive response followed by a line containing a termination octet and a CRLF
    /// pair."
    /// </remarks>
    private Pop3CommandResult List(Pop3Command command) =>
        Listing(command, "LIST", slot => Pop3Responses.ScanLine(slot.Number, slot.SizeBytes));

    /// <summary><c>UIDL</c> — the unique-id listing. RFC 1939 §7.</summary>
    private Pop3CommandResult Uidl(Pop3Command command) =>
        Listing(command, "UIDL", slot => Pop3Responses.UniqueLine(slot.Number, slot.UniqueId));

    /// <summary>
    /// The shape <c>LIST</c> and <c>UIDL</c> share.
    /// </summary>
    /// <remarks>
    /// §5 and §7 describe them in the same words down to the sentence "Note that messages marked
    /// as deleted are not listed", so writing them twice would be two chances to honour it once.
    /// </remarks>
    private Pop3CommandResult Listing(
        Pop3Command command,
        string keyword,
        Func<Pop3MessageSlot, string> line)
    {
        if (_session.Maildrop is not { } maildrop)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState(keyword));
        }

        string argument = command.Argument.Trim();

        if (argument.Length == 0)
        {
            List<string> lines = [];

            foreach (Pop3MessageSlot slot in maildrop.Live)
            {
                lines.Add(line(slot));
            }

            return new Pop3CommandResult(Pop3Response.OkWithLines(
                string.Create(CultureInfo.InvariantCulture, $"{maildrop.Count} messages"),
                lines));
        }

        if (!Pop3Command.TryReadNumber(argument, out int number) ||
            !maildrop.TryGet(number, out Pop3MessageSlot single))
        {
            return new Pop3CommandResult(Pop3Responses.NoSuchMessage(maildrop.Count));
        }

        return new Pop3CommandResult(Pop3Response.Ok(line(single)));
    }

    /// <summary>
    /// <c>DELE</c> — marks a message. RFC 1939 §5.
    /// </summary>
    /// <remarks>
    /// §5: "The POP3 server marks the message as deleted. Any future reference to the
    /// message-number associated with the message in a POP3 command generates an error. The POP3
    /// server does not actually delete the message until the POP3 session enters the UPDATE
    /// state."
    /// </remarks>
    private Pop3CommandResult Dele(Pop3Command command)
    {
        if (_session.Maildrop is not { } maildrop)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState("DELE"));
        }

        string argument = command.Argument.Trim();

        if (!Pop3Command.TryReadNumber(argument, out int number))
        {
            return new Pop3CommandResult(Pop3Responses.NoSuchMessage(maildrop.Count));
        }

        // §5's own example distinguishes the two refusals: "-ERR message 2 already deleted".
        if (maildrop.IsMarked(number))
        {
            return new Pop3CommandResult(Pop3Response.Error(string.Create(
                CultureInfo.InvariantCulture,
                $"message {number} already deleted")));
        }

        if (!maildrop.Mark(number))
        {
            return new Pop3CommandResult(Pop3Responses.NoSuchMessage(maildrop.Count));
        }

        return new Pop3CommandResult(Pop3Response.Ok(string.Create(
            CultureInfo.InvariantCulture,
            $"message {number} deleted")));
    }

    /// <summary>
    /// <c>RSET</c> — RFC 1939 §5. "If any messages have been marked as deleted […] they are
    /// unmarked."
    /// </summary>
    private Pop3CommandResult Rset()
    {
        if (_session.Maildrop is not { } maildrop)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState("RSET"));
        }

        maildrop.Reset();

        return new Pop3CommandResult(Pop3Response.Ok(string.Create(
            CultureInfo.InvariantCulture,
            $"maildrop has {maildrop.Count} messages ({maildrop.TotalOctets} octets)")));
    }

    /// <summary>
    /// <c>RETR</c> — a whole message. RFC 1939 §5.
    /// </summary>
    /// <remarks>
    /// §5: "the POP3 server sends the message corresponding to the given message-number, being
    /// careful to byte-stuff the termination character (as with all multi-line responses)." The
    /// stuffing and the terminator are <see cref="Pop3DotStuffing.Frame"/>'s, so no call site can
    /// perform one without the other.
    /// </remarks>
    private async ValueTask<Pop3CommandResult> RetrAsync(
        Pop3Command command,
        CancellationToken cancellationToken)
    {
        if (_session.Maildrop is not { } maildrop)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState("RETR"));
        }

        if (!Pop3Command.TryReadNumber(command.Argument.Trim(), out int number) ||
            !maildrop.TryGet(number, out Pop3MessageSlot slot))
        {
            return new Pop3CommandResult(Pop3Responses.NoSuchMessage(maildrop.Count));
        }

        ReadOnlyMemory<byte>? content = await ReadAsync(slot, cancellationToken)
            .ConfigureAwait(false);

        if (content is null)
        {
            return new Pop3CommandResult(Pop3Response.Error("Message could not be read"));
        }

        return new Pop3CommandResult(Pop3Response.OkWithOctets(
            string.Create(CultureInfo.InvariantCulture, $"{slot.SizeBytes} octets"),
            Pop3DotStuffing.Frame(content.Value)));
    }

    /// <summary>
    /// <c>TOP</c> — the header and the first lines of the body. RFC 1939 §7.
    /// </summary>
    /// <remarks>
    /// §7: "a message-number (required) which may NOT refer to a message marked as deleted, and a
    /// non-negative number of lines (required)". Both are required, so a bare <c>TOP 1</c> is a
    /// malformed command rather than a request for the header alone — <c>TOP 1 0</c> is how a
    /// client asks for that.
    /// </remarks>
    private async ValueTask<Pop3CommandResult> TopAsync(
        Pop3Command command,
        CancellationToken cancellationToken)
    {
        if (_session.Maildrop is not { } maildrop)
        {
            return new Pop3CommandResult(Pop3Responses.WrongState("TOP"));
        }

        string[] arguments = command.Argument.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (arguments.Length != 2 ||
            !Pop3Command.TryReadNumber(arguments[0], out int number) ||
            !Pop3Command.TryReadNumber(arguments[1], out int lines))
        {
            return new Pop3CommandResult(Pop3Response.Error("TOP requires a message number and a line count"));
        }

        if (!maildrop.TryGet(number, out Pop3MessageSlot slot))
        {
            return new Pop3CommandResult(Pop3Responses.NoSuchMessage(maildrop.Count));
        }

        ReadOnlyMemory<byte>? content = await ReadAsync(slot, cancellationToken)
            .ConfigureAwait(false);

        if (content is null)
        {
            return new Pop3CommandResult(Pop3Response.Error("Message could not be read"));
        }

        return new Pop3CommandResult(Pop3Response.OkWithOctets(
            "top of message follows",
            Pop3DotStuffing.Frame(Pop3DotStuffing.Top(content.Value, lines))));
    }

    /// <summary>
    /// <c>QUIT</c> — RFC 1939 §4 and §6.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §6: "When the client issues the QUIT command from the TRANSACTION state, the POP3 session
    /// enters the UPDATE state. (Note that if the client issues the QUIT command from the
    /// AUTHORIZATION state, the POP3 session terminates but does NOT enter the UPDATE state.)"
    /// </para>
    /// <para>
    /// <b>The removal is the only thing the UPDATE state does, and only a <c>QUIT</c> reaches
    /// it.</b> §6: "If a session terminates for some reason other than a client-issued QUIT
    /// command, the POP3 session does NOT enter the UPDATE state and MUST not remove any messages
    /// from the maildrop." A dropped connection therefore removes nothing, which is what makes
    /// "leave mail on server" safe against a flaky network.
    /// </para>
    /// <para>
    /// <b>The lock is released whether or not the removal worked.</b> §6: "Whether the removal was
    /// successful or not, the server then releases any exclusive-access lock on the maildrop and
    /// closes the TCP connection."
    /// </para>
    /// </remarks>
    private async ValueTask<Pop3CommandResult> QuitAsync(CancellationToken cancellationToken)
    {
        if (_session.State != Pop3SessionState.Transaction || _session.Maildrop is not { } maildrop)
        {
            ReleaseMaildrop();

            return new Pop3CommandResult(
                Pop3Response.Ok("POP3 server signing off"),
                Pop3SessionAction.CloseAfterResponse);
        }

        _session.EnterUpdate();

        IReadOnlyList<long> marked = maildrop.MarkedUids;
        bool removed = true;

        if (marked.Count > 0 && _writer is not null)
        {
            try
            {
                await _writer
                    .DeleteMessagesAsync(
                        _session.AuthenticatedMailboxId!.Value,
                        _session.MaildropFolderId!.Value,
                        marked,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // §6 has a reply for exactly this: "-ERR some deleted messages not removed".
                _logger.LogError(ex, "A POP3 session's deletions could not be committed.");

                removed = false;
            }
        }
        else if (marked.Count > 0)
        {
            removed = false;
        }

        ReleaseMaildrop();

        return new Pop3CommandResult(
            removed
                ? Pop3Response.Ok(string.Create(
                    CultureInfo.InvariantCulture,
                    $"POP3 server signing off ({maildrop.Count} messages left)"))
                : Pop3Response.Error("some deleted messages not removed"),
            Pop3SessionAction.CloseAfterResponse);
    }

    /// <summary>
    /// Reads one message's octets, or null when they cannot be read.
    /// </summary>
    /// <remarks>
    /// Whole rather than streamed, for the same reason IMAP's <c>FETCH</c> reads whole: the
    /// stuffing has to be applied before the first octet goes out, so a stream would have to be
    /// transformed on the way anyway. <c>docs/POP3.md</c> records what that costs.
    /// </remarks>
    private async ValueTask<ReadOnlyMemory<byte>?> ReadAsync(
        Pop3MessageSlot slot,
        CancellationToken cancellationToken)
    {
        if (_mailboxes is null || _messages is null)
        {
            return null;
        }

        IReadOnlyDictionary<long, StoredMessageId> located = await _mailboxes
            .ReadMessageIdsAsync(
                _session.AuthenticatedMailboxId!.Value,
                _session.MaildropFolderId!.Value,
                [slot.Uid],
                cancellationToken)
            .ConfigureAwait(false);

        if (!located.TryGetValue(slot.Uid, out StoredMessageId messageId))
        {
            return null;
        }

        try
        {
            await using Stream stream = await _messages
                .OpenReadAsync(messageId, cancellationToken)
                .ConfigureAwait(false);

            using MemoryStream buffer = new();

            await stream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);

            return buffer.ToArray();
        }
        catch (IOException ex)
        {
            // A row naming a file that is not there. One unreadable message must not end the
            // session: the client can still fetch the others.
            _logger.LogWarning(ex, "A stored message could not be read for POP3.");

            return null;
        }
    }
}
