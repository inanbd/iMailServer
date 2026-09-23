using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Infrastructure.Time;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Imap;

/// <summary>What the connection loop must do after sending the responses.</summary>
public enum ImapSessionAction
{
    /// <summary>Carry on reading commands.</summary>
    Continue = 0,

    /// <summary>
    /// Send the responses, perform the TLS handshake, then carry on.
    /// </summary>
    /// <remarks>
    /// RFC 3501 §6.2.1: the handshake begins immediately after the tagged <c>OK</c>, and the
    /// server must discard anything read from the client beforehand. The loop owns both — the
    /// stream to wrap and the reader to empty — so this action is how the processor asks for
    /// them without holding either.
    /// </remarks>
    StartTlsHandshake = 1,

    /// <summary>Send the responses, then close the connection.</summary>
    CloseAfterResponse = 2,

    /// <summary>
    /// Send the continuation request, then read one more line and feed it back through
    /// <see cref="ImapCommandProcessor.ContinueAuthenticationAsync"/>.
    /// </summary>
    /// <remarks>
    /// The line that comes back is a credential, not a command, and it must never reach the
    /// command parser — which is why it has its own action rather than being read by the
    /// ordinary loop. The same reasoning as <see cref="Smtp.SmtpSessionAction"/>'s equivalent,
    /// and it matters more here: an IMAP line that reached the parser would be echoed into the
    /// <c>BAD</c> it earned.
    /// </remarks>
    ReadAuthenticationResponse = 3,

    /// <summary>
    /// Hold the connection idle, pushing mailbox updates, until the client sends <c>DONE</c>.
    /// </summary>
    /// <remarks>
    /// RFC 2177 §3: "The IDLE command remains active until the client responds to the
    /// continuation, and as long as an IDLE command is active, the server is now free to send
    /// untagged EXISTS, EXPUNGE, and other messages at any time." Only the loop can do that: it
    /// owns the stream and the clock, and the processor owns neither.
    /// </remarks>
    Idle = 4,
}

/// <summary>Responses to send, and what to do next.</summary>
/// <remarks>
/// A list rather than one response, which is the shape difference from
/// <see cref="Smtp.SmtpCommandResult"/>. An SMTP command produces exactly one reply; an IMAP
/// command routinely produces several — untagged data first, then the tagged completion that
/// ends it. <c>SELECT</c> emits eight. Modelling that as one response with the rest smuggled
/// into its text is how a server ends up building line structure out of strings, which is
/// precisely what <see cref="ImapResponse"/> exists to prevent.
/// </remarks>
public sealed record ImapCommandResult(
    IReadOnlyList<ImapResponse> Responses,
    ImapSessionAction Action = ImapSessionAction.Continue)
{
    /// <summary>One response, and carry on.</summary>
    public static ImapCommandResult Single(
        ImapResponse response,
        ImapSessionAction action = ImapSessionAction.Continue) =>
        new([response], action);
}

/// <summary>Everything the processor needs that comes from configuration.</summary>
/// <param name="ProductName">Product string for the greeting.</param>
/// <param name="Role">The listener this connection arrived on.</param>
/// <param name="IsAuthenticationAvailable">
/// Whether <c>LOGIN</c>/<c>AUTHENTICATE</c> are implemented and enabled. False turns them into
/// refusals and turns <c>LOGINDISABLED</c> on, which is the truthful pairing.
/// </param>
/// <param name="MaxAuthenticationAttempts">
/// Failed attempts allowed on one connection before it is closed. From
/// <c>MailServer:Limits:MaxAuthAttemptsPerSession</c>.
/// </param>
public sealed record ImapProcessorOptions(
    string ProductName,
    ImapListenerRole Role,
    bool IsAuthenticationAvailable = false,
    int MaxAuthenticationAttempts = 3);

/// <summary>
/// Turns one parsed command into the responses it earns, against one session.
/// </summary>
/// <remarks>
/// <para>
/// The order of the checks is the design, and it is the same order
/// <see cref="Smtp.SmtpCommandProcessor"/> uses: whether the command exists, then whether it is
/// in sequence, then whether policy permits it, and only then its arguments. A command that is
/// out of sequence is refused before anything parses what it carries — which on this protocol
/// also means before anything can be echoed back, since the text of a refusal is the one place
/// a client's bytes reach the wire.
/// </para>
/// <para>
/// The processor never touches the socket. It is handed a command and returns responses and an
/// action, which makes the whole command surface testable without a network — including the
/// refusals, which are the part that matters and the part hardest to provoke against a real
/// listener.
/// </para>
/// <para>
/// <b>What is implemented here is deliberately a fraction of RFC 3501.</b> The any-state
/// commands, <c>STARTTLS</c> and authentication need nothing but the session; every command that
/// touches a mailbox needs reads this repository does not have yet. Those are answered with a
/// tagged <c>NO</c> saying so, rather than left to fall through a default into something that
/// looks like success. <see cref="ImapCapabilities"/> is told the same truth, so a client is
/// never offered a command this refuses.
/// </para>
/// </remarks>
public sealed class ImapCommandProcessor
{
    private readonly ImapSessionContext _session;
    private readonly ImapProcessorOptions _options;
    private readonly ILogger _logger;
    private readonly IMailboxAuthenticator _authenticator;
    private readonly IImapMailboxReader? _mailboxes;

    private readonly IImapMailboxWriter? _writer;

    /// <summary>
    /// The clock for anything this session writes.
    /// </summary>
    /// <remarks>
    /// Not <see cref="ImapSessionContext.StartedAt"/>, which is when the connection opened. An
    /// IMAP session can stay open for hours - RFC 3501 §5.4 requires a server to tolerate 30
    /// minutes of silence and clients hold connections far longer than that - so stamping a
    /// folder created near the end of one with the time it began would be wrong by the length of
    /// the session, and UIDVALIDITY is derived from that stamp.
    /// </remarks>
    private readonly IClock _clock;

    /// <summary>Where a message's octets live. Null until a listener supplies one.</summary>
    private readonly IMessageStore? _messages;

    /// <summary>The mechanism mid-exchange, or null when no <c>AUTHENTICATE</c> is in flight.</summary>
    private ISaslMechanism? _mechanism;

    /// <summary>The tag of the in-flight <c>AUTHENTICATE</c>, so its completion can be tagged.</summary>
    /// <remarks>
    /// Held because the continuation line carries no tag of its own: RFC 3501 §7.5's exchange is
    /// one command spread over several lines, and the completion belongs to the command that
    /// started it. A server that lost the tag could only answer untagged, and the client would
    /// wait for a completion it never got.
    /// </remarks>
    private string? _authenticatingTag;

    public ImapCommandProcessor(
        ImapSessionContext session,
        ImapProcessorOptions options,
        ILogger logger,
        IMailboxAuthenticator? authenticator = null,
        IImapMailboxReader? mailboxes = null,
    IImapMailboxWriter? writer = null,
    IClock? clock = null,
    IMessageStore? messages = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _session = session;
        _options = options;
        _logger = logger;

        // Optional so a test can build a processor for the many paths that never authenticate.
        // A session that reaches LOGIN without one is refused, not crashed.
        _authenticator = authenticator ?? UnavailableAuthenticator.Instance;

        // Null is a legitimate configuration rather than a missing dependency, and it is what
        // makes the "not implemented yet" answers below honest rather than a stub: a processor
        // built without a reader refuses every mailbox command instead of pretending.
        _mailboxes = mailboxes;
        _writer = writer;
        _clock = clock ?? new SystemClock();
        _messages = messages;
    }

    /// <summary>The session this processor drives.</summary>
    public ImapSessionContext Session => _session;

    /// <summary>Whether an <c>AUTHENTICATE</c> exchange is waiting for the client's next line.</summary>
    public bool IsAuthenticationInFlight => _mechanism is not null;

    /// <summary>The capability listing for the session as it stands right now.</summary>
    public IReadOnlyList<string> Capabilities() => ImapCapabilities.For(CapabilityContext());

    /// <summary>
    /// The greeting sent when the connection opens. RFC 3501 §7.1.1.
    /// </summary>
    /// <remarks>
    /// Carries the capability listing inline, which RFC 3501 §7.2.1 permits and which saves the
    /// client the round trip it would otherwise spend on <c>CAPABILITY</c> before it can decide
    /// whether it may log in.
    /// </remarks>
    public ImapResponse Greeting() => ImapResponses.Greeting(_options.ProductName, Capabilities());

    /// <summary>
    /// The answer to a line whose tag could not be parsed.
    /// </summary>
    /// <remarks>
    /// Untagged, necessarily: RFC 3501 §7.1.3's untagged <c>BAD</c> is defined for "a
    /// protocol-level error for which the associated command can not be determined", and there
    /// is nothing to tag the answer with. The offending tag is not echoed in any form — see
    /// <see cref="ImapCommand.TryParse"/> on why repairing it would be worse than refusing it.
    /// </remarks>
    public ImapCommandResult MalformedLine(ImapTagFailure failure) =>
        ImapCommandResult.Single(ImapResponses.UntaggedBad(failure switch
        {
            ImapTagFailure.Missing => "Every command must begin with a tag",
            ImapTagFailure.TooLong => "Tag too long",
            _ => "Invalid tag",
        }));

    /// <summary>Executes one command.</summary>
    public async ValueTask<ImapCommandResult> ExecuteAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.Verb == ImapVerb.Unknown)
        {
            // Not echoed. The unrecognised word is the client's own text, and the one thing a
            // refusal must not do is quote it back; an operator who needs it can read the
            // connection log at Debug.
            _logger.LogDebug(
                "Unrecognised IMAP command from {RemoteAddress}.",
                _session.RemoteAddress.Value);

            return ImapCommandResult.Single(ImapResponses.Bad(command.Tag, "Unrecognised command"));
        }

        if (!ImapStateMachine.IsInSequence(_session.State, command.Verb))
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                $"{Describe(command.Verb)} is not valid in this state"));
        }

        if (command.Verb != ImapVerb.Idle)
        {
            // Every command but IDLE ends any flag watch, which is deliberately the inverse of
            // listing the commands that invalidate one - see ImapSessionContext.FlagWatch. IDLE
            // is exempt so that a client following RFC 2177 §3's advice to re-issue it "at least
            // every 29 minutes" keeps the watch across the DONE rather than restarting it from
            // whatever the folder looks like by then.
            _session.EndFlagWatch();
        }

        return command.Verb switch
        {
            ImapVerb.Capability => Capability(command.Tag),
            ImapVerb.Noop => ImapCommandResult.Single(ImapResponses.Ok(command.Tag, "NOOP completed")),
            ImapVerb.Logout => Logout(command.Tag),
            ImapVerb.StartTls => StartTls(command.Tag),
            ImapVerb.Login => await LoginAsync(command, cancellationToken).ConfigureAwait(false),
            ImapVerb.Authenticate => await AuthenticateAsync(command, cancellationToken).ConfigureAwait(false),
            ImapVerb.Select => await SelectAsync(command, readOnly: false, cancellationToken).ConfigureAwait(false),
            ImapVerb.Examine => await SelectAsync(command, readOnly: true, cancellationToken).ConfigureAwait(false),
            ImapVerb.List => await ListAsync(command, subscribedOnly: false, cancellationToken).ConfigureAwait(false),
            ImapVerb.Lsub => await ListAsync(command, subscribedOnly: true, cancellationToken).ConfigureAwait(false),
            ImapVerb.Status => await StatusAsync(command, cancellationToken).ConfigureAwait(false),
            ImapVerb.Fetch => await FetchAsync(command, cancellationToken).ConfigureAwait(false),
            ImapVerb.Store => await StoreAsync(command, cancellationToken).ConfigureAwait(false),
            ImapVerb.Expunge => await ExpungeAsync(command, cancellationToken).ConfigureAwait(false),
            ImapVerb.Close => await CloseAsync(command, cancellationToken).ConfigureAwait(false),
            ImapVerb.Check => Check(command),
            ImapVerb.Unselect => Unselect(command),
            ImapVerb.Namespace => Namespace(command),
            ImapVerb.Create => await FolderAsync(command, ImapFolderCommand.Create, cancellationToken).ConfigureAwait(false),
            ImapVerb.Delete => await FolderAsync(command, ImapFolderCommand.Delete, cancellationToken).ConfigureAwait(false),
            ImapVerb.Rename => await FolderAsync(command, ImapFolderCommand.Rename, cancellationToken).ConfigureAwait(false),
            ImapVerb.Subscribe => await FolderAsync(command, ImapFolderCommand.Subscribe, cancellationToken).ConfigureAwait(false),
            ImapVerb.Unsubscribe => await FolderAsync(command, ImapFolderCommand.Unsubscribe, cancellationToken).ConfigureAwait(false),
            ImapVerb.Copy => await CopyAsync(command, move: false, cancellationToken).ConfigureAwait(false),
            ImapVerb.Move => await CopyAsync(command, move: true, cancellationToken).ConfigureAwait(false),
            ImapVerb.Append => AppendRefusal(command),
            ImapVerb.Search => await SearchAsync(command, cancellationToken).ConfigureAwait(false),
            ImapVerb.Idle => Idle(command),
            _ => NotImplemented(command),
        };
    }

    private ImapCommandResult Capability(string tag) =>
        new([ImapResponses.Capability(Capabilities()), ImapResponses.Ok(tag, "CAPABILITY completed")]);

    /// <summary>RFC 3501 §6.1.3.</summary>
    /// <remarks>
    /// The untagged <c>BYE</c> comes first and the tagged <c>OK</c> second, in that order and
    /// both of them. §6.1.3 is explicit: "The server MUST send a BYE untagged response before
    /// the (tagged) OK response". A client that saw only the <c>OK</c> would have no way to tell
    /// an orderly close from the connection dropping.
    /// </remarks>
    private ImapCommandResult Logout(string tag)
    {
        _session.Logout();

        return new ImapCommandResult(
            [
                ImapResponses.Bye("IMAP4rev1 server logging out"),
                ImapResponses.Ok(tag, "LOGOUT completed"),
            ],
            ImapSessionAction.CloseAfterResponse);
    }

    /// <summary>RFC 3501 §6.2.1.</summary>
    /// <remarks>
    /// Refused inside the tunnel it would create, and refused on the implicit-TLS listener,
    /// where the connection was encrypted before the greeting. Neither is caught by
    /// <see cref="ImapStateMachine"/>: a successful <c>STARTTLS</c> leaves the session in the
    /// not-authenticated state, so sequencing alone would let a client ask twice.
    /// <see cref="ImapCapabilities.MayOfferStartTls"/> already declines to advertise it in both
    /// cases, and this refuses it as well — a defence resting on advertisement alone fails the
    /// moment a client guesses.
    /// </remarks>
    private ImapCommandResult StartTls(string tag)
    {
        if (_options.Role == ImapListenerRole.ImplicitTls)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(tag, "STARTTLS is not available on this listener"));
        }

        if (_session.IsTlsActive)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(tag, "TLS is already active"));
        }

        return ImapCommandResult.Single(
            ImapResponses.Ok(tag, "Begin TLS negotiation now"),
            ImapSessionAction.StartTlsHandshake);
    }

    /// <summary>
    /// RFC 3501 §6.2.3.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The argument is a username and a password in the clear.</b> Unlike SMTP's
    /// <c>AUTH PLAIN</c>, nothing about it is encoded. It is never logged, never echoed, and
    /// never reaches a response — including the refusals, which say only that the attempt
    /// failed.
    /// </para>
    /// <para>
    /// The TLS check is not redundant with <c>LOGINDISABLED</c>. RFC 2595 §3.2's capability
    /// tells a complying client not to try; this is what happens when one tries anyway, and
    /// RFC 3501 §6.2.3 requires the refusal to exist as well as the advertisement.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> LoginAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        if (!_session.IsTlsActive)
        {
            return ImapCommandResult.Single(
                ImapResponses.No(command.Tag, "LOGIN is disabled without TLS"));
        }

        if (!_options.IsAuthenticationAvailable)
        {
            return ImapCommandResult.Single(ImapResponses.No(command.Tag, "LOGIN is not available"));
        }

        if (HasExhaustedAttempts)
        {
            return TooManyAttempts(command.Tag);
        }

        ImapAstringReader reader = new(command.Argument, command.Literals);

        if (!reader.TryReadText(out string? user) ||
            !reader.TryReadText(out string? password) ||
            !reader.AtEnd)
        {
            // A BAD, not a NO: the command was malformed rather than refused. Note what is not
            // said - nothing about which of the two arguments was wrong, because "the username
            // was fine" is a fact about which mailboxes exist.
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "LOGIN expects a userid and a password"));
        }

        return await VerifyAsync(command.Tag, user, password, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>RFC 3501 §6.2.2.</summary>
    /// <remarks>
    /// The mechanisms are <see cref="ImapCapabilities.SaslMechanisms"/>'s, which are
    /// <see cref="SmtpCapabilities"/>'s — one list for both protocols, so the advertised set and
    /// the implemented set cannot drift apart in one protocol and not the other. RFC 3501 §6.2.2
    /// specifies only that this protocol's SASL service name is <c>imap</c>, and neither PLAIN
    /// nor LOGIN carries a service name, so the mechanisms themselves need no IMAP variant.
    /// </remarks>
    private async ValueTask<ImapCommandResult> AuthenticateAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        if (!_session.IsTlsActive)
        {
            return ImapCommandResult.Single(
                ImapResponses.No(command.Tag, "AUTHENTICATE is disabled without TLS"));
        }

        if (!_options.IsAuthenticationAvailable)
        {
            return ImapCommandResult.Single(
                ImapResponses.No(command.Tag, "AUTHENTICATE is not available"));
        }

        if (HasExhaustedAttempts)
        {
            return TooManyAttempts(command.Tag);
        }

        ImapAstringReader reader = new(command.Argument, command.Literals);

        if (!reader.TryReadText(out string? mechanismName))
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "AUTHENTICATE expects a mechanism"));
        }

        // RFC 4959's initial response rides on the same line. It is base64 and it is a
        // credential, so it is read but never reported.
        string? initialResponse = reader.AtEnd ? null : reader.Remainder.Trim();

        ISaslMechanism? mechanism = SaslMechanisms.Create(mechanismName);

        if (mechanism is null)
        {
            // Logged at Debug, not echoed. A client that sends "AUTHENTICATE <base64>" with no
            // mechanism puts its credential in the mechanism position, and no shape test
            // separates that from a mistyped mechanism name.
            _logger.LogDebug(
                "Unsupported SASL mechanism requested from {RemoteAddress}.",
                _session.RemoteAddress.Value);

            return ImapCommandResult.Single(
                ImapResponses.No(command.Tag, "Unsupported authentication mechanism"));
        }

        _mechanism = mechanism;
        _authenticatingTag = command.Tag;

        return await AdvanceAsync(mechanism.Start(initialResponse), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Feeds the client's answer to a continuation request back into the in-flight exchange.
    /// </summary>
    /// <remarks>
    /// The line is a credential. It reaches this method directly from the connection loop and is
    /// never parsed as a command — a session mid-<c>AUTHENTICATE</c> has no command grammar, and
    /// treating the line as one would turn a password into a verb and then echo it inside the
    /// <c>BAD</c> that verb earned.
    /// </remarks>
    public async ValueTask<ImapCommandResult> ContinueAuthenticationAsync(
        string response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (_mechanism is null || _authenticatingTag is null)
        {
            // A caller bug rather than a client one: the loop asked for a continuation line
            // without an exchange in flight.
            return ImapCommandResult.Single(ImapResponses.UntaggedBad("No authentication in progress"));
        }

        // RFC 3501 §6.2.2: "If the client wishes to cancel an authentication exchange, it issues
        // a line consisting of a single '*'." The mechanisms treat it as a cancellation too, but
        // checking here keeps the meaning where the protocol puts it.
        return await AdvanceAsync(_mechanism.Advance(response), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Turns one SASL step into responses, verifying the credential when there is one.</summary>
    private async ValueTask<ImapCommandResult> AdvanceAsync(
        SaslStep step,
        CancellationToken cancellationToken)
    {
        string tag = _authenticatingTag ?? throw new InvalidOperationException("No tag for the exchange.");

        switch (step.Outcome)
        {
            case SaslOutcome.Challenge:
                return ImapCommandResult.Single(
                    ImapResponse.Continuation(step.Challenge ?? string.Empty),
                    ImapSessionAction.ReadAuthenticationResponse);

            case SaslOutcome.Completed when step.Credential is not null:
                using (SaslCredential credential = step.Credential)
                {
                    EndExchange();

                    return await VerifyAsync(
                        tag,
                        credential.AuthenticationIdentity,
                        credential,
                        cancellationToken).ConfigureAwait(false);
                }

            case SaslOutcome.Cancelled:
                EndExchange();
                return ImapCommandResult.Single(ImapResponses.Bad(tag, "Authentication cancelled"));

            default:
                EndExchange();
                return CountFailure(tag, step.Diagnostic);
        }
    }

    /// <summary>Verifies a <c>LOGIN</c>'s two arguments.</summary>
    private async ValueTask<ImapCommandResult> VerifyAsync(
        string tag,
        string user,
        string password,
        CancellationToken cancellationToken)
    {
        // The buffer is this method's to own and clear, which is what SaslCredential's contract
        // asks for; the string the reader produced cannot be cleared, and that is a limitation of
        // reading a line into a string at all rather than of this path.
        using SaslCredential credential = new(user, user, password.ToCharArray());

        return await VerifyAsync(tag, user, credential, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<ImapCommandResult> VerifyAsync(
        string tag,
        string identity,
        SaslCredential credential,
        CancellationToken cancellationToken)
    {
        MailboxAuthenticationResult result = await _authenticator
            .AuthenticateAsync(credential, MailboxAccess.Imap, _session.RemoteAddress, cancellationToken)
            .ConfigureAwait(false);

        if (!result.IsSuccess || result.Mailbox is null || result.MailboxId is null)
        {
            // One answer for a wrong password, an unknown mailbox and a locked-out one alike -
            // see MailboxAuthenticationOutcome's own remarks. Any difference between them, in
            // the response or in the timing, tells an attacker which addresses exist.
            return CountFailure(tag, result.Diagnostic);
        }

        if (!EmailAddress.TryParse(identity, out EmailAddress? address))
        {
            // The authenticator said yes to something that is not an address. Treated as a
            // failure rather than trusted, because the session's identity is what every later
            // authorisation decision is made against.
            return CountFailure(tag, "The authenticated identity is not a mailbox address.");
        }

        _session.Authenticate(result.MailboxId.Value, address);

        _logger.LogInformation(
            "IMAP session authenticated from {RemoteAddress}.",
            _session.RemoteAddress.Value);

        // RFC 3501 §7.2.1: the capability list changes on authentication - STARTTLS,
        // LOGINDISABLED and the AUTH= atoms all drop out - so it rides on the completion and
        // saves the client a round trip discovering that.
        return ImapCommandResult.Single(ImapResponses.Ok(
            tag,
            "Authentication successful",
            ImapResponseCode.Capability(Capabilities())));
    }

    /// <summary>Counts a failed attempt and closes the session once the budget is spent.</summary>
    private ImapCommandResult CountFailure(string tag, string? diagnostic)
    {
        int attempts = _session.RecordFailedAuthentication();

        _logger.LogWarning(
            "IMAP authentication failed from {RemoteAddress} (attempt {Attempt}): {Diagnostic}",
            _session.RemoteAddress.Value,
            attempts,
            diagnostic ?? "no diagnostic");

        if (attempts >= _options.MaxAuthenticationAttempts)
        {
            return TooManyAttempts(tag);
        }

        return ImapCommandResult.Single(ImapResponses.No(tag, "Authentication failed"));
    }

    /// <summary>
    /// The refusal that ends the connection.
    /// </summary>
    /// <remarks>
    /// An untagged <c>BYE</c> before the tagged <c>NO</c>, because the connection is about to go
    /// away and RFC 3501 §7.1.5 is how a server says so. Closing without one is
    /// indistinguishable from a network failure, which invites the reconnect-and-retry loop that
    /// makes an attempt limit pointless.
    /// </remarks>
    private ImapCommandResult TooManyAttempts(string tag) =>
        new(
            [
                ImapResponses.Bye("Too many authentication failures"),
                ImapResponses.No(tag, "Authentication failed"),
            ],
            ImapSessionAction.CloseAfterResponse);

    private bool HasExhaustedAttempts =>
        _session.FailedAuthenticationAttempts >= _options.MaxAuthenticationAttempts;

    private void EndExchange()
    {
        _mechanism?.Dispose();
        _mechanism = null;
        _authenticatingTag = null;
    }

    /// <summary>
    /// <c>SELECT</c> and <c>EXAMINE</c>. RFC 3501 §6.3.1 and §6.3.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One method for both, because §6.3.2 defines <c>EXAMINE</c> as "identical to SELECT and
    /// returns the same output; however, the selected mailbox is identified as read-only". Two
    /// methods would be the same eight responses written twice, with the read-only flag as the
    /// only difference and two places for it to be got wrong.
    /// </para>
    /// <para>
    /// <b>The deselect happens first, and it happens even when the selection fails.</b>
    /// §6.3.1: "if a SELECT command that fails is attempted, no mailbox is selected." A session
    /// that had Inbox open and then asked for a folder that does not exist is left with nothing
    /// open — not with Inbox still open. Leaving the old selection in place would mean a
    /// following <c>FETCH</c> silently reads the wrong folder, which is the quiet,
    /// wrong-mail-to-the-user failure this subsystem is most dangerous for.
    /// </para>
    /// <para>
    /// The responses are in the order §6.3.1's own example gives, with the tagged completion
    /// last — which the RFC does require. <c>RECENT</c> is emitted as a truthful zero and
    /// <c>[UNSEEN]</c> is omitted when there is nothing unseen, both for the reasons
    /// <see cref="ImapResponses.Recent"/> and <see cref="ImapFolderSnapshot.HasUnseen"/> give.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> SelectAsync(
        ImapCommand command,
        bool readOnly,
        CancellationToken cancellationToken)
    {
        // Before anything can fail, so that every exit below leaves no mailbox selected unless
        // it selected one itself.
        _session.Deselect();

        if (_mailboxes is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null)
        {
            // Unreachable through the state machine, which refuses both commands before
            // authentication. Answered rather than asserted because a caller bug must not be a
            // dropped connection.
            return ImapCommandResult.Single(ImapResponses.Bad(command.Tag, "Not authenticated"));
        }

        ImapAstringReader reader = new(command.Argument, command.Literals);

        if (!reader.TryReadText(out string? wireName) || !reader.AtEnd)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, $"{Describe(command.Verb)} expects one mailbox name"));
        }

        if (!ImapMailboxName.TryDecode(wireName, out string? path))
        {
            // The name did not decode, so it names no folder. Refused without being echoed:
            // a malformed name is client text, and the one thing a refusal must not do is quote
            // it back.
            return ImapCommandResult.Single(
                ImapResponses.No(command.Tag, "Mailbox name is not valid modified UTF-7"));
        }

        ImapFolderSnapshot? snapshot = await _mailboxes
            .OpenFolderAsync(_session.AuthenticatedMailboxId.Value, path, cancellationToken)
            .ConfigureAwait(false);

        if (snapshot is null)
        {
            // No [TRYCREATE]: RFC 3501 §6.3.11 and §6.4.7 attach that code to APPEND and COPY,
            // where creating the mailbox and retrying is the recovery. A client cannot recover
            // from selecting a folder that is not there by creating one - it wanted the mail
            // that was supposed to be in it.
            return ImapCommandResult.Single(ImapResponses.No(command.Tag, "No such mailbox"));
        }

        _session.Select(snapshot.FolderId, snapshot.UidValidity, readOnly);
        _session.ReportExists(snapshot.ExistsCount);

        List<ImapResponse> responses =
        [
            ImapResponses.Flags(ImapFlagNames.Settable),
            ImapResponses.Exists(snapshot.ExistsCount),
            ImapResponses.Recent(0),
        ];

        if (snapshot.HasUnseen)
        {
            responses.Add(ImapResponse.Untagged(
                ImapResponseStatus.Ok,
                "First unseen message",
                ImapResponseCode.Unseen(snapshot.FirstUnseenSequenceNumber!.Value)));
        }

        responses.Add(ImapResponse.Untagged(
            ImapResponseStatus.Ok,
            "Flags permitted",

            // Empty for EXAMINE, and meaningfully so: nothing may be changed, so nothing
            // persists. RFC 3501 §6.3.2.
            ImapResponseCode.PermanentFlags(readOnly ? MessageFlags.None : ImapFlagNames.Settable)));

        responses.Add(ImapResponse.Untagged(
            ImapResponseStatus.Ok,
            "UIDs valid",
            ImapResponseCode.UidValidity(snapshot.UidValidity)));

        responses.Add(ImapResponse.Untagged(
            ImapResponseStatus.Ok,
            "Predicted next UID",
            ImapResponseCode.UidNext(snapshot.UidNext)));

        responses.Add(ImapResponses.Ok(
            command.Tag,
            $"{Describe(command.Verb)} completed",
            readOnly ? ImapResponseCode.ReadOnly : ImapResponseCode.ReadWrite));

        return new ImapCommandResult(responses);
    }

    /// <summary>
    /// The answer to a command this server understands, allows here, and has not built.
    /// </summary>
    /// <remarks>
    /// A tagged <c>NO</c> naming the command, not a <c>BAD</c>: the client's request was
    /// well-formed and in sequence, and telling it otherwise would send someone debugging a mail
    /// client looking for a syntax error that is not there. None of these is advertised in the
    /// capability listing either, so a complying client never sends one.
    /// </remarks>
    /// <summary>
    /// <c>LIST</c> and <c>LSUB</c> — RFC 3501 §6.3.8 and §6.3.9.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One handler for both, because the commands differ in their input and not in their
    /// logic.</b> §6.3.9: "The arguments to LSUB are in the same form as those for LIST." What
    /// changes is which folders are eligible — all of them, or the subscribed ones — and the
    /// keyword on the untagged line. Everything between is the same matching, so writing it
    /// twice would mean the <c>%</c> rule below could be fixed in one command and left wrong in
    /// the other.
    /// </para>
    /// <para>
    /// <b>The pattern is decoded from modified UTF-7 before it is matched, and the order
    /// matters.</b> Matching the encoded form would let an encoded run interact with a wildcard,
    /// because <c>&amp;</c> begins a base64 sequence and a <c>*</c> on either side of it would
    /// then be matched against characters that are not in the name the user sees. Decoding first
    /// is safe in the other direction: RFC 3501 §5.1.3's base64 alphabet uses <c>,</c> in place
    /// of <c>/</c> and contains neither wildcard, so decoding can neither introduce nor destroy
    /// one.
    /// </para>
    /// <para>
    /// <b>A trailing <c>%</c> obliges this server to report hierarchy levels that are not
    /// mailboxes.</b> §6.3.8: "If the <c>%</c> wildcard is the last character of a mailbox name
    /// argument, matching levels of hierarchy are also returned. If these levels of hierarchy are
    /// not also selectable mailboxes, they are returned with the <c>\Noselect</c> mailbox name
    /// attribute." So a mailbox holding only <c>Projects/2026/Q1</c> answers <c>LIST "" "%"</c>
    /// with <c>Projects</c> — a name no row in the table carries. Omitting it would show the
    /// client a tree with the trunk missing.
    /// </para>
    /// <para>
    /// <b>For <c>LSUB</c> the same rule is a MUST and is stranger.</b> §6.3.9: "Consider what
    /// happens if <c>foo/bar</c> […] is subscribed but <c>foo</c> is not. A <c>%</c> wildcard to
    /// LSUB must return foo, not foo/bar, in the LSUB response, and it MUST be flagged with the
    /// <c>\Noselect</c> attribute." Note what that means: <c>foo</c> may be a perfectly
    /// selectable mailbox and is still flagged <c>\Noselect</c>, because here the attribute is
    /// reporting absence from the subscription list rather than unselectability. It is the RFC's
    /// instruction and it is followed literally; a client that treats <c>LSUB</c>'s flags as
    /// authoritative has been told not to — §6.3.9: "the flags in the untagged LIST are
    /// considered more authoritative".
    /// </para>
    /// <para>
    /// <b>RFC 3348's child attributes are sent on <c>LSUB</c> too, which is a decision and not an
    /// oversight.</b> §3 anticipates the opposite: "The <c>\HasChildren</c> and
    /// <c>\HasNoChildren</c> attributes might not be returned in response to a LSUB response.
    /// Many servers maintain a simple mailbox subscription list that is not updated when the
    /// underlying mailbox structure is changed. A client MUST NOT assume that hierarchy
    /// information will be maintained in the subscription list." That is permission to omit them
    /// and a warning to clients, not a prohibition — and the reason it gives does not hold here,
    /// because this server's subscription flag is a column on the folder row, so the hierarchy
    /// behind it is the live one. The attribute is therefore a true statement about the mailbox
    /// rather than a stale one about a name list, and a client that ignores it loses nothing.
    /// </para>
    /// <para>
    /// <b>That coupling is also a known limitation, and this is where it will first bite.</b>
    /// §6.3.9: "The server MUST NOT unilaterally remove an existing mailbox name from the
    /// subscription list even if a mailbox by that name no longer exists." A subscription stored
    /// on the folder row cannot outlive the folder, so once <c>DELETE</c> exists this server will
    /// not be able to honour that MUST without moving subscriptions into a list of their own.
    /// Recorded rather than worked around, because the deviation is not reachable until
    /// <c>DELETE</c> is implemented and the fix is a schema change rather than a handler change.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> ListAsync(
        ImapCommand command,
        bool subscribedOnly,
        CancellationToken cancellationToken)
    {
        if (_mailboxes is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null)
        {
            // Unreachable through the state machine, which refuses both commands before
            // authentication. Answered rather than asserted for the reason SelectAsync gives.
            return ImapCommandResult.Single(ImapResponses.Bad(command.Tag, "Not authenticated"));
        }

        ImapAstringReader reader = new(command.Argument, command.Literals);

        if (!reader.TryReadText(out string? wireReference) ||
            !reader.TryReadListMailbox(out string? wirePattern) ||
            !reader.AtEnd)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                $"{Describe(command.Verb)} expects a reference name and a mailbox pattern"));
        }

        // RFC 3501 §6.3.8: "An empty ("" string) mailbox name argument is a special request to
        // return the hierarchy delimiter and the root name of the name given in the reference."
        // This server has no namespace prefixes and no break-out characters, so the root name of
        // every reference is the empty string - see ImapMailboxPattern.TryCombine. LSUB is
        // answered the same way: §6.3.9 does not restate the special case, but it does say the
        // arguments take the same form, and a client that probes with LSUB is better served by
        // the delimiter than by a bare OK.
        if (wirePattern.Length == 0)
        {
            return new ImapCommandResult(
                [
                    subscribedOnly
                        ? ImapResponses.LsubHierarchyDelimiter(string.Empty)
                        : ImapResponses.HierarchyDelimiter(string.Empty),
                    ImapResponses.Ok(command.Tag, $"{Describe(command.Verb)} completed"),
                ],
                ImapSessionAction.Continue);
        }

        if (!ImapMailboxName.TryDecode(wireReference, out string? reference) ||
            !ImapMailboxName.TryDecode(wirePattern, out string? decodedPattern))
        {
            // Refused without being echoed, as in SelectAsync: a malformed name is client text.
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "Mailbox name is not valid modified UTF-7"));
        }

        if (!ImapMailboxPattern.TryCombine(reference, decodedPattern, out ImapMailboxPattern? pattern))
        {
            // NO rather than BAD: §6.3.8's own result codes list "NO - list failure: can't list
            // that reference or name", which is exactly a pattern this server will not match.
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                $"{Describe(command.Verb)} pattern is too long"));
        }

        IReadOnlyList<ImapFolderListing> folders = await _mailboxes
            .ListFoldersAsync(_session.AuthenticatedMailboxId.Value, cancellationToken)
            .ConfigureAwait(false);

        // LSUB's names come from the subscription list, not from the folders. A subscription may
        // name a mailbox that no longer exists and RFC 3501 §6.3.6 requires it to survive that,
        // so deriving the set from the folders would silently drop exactly the names the MUST NOT
        // exists to protect.
        IReadOnlyList<string> subscribed = subscribedOnly
            ? await _mailboxes
                .ListSubscriptionsAsync(_session.AuthenticatedMailboxId.Value, cancellationToken)
                .ConfigureAwait(false)
            : [];

        List<ImapResponse> responses = [];

        foreach ((string name, ImapMailboxAttribute attributes) in
            Matches(folders, subscribed, pattern, subscribedOnly))
        {
            responses.Add(subscribedOnly
                ? ImapResponses.Lsub(attributes, name)
                : ImapResponses.List(attributes, name));
        }

        responses.Add(ImapResponses.Ok(command.Tag, $"{Describe(command.Verb)} completed"));

        return new ImapCommandResult(responses, ImapSessionAction.Continue);
    }

    /// <summary>
    /// The names a pattern selects, with their attributes, ordered.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Sorted ordinally so that a parent always precedes its children and two captures of the
    /// same mailbox read alike. RFC 3501 §7.2.2 imposes no order on untagged <c>LIST</c>
    /// responses, so this is for whoever has to read the transcript rather than for conformance —
    /// but a client building a tree incrementally benefits from seeing <c>Projects</c> before
    /// <c>Projects/2026</c>, and nothing is lost by giving it that.
    /// </para>
    /// <para>
    /// The eligible set is computed once and the derived levels are taken from it, not from every
    /// folder: for <c>LSUB</c> that is the difference between reporting the parent of a
    /// subscribed folder, which §6.3.9 requires, and reporting the parent of any folder at all,
    /// which would leak the existence of folders the user has not subscribed to into a command
    /// that is supposed to be about the subscription list.
    /// </para>
    /// </remarks>
    private static IEnumerable<(string Name, ImapMailboxAttribute Attributes)> Matches(
        IReadOnlyList<ImapFolderListing> folders,
        IReadOnlyList<string> subscribed,
        ImapMailboxPattern pattern,
        bool subscribedOnly)
    {
        Dictionary<string, ImapFolderListing> byPath = new(StringComparer.Ordinal);

        foreach (ImapFolderListing folder in folders)
        {
            byPath[folder.Path] = folder;
        }

        // The eligible names, paired with what this server can honestly say about each.
        List<(string Path, ImapMailboxAttribute Attributes)> eligible = [];

        if (subscribedOnly)
        {
            foreach (string name in subscribed)
            {
                eligible.Add(byPath.TryGetValue(name, out ImapFolderListing? listing)

                    // A subscribed name with a folder behind it says what the folder says.
                    ? (name, listing.Attributes)

                    // One without is exactly what §7.2.2 defines \Noselect for: "It is not
                    // possible to use this name as a selectable mailbox." No child attribute is
                    // offered, because there is no mailbox whose children could be counted -
                    // and RFC 3348 §3 anticipates their absence from LSUB in any case.
                    : (name, ImapMailboxAttribute.NoSelect));
            }
        }
        else
        {
            foreach (ImapFolderListing folder in folders)
            {
                eligible.Add((folder.Path, folder.Attributes));
            }
        }

        Dictionary<string, ImapMailboxAttribute> selected = new(StringComparer.Ordinal);

        foreach ((string path, ImapMailboxAttribute attributes) in eligible)
        {
            if (pattern.Matches(path))
            {
                selected[path] = attributes;
            }
        }

        if (pattern.EndsWithHierarchyWildcard)
        {
            foreach ((string path, _) in eligible)
            {
                foreach (string level in ImapMailboxPattern.HierarchyLevelsOf(path))
                {
                    // A level that is itself eligible has already been added with its real
                    // attributes, and must not be overwritten with \Noselect.
                    if (pattern.Matches(level) && !selected.ContainsKey(level))
                    {
                        // \HasChildren as well as \Noselect: this name exists only because
                        // something is nested beneath it, so the attribute is not a guess.
                        selected[level] =
                            ImapMailboxAttribute.NoSelect | ImapMailboxAttribute.HasChildren;
                    }
                }
            }
        }

        List<string> names = [.. selected.Keys];

        names.Sort(string.CompareOrdinal);

        foreach (string name in names)
        {
            yield return (name, selected[name]);
        }
    }

    /// <summary>
    /// <c>STATUS</c> — RFC 3501 §6.3.10.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The selected mailbox is not touched, and neither is any message.</b> §6.3.10: it "does
    /// not change the currently selected mailbox, nor does it affect the state of any messages in
    /// the queried mailbox (in particular, STATUS MUST NOT cause messages to lose the
    /// <c>\Recent</c> flag)". So there is no <c>Select</c> or <c>Deselect</c> anywhere below,
    /// which is what makes the MUST structural rather than remembered.
    /// </para>
    /// <para>
    /// <b>An empty item list is a syntax error.</b> §9 requires at least one <c>status-att</c>,
    /// and <see cref="ImapStatusItems.TryParseList"/> enforces it — so <c>STATUS INBOX ()</c>
    /// earns <c>BAD</c> rather than an untagged line reporting nothing.
    /// </para>
    /// <para>
    /// The item list is read as the remainder of the line rather than as further arguments,
    /// because the brackets and names are their own production and are not an
    /// <c>astring</c>. <see cref="ImapAstringReader.Remainder"/> exists for exactly this.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> StatusAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        if (_mailboxes is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(command.Tag, "Not authenticated"));
        }

        ImapAstringReader reader = new(command.Argument, command.Literals);

        if (!reader.TryReadText(out string? wireName))
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "STATUS expects a mailbox name and a list of data items"));
        }

        if (!ImapStatusItems.TryParseList(reader.Remainder, out IReadOnlyList<ImapStatusItem> items))
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "STATUS expects a parenthesised list of MESSAGES, RECENT, UIDNEXT, " +
                "UIDVALIDITY or UNSEEN"));
        }

        if (!ImapMailboxName.TryDecode(wireName, out string? path))
        {
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "Mailbox name is not valid modified UTF-7"));
        }

        ImapFolderStatus? status = await _mailboxes
            .ReadStatusAsync(_session.AuthenticatedMailboxId.Value, path, cancellationToken)
            .ConfigureAwait(false);

        if (status is null)
        {
            // §6.3.10's own result list: "NO - status failure: no status for that name".
            return ImapCommandResult.Single(ImapResponses.No(command.Tag, "No such mailbox"));
        }

        // The DECODED name, not the wire token. ImapResponses.Status encodes what it is given,
        // and modified UTF-7 is not idempotent - '&' opens a shift sequence and is itself written
        // "&-", so encoding an already-encoded name escapes every '&' a second time and the
        // client cannot match the response against the command it sent. Decoding preserves the
        // client's own spelling of everything directly representable, so echoing the decoded name
        // still returns the inbox in whatever case the client asked for. LIST has always passed a
        // decoded path, which is why only STATUS was wrong.
        return new ImapCommandResult(
            [
                ImapResponses.Status(path, items, status),
                ImapResponses.Ok(command.Tag, "STATUS completed"),
            ],
            ImapSessionAction.Continue);
    }

    /// <summary>
    /// <c>FETCH</c> and <c>UID FETCH</c> — RFC 3501 §6.4.5 and §6.4.8.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The UID form is the same handler with one flag, because §6.4.8 makes it the same
    /// command.</b> "In the first form, it takes as its arguments a COPY, FETCH, or STORE command
    /// with arguments appropriate for the associated command. However, the numbers in the
    /// sequence set argument are unique identifiers instead of message sequence numbers." What
    /// changes is what the numbers mean, and nothing else.
    /// </para>
    /// <para>
    /// <b>The UID is added to the response whether or not it was asked for.</b> §6.4.8: "server
    /// implementations MUST implicitly include the UID message data item as part of any FETCH
    /// response caused by a UID command, regardless of whether a UID was specified as a message
    /// data item to the FETCH." A client that sent <c>UID FETCH 1:* FLAGS</c> has no other way to
    /// know which message each line is about — the number after the <c>*</c> is a sequence
    /// number, which is exactly what it was avoiding by using UIDs.
    /// </para>
    /// <para>
    /// <b>Messages that are not there are passed over in silence.</b> §6.4.8: "A non-existent
    /// unique identifier is ignored without any error message generated. Thus, it is possible for
    /// a UID FETCH command to return an OK without any data." A tagged <c>NO</c> would be wrong
    /// here, and a client that treated it as one would report a failure to the user for a
    /// message it had simply already deleted.
    /// </para>
    /// <para>
    /// <b>Items this server cannot answer yet earn a tagged <c>NO</c> naming them.</b> §6.4.5
    /// distinguishes "BAD - command unknown or arguments invalid" from "NO - fetch error: can't
    /// fetch that data", and <c>ENVELOPE</c> is the second: the request was well-formed and this
    /// server cannot serve it. Answering a partial response instead would be worse than either,
    /// because a client cannot tell a missing item from an item the message does not have.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> FetchAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        if (_mailboxes is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null || _session.SelectedFolderId is null)
        {
            // Unreachable through the state machine, which admits FETCH only in the selected
            // state. Answered rather than asserted, as elsewhere.
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "No mailbox is selected"));
        }

        string argument = command.Argument.Trim();
        int split = argument.IndexOf(' ', StringComparison.Ordinal);

        if (split <= 0)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "FETCH expects a sequence set and one or more data items"));
        }

        if (!ImapSequenceSet.TryParse(argument[..split], out ImapSequenceSet? set))
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "FETCH sequence set is not valid"));
        }

        if (!ImapFetchItems.TryParseRequestItems(
            argument[split..],
            out IReadOnlyList<ImapFetchRequestItem> requested))
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "FETCH expects a data item, a macro, or a parenthesised list of data items"));
        }

        foreach (ImapFetchRequestItem item in requested)
        {
            // An item read out of the message needs somewhere to read it from. A deployment
            // without a message store can still answer the folder's own columns.
            if (ImapFetchItems.NeedsContent(item.Item) && _messages is null)
            {
                return NotImplemented(command);
            }

            if (!ImapFetchItems.Available.Contains(item.Item))
            {
                return ImapCommandResult.Single(ImapResponses.No(
                    command.Tag,
                    $"FETCH of {ImapFetchItems.NameOf(item.Item)} is not implemented yet"));
            }
        }

        IReadOnlyList<ImapFetchItem> items = [.. requested.Select(r => r.Item)];

        IReadOnlyList<ImapMessageSummary> summaries = await _mailboxes
            .ReadSummariesAsync(
                _session.AuthenticatedMailboxId.Value,
                _session.SelectedFolderId.Value,
                set,
                command.IsUid,
                cancellationToken)
            .ConfigureAwait(false);

        // The §6.4.8 MUST, applied once rather than per message so that the order is the same on
        // every line: the client's own items first, then the UID it did not ask for.
        List<ImapFetchItem> reported = [.. items];

        if (command.IsUid && !reported.Contains(ImapFetchItem.Uid))
        {
            reported.Add(ImapFetchItem.Uid);
        }

        bool wantsContent = requested.Any(r => ImapFetchItems.NeedsContent(r.Item));

        if (!wantsContent)
        {
            List<ImapResponse> plain = [];

            foreach (ImapMessageSummary summary in summaries)
            {
                plain.Add(ImapResponses.Fetch(summary.SequenceNumber, reported, summary));
            }

            plain.Add(ImapResponses.Ok(
                command.Tag,
                command.IsUid ? "UID FETCH completed" : "FETCH completed"));

            return new ImapCommandResult(plain, ImapSessionAction.Continue);
        }

        return await FetchWithBodyAsync(command, requested, reported, summaries, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// The <c>FETCH</c> path that reads message content.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A <c>BODY[…]</c> without <c>.PEEK</c> sets <c>\Seen</c>, and the response says so.</b>
    /// RFC 3501 §6.4.5: "The \Seen flag is implicitly set; if this causes the flags to change,
    /// they SHOULD be included as part of the FETCH responses." A client that opened a message
    /// and was not told it became read would show it unread until its next synchronisation, and
    /// would then show a change the user did not make.
    /// </para>
    /// <para>
    /// <b>The flag is set before the content is read back</b>, so the flags reported are the
    /// flags the message now has rather than the ones it had a moment ago.
    /// </para>
    /// <para>
    /// A message whose octets are missing from the store answers <c>NIL</c> rather than failing
    /// the command. §9's <c>nstring</c> has that form for exactly this, and a folder with one
    /// unreadable message should still open.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> FetchWithBodyAsync(
        ImapCommand command,
        IReadOnlyList<ImapFetchRequestItem> requested,
        IReadOnlyList<ImapFetchItem> reported,
        IReadOnlyList<ImapMessageSummary> summaries,
        CancellationToken cancellationToken)
    {
        MailboxId mailboxId = _session.AuthenticatedMailboxId!.Value;
        MailboxFolderId folderId = _session.SelectedFolderId!.Value;

        bool setsSeen =
            !_session.IsSelectedReadOnly &&
            requested.Any(r => r.Section is { Peek: false });

        IReadOnlyList<ImapMessageSummary> current = summaries;

        if (setsSeen && summaries.Count > 0 && _writer is not null)
        {
            long[] uids = [.. summaries.Select(m => m.Uid)];

            if (ImapSequenceSet.TryParse(string.Join(',', uids), out ImapSequenceSet? touched))
            {
                IReadOnlyList<ImapMessageSummary> updated = await _writer
                    .StoreFlagsAsync(
                        mailboxId,
                        folderId,
                        touched,
                        byUid: true,
                        new ImapStoreRequest(
                            ImapStoreMode.Add,
                            Silent: true,
                            MessageFlags.Seen,
                            HadUnstorableFlags: false),
                        cancellationToken)
                    .ConfigureAwait(false);

                if (updated.Count == summaries.Count)
                {
                    current = updated;
                }
            }
        }

        IReadOnlyDictionary<long, StoredMessageId> located = await _mailboxes!
            .ReadMessageIdsAsync(
                mailboxId,
                folderId,
                [.. current.Select(m => m.Uid)],
                cancellationToken)
            .ConfigureAwait(false);

        List<ImapResponse> responses = [];

        foreach (ImapMessageSummary summary in current)
        {
            ReadOnlyMemory<byte> content = ReadOnlyMemory<byte>.Empty;
            bool haveContent = false;

            if (located.TryGetValue(summary.Uid, out StoredMessageId messageId))
            {
                content = await ReadMessageAsync(messageId, cancellationToken).ConfigureAwait(false);
                haveContent = !content.IsEmpty;
            }

            List<ImapFetchPart> parts = [];

            // Parsed at most once per message and only when something asks for it, because a
            // FETCH 1:* BODY[] must not walk every message's MIME structure to answer.
            ImapBodyPart? tree = null;

            ImapBodyPart Tree() => tree ??= ImapMimeTree.Parse(content);

            foreach (ImapFetchRequestItem item in requested)
            {
                if (item.Item == ImapFetchItem.Envelope)
                {
                    // Parsed per message rather than once, because each message has its own
                    // header. A message whose octets are gone still answers, with the empty
                    // structure: §9's msg-att-static has no NIL for an envelope.
                    ImapSegmentBuilder envelope = new();

                    ImapEnvelopes.Format(
                        haveContent ? ImapEnvelopes.Read(content) : ImapEnvelopes.Missing,
                        envelope);

                    parts.Add(ImapFetchPart.Composite("ENVELOPE", envelope.Build()));
                    continue;
                }

                if (item.Item is ImapFetchItem.Body or ImapFetchItem.BodyStructure)
                {
                    // §9's msg-att-static is "BODY" SP body with no NIL alternative, so a
                    // message whose octets are gone is described as what an empty message is:
                    // RFC 2045 §5.2's default type, holding nothing.
                    ImapSegmentBuilder structure = new();

                    ImapBodyStructure.Format(
                        Tree(),
                        item.Item == ImapFetchItem.BodyStructure,
                        structure);

                    parts.Add(ImapFetchPart.Composite(
                        ImapFetchItems.NameOf(item.Item),
                        structure.Build()));

                    continue;
                }

                if (item.Section is null)
                {
                    // A metadata item alongside a body one: rendered as text, then handed over
                    // as octets so one response can carry both.
                    if (summary.ValueOf(item.Item) is { } value)
                    {
                        parts.Add(ImapFetchPart.Metadata(
                            $"{ImapFetchItems.NameOf(item.Item)} {value}"));
                    }

                    continue;
                }

                ReadOnlyMemory<byte>? octets = !haveContent
                    ? null
                    : item.Section.NeedsMimeTree
                        ? ImapMimeTree.Extract(Tree(), content, item.Section)
                        : ImapBodySection.Extract(content, item.Section);

                parts.Add(ImapFetchPart.Section(item.ResponseName, octets));
            }

            // The implicit \Seen is only worth reporting when it changed something, and the
            // reported flags come from the write above rather than from the request.
            if (setsSeen && !reported.Contains(ImapFetchItem.Flags))
            {
                parts.Insert(0, ImapFetchPart.Metadata(
                    $"FLAGS ({ImapFlagNames.Format(summary.Flags)})"));
            }

            responses.Add(ImapResponses.FetchWithLiterals(summary.SequenceNumber, parts));
        }

        responses.Add(ImapResponses.Ok(
            command.Tag,
            command.IsUid ? "UID FETCH completed" : "FETCH completed"));

        return new ImapCommandResult(responses, ImapSessionAction.Continue);
    }

    /// <summary>Reads a stored message whole, or nothing if it cannot be read.</summary>
    /// <remarks>
    /// Whole rather than streamed, which is a deliberate limit rather than an oversight: the
    /// response shape needs the octet count before the first byte goes out, and §9's literal
    /// cannot be written without it. docs/IMAP.md records what that costs on a large mailbox.
    /// </remarks>
    private async ValueTask<ReadOnlyMemory<byte>> ReadMessageAsync(
        StoredMessageId messageId,
        CancellationToken cancellationToken)
    {
        try
        {
            await using Stream stream = await _messages!
                .OpenReadAsync(messageId, cancellationToken)
                .ConfigureAwait(false);

            using MemoryStream buffer = new();

            await stream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);

            return buffer.ToArray();
        }
        catch (IOException ex)
        {
            // A row naming a file that is not there. Answered NIL rather than failing the
            // command, so one damaged message does not make a folder unopenable.
            _logger.LogWarning(ex, "A stored message could not be read for FETCH.");

            return ReadOnlyMemory<byte>.Empty;
        }
    }

    /// <summary>
    /// <c>STORE</c> and <c>UID STORE</c> — RFC 3501 §6.4.6.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Refused outright on a mailbox opened with <c>EXAMINE</c>.</b> §6.3.2: "The EXAMINE
    /// command is identical to SELECT and returns the same output; however, the selected mailbox
    /// is identified as read-only. No changes to the permanent state of the mailbox, including
    /// per-user state, are permitted". The session already told the client so, with
    /// <c>[PERMANENTFLAGS ()]</c> and a <c>[READ-ONLY]</c> completion, so a client sending this
    /// has ignored two notices and gets a tagged <c>NO</c> rather than a silently discarded
    /// write.
    /// </para>
    /// <para>
    /// <b>The untagged <c>FETCH</c> responses are the point of the command, not a courtesy.</b>
    /// §6.4.6: "Normally, STORE will return the updated value of the data with an untagged FETCH
    /// response", and the values come back from the write rather than being predicted here — see
    /// <see cref="IImapMailboxWriter.StoreFlagsAsync"/>. <c>.SILENT</c> suppresses them, and
    /// suppresses only them: the work still happens and the tagged <c>OK</c> still arrives.
    /// </para>
    /// <para>
    /// <b><c>UID STORE</c> carries the UID on every line it does send.</b> §6.4.8's MUST is about
    /// "any FETCH response caused by a UID command", and a <c>STORE</c>'s untagged <c>FETCH</c>
    /// is caused by one — the note under it says so explicitly: "The rule about including the UID
    /// message data item as part of a FETCH response primarily applies to the UID FETCH and UID
    /// STORE commands".
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> StoreAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        if (_writer is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null || _session.SelectedFolderId is null)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "No mailbox is selected"));
        }

        if (_session.IsSelectedReadOnly)
        {
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "Mailbox is open read-only; flags cannot be changed"));
        }

        string argument = command.Argument.Trim();
        int split = argument.IndexOf(' ', StringComparison.Ordinal);

        if (split <= 0)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "STORE expects a sequence set, a data item and a flag list"));
        }

        if (!ImapSequenceSet.TryParse(argument[..split], out ImapSequenceSet? set))
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "STORE sequence set is not valid"));
        }

        if (!ImapStore.TryParse(argument[(split + 1)..], out ImapStoreRequest? request))
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "STORE expects FLAGS, +FLAGS or -FLAGS, optionally .SILENT, and a flag list"));
        }

        IReadOnlyList<ImapMessageSummary> stored = await _writer
            .StoreFlagsAsync(
                _session.AuthenticatedMailboxId.Value,
                _session.SelectedFolderId.Value,
                set,
                command.IsUid,
                request,
                cancellationToken)
            .ConfigureAwait(false);

        if (request.HadUnstorableFlags)
        {
            // Logged rather than reported. RFC 3501 §7.1 permits ignoring a flag outside
            // PERMANENTFLAGS, and the untagged FETCH already shows the client what it got - but
            // an operator looking at why a client keeps re-sending a keyword wants to see it.
            _logger.LogInformation(
                "IMAP STORE named one or more flags this server does not store; they were ignored.");
        }

        List<ImapResponse> responses = [];

        if (!request.Silent)
        {
            List<ImapFetchItem> items = [ImapFetchItem.Flags];

            if (command.IsUid)
            {
                items.Add(ImapFetchItem.Uid);
            }

            foreach (ImapMessageSummary summary in stored)
            {
                responses.Add(ImapResponses.Fetch(summary.SequenceNumber, items, summary));
            }
        }

        responses.Add(ImapResponses.Ok(
            command.Tag,
            command.IsUid ? "UID STORE completed" : "STORE completed"));

        return new ImapCommandResult(responses, ImapSessionAction.Continue);
    }

    /// <summary>
    /// <c>EXPUNGE</c> — RFC 3501 §6.4.3.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §6.4.3: it "permanently removes all messages that have the <c>\Deleted</c> flag set from
    /// the currently selected mailbox. Before returning an OK to the client, an untagged EXPUNGE
    /// response is sent for each message that is removed."
    /// </para>
    /// <para>
    /// <b>The responses go out highest position first</b>, which is the half of §7.4.1's rule
    /// that needs no arithmetic — see <see cref="IImapMailboxWriter.ExpungeAsync"/>. The RFC
    /// names both orders as legal and this one keeps every number valid at the moment it is sent.
    /// </para>
    /// <para>
    /// <b>No <c>EXISTS</c> follows.</b> §7.4.1: "The EXPUNGE response also decrements the number
    /// of messages in the mailbox; it is not necessary to send an EXISTS response with the new
    /// value." Sending one would not be wrong, but a client that had already decremented would
    /// have to reconcile two statements of the same fact.
    /// </para>
    /// <para>
    /// <b>Refused on a read-only mailbox</b>, where §6.3.2 permits "No changes to the permanent
    /// state of the mailbox", and §6.4.3's own result list has the shape for it: "NO - expunge
    /// failure: can't expunge (e.g., permission denied)". Note that <c>CLOSE</c> is treated
    /// differently and deliberately so — see <see cref="CloseAsync"/>.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> ExpungeAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        if (_writer is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null || _session.SelectedFolderId is null)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "No mailbox is selected"));
        }

        // §9: expunge = "EXPUNGE" - the whole production. Anything after it is an argument the
        // grammar has nowhere to put.
        if (command.Argument.Trim().Length != 0)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "EXPUNGE takes no arguments"));
        }

        if (_session.IsSelectedReadOnly)
        {
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "Mailbox is open read-only; messages cannot be expunged"));
        }

        IReadOnlyList<long> removed = await _writer
            .ExpungeAsync(
                _session.AuthenticatedMailboxId.Value,
                _session.SelectedFolderId.Value,
                cancellationToken)
            .ConfigureAwait(false);

        List<ImapResponse> responses = [];

        foreach (long sequenceNumber in removed)
        {
            responses.Add(ImapResponses.Expunge(sequenceNumber));
        }

        // §7.4.1: "The EXPUNGE response also decrements the number of messages in the mailbox".
        // So the client's count falls by one per line, without an EXISTS being sent.
        _session.ReportExists(Math.Max(0, _session.ReportedExists - removed.Count));

        responses.Add(ImapResponses.Ok(command.Tag, "EXPUNGE completed"));

        return new ImapCommandResult(responses, ImapSessionAction.Continue);
    }

    /// <summary>
    /// <c>CLOSE</c> — RFC 3501 §6.4.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §6.4.2: it "permanently removes all messages that have the <c>\Deleted</c> flag set from
    /// the currently selected mailbox, and returns to the authenticated state from the selected
    /// state. <b>No untagged EXPUNGE responses are sent.</b>" That silence is the whole point of
    /// the command, and the RFC says why: "when many messages are deleted, a CLOSE-LOGOUT or
    /// CLOSE-SELECT sequence is considerably faster than an EXPUNGE-LOGOUT or EXPUNGE-SELECT
    /// because no untagged EXPUNGE responses (which the client would probably ignore) are sent."
    /// </para>
    /// <para>
    /// <b>On a read-only mailbox this succeeds and removes nothing, where <c>EXPUNGE</c>
    /// refuses.</b> The asymmetry is the RFC's, stated outright in §6.4.2: "No messages are
    /// removed, and no error is given, if the mailbox is selected by an EXAMINE command or is
    /// otherwise selected read-only." The command's result list bears it out — <c>CLOSE</c> has
    /// only <c>OK</c> and <c>BAD</c>, with no <c>NO</c> case at all, while <c>EXPUNGE</c> has
    /// one. A server that refused here would fail a client that closes every mailbox it opens.
    /// </para>
    /// <para>
    /// The deselect happens either way, because returning to the authenticated state is what the
    /// command is for and it is not conditional on anything having been removed.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> CloseAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        if (_writer is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null || _session.SelectedFolderId is null)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "No mailbox is selected"));
        }

        if (command.Argument.Trim().Length != 0)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "CLOSE takes no arguments"));
        }

        // Read-only: remove nothing, say nothing about it, and still close. §6.4.2's "no error is
        // given" is explicit, so this is not a refusal path.
        if (!_session.IsSelectedReadOnly)
        {
            await _writer
                .ExpungeAsync(
                    _session.AuthenticatedMailboxId.Value,
                    _session.SelectedFolderId.Value,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        _session.Deselect();

        return ImapCommandResult.Single(ImapResponses.Ok(command.Tag, "CLOSE completed"));
    }

    /// <summary>
    /// <c>CHECK</c> — RFC 3501 §6.4.1.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A checkpoint of the selected mailbox, meaning "any implementation-dependent housekeeping
    /// associated with the mailbox (e.g., resolving the server's in-memory state of the mailbox
    /// with the state on its disk) that is not normally executed as part of each command". This
    /// server keeps no such state: every command reads and writes through the database, which
    /// owns durability. §6.4.1 anticipates exactly that — "If a server implementation has no such
    /// housekeeping considerations, CHECK is equivalent to NOOP" — so answering <c>OK</c> and
    /// doing nothing is the specified behaviour rather than a shortcut.
    /// </para>
    /// <para>
    /// Nothing untagged is sent, deliberately. §6.4.1: "There is no guarantee that an EXISTS
    /// untagged response will happen as a result of CHECK. NOOP, not CHECK, SHOULD be used for
    /// new message polling."
    /// </para>
    /// </remarks>
    private ImapCommandResult Check(ImapCommand command)
    {
        if (_session.SelectedFolderId is null)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "No mailbox is selected"));
        }

        if (command.Argument.Trim().Length != 0)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "CHECK takes no arguments"));
        }

        return ImapCommandResult.Single(ImapResponses.Ok(command.Tag, "CHECK completed"));
    }

    /// <summary>
    /// <c>UNSELECT</c> — RFC 3691 §2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §2: it "frees server's resources associated with the selected mailbox and returns the
    /// server to the authenticated state. This command performs the same actions as CLOSE, except
    /// that no messages are permanently removed from the currently selected mailbox." So this is
    /// <see cref="CloseAsync"/> minus the expunge, and the abstract says why a client wants it:
    /// the alternatives are "a SELECT command with a nonexistent mailbox name or reselecting the
    /// same mailbox with EXAMINE command", both of which work by side effect.
    /// </para>
    /// <para>
    /// <b>Without a selected mailbox this is <c>BAD</c>, not <c>NO</c>.</b> §2's result list says
    /// so in as many words: "BAD - no mailbox selected, or argument supplied but none permitted."
    /// The command is out of sequence rather than refused, and the state machine reaches the same
    /// verdict first.
    /// </para>
    /// </remarks>
    private ImapCommandResult Unselect(ImapCommand command)
    {
        if (_session.SelectedFolderId is null)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "No mailbox is selected"));
        }

        if (command.Argument.Trim().Length != 0)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "UNSELECT takes no arguments"));
        }

        _session.Deselect();

        return ImapCommandResult.Single(ImapResponses.Ok(command.Tag, "UNSELECT completed"));
    }

    /// <summary>
    /// <c>NAMESPACE</c> — RFC 2342 §5.
    /// </summary>
    /// <remarks>
    /// One personal namespace with no prefix and <c>/</c> as its delimiter, and <c>NIL</c> for
    /// the other two classes — RFC 2342's own Example 5.1. See
    /// <see cref="ImapResponses.Namespace"/> for why the <c>NIL</c>s earn their place.
    /// </remarks>
    private ImapCommandResult Namespace(ImapCommand command)
    {
        if (command.Argument.Trim().Length != 0)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "NAMESPACE takes no arguments"));
        }

        return new ImapCommandResult(
            [
                ImapResponses.Namespace(),
                ImapResponses.Ok(command.Tag, "NAMESPACE completed"),
            ],
            ImapSessionAction.Continue);
    }

    /// <summary>Which folder-shaped command is being run.</summary>
    private enum ImapFolderCommand
    {
        Create,
        Delete,
        Rename,
        Subscribe,
        Unsubscribe,
    }

    /// <summary>
    /// <c>CREATE</c>, <c>DELETE</c>, <c>RENAME</c>, <c>SUBSCRIBE</c> and <c>UNSUBSCRIBE</c> —
    /// RFC 3501 §6.3.3 to §6.3.7.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One handler, because the five differ only in which repository call they make and how
    /// many mailbox names they take.</b> Everything around that — the argument shape, decoding
    /// modified UTF-7, refusing a name that will not decode without echoing it back, and turning
    /// a repository outcome into a tagged response — is identical, and writing it five times
    /// would be five chances for the refusals to drift apart.
    /// </para>
    /// <para>
    /// <b>Every failure is a tagged <c>NO</c>, not a <c>BAD</c>.</b> §6.3.3 and §6.3.4 both phrase
    /// theirs as ordinary outcomes — "Any error in creation will return a tagged NO response" —
    /// because a client creating a folder that already exists has done something reasonable with
    /// stale information. <c>BAD</c> is reserved for a line the grammar does not admit.
    /// </para>
    /// <para>
    /// <b><c>RENAME</c> takes two names and is the only one that does</b>, which is the whole of
    /// why the argument reading is not shared with the others.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> FolderAsync(
        ImapCommand command,
        ImapFolderCommand which,
        CancellationToken cancellationToken)
    {
        if (_writer is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(command.Tag, "Not authenticated"));
        }

        ImapAstringReader reader = new(command.Argument, command.Literals);

        if (!reader.TryReadText(out string? wireName))
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                $"{Describe(command.Verb)} expects a mailbox name"));
        }

        string? wireTarget = null;

        if (which == ImapFolderCommand.Rename && !reader.TryReadText(out wireTarget))
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "RENAME expects an existing mailbox name and a new one"));
        }

        if (!reader.AtEnd)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                $"{Describe(command.Verb)} has too many arguments"));
        }

        if (!ImapMailboxName.TryDecode(wireName, out string? path) ||
            (wireTarget is not null && !ImapMailboxName.TryDecode(wireTarget, out _)))
        {
            // Refused without being echoed, as everywhere else: a malformed name is client text.
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "Mailbox name is not valid modified UTF-7"));
        }

        MailboxId mailboxId = _session.AuthenticatedMailboxId.Value;
        DateTimeOffset now = _clock.UtcNow;

        ImapFolderMutation outcome = which switch
        {
            ImapFolderCommand.Create =>
                await _writer.CreateFolderAsync(mailboxId, path, now, cancellationToken)
                    .ConfigureAwait(false),

            ImapFolderCommand.Delete =>
                await _writer.DeleteFolderAsync(mailboxId, path, cancellationToken)
                    .ConfigureAwait(false),

            ImapFolderCommand.Rename =>
                await RenameAsync(mailboxId, path, wireTarget!, now, cancellationToken)
                    .ConfigureAwait(false),

            ImapFolderCommand.Subscribe =>
                await _writer
                    .SetSubscriptionAsync(mailboxId, path, subscribed: true, now, cancellationToken)
                    .ConfigureAwait(false),

            _ => await _writer
                .SetSubscriptionAsync(mailboxId, path, subscribed: false, now, cancellationToken)
                .ConfigureAwait(false),
        };

        if (outcome == ImapFolderMutation.Done)
        {
            return ImapCommandResult.Single(
                ImapResponses.Ok(command.Tag, $"{Describe(command.Verb)} completed"));
        }

        return ImapCommandResult.Single(ImapResponses.No(command.Tag, Explain(command.Verb, outcome)));
    }

    private async ValueTask<ImapFolderMutation> RenameAsync(
        MailboxId mailboxId,
        string from,
        string wireTarget,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ImapMailboxName.TryDecode(wireTarget, out string? to);

        return await _writer!
            .RenameFolderAsync(mailboxId, from, to!, now, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>The refusal text for one outcome, in the terms the RFC uses for that command.</summary>
    private static string Explain(ImapVerb verb, ImapFolderMutation outcome) => outcome switch
    {
        ImapFolderMutation.AlreadyExists => "Mailbox already exists",

        ImapFolderMutation.NotFound => verb == ImapVerb.Subscribe

            // §6.3.6 permits validating the name, and this server does - so say which check failed
            // rather than leaving a user to wonder why a subscription did not take.
            ? "No such mailbox to subscribe to"
            : "No such mailbox",

        // §6.3.3 and §6.3.4 both name INBOX as the one mailbox that may be neither created nor
        // deleted. RENAME reaches this only for a destination of INBOX, which would be a create.
        ImapFolderMutation.Reserved => "INBOX is reserved and cannot be created or deleted",

        ImapFolderMutation.Invalid => "Mailbox name is not valid",

        _ => "Command failed",
    };

    /// <summary>
    /// <c>COPY</c> and <c>MOVE</c>, and their <c>UID</c> forms — RFC 3501 §6.4.7 and RFC 6851 §3.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A missing destination earns <c>[TRYCREATE]</c>, and that is a MUST.</b> §6.4.7: "Unless
    /// it is certain that the destination mailbox can not be created, the server MUST send the
    /// response code "[TRYCREATE]" as the prefix of the text of the tagged NO response. This
    /// gives a hint to the client that it can attempt a CREATE command and retry the COPY if the
    /// CREATE is successful." RFC 6851 §4 extends it to <c>MOVE</c>: "Response codes such as
    /// TRYCREATE […] are sent as appropriate." This is the one place in this server where the
    /// code appears — <c>SELECT</c> deliberately does not use it, because a client cannot recover
    /// from opening a missing folder by creating an empty one.
    /// </para>
    /// <para>
    /// <b><c>MOVE</c> reports untagged <c>EXPUNGE</c> and never a <c>FETCH</c>.</b> RFC 6851
    /// §3.3 describes the move as equivalent to a copy, a <c>STORE +FLAGS.SILENT \Deleted</c> and
    /// an expunge, then forbids the middle step's traces: "response codes for a STORE MUST NOT be
    /// generated and the <c>\Deleted</c> flag MUST NOT be set for any message." So nothing is
    /// flagged and nothing is echoed; the expunges are sent because the messages genuinely left.
    /// </para>
    /// <para>
    /// A set naming nothing that exists is an <c>OK</c> with no data, per §6.4.8 — the same rule
    /// <c>FETCH</c> and <c>STORE</c> follow.
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> CopyAsync(
        ImapCommand command,
        bool move,
        CancellationToken cancellationToken)
    {
        if (_writer is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null || _session.SelectedFolderId is null)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "No mailbox is selected"));
        }

        string verb = move ? "MOVE" : "COPY";
        string argument = command.Argument.Trim();
        int split = argument.IndexOf(' ', StringComparison.Ordinal);

        if (split <= 0)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                $"{verb} expects a sequence set and a mailbox name"));
        }

        if (!ImapSequenceSet.TryParse(argument[..split], out ImapSequenceSet? set))
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, $"{verb} sequence set is not valid"));
        }

        ImapAstringReader reader = new(argument[(split + 1)..], command.Literals);

        if (!reader.TryReadText(out string? wireName) || !reader.AtEnd)
        {
            return ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                $"{verb} expects one destination mailbox name"));
        }

        if (!ImapMailboxName.TryDecode(wireName, out string? path))
        {
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "Mailbox name is not valid modified UTF-7"));
        }

        ImapCopyResult result = await _writer
            .CopyAsync(
                _session.AuthenticatedMailboxId.Value,
                _session.SelectedFolderId.Value,
                set,
                command.IsUid,
                path,
                removeFromSource: move,
                _clock.UtcNow,
                cancellationToken)
            .ConfigureAwait(false);

        if (result.Outcome == ImapFolderMutation.NotFound)
        {
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "No such destination mailbox",
                ImapResponseCode.TryCreate));
        }

        List<ImapResponse> responses = [];

        foreach (long sequenceNumber in result.RemovedSequenceNumbers)
        {
            responses.Add(ImapResponses.Expunge(sequenceNumber));
        }

        // A MOVE takes its messages out of the selected folder, and §7.4.1 makes each EXPUNGE
        // line a decrement of the count the client holds.
        _session.ReportExists(
            Math.Max(0, _session.ReportedExists - result.RemovedSequenceNumbers.Count));

        responses.Add(ImapResponses.Ok(
            command.Tag,
            command.IsUid ? $"UID {verb} completed" : $"{verb} completed"));

        return new ImapCommandResult(responses, ImapSessionAction.Continue);
    }

    /// <summary>
    /// Plans an <c>APPEND</c>: everything decidable before its octets arrive.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Split from the rest because the processor never sees a stream.</b> The octets are on
    /// the connection, and this type's whole arrangement is that the loop owns the stream while
    /// the processor owns the protocol. So the loop asks what the command says, streams the
    /// literal itself, and comes back with what it stored.
    /// </para>
    /// <para>
    /// Returns null when the line is not a usable <c>APPEND</c>; the refusal is in
    /// <paramref name="refusal"/> and is already the response to send.
    /// </para>
    /// </remarks>
    public ImapAppendRequest? PlanAppend(ImapCommand command, out ImapCommandResult refusal)
    {
        ArgumentNullException.ThrowIfNull(command);

        refusal = ImapCommandResult.Single(ImapResponses.Bad(command.Tag, "APPEND is malformed"));

        if (_writer is null || _messages is null)
        {
            refusal = NotImplemented(command);
            return null;
        }

        if (_session.AuthenticatedMailboxId is null)
        {
            refusal = ImapCommandResult.Single(ImapResponses.Bad(command.Tag, "Not authenticated"));
            return null;
        }

        if (!ImapAppend.TryParse(command.Argument, command.Literals, out ImapAppendRequest? request))
        {
            refusal = ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "APPEND expects a mailbox name, optional flags, an optional date-time and a literal"));

            return null;
        }

        return request;
    }

    /// <summary>
    /// Finishes an <c>APPEND</c> once its octets are stored.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A missing destination is a <c>NO</c> with <c>[TRYCREATE]</c>, and both halves are
    /// MUSTs.</b> RFC 3501 §6.3.11: "If the destination mailbox does not exist, a server MUST
    /// return an error, and MUST NOT automatically create the mailbox. Unless it is certain that
    /// the destination mailbox can not be created, the server MUST send the response code
    /// "[TRYCREATE]" as the prefix of the text of the tagged NO response."
    /// </para>
    /// <para>
    /// <b>An untagged <c>EXISTS</c> follows when the client has that mailbox open.</b> §6.3.11:
    /// "If the mailbox is currently selected, the normal new message actions SHOULD occur.
    /// Specifically, the server SHOULD notify the client immediately via an untagged EXISTS
    /// response." Without it a client that appends to the folder it is reading does not see its
    /// own message until it polls.
    /// </para>
    /// <para>
    /// <c>\Recent</c> is not set, though §6.3.11 says "In either case, the Recent flag is also
    /// set". This server never sets that flag anywhere — see
    /// <see cref="ImapResponses.Recent"/> — and setting it here alone would make
    /// <c>RECENT</c> report a number no other command could ever produce.
    /// </para>
    /// </remarks>
    public async Task<ImapCommandResult> CompleteAppendAsync(
        ImapCommand command,
        ImapAppendRequest request,
        StoredMessage stored,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(stored);

        ImapAppendResult result = await _writer!
            .AppendAsync(
                _session.AuthenticatedMailboxId!.Value,
                request.Mailbox,
                stored,
                request.Flags,
                request.InternalDate ?? _clock.UtcNow,
                _clock.UtcNow,
                cancellationToken)
            .ConfigureAwait(false);

        if (result.Outcome != ImapFolderMutation.Done)
        {
            return ImapCommandResult.Single(ImapResponses.No(
                command.Tag,
                "No such destination mailbox",
                ImapResponseCode.TryCreate));
        }

        List<ImapResponse> responses = [];

        if (_session.SelectedFolderId == result.FolderId)
        {
            responses.Add(ImapResponses.Exists(result.ExistsCount));
            _session.ReportExists(result.ExistsCount);
        }

        responses.Add(ImapResponses.Ok(command.Tag, "APPEND completed"));

        return new ImapCommandResult(responses, ImapSessionAction.Continue);
    }

    /// <summary>The answer when an <c>APPEND</c> reaches the ordinary dispatch.</summary>
    /// <remarks>
    /// It should not: the loop intercepts the verb before dispatching, because only the loop can
    /// read the literal. Reaching here means no stream owner was available, which is the
    /// processor-without-a-listener case the tests drive.
    /// </remarks>
    private ImapCommandResult AppendRefusal(ImapCommand command) =>
        _writer is null || _messages is null
            ? NotImplemented(command)
            : ImapCommandResult.Single(ImapResponses.Bad(
                command.Tag,
                "APPEND requires a message literal"));

    /// <summary>
    /// <c>SEARCH</c> and <c>UID SEARCH</c> — RFC 3501 §6.4.4.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The numbers reported differ by form.</b> §7.2.5: "For SEARCH, these are message
    /// sequence numbers; for UID SEARCH, these are unique identifiers." That is the only
    /// difference between the two commands' output — the criteria mean the same thing in both.
    /// </para>
    /// <para>
    /// <b>Message content is loaded only when the criteria need it.</b> A search for
    /// <c>UNSEEN</c> is answered from stored columns and opens nothing;
    /// <c>BODY "quarterly"</c> reads every message in the folder. §6.4.4 warns that search "is
    /// not guaranteed to be fast", but a client asking about flags should not pay for that — see
    /// <see cref="ImapSearchKey.NeedsContent"/>.
    /// </para>
    /// <para>
    /// <b>A search never marks anything read.</b> Nothing here writes, and the section
    /// specifiers the evaluator uses are built peeking, so the property holds wherever they are
    /// used rather than wherever someone remembered.
    /// </para>
    /// <para>
    /// An unsupported <c>CHARSET</c> is a tagged <c>NO</c>, which is what §6.4.4 provides for:
    /// "NO - search error: can't search that [CHARSET] or criteria".
    /// </para>
    /// </remarks>
    private async ValueTask<ImapCommandResult> SearchAsync(
        ImapCommand command,
        CancellationToken cancellationToken)
    {
        if (_mailboxes is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null || _session.SelectedFolderId is null)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "No mailbox is selected"));
        }

        if (!ImapSearch.TryParse(command.Argument, command.Literals, out ImapSearchKey? key, out bool badCharset))
        {
            return ImapCommandResult.Single(badCharset
                ? ImapResponses.No(command.Tag, "Unsupported CHARSET; this server searches US-ASCII and UTF-8")
                : ImapResponses.Bad(command.Tag, "SEARCH criteria are not valid"));
        }

        MailboxId mailboxId = _session.AuthenticatedMailboxId.Value;
        MailboxFolderId folderId = _session.SelectedFolderId.Value;

        // The whole folder: a search has no sequence set of its own, and any criterion may match
        // any message. §6.4.4's own warning about speed is about exactly this.
        ImapSequenceSet.TryParse("1:*", out ImapSequenceSet? everything);

        IReadOnlyList<ImapMessageSummary> summaries = await _mailboxes
            .ReadSummariesAsync(mailboxId, folderId, everything!, byUid: false, cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyDictionary<long, StoredMessageId> located =
            key.NeedsContent && _messages is not null
                ? await _mailboxes
                    .ReadMessageIdsAsync(
                        mailboxId,
                        folderId,
                        [.. summaries.Select(m => m.Uid)],
                        cancellationToken)
                    .ConfigureAwait(false)
                : new Dictionary<long, StoredMessageId>();

        long maxValue = summaries.Count == 0 ? 0 : summaries[^1].SequenceNumber;
        long maxUid = summaries.Count == 0 ? 0 : summaries[^1].Uid;

        List<long> matched = [];

        foreach (ImapMessageSummary summary in summaries)
        {
            ReadOnlyMemory<byte> content = ReadOnlyMemory<byte>.Empty;

            if (located.TryGetValue(summary.Uid, out StoredMessageId messageId))
            {
                content = await ReadMessageAsync(messageId, cancellationToken).ConfigureAwait(false);
            }

            if (ImapSearchEvaluator.Matches(
                key,
                new ImapSearchCandidate(summary, content),
                maxValue,
                maxUid))
            {
                matched.Add(command.IsUid ? summary.Uid : summary.SequenceNumber);
            }
        }

        return new ImapCommandResult(
            [
                ImapResponses.Search(matched),
                ImapResponses.Ok(
                    command.Tag,
                    command.IsUid ? "UID SEARCH completed" : "SEARCH completed"),
            ],
            ImapSessionAction.Continue);
    }

    /// <summary>
    /// <c>IDLE</c> — RFC 2177 §3.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The command itself is only the continuation; everything that makes it useful happens in
    /// the connection loop, which owns the stream the updates go out on and the clock that paces
    /// them. §3: "The server requests a response to the IDLE command using the continuation
    /// ("+") response."
    /// </para>
    /// <para>
    /// <b>Not refused for want of a selected mailbox.</b> §3 says nothing about which state the
    /// command belongs to; §4 does, by putting <c>idle</c> in <c>command_auth</c> and annotating
    /// it ";; Valid only in Authenticated or Selected state". So a client that has logged in and
    /// not yet selected anything may idle, and there is simply nothing to tell it — which is a
    /// quiet connection, not a protocol error. <see cref="ImapStateMachine"/> has always read it
    /// that way; a second test of the same rule here that disagreed with it was a rule enforced
    /// twice and obeyed once.
    /// </para>
    /// <para>
    /// The authenticated state is checked for all the same, because everything past it depends
    /// on an identity — but <see cref="ImapStateMachine"/> has already refused an unauthenticated
    /// <c>IDLE</c>, so this is the second line of defence rather than the rule.
    /// </para>
    /// </remarks>
    private ImapCommandResult Idle(ImapCommand command)
    {
        if (_mailboxes is null)
        {
            return NotImplemented(command);
        }

        if (_session.AuthenticatedMailboxId is null)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "IDLE requires an authenticated session"));
        }

        if (command.Argument.Trim().Length != 0)
        {
            return ImapCommandResult.Single(
                ImapResponses.Bad(command.Tag, "IDLE takes no arguments"));
        }

        return new ImapCommandResult(
            [ImapResponse.Continuation("idling")],
            ImapSessionAction.Idle);
    }

    /// <summary>
    /// Reads the two numbers an idling connection watches: the folder's size and its
    /// flag-change counter.
    /// </summary>
    /// <remarks>
    /// Exposed for the loop, which cannot reach the repository itself. Returns null when there
    /// is nothing to watch, which ends the idle rather than looping on an error.
    /// </remarks>
    public async ValueTask<ImapFolderPoll?> PollSelectedAsync(CancellationToken cancellationToken)
    {
        if (_mailboxes is null ||
            _session.AuthenticatedMailboxId is null ||
            _session.SelectedFolderId is null)
        {
            return null;
        }

        return await _mailboxes
            .PollFolderAsync(
                _session.AuthenticatedMailboxId.Value,
                _session.SelectedFolderId.Value,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Reads every UID in the selected folder with its flags, for a watch to compare against.
    /// </summary>
    /// <remarks>
    /// Only ever called when <see cref="PollSelectedAsync"/> has already said something changed,
    /// or to seed a new watch. Calling it on the poll timer instead would be the cost the
    /// counter exists to avoid — see <c>IImapMailboxReader.PollFolderAsync</c>.
    /// </remarks>
    public async ValueTask<IReadOnlyList<ImapFlagState>?> ReadSelectedFlagsAsync(
        CancellationToken cancellationToken)
    {
        if (_mailboxes is null ||
            _session.AuthenticatedMailboxId is null ||
            _session.SelectedFolderId is null)
        {
            return null;
        }

        return await _mailboxes
            .ReadFlagsAsync(
                _session.AuthenticatedMailboxId.Value,
                _session.SelectedFolderId.Value,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static ImapCommandResult NotImplemented(ImapCommand command) =>
        ImapCommandResult.Single(ImapResponses.No(
            command.Tag,
            $"{Describe(command.Verb)} is not implemented yet"));

    /// <summary>The wire name of a verb, for a refusal's text.</summary>
    /// <remarks>
    /// From the enum, never from the client's own line. The two agree case-insensitively for
    /// every command this server knows, and using the enum means a refusal cannot quote the peer.
    /// </remarks>
    private static string Describe(ImapVerb verb) => verb switch
    {
        ImapVerb.StartTls => "STARTTLS",
        ImapVerb.Unknown => "That command",
        _ => verb.ToString().ToUpperInvariant(),
    };

    /// <summary>Stands in when no authenticator was supplied, and refuses everything.</summary>
    private sealed class UnavailableAuthenticator : IMailboxAuthenticator
    {
        public static UnavailableAuthenticator Instance { get; } = new();

        public Task<MailboxAuthenticationResult> AuthenticateAsync(
            SaslCredential credential,
            MailboxAccess protocol,
            IpAddressValue remoteAddress,
            CancellationToken cancellationToken) =>
            Task.FromResult(new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Failed,
                null,
                "No authenticator is configured for this listener."));
    }

    private ImapCapabilityContext CapabilityContext() => new(
        _options.Role,
        _session.IsTlsActive,
        _session.State,
        _options.IsAuthenticationAvailable,

        // Tied to whether LIST can run at all. Without a mailbox reader every LIST is answered
        // "not implemented", and advertising CHILDREN would be undertaking to send attributes on
        // a response this session will never produce.
        IsChildrenAvailable: _mailboxes is not null,

        // Both are implemented outright and depend on nothing optional, so they are advertised
        // unconditionally. The two RFCs put it differently and the difference is worth keeping
        // straight: RFC 2342 §4 is a MUST - "IMAP4 servers that support this extension MUST list
        // the keyword NAMESPACE in their CAPABILITY response" - while RFC 3691 §1 only says "A
        // server which supports this extension indicates this with a capability name of
        // 'UNSELECT'". Advertising both is required in one case and the only way a client can
        // discover the command in the other.
        // RFC 2177 §3: "The IDLE command may be used with any IMAP4 server implementation that
        // returns "IDLE" as one of the supported capabilities to the CAPABILITY command. If the
        // server does not advertise the IDLE capability, the client MUST NOT use the IDLE
        // command and must poll for mailbox updates."
        IsIdleAvailable: _mailboxes is not null,
        IsNamespaceAvailable: true,
        IsUnselectAvailable: true,

        // RFC 6851 §1: "The MOVE extension is present in any IMAP implementation that returns
        // "MOVE" as one of the supported capabilities to the CAPABILITY command." Tied to the
        // writer, because without one every MOVE is refused as unimplemented - and the atom is
        // the only thing that makes the command present.
        IsMoveAvailable: _writer is not null,

        // RFC 7888 §4: the atom is the promise that a non-synchronising literal is "automatically
        // limited to 4096 octets", and ImapConnectionHandler.MaxInlineLiteralOctets is that
        // limit. Unconditional like NAMESPACE, because reading a literal depends on nothing
        // optional - it is the connection's own loop, not a repository or a store - and because
        // withholding the atom would not make this server refuse {n+}, only make a client spend
        // a round trip per argument finding out that it need not have.
        IsLiteralMinusAvailable: true);
}
