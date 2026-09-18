using MailServer.Application.Abstractions.Repositories;
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
        IImapMailboxReader? mailboxes = null)
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

        ImapAstringReader reader = new(command.Argument);

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

        ImapAstringReader reader = new(command.Argument);

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
            .AuthenticateAsync(credential, _session.RemoteAddress, cancellationToken)
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

        ImapAstringReader reader = new(command.Argument);

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

        ImapAstringReader reader = new(command.Argument);

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

        List<ImapResponse> responses = [];

        foreach ((string name, ImapMailboxAttribute attributes) in
            Matches(folders, pattern, subscribedOnly))
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
        ImapMailboxPattern pattern,
        bool subscribedOnly)
    {
        List<ImapFolderListing> eligible = [];

        foreach (ImapFolderListing folder in folders)
        {
            if (!subscribedOnly || folder.IsSubscribed)
            {
                eligible.Add(folder);
            }
        }

        Dictionary<string, ImapMailboxAttribute> selected = new(StringComparer.Ordinal);

        foreach (ImapFolderListing folder in eligible)
        {
            if (pattern.Matches(folder.Path))
            {
                selected[folder.Path] = folder.Attributes;
            }
        }

        if (pattern.EndsWithHierarchyWildcard)
        {
            foreach (ImapFolderListing folder in eligible)
            {
                foreach (string level in ImapMailboxPattern.HierarchyLevelsOf(folder.Path))
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

        ImapAstringReader reader = new(command.Argument);

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

        // Echoed as the client spelled it, not as the folder is stored. The two differ only for
        // the inbox, whose case the client may have chosen - and a client matching the response
        // against the name it sent should find them equal.
        return new ImapCommandResult(
            [
                ImapResponses.Status(wireName, items, status),
                ImapResponses.Ok(command.Tag, "STATUS completed"),
            ],
            ImapSessionAction.Continue);
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
        IsChildrenAvailable: _mailboxes is not null);
}
