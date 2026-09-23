using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Spf;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Smtp;

/// <summary>What the connection loop must do after sending the reply.</summary>
public enum SmtpSessionAction
{
    /// <summary>Carry on reading commands.</summary>
    Continue = 0,

    /// <summary>Perform the TLS handshake, then start again from the banner state.</summary>
    StartTlsHandshake = 1,

    /// <summary>Read message content until the end-of-data marker.</summary>
    ReceiveMessageData = 2,

    /// <summary>Send the reply, then close.</summary>
    CloseAfterReply = 3,

    /// <summary>
    /// Send the 334 challenge, then read one more line and feed it back through
    /// <see cref="SmtpCommandProcessor.ContinueAuthenticationAsync"/>.
    /// </summary>
    /// <remarks>
    /// SASL is the only part of SMTP where the server asks and waits mid-command. The line that
    /// comes back is a credential, not a command, and it must never reach the command parser —
    /// which is why it has its own action rather than being read by the ordinary loop.
    /// </remarks>
    ReadAuthenticationResponse = 4,
}

/// <summary>A reply to send and what to do next.</summary>
public sealed record SmtpCommandResult(SmtpReply Reply, SmtpSessionAction Action = SmtpSessionAction.Continue);

/// <summary>Everything the processor needs to know that comes from configuration.</summary>
/// <param name="Hostname">This server's name, as it appears in the banner and in EHLO.</param>
/// <param name="ProductName">Product string for the banner.</param>
/// <param name="MaxRecipientsPerMessage">Recipient cap. Bounds RCPT flooding.</param>
/// <param name="MaxMessageSizeBytes">Size limit advertised in SIZE and enforced during DATA.</param>
/// <param name="IsAuthenticationAvailable">Whether SASL is implemented and enabled.</param>
/// <param name="IsSmtpUtf8Available">Whether SMTPUTF8 is implemented and enabled.</param>
/// <param name="IsChunkingAvailable">Whether BDAT is implemented and enabled.</param>
/// <param name="MaxAuthenticationAttempts">
/// Failed AUTH attempts allowed on one connection before it is closed. From
/// <c>MailServer:Limits:MaxAuthAttemptsPerSession</c>.
/// </param>
public sealed record SmtpProcessorOptions(
    string Hostname,
    string ProductName,
    int MaxRecipientsPerMessage,
    long MaxMessageSizeBytes,
    bool IsAuthenticationAvailable = false,
    bool IsSmtpUtf8Available = false,
    bool IsChunkingAvailable = false,
    int MaxAuthenticationAttempts = 3);

/// <summary>
/// Turns one parsed command into one reply, against one session.
/// </summary>
/// <remarks>
/// <para>
/// The order of the checks is the design. Sequencing first, then policy, then parsing, then the
/// directory — so that a command which is out of sequence is refused before anything looks at
/// its argument, and a recipient in a domain this server does not host is refused before a
/// database is asked about it. Cheap refusals first is a denial-of-service property as much as
/// a tidiness one.
/// </para>
/// <para>
/// The processor never touches the socket. It is handed a command and returns a reply and an
/// action, which makes the entire command surface of the server testable without a network —
/// including the refusals, which are the part that matters and the part that is hardest to
/// provoke against a real listener.
/// </para>
/// </remarks>
public sealed class SmtpCommandProcessor
{
    private readonly SmtpSessionContext _session;
    private readonly SmtpProcessorOptions _options;
    private readonly ISmtpDirectory _directory;
    private readonly RelayPolicy _relayPolicy;
    private readonly ILogger _logger;
    private readonly IMailboxAuthenticator _authenticator;
    private readonly SubmissionPolicy _submissionPolicy;
    private readonly ISubmissionRateLimiter? _rateLimiter;
    private readonly SpfEvaluator? _spfEvaluator;
    private readonly SmtpAbusePolicy _abusePolicy;

    /// <summary>The mechanism mid-exchange, or null when no AUTH is in flight.</summary>
    /// <remarks>
    /// One at a time. A session that could run two exchanges at once would have two answers to
    /// "who is this", and the wrong one would decide whether relaying is permitted.
    /// </remarks>
    private ISaslMechanism? _mechanism;

    public SmtpCommandProcessor(
        SmtpSessionContext session,
        SmtpProcessorOptions options,
        ISmtpDirectory directory,
        RelayPolicy relayPolicy,
        ILogger logger,
        IMailboxAuthenticator? authenticator = null,
        SubmissionPolicy? submissionPolicy = null,
        ISubmissionRateLimiter? rateLimiter = null,
        SpfEvaluator? spfEvaluator = null,
        SmtpAbusePolicy? abusePolicy = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(relayPolicy);
        ArgumentNullException.ThrowIfNull(logger);

        _session = session;
        _options = options;
        _directory = directory;
        _relayPolicy = relayPolicy;
        _logger = logger;
        _abusePolicy = abusePolicy ?? SmtpAbusePolicy.Default;

        // Optional so a test can build a processor for the many paths that never authenticate.
        // A session that reaches AUTH without one is refused, not crashed - see Authenticate.
        _authenticator = authenticator ?? UnavailableAuthenticator.Instance;

        // The policy is a pure function with no configuration, so a default instance is the
        // same instance. The rate limiter needs a database and is genuinely optional: a null
        // one means unlimited, which is correct for the MTA listener - inbound mail is not
        // submitted by anyone and has no mailbox to charge.
        _submissionPolicy = submissionPolicy ?? new SubmissionPolicy();
        _rateLimiter = rateLimiter;

        // Null is a legitimate configuration, not a missing dependency: SPF is only ever
        // evaluated for SmtpListenerRole.InboundMta (see MailFromAsync), so a processor built for
        // Submission never needs one.
        _spfEvaluator = spfEvaluator;
    }

    /// <summary>The session this processor drives.</summary>
    public SmtpSessionContext Session => _session;

    /// <summary>The banner sent when the connection opens.</summary>
    public SmtpReply Banner() => SmtpReplies.Greeting(_options.Hostname, _options.ProductName);

    /// <summary>Executes one command.</summary>
    public async ValueTask<SmtpCommandResult> ExecuteAsync(
        SmtpCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        // An unrecognised verb is a 500 and never a 503: telling a client its command was "out
        // of sequence" when the server simply does not know the command sends it looking for a
        // sequencing bug that is not there.
        if (command.Verb == SmtpVerb.Unknown)
        {
            return Account(
                command, new SmtpCommandResult(SmtpReplies.CommandNotRecognised(Describe(command))));
        }

        if (!SmtpStateMachine.IsInSequence(_session.State, command.Verb))
        {
            return Account(
                command, new SmtpCommandResult(SmtpReplies.BadSequence(OutOfSequenceReason(command.Verb))));
        }

        SmtpCommandResult result = command.Verb switch
        {
            SmtpVerb.Ehlo => Greet(command.Argument, extended: true),
            SmtpVerb.Helo => Greet(command.Argument, extended: false),
            SmtpVerb.StartTls => StartTls(),
            SmtpVerb.Auth => await AuthenticateAsync(command.Argument, cancellationToken).ConfigureAwait(false),
            SmtpVerb.MailFrom => await MailFromAsync(command.Argument, cancellationToken).ConfigureAwait(false),
            SmtpVerb.RcptTo => await RcptToAsync(command.Argument, cancellationToken).ConfigureAwait(false),
            SmtpVerb.Data => Data(),
            SmtpVerb.Rset => Reset(),
            SmtpVerb.Noop => new SmtpCommandResult(SmtpReplies.Ok()),
            SmtpVerb.Quit => Quit(),
            SmtpVerb.Vrfy => new SmtpCommandResult(Vrfy()),
            SmtpVerb.Expn => new SmtpCommandResult(SmtpReplies.CommandNotImplemented("EXPN")),
            SmtpVerb.Help => new SmtpCommandResult(Help()),
            _ => new SmtpCommandResult(SmtpReplies.CommandNotRecognised(Describe(command))),
        };

        return Account(command, result);
    }

    /// <summary>
    /// Counts what this server refused, and closes the connection when a session stops being a
    /// mail delivery and becomes something else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>In one place, on the way out, rather than at each refusal.</b> Every path that returns
    /// a 4xx or 5xx is counted without anybody remembering to count it, so a refusal added to
    /// this processor later is bounded from the day it is written. A counter sprinkled across
    /// twenty return statements is a counter that is missing from the twenty-first.
    /// </para>
    /// <para>
    /// <b>It only ever escalates.</b> A result that already asked to close — the AUTH limit's
    /// own, or <c>QUIT</c> — keeps its action. Overwriting it with <c>Continue</c> would turn
    /// this accounting into a way to stay connected past a limit that had already fired.
    /// </para>
    /// </remarks>
    private SmtpCommandResult Account(SmtpCommand command, SmtpCommandResult result)
    {
        // 2xx accepted it and 3xx asked for more; neither is a refusal. QUIT's 221 is a 2xx.
        if (result.Reply.Code < 400)
        {
            return result;
        }

        if (command.Verb == SmtpVerb.RcptTo)
        {
            // Counted as a recipient refusal rather than a command one, because that is the
            // number a directory harvest drives up. Counting it as both would let a harvester
            // trip the (higher) command limit first and be told a different story.
            _session.RecordRejectedRecipient();
        }
        else
        {
            _session.RecordRejectedCommand();
        }

        SmtpAbuseVerdict verdict = _abusePolicy.Evaluate(
            new SmtpSessionConduct(_session.RejectedCommands, _session.RejectedRecipients));

        if (verdict == SmtpAbuseVerdict.Continue || result.Action != SmtpSessionAction.Continue)
        {
            return result;
        }

        _logger.LogWarning(
            "Closing the SMTP session from {RemoteAddress}: {Verdict} ({Commands} refused commands, {Recipients} refused recipients).",
            _session.RemoteAddress.Value,
            verdict,
            _session.RejectedCommands,
            _session.RejectedRecipients);

        return new SmtpCommandResult(
            new SmtpReply(421, "4.7.0", SmtpAbusePolicy.DiagnosticFor(verdict)),
            SmtpSessionAction.CloseAfterReply);
    }

    // ---- Greeting ---------------------------------------------------------------------------

    private SmtpCommandResult Greet(string argument, bool extended)
    {
        if (string.IsNullOrWhiteSpace(argument))
        {
            return new SmtpCommandResult(
                SmtpReplies.SyntaxError("EHLO requires the client's fully-qualified domain name."));
        }

        // The name is whatever the client typed. It is recorded, appears in the Received header
        // as a claim, and is never used to make a decision - in particular, never to decide
        // whether relaying is permitted.
        _session.Greet(argument, extended);

        if (!extended)
        {
            // HELO gets no capability list at all: a HELO client has not asked for extensions
            // and would not understand the multi-line reply.
            return new SmtpCommandResult(new SmtpReply(250, null, $"{_options.Hostname} greets you"));
        }

        return new SmtpCommandResult(SmtpReplies.EhloResponse(_options.Hostname, Capabilities()));
    }

    private IReadOnlyList<string> Capabilities() => SmtpCapabilities.For(CapabilityContext());

    private SmtpCapabilityContext CapabilityContext() => new(
        _session.Role,
        _session.IsTlsActive,
        _options.IsAuthenticationAvailable,
        _options.MaxMessageSizeBytes,
        _options.IsSmtpUtf8Available,
        _options.IsChunkingAvailable);

    // ---- Security -----------------------------------------------------------------------------

    private SmtpCommandResult StartTls()
    {
        if (!SmtpCapabilities.MayOfferStartTls(CapabilityContext()))
        {
            // Refused with the same reason it was not advertised. RFC 3207 §4.2: a server that
            // has already negotiated TLS answers 454 or 502; 502 says plainly that the command
            // is not available on this connection.
            return new SmtpCommandResult(
                SmtpReplies.CommandNotImplemented("STARTTLS is not available on this connection"));
        }

        // The handshake itself, the session reset and the discarding of buffered input are the
        // connection loop's to perform, because only it owns the socket and the reader. The
        // reply must be written and flushed BEFORE the handshake begins, or the client waits
        // for a 220 that is sitting behind a TLS record it cannot yet read.
        return new SmtpCommandResult(SmtpReplies.ReadyForTls(), SmtpSessionAction.StartTlsHandshake);
    }

    /// <summary>
    /// Begins an AUTH exchange.
    /// </summary>
    /// <remarks>
    /// The argument is <c>MECHANISM [initial-response]</c>. The initial response is base64 and is
    /// a credential, so it is never echoed, never logged, and never appears in a reply.
    /// </remarks>
    private async ValueTask<SmtpCommandResult> AuthenticateAsync(
        string argument,
        CancellationToken cancellationToken)
    {
        if (_session.IsAuthenticated)
        {
            // RFC 4954 §4: a session authenticates once. A second attempt would raise the
            // question of what happens to state collected under the first identity.
            return new SmtpCommandResult(SmtpReplies.BadSequence("This session has already authenticated."));
        }

        if (_session.Role is SmtpListenerRole.InboundMta)
        {
            // Not "wrong password" and not "try TLS first". There is no authentication on this
            // listener at all, and saying so leaks nothing.
            return new SmtpCommandResult(
                SmtpReplies.CommandNotImplemented("AUTH is not available on this listener"));
        }

        if (!_session.IsTlsActive)
        {
            // Rule 105: no plaintext SMTP AUTH over Internet. The capability was not advertised,
            // and it is refused here too - a defence that relied on advertisement alone would
            // fail the moment a client guessed.
            return new SmtpCommandResult(SmtpReplies.TlsRequired());
        }

        if (!_options.IsAuthenticationAvailable)
        {
            return new SmtpCommandResult(SmtpReplies.CommandNotImplemented("AUTH"));
        }

        if (HasExhaustedAttempts)
        {
            return new SmtpCommandResult(
                SmtpReplies.TooManyAuthenticationAttempts(),
                SmtpSessionAction.CloseAfterReply);
        }

        // Split on the FIRST space only: everything after it is base64, which may contain no
        // space but must not be re-split if it somehow does.
        int space = argument.IndexOf(' ', StringComparison.Ordinal);

        string mechanismName = space < 0 ? argument : argument[..space];
        string? initialResponse = space < 0 ? null : argument[(space + 1)..].Trim();

        if (mechanismName.Length == 0)
        {
            return new SmtpCommandResult(SmtpReplies.SyntaxError("AUTH requires a mechanism."));
        }

        ISaslMechanism? mechanism = SaslMechanisms.Create(mechanismName);

        if (mechanism is null)
        {
            // Logged, not echoed. A client that sends "AUTH <base64>" with no mechanism puts its
            // credential in the mechanism position, and no shape test separates that from a
            // mistyped mechanism name - a great many passwords match RFC 4422's charset exactly.
            // Debug level, so the name reaches an operator and not the peer.
            _logger.LogDebug(
                "Unsupported SASL mechanism requested from {RemoteAddress}: {Mechanism}",
                _session.RemoteAddress.Value,
                mechanismName);

            return new SmtpCommandResult(SmtpReplies.UnsupportedAuthenticationMechanism());
        }

        _mechanism = mechanism;

        return await AdvanceAsync(
            mechanism.Start(initialResponse),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Feeds the client's answer to a 334 back into the in-flight exchange.
    /// </summary>
    /// <remarks>
    /// The line is a credential. It reaches this method directly from the connection loop and is
    /// never parsed as a command — a session mid-AUTH has no command grammar, and treating the
    /// line as one would turn a password into a verb.
    /// </remarks>
    public async ValueTask<SmtpCommandResult> ContinueAuthenticationAsync(
        string response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);

        if (_mechanism is null)
        {
            return new SmtpCommandResult(SmtpReplies.BadSequence("No authentication exchange is in progress."));
        }

        return await AdvanceAsync(_mechanism.Advance(response), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Turns one SASL step into a reply, verifying the credential when there is one.</summary>
    private async ValueTask<SmtpCommandResult> AdvanceAsync(SaslStep step, CancellationToken cancellationToken)
    {
        switch (step.Outcome)
        {
            case SaslOutcome.Challenge:
                return new SmtpCommandResult(
                    SmtpReplies.AuthenticationChallenge(step.Challenge ?? string.Empty),
                    SmtpSessionAction.ReadAuthenticationResponse);

            case SaslOutcome.Cancelled:
                // RFC 4954 §4. A client that changed its mind has not failed a password, so this
                // does NOT count against the attempt budget - counting it would walk a hesitant
                // client into a lockout it never earned.
                EndExchange();

                return new SmtpCommandResult(SmtpReplies.AuthenticationCancelled());

            case SaslOutcome.Failed:
                EndExchange();

                // A malformed exchange counts. Otherwise a client could probe indefinitely by
                // sending garbage, and the attempt budget would bound nothing.
                return CountFailure(SmtpReplies.AuthenticationFailed(), step.Diagnostic);

            case SaslOutcome.Completed:
                return await VerifyAsync(step.Credential!, cancellationToken).ConfigureAwait(false);

            default:
                EndExchange();

                return CountFailure(SmtpReplies.AuthenticationFailed(), "Unrecognised SASL outcome.");
        }
    }

    private async ValueTask<SmtpCommandResult> VerifyAsync(
        SaslCredential credential,
        CancellationToken cancellationToken)
    {
        EndExchange();

        // Disposed on every path, including the exception one. The password lives in a clearable
        // buffer precisely so that this can overwrite it the moment it is no longer needed.
        using (credential)
        {
            MailboxAuthenticationResult result = await _authenticator
                .AuthenticateAsync(credential, MailboxAccess.Submission, _session.RemoteAddress, cancellationToken)
                .ConfigureAwait(false);

            if (result.IsSuccess && result.Mailbox is not null)
            {
                _session.Authenticate(result.Mailbox);

                _logger.LogInformation(
                    "{Mailbox} authenticated from {RemoteAddress}.",
                    result.Mailbox.Value,
                    _session.RemoteAddress.Value);

                return new SmtpCommandResult(SmtpReplies.AuthenticationSucceeded());
            }

            // A locked-out mailbox receives exactly the reply a wrong password receives.
            // "This account is locked" confirms the account exists, which is the enumeration
            // answer the whole path is careful not to give.
            return CountFailure(SmtpReplies.AuthenticationFailed(), result.Diagnostic);
        }
    }

    /// <summary>Counts a failed attempt and closes the session once the budget is spent.</summary>
    /// <remarks>
    /// Bounds online guessing at the connection level, underneath the per-mailbox lockout. The
    /// two are different defences: lockout protects one account across every connection, and
    /// this stops one connection being used to walk a dictionary across many accounts.
    /// </remarks>
    private SmtpCommandResult CountFailure(SmtpReply reply, string? diagnostic)
    {
        int attempts = _session.RecordFailedAuthentication();

        _logger.LogInformation(
            "Submission authentication attempt {Attempt} of {Max} failed from {RemoteAddress}: {Reason}",
            attempts,
            _options.MaxAuthenticationAttempts,
            _session.RemoteAddress.Value,
            diagnostic ?? "no detail");

        if (attempts < _options.MaxAuthenticationAttempts)
        {
            return new SmtpCommandResult(reply);
        }

        return new SmtpCommandResult(
            SmtpReplies.TooManyAuthenticationAttempts(),
            SmtpSessionAction.CloseAfterReply);
    }

    private bool HasExhaustedAttempts =>
        _session.FailedAuthenticationAttempts >= _options.MaxAuthenticationAttempts;

    private void EndExchange()
    {
        _mechanism?.Dispose();
        _mechanism = null;
    }

    /// <summary>Stands in when no authenticator was supplied, and refuses everything.</summary>
    /// <remarks>
    /// Fails closed. A missing dependency must not become a session that authenticates, and a
    /// null reference here would be an unhandled exception on the credential path.
    /// </remarks>
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
                "No authenticator is configured on this server."));
    }

    // ---- Envelope ------------------------------------------------------------------------------

    private async ValueTask<SmtpCommandResult> MailFromAsync(
        string argument,
        CancellationToken cancellationToken)
    {
        if (RequiresAuthentication())
        {
            return new SmtpCommandResult(SmtpReplies.AuthenticationRequired());
        }

        if (!SmtpPath.TryParse(argument, out EmailAddress? reversePath, out IReadOnlyList<string> parameters))
        {
            return new SmtpCommandResult(
                SmtpReplies.SyntaxError("MAIL FROM requires a reverse-path in angle brackets."));
        }

        long? declaredSize = SmtpPath.ReadSizeParameter(parameters);

        if (declaredSize > _options.MaxMessageSizeBytes)
        {
            // The sender's own claim exceeds the limit, so there is no point receiving the
            // message to find out. Advisory or not, a claim over the limit is a refusal the
            // sender asked for.
            return new SmtpCommandResult(SmtpReplies.MessageTooLarge(_options.MaxMessageSizeBytes));
        }

        if (_session.IsAuthenticated && _session.AuthenticatedMailbox is { } mailbox)
        {
            SmtpCommandResult? refusal = await CheckSubmissionAsync(
                mailbox,
                reversePath,
                cancellationToken).ConfigureAwait(false);

            if (refusal is not null)
            {
                return refusal;
            }
        }

        SpfEvaluationOutcome? spfOutcome = null;

        if (_session.Role == SmtpListenerRole.InboundMta && _spfEvaluator is not null)
        {
            (SmtpCommandResult? spfRefusal, spfOutcome) = await EvaluateSpfAsync(reversePath, cancellationToken)
                .ConfigureAwait(false);

            if (spfRefusal is not null)
            {
                return spfRefusal;
            }
        }

        _session.BeginTransaction(reversePath, declaredSize);

        if (spfOutcome is not null)
        {
            _session.RecordSpfOutcome(spfOutcome);
        }

        return new SmtpCommandResult(SmtpReplies.Ok("Sender accepted"));
    }

    /// <summary>
    /// Evaluates SPF for the sender's domain (the <c>MAIL FROM</c> domain, or the greeting name
    /// when the reverse path is null, per <c>docs/SPF.md</c>).
    /// </summary>
    /// <remarks>
    /// Only <see cref="SpfResult.TempError"/> refuses the command directly (the first tuple
    /// element); every other result (Pass, Fail, SoftFail, Neutral, None, PermError) is returned
    /// as an outcome for the caller to record once its transaction opens —
    /// <see cref="SmtpSessionContext.RecordSpfOutcome"/> requires one to already exist, and this
    /// method runs before <c>BeginTransaction</c> so it cannot record the outcome itself. SPF's
    /// own result is never enforced here beyond the transient case; DMARC alignment is what acts
    /// on Fail/SoftFail/Neutral/PermError.
    /// </remarks>
    private async ValueTask<(SmtpCommandResult? Refusal, SpfEvaluationOutcome? Outcome)> EvaluateSpfAsync(
        EmailAddress? reversePath, CancellationToken cancellationToken)
    {
        DomainName? checkedDomain = reversePath?.Domain;

        if (checkedDomain is null && _session.GreetedName is not null)
        {
            DomainName.TryParse(_session.GreetedName, out checkedDomain);
        }

        if (checkedDomain is null)
        {
            // Null reverse path and no usable greeting name: nothing to check SPF against.
            return (null, null);
        }

        SpfEvaluationResult result = await _spfEvaluator!
            .EvaluateAsync(checkedDomain, _session.RemoteAddress, cancellationToken)
            .ConfigureAwait(false);

        if (result.Result == SpfResult.TempError)
        {
            return (new SmtpCommandResult(SmtpReplies.SpfTemporaryError()), null);
        }

        return (null, new SpfEvaluationOutcome(result.Result, checkedDomain, result.Diagnostic));
    }

    /// <summary>
    /// Checks what an authenticated client may send and how much. Returns null when it may.
    /// </summary>
    /// <remarks>
    /// Both checks run at MAIL FROM, before a recipient is named and long before a body arrives.
    /// A client that is over its limit or claiming somebody else's address should learn so at the
    /// cheapest possible moment.
    /// </remarks>
    private async ValueTask<SmtpCommandResult?> CheckSubmissionAsync(
        EmailAddress mailbox,
        EmailAddress? reversePath,
        CancellationToken cancellationToken)
    {
        bool mayActAs = reversePath is not null && await _directory
            .MayActAsAsync(mailbox, reversePath, cancellationToken)
            .ConfigureAwait(false);

        SubmissionPolicy.Result decision = _submissionPolicy.Evaluate(
            new SubmissionContext(mailbox, reversePath),
            _ => mayActAs);

        if (!decision.IsPermitted)
        {
            // The signal that a compromised account is being used to forge a colleague's
            // address, which is most of what a stolen password is worth to an attacker.
            _logger.LogWarning(
                "Sender forgery refused: {Mailbox} from {RemoteAddress} tried to send as {ClaimedSender}.",
                mailbox.Value,
                _session.RemoteAddress.Value,
                reversePath?.Value ?? "<>");

            return new SmtpCommandResult(SmtpReplies.SenderNotPermitted(decision.Reason));
        }

        if (_rateLimiter is null)
        {
            return null;
        }

        SubmissionRateDecision rate = await _rateLimiter
            .CheckAsync(mailbox, cancellationToken)
            .ConfigureAwait(false);

        if (rate.IsWithinLimit)
        {
            return null;
        }

        _logger.LogWarning(
            "{Mailbox} has submitted {Count} message(s) in the last {Window} and is over its limit of {Limit}.",
            mailbox.Value,
            rate.MessagesInWindow,
            rate.Window,
            rate.MessageLimit);

        return new SmtpCommandResult(SmtpReplies.SubmissionRateExceeded(rate.MessageLimit, rate.Window));
    }

    private async ValueTask<SmtpCommandResult> RcptToAsync(
        string argument,
        CancellationToken cancellationToken)
    {
        if (_session.Recipients.Count >= _options.MaxRecipientsPerMessage)
        {
            // Transient, not permanent: the sender can succeed by splitting the message, and
            // this is our own throttle rather than anything wrong with their mail.
            return new SmtpCommandResult(SmtpReplies.TooManyRecipients(_options.MaxRecipientsPerMessage));
        }

        if (!SmtpPath.TryParse(argument, out EmailAddress? recipient, out _) || recipient is null)
        {
            // RCPT TO:<> has no meaning - the null path is a sender, never a recipient.
            return new SmtpCommandResult(
                SmtpReplies.SyntaxError("RCPT TO requires a forward-path in angle brackets."));
        }

        RelayPolicy.Result decision = await EvaluateRelayAsync(recipient, cancellationToken)
            .ConfigureAwait(false);

        if (decision.Decision == RelayDecision.Deny)
        {
            _logger.LogWarning(
                "Relay refused for {Recipient} from {RemoteAddress} on {Role}: {Reason}",
                recipient.ToString(),
                _session.RemoteAddress.Value,
                _session.Role,
                decision.Reason);

            return new SmtpCommandResult(SmtpReplies.RelayDenied(decision.Reason));
        }

        if (decision.Decision == RelayDecision.AcceptLocal)
        {
            LocalRecipientStatus status = await _directory
                .InspectLocalRecipientAsync(recipient, cancellationToken)
                .ConfigureAwait(false);

            SmtpReply? refusal = status switch
            {
                LocalRecipientStatus.Deliverable => null,
                LocalRecipientStatus.NoSuchMailbox => SmtpReplies.MailboxNotFound(recipient.ToString()),
                LocalRecipientStatus.Disabled => SmtpReplies.MailboxDisabled(recipient.ToString()),
                LocalRecipientStatus.OverQuota => SmtpReplies.MailboxFull(recipient.ToString()),

                // An unmapped status is refused transiently rather than accepted. A new value
                // added to the enum must not become a delivery.
                _ => SmtpReplies.LocalError("recipient status could not be determined"),
            };

            if (refusal is not null)
            {
                return new SmtpCommandResult(refusal);
            }
        }

        _session.AcceptRecipient(recipient, decision.Decision);

        return new SmtpCommandResult(SmtpReplies.Ok("Recipient accepted"));
    }

    /// <summary>
    /// Resolves the facts the relay policy needs, then lets the policy decide.
    /// </summary>
    /// <remarks>
    /// The lookups happen here and the decision happens in <c>RelayPolicy</c>, which is a pure
    /// total function with an exhaustive test suite. Nothing in this method can return an
    /// acceptance: it can only supply facts, and the shape of the code is what keeps the single
    /// most consequential decision in the product in one reviewable place.
    /// </remarks>
    private async ValueTask<RelayPolicy.Result> EvaluateRelayAsync(
        EmailAddress recipient,
        CancellationToken cancellationToken)
    {
        bool isLocal = await _directory
            .IsLocalDomainAsync(recipient.Domain, cancellationToken)
            .ConfigureAwait(false);

        bool mayRelayAs = false;

        if (!isLocal && _session.IsAuthenticated && _session.AuthenticatedMailbox is not null)
        {
            mayRelayAs = await _directory
                .MayRelayAsAsync(_session.AuthenticatedMailbox, recipient, cancellationToken)
                .ConfigureAwait(false);
        }

        bool isAuthorizedRelayAddress = false;

        if (!isLocal)
        {
            isAuthorizedRelayAddress = await _directory
                .IsAuthorizedRelayAddressAsync(_session.RemoteAddress, cancellationToken)
                .ConfigureAwait(false);
        }

        return _relayPolicy.Evaluate(
            _session.ToRelayContext(),
            recipient,
            _ => isLocal,
            _ => isAuthorizedRelayAddress,
            (_, _) => mayRelayAs);
    }

    private SmtpCommandResult Data()
    {
        if (_session.Recipients.Count == 0)
        {
            // Unreachable through the state machine, and refused anyway. Reaching DATA with no
            // recipients would mean receiving a message with nowhere to put it.
            return new SmtpCommandResult(SmtpReplies.BadSequence("No recipients have been accepted."));
        }

        _session.BeginData();

        return new SmtpCommandResult(SmtpReplies.StartMailInput(), SmtpSessionAction.ReceiveMessageData);
    }

    // ---- Housekeeping ----------------------------------------------------------------------------

    private SmtpCommandResult Reset()
    {
        _session.Reset();

        return new SmtpCommandResult(SmtpReplies.Ok("Reset"));
    }

    private SmtpCommandResult Quit()
    {
        _session.Close();

        return new SmtpCommandResult(
            SmtpReplies.Closing(_options.Hostname),
            SmtpSessionAction.CloseAfterReply);
    }

    /// <summary>
    /// 252, which says nothing.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §3.5.3 offers 252 for a server that cannot verify an address, and this server
    /// chooses not to. Answering truthfully would turn VRFY into an address-enumeration oracle:
    /// a spammer walks a dictionary and learns which mailboxes exist. 252 is the same answer for
    /// every address, so it leaks nothing.
    /// </remarks>
    private static SmtpReply Vrfy() =>
        new(252, "2.5.2", "Cannot verify the address; will attempt delivery if you send the message");

    private SmtpReply Help() =>
        new(214, "2.0.0", $"{_options.ProductName}. Supported commands: {SupportedCommands()}");

    private string SupportedCommands()
    {
        List<string> commands = ["EHLO", "HELO", "MAIL FROM", "RCPT TO", "DATA", "RSET", "NOOP", "QUIT", "HELP"];

        if (SmtpCapabilities.MayOfferStartTls(CapabilityContext()))
        {
            commands.Add("STARTTLS");
        }

        if (SmtpCapabilities.MayOfferAuthentication(CapabilityContext()))
        {
            commands.Add("AUTH");
        }

        return string.Join(' ', commands);
    }

    /// <summary>
    /// Whether this listener requires authentication before a message may be submitted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Submission listeners exist to accept mail from authenticated clients, so an
    /// unauthenticated MAIL FROM on one is refused outright. Letting it through would reach
    /// RCPT TO and be refused there for a foreign domain — correct — but would also accept mail
    /// for local domains without authentication on a port intended for none.
    /// </para>
    /// <para>
    /// <b>Deliberately not conditioned on whether SASL is implemented.</b> While authentication
    /// is unavailable this makes a submission listener refuse everything, which is the safe
    /// failure: the alternative is a listener that quietly accepts unauthenticated mail because
    /// the mechanism for authenticating had not been written yet.
    /// </para>
    /// </remarks>
    private bool RequiresAuthentication() =>
        _session.Role is SmtpListenerRole.Submission or SmtpListenerRole.ImplicitTlsSubmission &&
        !_session.IsAuthenticated;

    private static string OutOfSequenceReason(SmtpVerb verb) => verb switch
    {
        SmtpVerb.MailFrom => "Send EHLO or HELO first, and finish any open transaction.",
        SmtpVerb.RcptTo => "Send MAIL FROM first.",
        SmtpVerb.Data => "Send at least one RCPT TO first.",
        SmtpVerb.StartTls => "Send EHLO first, and do not start TLS inside a mail transaction.",
        SmtpVerb.Auth => "Send EHLO first, and do not authenticate inside a mail transaction.",
        _ => "That command is not valid at this point in the session.",
    };

    /// <summary>
    /// Describes an unrecognised command for the reply, bounded in length.
    /// </summary>
    /// <remarks>
    /// The text goes back to the peer that sent it, so it is truncated: echoing a four-kilobyte
    /// line would let a peer make this server send four kilobytes per refused command, which is
    /// an amplification the peer controls. <c>SmtpReply.Format</c> strips control characters, so
    /// this only has to bound the length.
    /// </remarks>
    private static string Describe(SmtpCommand command)
    {
        const int MaxEcho = 60;

        string raw = command.Raw;

        return raw.Length <= MaxEcho ? raw : string.Concat(raw.AsSpan(0, MaxEcho), "...");
    }
}
