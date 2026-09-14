using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
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
public sealed record SmtpProcessorOptions(
    string Hostname,
    string ProductName,
    int MaxRecipientsPerMessage,
    long MaxMessageSizeBytes,
    bool IsAuthenticationAvailable = false,
    bool IsSmtpUtf8Available = false,
    bool IsChunkingAvailable = false);

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

    public SmtpCommandProcessor(
        SmtpSessionContext session,
        SmtpProcessorOptions options,
        ISmtpDirectory directory,
        RelayPolicy relayPolicy,
        ILogger logger)
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
            return new SmtpCommandResult(SmtpReplies.CommandNotRecognised(Describe(command)));
        }

        if (!SmtpStateMachine.IsInSequence(_session.State, command.Verb))
        {
            return new SmtpCommandResult(SmtpReplies.BadSequence(OutOfSequenceReason(command.Verb)));
        }

        return command.Verb switch
        {
            SmtpVerb.Ehlo => Greet(command.Argument, extended: true),
            SmtpVerb.Helo => Greet(command.Argument, extended: false),
            SmtpVerb.StartTls => StartTls(),
            SmtpVerb.Auth => Authenticate(),
            SmtpVerb.MailFrom => MailFrom(command.Argument),
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

    private SmtpCommandResult Authenticate()
    {
        if (!_options.IsAuthenticationAvailable)
        {
            return new SmtpCommandResult(SmtpReplies.CommandNotImplemented("AUTH"));
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
            // and it is refused here too.
            return new SmtpCommandResult(SmtpReplies.TlsRequired());
        }

        // SASL lands in Milestone 7. Until then the capability is not advertised, so a client
        // only reaches this line by guessing, and it is told the truth.
        return new SmtpCommandResult(SmtpReplies.CommandNotImplemented("AUTH"));
    }

    // ---- Envelope ------------------------------------------------------------------------------

    private SmtpCommandResult MailFrom(string argument)
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

        _session.BeginTransaction(reversePath, declaredSize);

        return new SmtpCommandResult(SmtpReplies.Ok("Sender accepted"));
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
