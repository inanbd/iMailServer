using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Smtp;

/// <summary>How an authentication attempt ended.</summary>
/// <remarks>
/// <b>There is no "no such mailbox" outcome, and that is deliberate.</b> An unknown address and
/// a wrong password are the same answer — <see cref="Failed"/> — because any difference between
/// them, in the reply, in the timing, or in the log, tells an attacker which addresses exist.
/// Address enumeration is the first step of every credential-stuffing run against a mail server.
/// </remarks>
public enum MailboxAuthenticationOutcome
{
    /// <summary>Refused. Covers a wrong password, an unknown mailbox, and a disabled one alike.</summary>
    Failed = 0,

    /// <summary>The credential is correct and the mailbox may submit.</summary>
    Succeeded = 1,

    /// <summary>
    /// The mailbox is locked out after repeated failures.
    /// </summary>
    /// <remarks>
    /// Reported separately from <see cref="Failed"/> only so the <i>server</i> can log it. The
    /// reply the client receives is identical, because "this account is locked" confirms the
    /// account exists.
    /// </remarks>
    LockedOut = 2,
}

/// <summary>The result of an authentication attempt.</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Mailbox">The authenticated mailbox, when it succeeded. Null otherwise.</param>
/// <param name="Diagnostic">
/// For the server's own log. Never sent to the client, and never contains credential material.
/// </param>
public sealed record MailboxAuthenticationResult(
    MailboxAuthenticationOutcome Outcome,
    EmailAddress? Mailbox,
    string Diagnostic)
{
    public bool IsSuccess => Outcome == MailboxAuthenticationOutcome.Succeeded;
}

/// <summary>Verifies a SASL credential against a mailbox.</summary>
public interface IMailboxAuthenticator
{
    /// <summary>
    /// Verifies a credential.
    /// </summary>
    /// <param name="credential">
    /// The credential, still in its clearable buffer. This method does not dispose it — the
    /// caller owns it and must, whatever the outcome.
    /// </param>
    /// <param name="remoteAddress">The peer, for the security event.</param>
    Task<MailboxAuthenticationResult> AuthenticateAsync(
        SaslCredential credential,
        IpAddressValue remoteAddress,
        CancellationToken cancellationToken);
}
