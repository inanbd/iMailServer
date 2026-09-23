using MailServer.Domain.Enums;
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

    /// <summary>The credential is correct and the mailbox may use the protocol that asked.</summary>
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
/// <param name="MailboxId">
/// The authenticated mailbox's identity, when it succeeded. Null otherwise.
/// </param>
/// <remarks>
/// <para>
/// <see cref="MailboxId"/> arrived with IMAP and is why it has a default rather than a position
/// alongside the others: SMTP never needed it, because an SMTP session records who authenticated
/// as an address and nothing more. An IMAP session caches the identity for the life of the
/// connection — see <c>ImapSessionContext</c>'s remarks on why — so it needs the id, and the
/// authenticator has already loaded the mailbox in order to check the credential. Returning what
/// it is holding costs nothing; making the caller look the same row up again would be a second
/// query to answer a question that was just answered.
/// </para>
/// <para>
/// Null on every failure, and deliberately so: a result that carried an id alongside
/// <see cref="MailboxAuthenticationOutcome.Failed"/> would be a refusal that still told the
/// caller the mailbox exists.
/// </para>
/// </remarks>
public sealed record MailboxAuthenticationResult(
    MailboxAuthenticationOutcome Outcome,
    EmailAddress? Mailbox,
    string Diagnostic,
    MailboxId? MailboxId = null)
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
    /// <param name="protocol">
    /// The access being asked for — exactly one of <see cref="MailboxAccess.Submission"/>,
    /// <see cref="MailboxAccess.Imap"/> or <see cref="MailboxAccess.Pop3"/> — checked against the
    /// mailbox's own access flags.
    /// </param>
    /// <param name="remoteAddress">The peer, for the security event.</param>
    /// <remarks>
    /// <b>The protocol is required and has no default, on purpose.</b> This port was written for
    /// submission and IMAP and POP3 later reused it without saying who was asking, so every
    /// sign-in was checked against the submission flag: an IMAP-only mailbox could not read its
    /// mail, and a send-only one could read and delete it over IMAP and POP3, whose flags were
    /// never consulted at all. A caller that cannot compile without naming its protocol cannot
    /// make that mistake again.
    /// </remarks>
    Task<MailboxAuthenticationResult> AuthenticateAsync(
        SaslCredential credential,
        MailboxAccess protocol,
        IpAddressValue remoteAddress,
        CancellationToken cancellationToken);
}
