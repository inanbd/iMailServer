using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Smtp;

/// <summary>
/// Verifies a SASL credential against a mailbox's Argon2id verifier.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every refusal costs the same and says the same.</b> An unknown address, a disabled
/// mailbox, a mailbox not permitted to submit and a wrong password all return
/// <see cref="MailboxAuthenticationOutcome.Failed"/>, and every one of them spends a full Argon2
/// verification first. Returning early on an unknown address would make the refusal arrive in
/// microseconds instead of ~100 ms, and that difference is measurable from anywhere on the
/// Internet — it turns the submission port into an address-enumeration oracle, which is the
/// first step of every credential-stuffing run against a mail server.
/// </para>
/// <para>
/// The credential belongs to the caller. This class reads it and does not dispose it, because
/// the caller has to dispose it on every path including the ones that never reach here.
/// </para>
/// </remarks>
public sealed class MailboxAuthenticator(
    IMailboxRepository mailboxes,
    IPasswordHasher passwordHasher,
    ISecuritySettings securitySettings,
    ISecurityEventRecorder securityEvents,
    IClock clock,
    ILogger<MailboxAuthenticator> logger) : IMailboxAuthenticator
{
    /// <inheritdoc />
    public async Task<MailboxAuthenticationResult> AuthenticateAsync(
        SaslCredential credential,
        IpAddressValue remoteAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(remoteAddress);

        if (!EmailAddress.TryParse(credential.AuthenticationIdentity, out EmailAddress? address))
        {
            // Not even an address. Still pays for a verification, because "that is not an
            // address" arriving instantly is itself a signal worth denying an attacker.
            return await RefuseAsync(
                credential,
                subject: null,
                remoteAddress,
                "The authentication identity is not a valid address.",
                cancellationToken).ConfigureAwait(false);
        }

        // An authorization identity is accepted only when it names the same mailbox. Allowing
        // one mailbox to act as another is a delegation feature this server does not have, and
        // silently ignoring the field would mean a client that asked for it got something
        // different from what it asked for.
        if (credential.AuthorizationIdentity.Length > 0 &&
            !(EmailAddress.TryParse(credential.AuthorizationIdentity, out EmailAddress? authorization) &&
              authorization.NormalizedValue.Equals(address.NormalizedValue, StringComparison.Ordinal)))
        {
            return await RefuseAsync(
                credential,
                address.Value,
                remoteAddress,
                "The authorization identity names a different mailbox, which this server does not permit.",
                cancellationToken).ConfigureAwait(false);
        }

        Mailbox? mailbox = await mailboxes
            .GetByAddressAsync(address, cancellationToken)
            .ConfigureAwait(false);

        MailboxCredential? stored = mailbox is null
            ? null
            : await mailboxes.GetCredentialAsync(mailbox.Id, cancellationToken).ConfigureAwait(false);

        if (mailbox is null || stored is null)
        {
            return await RefuseAsync(
                credential,
                address.Value,
                remoteAddress,
                mailbox is null
                    ? "No mailbox with that address."
                    : "The mailbox has no password set.",
                cancellationToken).ConfigureAwait(false);
        }

        DateTimeOffset now = clock.UtcNow;

        if (stored.IsLockedOut(now))
        {
            // Spends the work anyway. A locked account that answers instantly while an unlocked
            // one takes 100 ms tells an attacker their guessing worked well enough to trip the
            // lock, which is information about the account.
            passwordHasher.VerifyAgainstDummy(string.Empty);

            await securityEvents.RecordAsync(
                SecurityEventType.MailboxLockedOut,
                address.Value,
                remoteAddress.Value,
                $"Authentication refused: the mailbox is locked out for a further {stored.GetRemainingLockout(now)}.",
                cancellationToken).ConfigureAwait(false);

            return new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.LockedOut,
                null,
                "The mailbox is locked out.");
        }

        PasswordVerificationResult verification = passwordHasher.Verify(credential.Password, stored.PasswordHash);

        if (!verification.IsValid)
        {
            LockoutPolicy policy = securitySettings.LockoutPolicy;

            bool locked = stored.RecordFailure(policy, now);

            // Written on its own, outside any transaction the session may later open. A failure
            // counter rolled back by the transaction that recorded it is a lockout that never
            // happens - the defect this project already met once, in Milestone 2.
            await mailboxes.UpdateCredentialAsync(stored, cancellationToken).ConfigureAwait(false);

            await securityEvents.RecordAsync(
                locked ? SecurityEventType.MailboxLockedOut : SecurityEventType.MailboxAuthenticationFailed,
                address.Value,
                remoteAddress.Value,
                locked
                    ? $"The mailbox was locked out after {stored.ConsecutiveFailures} consecutive failures."
                    : "Authentication failed.",
                cancellationToken).ConfigureAwait(false);

            return new MailboxAuthenticationResult(
                locked ? MailboxAuthenticationOutcome.LockedOut : MailboxAuthenticationOutcome.Failed,
                null,
                "The password did not match.");
        }

        // Correct password. Everything below is about whether this mailbox may submit at all,
        // and each refusal is still reported to the client as an ordinary failure.
        if (!mailbox.AllowsLogin)
        {
            return await RefuseAfterCorrectPasswordAsync(
                address,
                remoteAddress,
                $"The mailbox is {mailbox.Status} and may not sign in.",
                cancellationToken).ConfigureAwait(false);
        }

        if (!mailbox.AllowsAccess(MailboxAccess.Submission))
        {
            return await RefuseAfterCorrectPasswordAsync(
                address,
                remoteAddress,
                "The mailbox is not permitted to submit mail.",
                cancellationToken).ConfigureAwait(false);
        }

        stored.RecordSuccess(now);

        if (verification.NeedsRehash)
        {
            // The one moment the plaintext is available. Raising the work factors must not
            // invalidate existing passwords, so each is upgraded the next time its owner signs
            // in rather than by a migration that cannot see them.
            stored.UpgradePasswordHash(passwordHasher.Hash(credential.Password));

            logger.LogInformation(
                "Upgraded the stored password hash for {Mailbox} to the current work factors.",
                address.Value);
        }

        await mailboxes.UpdateCredentialAsync(stored, cancellationToken).ConfigureAwait(false);

        await securityEvents.RecordAsync(
            SecurityEventType.MailboxAuthenticationSucceeded,
            address.Value,
            remoteAddress.Value,
            "Authenticated on a submission listener.",
            cancellationToken).ConfigureAwait(false);

        return new MailboxAuthenticationResult(
            MailboxAuthenticationOutcome.Succeeded,
            mailbox.Address,
            "Authenticated.",
            mailbox.Id);
    }

    /// <summary>Refuses, having first spent a verification's worth of work.</summary>
    private async Task<MailboxAuthenticationResult> RefuseAsync(
        SaslCredential credential,
        string? subject,
        IpAddressValue remoteAddress,
        string diagnostic,
        CancellationToken cancellationToken)
    {
        // The whole point: this costs the same as a real verification, so the two are
        // indistinguishable from the outside.
        passwordHasher.VerifyAgainstDummy(credential.Password);

        await securityEvents.RecordAsync(
            SecurityEventType.MailboxAuthenticationFailed,
            subject,
            remoteAddress.Value,

            // Deliberately uniform. The specific reason goes to the log at debug level for an
            // operator; putting it in the event row would hand whoever can read that row the
            // same enumeration oracle the reply codes refuse to give.
            "Authentication failed.",
            cancellationToken).ConfigureAwait(false);

        logger.LogDebug("Submission authentication refused from {RemoteAddress}: {Reason}", remoteAddress.Value, diagnostic);

        return new MailboxAuthenticationResult(MailboxAuthenticationOutcome.Failed, null, diagnostic);
    }

    /// <summary>Refuses after a correct password, where no further work is needed.</summary>
    private async Task<MailboxAuthenticationResult> RefuseAfterCorrectPasswordAsync(
        EmailAddress address,
        IpAddressValue remoteAddress,
        string diagnostic,
        CancellationToken cancellationToken)
    {
        // No timing concern here: whoever sent this knows the password already, so nothing about
        // the mailbox's existence is being protected.
        await securityEvents.RecordAsync(
            SecurityEventType.MailboxAuthenticationFailed,
            address.Value,
            remoteAddress.Value,
            $"Authentication refused despite a correct password: {diagnostic}",
            cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "Submission refused for {Mailbox} from {RemoteAddress}: {Reason}",
            address.Value,
            remoteAddress.Value,
            diagnostic);

        return new MailboxAuthenticationResult(MailboxAuthenticationOutcome.Failed, null, diagnostic);
    }
}
