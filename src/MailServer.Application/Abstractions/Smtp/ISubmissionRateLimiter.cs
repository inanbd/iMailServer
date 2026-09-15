using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Smtp;

/// <summary>What a mailbox has sent recently, against what it is allowed.</summary>
/// <param name="IsWithinLimit">Whether another message may be accepted.</param>
/// <param name="MessagesInWindow">Messages accepted from this mailbox in the window.</param>
/// <param name="MessageLimit">The limit that applies.</param>
/// <param name="Window">The period the count covers.</param>
public sealed record SubmissionRateDecision(
    bool IsWithinLimit,
    long MessagesInWindow,
    int MessageLimit,
    TimeSpan Window);

/// <summary>
/// Bounds how much mail one authenticated mailbox may submit.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is what turns a stolen password into a nuisance rather than an incident.</b> An
/// attacker with valid credentials passes authentication, passes the submission policy if they
/// send as the mailbox they stole, and then sends as fast as the server will take it — from a
/// server with the organisation's reputation, its SPF record and its DKIM signature. By the time
/// anybody notices, the damage is to a domain's standing with every receiver, which takes weeks
/// to undo and cannot be undone by changing the password.
/// </para>
/// <para>
/// A limit is not a detection mechanism. It is the thing that keeps the blast radius small
/// enough that detection has time to work.
/// </para>
/// </remarks>
public interface ISubmissionRateLimiter
{
    /// <summary>Whether this mailbox may submit another message now.</summary>
    Task<SubmissionRateDecision> CheckAsync(EmailAddress mailbox, CancellationToken cancellationToken);
}
