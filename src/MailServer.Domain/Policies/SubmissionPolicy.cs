using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Policies;

/// <summary>What an authenticated client is asking to do.</summary>
/// <param name="AuthenticatedMailbox">The mailbox that proved its identity.</param>
/// <param name="ReversePath">
/// The sender it wants to use, or null for the null reverse path.
/// </param>
public sealed record SubmissionContext(EmailAddress AuthenticatedMailbox, EmailAddress? ReversePath);

/// <summary>
/// Whether an authenticated sender may use the reverse path it asked for.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is for.</b> Authentication proves who is connecting; it does not entitle them to
/// claim anybody's address. Without this check, one stolen password lets an attacker send as
/// every colleague in the organisation — from the real server, over the real TLS, passing SPF,
/// DKIM and DMARC, because as far as every downstream check is concerned the mail is genuine.
/// That is what a compromised mailbox is worth to an attacker, and it is what this refuses.
/// </para>
/// <para>
/// Like <see cref="RelayPolicy"/> this is a <b>total function with no default-allow branch</b>.
/// Deny is the fall-through.
/// </para>
/// </remarks>
public sealed class SubmissionPolicy
{
    /// <summary>The decision, with the reason it was reached.</summary>
    /// <param name="IsPermitted">Whether the reverse path may be used.</param>
    /// <param name="Reason">Why. Shown to the client on a refusal, so it names what to change.</param>
    public sealed record Result(bool IsPermitted, string Reason);

    /// <summary>
    /// Decides whether the reverse path is one this mailbox may use.
    /// </summary>
    /// <param name="context">Who is authenticated and what they asked for.</param>
    /// <param name="mayActAs">
    /// Whether the mailbox owns a given address — an alias that resolves to it, or an address an
    /// operator has explicitly permitted it to use. Resolved by the caller, because it needs the
    /// directory and this must stay pure.
    /// </param>
    public Result Evaluate(SubmissionContext context, Func<EmailAddress, bool> mayActAs)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(mayActAs);

        if (context.ReversePath is null)
        {
            // The null reverse path is a BOUNCE's sender. A mail client does not send bounces —
            // only an MTA does, and an MTA does not authenticate to a submission port. Accepting
            // it here would let an authenticated client emit mail that cannot itself be bounced,
            // which is the shape of a backscatter campaign.
            return new Result(
                false,
                "The null reverse path is not accepted on a submission listener; it belongs to " +
                "bounce messages, which a mail client does not send.");
        }

        if (context.ReversePath.NormalizedValue.Equals(
                context.AuthenticatedMailbox.NormalizedValue,
                StringComparison.Ordinal))
        {
            return new Result(true, "The sender is the authenticated mailbox.");
        }

        if (mayActAs(context.ReversePath))
        {
            return new Result(
                true,
                $"'{context.AuthenticatedMailbox.Value}' is permitted to send as " +
                $"'{context.ReversePath.Value}'.");
        }

        // The fall-through, and the only outcome reachable without an explicit reason to allow.
        return new Result(
            false,
            $"'{context.AuthenticatedMailbox.Value}' may not send as '{context.ReversePath.Value}'. " +
            "An authenticated session may use its own address, or an alias that resolves to it.");
    }

    /// <summary>
    /// Stated outright: authentication alone never entitles a client to an arbitrary sender.
    /// </summary>
    /// <remarks>
    /// The counterpart of <see cref="RelayPolicy.MayEverActAsOpenRelay"/>. A test asserts it, so
    /// a future "trusted submission" setting cannot quietly become one.
    /// </remarks>
    public static bool MayAuthenticatedSenderUseAnyAddress => false;
}
