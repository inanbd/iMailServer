namespace MailServer.Domain.Policies;

/// <summary>What a session has done that this server refused.</summary>
/// <param name="RejectedCommands">Commands refused: bad syntax, bad sequence, unknown verb.</param>
/// <param name="RejectedRecipients">Recipients refused, across every transaction on the connection.</param>
/// <remarks>
/// <b>Failed AUTH attempts are not here, and that is deliberate.</b> The command processor
/// already bounds them with its own <c>MaxAuthenticationAttempts</c>, and a second limit on the
/// same fact would be a second number to keep in step — with the wrong one silently winning
/// whenever the two disagreed.
/// </remarks>
public readonly record struct SmtpSessionConduct(int RejectedCommands, int RejectedRecipients);

/// <summary>Why a session is being dropped.</summary>
public enum SmtpAbuseVerdict
{
    /// <summary>Nothing wrong. Carry on.</summary>
    Continue = 0,

    /// <summary>Too many refused commands. RFC 5321 §4.3.2 permits closing on this.</summary>
    TooManyRejectedCommands = 1,

    /// <summary>Too many refused recipients — the shape of a directory harvest.</summary>
    TooManyRejectedRecipients = 2,
}

/// <summary>
/// Decides when a connection has stopped being a mail delivery and become something else.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are the limits that cost an attacker something.</b> The concurrency cap bounds how
/// many connections one peer may hold; it says nothing about what a peer does inside a
/// connection it legitimately holds. A single session can issue unbounded bad commands or walk
/// a dictionary of addresses at no cost to the sender and considerable cost here, and RFC 5321
/// §4.3.2 explicitly contemplates closing the connection for it.
/// </para>
/// <para>
/// <b>Every threshold is far above what a working client does.</b> A correct client produces
/// approximately zero refused commands; a misconfigured one produces a handful. The numbers are
/// set so that reaching them means something is wrong, not that somebody was unlucky — a limit
/// that occasionally drops a real sender's connection is a limit an operator will turn off.
/// </para>
/// <para>
/// <b>What this does not do is ban an address.</b> Dropping the connection is enough: it costs
/// the peer a reconnection, it costs this server nothing, and it cannot be turned into a denial
/// of service against a third party by anybody able to spoof a source address on a connection
/// that never completes a handshake.
/// </para>
/// </remarks>
public sealed class SmtpAbusePolicy
{
    /// <summary>The default limits.</summary>
    public static SmtpAbusePolicy Default { get; } = new();

    /// <summary>
    /// Refused commands before the connection is closed.
    /// </summary>
    /// <remarks>
    /// Generous: a client probing for supported extensions, or one whose author misread a
    /// grammar, can legitimately collect a few. Twenty is well past either.
    /// </remarks>
    public int MaxRejectedCommands { get; init; } = 20;

    /// <summary>
    /// Refused recipients before the connection is closed.
    /// </summary>
    /// <remarks>
    /// The harvest bound. A real sender addressing a stale mailing list can collect a dozen in
    /// one transaction, so this sits above that and far below the thousands a dictionary walk
    /// needs to be worth running.
    /// </remarks>
    public int MaxRejectedRecipients { get; init; } = 25;

    /// <summary>Whether this session has earned a disconnection.</summary>
    public SmtpAbuseVerdict Evaluate(SmtpSessionConduct conduct)
    {
        // Harvesting first, because it is the less ambiguous of the two: a client can collect
        // refused commands by misreading a grammar, but nothing legitimate walks a directory.
        if (conduct.RejectedRecipients >= MaxRejectedRecipients)
        {
            return SmtpAbuseVerdict.TooManyRejectedRecipients;
        }

        return conduct.RejectedCommands >= MaxRejectedCommands
            ? SmtpAbuseVerdict.TooManyRejectedCommands
            : SmtpAbuseVerdict.Continue;
    }

    /// <summary>What to tell the peer before closing.</summary>
    /// <remarks>
    /// Deliberately vague about which limit was reached. A precise message tells a harvester
    /// exactly how many guesses they get per connection, which is the one piece of information
    /// that makes the limit easy to work around.
    /// </remarks>
    public static string DiagnosticFor(SmtpAbuseVerdict verdict) => verdict switch
    {
        SmtpAbuseVerdict.Continue => string.Empty,
        _ => "Too many errors on this connection.",
    };
}
