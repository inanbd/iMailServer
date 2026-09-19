namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>
/// An external clock to measure this server's against.
/// </summary>
/// <remarks>
/// <b>Separate from <c>IClock</c> on purpose.</b> <c>IClock</c> is what the server runs on and is
/// trusted everywhere; this is a second opinion, consulted only by the deliverability report and
/// never used to decide anything. A mail server that took its time from the network would be
/// handing an attacker who can answer a UDP packet the ability to expire its certificates.
/// </remarks>
public interface ITimeReference
{
    /// <summary>
    /// How far this server's clock is from the reference, or null when none could be reached.
    /// </summary>
    /// <remarks>
    /// Positive means this server is ahead. Null rather than zero for an unreachable reference:
    /// a report that could not measure the skew must not say the clock is right.
    /// </remarks>
    Task<TimeSpan?> GetSkewAsync(CancellationToken cancellationToken);
}
