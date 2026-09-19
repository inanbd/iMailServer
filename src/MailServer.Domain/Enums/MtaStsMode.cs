namespace MailServer.Domain.Enums;

/// <summary>
/// What a sending MTA should do when an MTA-STS policy fails to validate. RFC 8461 §5.
/// </summary>
public enum MtaStsMode
{
    /// <summary>
    /// The policy is published but asks for nothing.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §5 gives it exactly one use: "'none': In this mode, Sending MTAs should treat
    /// the Policy Domain as though it does not have any active policy", which §8.3 explains is
    /// how a domain withdraws one that senders have cached.
    /// </remarks>
    None = 0,

    /// <summary>
    /// Failures are reported through TLS-RPT and the message is delivered anyway.
    /// </summary>
    /// <remarks>
    /// §5: "in any case, messages may be delivered as though there were no MTA-STS validation
    /// failure." The mode to publish first, precisely because it cannot lose mail.
    /// </remarks>
    Testing = 1,

    /// <summary>
    /// Senders must not deliver to a host that fails validation.
    /// </summary>
    /// <remarks>
    /// §5: "'enforce': In this mode, Sending MTAs MUST NOT deliver the message to hosts that
    /// fail MX matching or certificate validation or that do not support STARTTLS."
    /// </remarks>
    Enforce = 2,
}
