namespace MailServer.Domain.Enums;

/// <summary>
/// What to do with mail addressed to a local domain but to no known mailbox or alias.
/// </summary>
public enum CatchAllPolicy
{
    /// <summary>
    /// Reject at RCPT TO with 550 5.1.1. The correct default: it tells legitimate senders
    /// immediately that they have the wrong address, and it denies spammers the ability to
    /// use the server as a directory-harvest oracle by observing which addresses are
    /// accepted. Deferring the rejection to a bounce instead makes the server a backscatter
    /// source, which is a fast route onto a blocklist.
    /// </summary>
    Reject = 0,

    /// <summary>
    /// Deliver to a nominated catch-all mailbox. Convenient, but it attracts every
    /// dictionary attack aimed at the domain into one mailbox; the UI says so when it is
    /// selected.
    /// </summary>
    DeliverToCatchAll = 1,

    /// <summary>
    /// Accept and silently discard. Offered for migration scenarios only. It loses mail
    /// with no notice to the sender, so the UI marks it clearly as data-destroying.
    /// </summary>
    Discard = 2,
}
