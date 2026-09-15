using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Smtp;

/// <summary>What the server knows about a recipient in a domain it hosts.</summary>
/// <remarks>
/// Four outcomes rather than a boolean, because each earns a different reply code and the codes
/// are not interchangeable: a sender told 550 gives up and bounces, a sender told 452 keeps the
/// message and retries. Collapsing "over quota" into "rejected" destroys mail that a few
/// minutes of tidying would have let through.
/// </remarks>
public enum LocalRecipientStatus
{
    /// <summary>No such mailbox, and no alias that expands to one. 550 5.1.1.</summary>
    NoSuchMailbox = 0,

    /// <summary>The mailbox exists and can take the message.</summary>
    Deliverable = 1,

    /// <summary>The mailbox exists but is disabled. 550 5.2.1.</summary>
    Disabled = 2,

    /// <summary>The mailbox exists and is over quota. 452 4.2.2 — transient.</summary>
    OverQuota = 3,
}

/// <summary>
/// The facts the SMTP session needs about a recipient, and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// <b>This port answers questions; it does not make decisions.</b> The relay decision belongs to
/// <c>RelayPolicy</c>, which is a pure function with an exhaustive test suite. If an
/// implementation of this interface could return "accepted", a bug in a repository or a
/// mis-wired fake would be able to open a relay, and the one function the whole product depends
/// on would no longer be the one that decides.
/// </para>
/// <para>
/// Every method is asked at <c>RCPT TO</c> time, before any message content has been received,
/// so that a message destined nowhere is refused before it costs bandwidth or disk.
/// </para>
/// </remarks>
public interface ISmtpDirectory
{
    /// <summary>Whether this server hosts the domain.</summary>
    ValueTask<bool> IsLocalDomainAsync(DomainName domain, CancellationToken cancellationToken);

    /// <summary>Whether a recipient in a hosted domain can actually be delivered to.</summary>
    /// <remarks>
    /// Asked only for local domains. The address is resolved through aliases, so a recipient
    /// that is an alias for a deliverable mailbox is deliverable.
    /// </remarks>
    ValueTask<LocalRecipientStatus> InspectLocalRecipientAsync(
        EmailAddress recipient,
        CancellationToken cancellationToken);

    /// <summary>
    /// Whether an address is on the explicit relay allow-list.
    /// </summary>
    /// <remarks>
    /// The narrow, deliberately awkward escape hatch for an internal application that cannot
    /// authenticate. It is an explicit list of addresses an operator typed, never a subnet
    /// inferred from the server's own interfaces, and never a default.
    /// </remarks>
    ValueTask<bool> IsAuthorizedRelayAddressAsync(
        IpAddressValue address,
        CancellationToken cancellationToken);

    /// <summary>
    /// Whether an authenticated mailbox owns a given address and may send as it.
    /// </summary>
    /// <remarks>
    /// True for the mailbox's own address and for any alias that resolves to it — the ordinary
    /// case of a person whose mail arrives at both <c>alice@</c> and <c>sales@</c> and who
    /// expects to be able to reply from either.
    /// </remarks>
    ValueTask<bool> MayActAsAsync(
        EmailAddress authenticatedMailbox,
        EmailAddress claimedSender,
        CancellationToken cancellationToken);

    /// <summary>Whether an authenticated mailbox is permitted to send to a given recipient.</summary>
    /// <remarks>
    /// The hook for per-mailbox restrictions — an account that may only send internally, say.
    /// A refusal here does not fall through to any other route to acceptance.
    /// </remarks>
    ValueTask<bool> MayRelayAsAsync(
        EmailAddress authenticatedMailbox,
        EmailAddress recipient,
        CancellationToken cancellationToken);
}
