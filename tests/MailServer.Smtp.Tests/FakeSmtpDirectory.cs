using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.ValueObjects;

namespace MailServer.Smtp.Tests;

/// <summary>
/// A directory whose answers a test states outright.
/// </summary>
/// <remarks>
/// It can only supply facts — which domains are hosted, what state a mailbox is in — and has no
/// way to express "accept this". That is the point of <see cref="ISmtpDirectory"/>'s shape: a
/// test fake cannot open a relay even by accident, because the decision is not the directory's
/// to make.
/// </remarks>
internal sealed class FakeSmtpDirectory : ISmtpDirectory
{
    public HashSet<string> LocalDomains { get; } = new(StringComparer.OrdinalIgnoreCase) { "example.com" };

    public Dictionary<string, LocalRecipientStatus> Mailboxes { get; } =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["user@example.com"] = LocalRecipientStatus.Deliverable,
            ["postmaster@example.com"] = LocalRecipientStatus.Deliverable,
        };

    public HashSet<string> AuthorizedRelayAddresses { get; } = [];

    /// <summary>Per-mailbox send restrictions. Absent means unrestricted.</summary>
    public Dictionary<string, Func<EmailAddress, bool>> RelayRestrictions { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public int LocalDomainLookups { get; private set; }
    public int RecipientInspections { get; private set; }

    public ValueTask<bool> IsLocalDomainAsync(DomainName domain, CancellationToken cancellationToken)
    {
        LocalDomainLookups++;

        return ValueTask.FromResult(LocalDomains.Contains(domain.Value));
    }

    public ValueTask<LocalRecipientStatus> InspectLocalRecipientAsync(
        EmailAddress recipient,
        CancellationToken cancellationToken)
    {
        RecipientInspections++;

        return ValueTask.FromResult(
            Mailboxes.TryGetValue(recipient.ToString(), out LocalRecipientStatus status)
                ? status
                : LocalRecipientStatus.NoSuchMailbox);
    }

    public ValueTask<bool> IsAuthorizedRelayAddressAsync(
        IpAddressValue address,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(AuthorizedRelayAddresses.Contains(address.Value));

    public ValueTask<bool> MayRelayAsAsync(
        EmailAddress authenticatedMailbox,
        EmailAddress recipient,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(
            !RelayRestrictions.TryGetValue(authenticatedMailbox.ToString(), out Func<EmailAddress, bool>? rule)
            || rule(recipient));
}
