using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Entities;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Smtp;

/// <summary>
/// Answers the SMTP session's questions about recipients from the database.
/// </summary>
/// <remarks>
/// <para>
/// <b>Facts only.</b> There is no method here that can say "accept this". The relay decision
/// belongs to <c>RelayPolicy</c>, which is a pure total function with an exhaustive test suite;
/// if this class could return an acceptance, a bug in a repository would be able to open a relay
/// and the one function the product depends on would no longer be the one that decides.
/// </para>
/// <para>
/// Every method runs at <c>RCPT TO</c> time, before a single octet of message body has been
/// received, so that a message destined nowhere is refused before it costs bandwidth or disk.
/// </para>
/// </remarks>
public sealed class SmtpDirectory(
    IDomainRepository domains,
    IMailboxRepository mailboxes,
    IAliasRepository aliases,
    AliasExpansionPolicy expansionPolicy,
    IOptionsMonitor<MailServerOptions> options,
    ILogger<SmtpDirectory> logger) : ISmtpDirectory
{
    /// <inheritdoc />
    public async ValueTask<bool> IsLocalDomainAsync(DomainName domain, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        MailDomain? found = await domains.GetByNameAsync(domain, cancellationToken).ConfigureAwait(false);

        // A domain that exists but is disabled is NOT local for this purpose. Treating it as
        // local would accept mail this server has been told to stop handling; treating it as
        // foreign makes the relay policy refuse it, which is the correct answer to "we no longer
        // take mail for that domain".
        //
        // Exact match only: a subdomain of a hosted domain is a different domain, and treating
        // it as local would accept mail for names the operator never configured.
        return found is { IsOperational: true };
    }

    /// <inheritdoc />
    public async ValueTask<LocalRecipientStatus> InspectLocalRecipientAsync(
        EmailAddress recipient,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recipient);

        Mailbox? mailbox = await mailboxes
            .GetByAddressAsync(recipient, cancellationToken)
            .ConfigureAwait(false);

        if (mailbox is not null)
        {
            return await InspectMailboxAsync(mailbox, cancellationToken).ConfigureAwait(false);
        }

        // Not a mailbox. It may still be an alias, and an alias for a deliverable mailbox is
        // deliverable - the sender addressed support@, and whether that is one mailbox or five
        // is none of its business.
        Alias? alias = await aliases
            .GetByAddressAsync(recipient, cancellationToken)
            .ConfigureAwait(false);

        if (alias is { IsEnabled: true })
        {
            return await InspectAliasAsync(alias, recipient, cancellationToken).ConfigureAwait(false);
        }

        return LocalRecipientStatus.NoSuchMailbox;
    }

    /// <summary>
    /// Whether an alias leads anywhere that can take the message.
    /// </summary>
    /// <remarks>
    /// Accepted if <b>any</b> target is deliverable. Refusing because one member of a
    /// distribution list is over quota would bounce the message for everyone else on it, and the
    /// sender cannot do anything about somebody else's full mailbox.
    /// </remarks>
    private async ValueTask<LocalRecipientStatus> InspectAliasAsync(
        Alias alias,
        EmailAddress recipient,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<Alias> enabled = await aliases
            .GetAllEnabledAsync(cancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, IReadOnlyList<EmailAddress>> map = new(StringComparer.OrdinalIgnoreCase);

        foreach (Alias candidate in enabled)
        {
            map[candidate.Address.NormalizedValue] = candidate.Targets;
        }

        AliasExpansion expansion = expansionPolicy.Expand(
            recipient,
            address => map.GetValueOrDefault(address.NormalizedValue));

        LocalRecipientStatus best = LocalRecipientStatus.NoSuchMailbox;

        foreach (EmailAddress target in expansion.Recipients)
        {
            Mailbox? mailbox = await mailboxes
                .GetByAddressAsync(target, cancellationToken)
                .ConfigureAwait(false);

            if (mailbox is null)
            {
                // An external target - forwarding - or an alias pointing at nothing. Neither is
                // resolvable here, and neither should veto a sibling that is deliverable.
                continue;
            }

            LocalRecipientStatus status = await InspectMailboxAsync(mailbox, cancellationToken)
                .ConfigureAwait(false);

            if (status == LocalRecipientStatus.Deliverable)
            {
                return LocalRecipientStatus.Deliverable;
            }

            // Prefer the most hopeful non-deliverable answer, so a full mailbox reports 4xx
            // (retry) rather than 5xx (bounce).
            if (status == LocalRecipientStatus.OverQuota || best == LocalRecipientStatus.NoSuchMailbox)
            {
                best = status;
            }
        }

        if (best == LocalRecipientStatus.NoSuchMailbox && expansion.Recipients.Count > 0)
        {
            logger.LogWarning(
                "Alias {Alias} expands to {Count} target(s), none of which is a local mailbox.",
                alias.Address.Value,
                expansion.Recipients.Count);
        }

        return best;
    }

    private async ValueTask<LocalRecipientStatus> InspectMailboxAsync(
        Mailbox mailbox,
        CancellationToken cancellationToken)
    {
        if (!mailbox.AcceptsMail)
        {
            // Disabled. Suspended mailboxes DO accept mail - suspension stops the owner logging
            // in, and bouncing their mail over a billing state they can fix would lose it.
            return LocalRecipientStatus.Disabled;
        }

        MailDomain? domain = await domains
            .GetByIdAsync(mailbox.DomainId, cancellationToken)
            .ConfigureAwait(false);

        QuotaBytes effective = mailbox.EffectiveQuota(domain?.DefaultMailboxQuota ?? QuotaBytes.Unlimited);

        // "Already full", not "might not fit". The message has not arrived, so its size is not
        // known here.
        //
        // The tempting check - would the LARGEST ALLOWED message fit? - is wrong by a wide
        // margin: the server-wide size limit is tens of megabytes and a typical mailbox quota is
        // smaller than that, so it would report every mailbox as full, including empty ones, and
        // the server would refuse all mail with a 452 nobody could explain.
        //
        // The real size is counted during DATA and charged at delivery. A message that tips a
        // mailbox past its quota is accepted; the next one is not, which is how every mail
        // server behaves and what a quota means in practice.
        return effective.IsExceededBy(mailbox.StorageUsedBytes)
            ? LocalRecipientStatus.OverQuota
            : LocalRecipientStatus.Deliverable;
    }

    /// <inheritdoc />
    /// <remarks>
    /// An explicit list of addresses an operator typed. Never a subnet inferred from this
    /// server's own interfaces, never a default, and never anything derived from what the peer
    /// said — the address comes from the transport.
    /// </remarks>
    public ValueTask<bool> IsAuthorizedRelayAddressAsync(
        IpAddressValue address,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        IList<string> authorized = options.CurrentValue.Smtp.AuthorizedRelayAddresses;

        if (authorized.Count == 0)
        {
            return ValueTask.FromResult(false);
        }

        foreach (string candidate in authorized)
        {
            // Compared as parsed addresses, not as strings. "::ffff:192.0.2.1" and "192.0.2.1"
            // are the same host, and a string comparison would authorise one and refuse the
            // other depending on how the connection happened to arrive.
            if (IpAddressValue.TryParse(candidate, out IpAddressValue? parsed) && parsed.Equals(address))
            {
                return ValueTask.FromResult(true);
            }
        }

        return ValueTask.FromResult(false);
    }

    /// <inheritdoc />
    /// <remarks>
    /// No per-mailbox send restrictions exist yet, so an authenticated mailbox may send anywhere.
    /// The hook is here rather than absent because adding it later would mean changing the relay
    /// path, and the relay path is the last place to be making structural changes.
    /// </remarks>
    public ValueTask<bool> MayRelayAsAsync(
        EmailAddress authenticatedMailbox,
        EmailAddress recipient,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatedMailbox);
        ArgumentNullException.ThrowIfNull(recipient);

        return ValueTask.FromResult(true);
    }
}
