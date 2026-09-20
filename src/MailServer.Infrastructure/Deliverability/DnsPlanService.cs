using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Dmarc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Gathers what this server knows about itself and hands it to <see cref="DnsRecordPlan"/>.
/// </summary>
/// <remarks>
/// <para>
/// Everything hard lives in the domain: this reads three things out of configuration and one out
/// of the database, and does no arithmetic of its own. The split is the same one every other
/// deliverability component takes — a probe that gathers and a pure function that decides — and
/// it is what lets the rules about character-string lengths and external reporting authorisation
/// be tested without a database.
/// </para>
/// <para>
/// <b>The key it publishes is the active one, and only one of them.</b> A domain mid-rotation has
/// an active key and a retired one, and both are legitimately in DNS — but the retired one is
/// there so that signatures already in flight still verify, not because an operator should
/// publish it afresh. Proposing it would have an operator re-publish a key they are in the
/// middle of removing.
/// </para>
/// </remarks>
public sealed class DnsPlanService(
    IDomainRepository domains,
    IDkimKeyRepository dkimKeys,
    IPublicSuffixListProvider publicSuffixList,
    IMtaStsPolicySource mtaSts,
    IOptions<MailServerOptions> options,
    ILogger<DnsPlanService> logger) : IDnsPlanService
{
    public async Task<DnsZonePlan> CreateAsync(
        DomainName domain,
        DnsPlanOptions planOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(planOptions);

        MailServerOptions settings = options.Value;

        return DnsRecordPlan.Create(new DnsPlanRequest(
            domain,
            DomainName.Parse(settings.Server.Hostname),
            Addresses(settings),
            await ActiveKeyAsync(domain, cancellationToken).ConfigureAwait(false),
            planOptions.DmarcReportAddress,
            planOptions.TlsReportAddress,
            planOptions.MtaStsId ?? PublishedPolicyId(),
            publicSuffixList.List));
    }

    /// <summary>
    /// The id of the policy this server is actually serving, when it is serving one.
    /// </summary>
    /// <remarks>
    /// <b>The caller's own value wins, and this is the fallback.</b> An operator planning a
    /// migration may want a plan for a policy that is not live yet; what they must not have to
    /// do is read a hash out of a log and retype it, because RFC 8461 §3.1 makes the id the one
    /// thing senders compare, and a TXT record advertising an id the served policy does not have
    /// is a policy no sender ever re-fetches. Defaulting to the live policy's own id keeps the
    /// record and the resource one fact.
    /// </remarks>
    private string? PublishedPolicyId() => mtaSts.Current()?.PolicyId();

    /// <summary>
    /// The addresses to put in SPF and to ask for reverse records on.
    /// </summary>
    /// <remarks>
    /// <b>Configuration, not what the host's interfaces happen to be.</b> A server behind NAT
    /// sees a private address on every interface and sends from a public one, and a server on a
    /// host with a dozen addresses sends from one of them. Enumerating interfaces would produce
    /// an SPF record authorising addresses that cannot send and omitting the one that does —
    /// which is why <c>MailServer:Server:PublicIpAddress</c> exists and why an unset one
    /// produces a plan that says so rather than a plan that guesses.
    /// </remarks>
    private static IReadOnlyList<IpAddressValue> Addresses(MailServerOptions settings) =>
        settings.Server.PublicIpAddress is { Length: > 0 } text &&
        IpAddressValue.TryParse(text, out IpAddressValue? address)
            ? [address]
            : [];

    private async Task<DkimKeyPublication?> ActiveKeyAsync(
        DomainName domain,
        CancellationToken cancellationToken)
    {
        try
        {
            MailDomain? record = await domains
                .GetByNameAsync(domain, cancellationToken)
                .ConfigureAwait(false);

            if (record is null)
            {
                return null;
            }

            DkimKey? key = await dkimKeys
                .GetActiveForDomainAsync(record.Id, cancellationToken)
                .ConfigureAwait(false);

            return key is null
                ? null
                : new DkimKeyPublication(key.Selector, key.Algorithm, key.PublicKeyBase64);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // The plan is still worth producing without it: every other record names the host
            // rather than the key, and the caveat that stands in for a missing key tells the
            // operator to generate one - which is the right next step whether the key is absent
            // or merely unreadable from here.
            logger.LogWarning(ex, "The active DKIM key for {Domain} could not be read.", domain.Value);

            return null;
        }
    }
}
