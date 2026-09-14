using System.Net;
using MailServer.Application.Abstractions.Acme;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dns;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Acme;

/// <summary>
/// The DNS-01 provider for operators with no supported DNS API: it tells them what to publish
/// and then checks whether they have.
/// </summary>
/// <remarks>
/// <para>
/// <b>A first-class implementation, not an error path.</b> Plenty of domains are hosted
/// somewhere with no usable API, and DNS-01 is the only way any of them can obtain a wildcard
/// certificate. Treating "no API" as a failure would exclude them from automation entirely.
/// </para>
/// <para>
/// The flow it supports is: publish instructions, operator creates the record, operator presses
/// Check, and only once the check passes is the CA asked to validate. That ordering is what
/// protects the failed-validation limit — five per hostname per hour, and asking the CA to look
/// at a record that has not propagated spends one of them for nothing.
/// </para>
/// <para>
/// <b>Propagation is checked at the authoritative nameservers.</b> Querying a recursive
/// resolver reports the record as soon as that resolver has it, which can be well before the
/// CA's resolver does, and produces exactly the premature validation this is meant to prevent.
/// </para>
/// </remarks>
internal sealed class ManualDnsChallengeProvider(
    DnsTxtResolver resolver,
    IAcmeSettings settings,
    ILogger<ManualDnsChallengeProvider> logger) : IDnsChallengeProvider
{
    /// <summary>
    /// Per-resolver timeout for a challenge lookup.
    /// </summary>
    /// <remarks>
    /// Short, because this runs behind an operator pressing a button and several resolvers are
    /// queried in turn. A resolver that has not answered in five seconds is not going to.
    /// </remarks>
    private static readonly TimeSpan LookupTimeout = TimeSpan.FromSeconds(5);

    public string Name => "Manual";

    public bool SupportsAutomaticPublication => false;

    public Task<DnsChallengePublication> PublishAsync(
        DomainName identifier,
        string recordName,
        string recordValue,
        CancellationToken cancellationToken)
    {
        // The instructions carry the record value, which is a digest of the key authorisation
        // and is meant to be published in public DNS. It is not a secret, unlike the account
        // key that produced it.
        string instructions =
            $"Create a DNS TXT record and wait for it to propagate:\n\n" +
            $"    Name:  {recordName}\n" +
            $"    Type:  TXT\n" +
            $"    Value: {recordValue}\n" +
            $"    TTL:   60 (or the lowest your provider allows)\n\n" +
            "Then use Check DNS. Do not continue until the check passes: asking the " +
            "certificate authority to validate a record it cannot see yet consumes one of " +
            "five failed validations per hostname per hour.";

        logger.LogInformation(
            "A DNS-01 challenge for {Identifier} needs a TXT record at {RecordName} to be " +
            "created by hand.",
            identifier,
            recordName);

        return Task.FromResult(new DnsChallengePublication(false, instructions));
    }

    /// <summary>
    /// Queries the configured resolvers for the challenge TXT record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every configured resolver is asked and the record counts as published only when they
    /// <b>all</b> return it. Requiring unanimity is the conservative direction: reporting "not
    /// yet" for a record that is in fact live costs one more check, whereas reporting "ready"
    /// early costs one of five failed validations per hostname per hour.
    /// </para>
    /// <para>
    /// The resolvers asked should be the zone's authoritative nameservers. Resolving that set
    /// needs NS and SOA handling that belongs with the full resolver in Milestone 9, so for now
    /// the servers come from configuration and the UI names the ones it used — which at least
    /// makes it obvious when a recursive resolver's cache is the thing being consulted.
    /// </para>
    /// </remarks>
    public async Task<bool> IsPublishedAsync(
        string recordName,
        string expectedValue,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(recordName);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedValue);

        IReadOnlyList<IPAddress> servers = settings.ChallengeCheckResolvers;

        if (servers.Count == 0)
        {
            logger.LogWarning(
                "No DNS resolvers are configured for challenge checking, so the record at " +
                "{RecordName} cannot be verified before validation is requested.",
                recordName);

            return false;
        }

        foreach (IPAddress server in servers)
        {
            IReadOnlyList<string> values = await resolver
                .QueryTxtAsync(recordName, server, LookupTimeout, cancellationToken)
                .ConfigureAwait(false);

            // Ordinal: a DNS-01 value is base64url and case-sensitive. A case-insensitive
            // comparison would accept a value the CA will reject.
            if (!values.Contains(expectedValue, StringComparer.Ordinal))
            {
                logger.LogDebug(
                    "{Server} does not yet return the expected TXT value for {RecordName} " +
                    "({Found} record(s) found).",
                    server,
                    recordName,
                    values.Count);

                return false;
            }
        }

        logger.LogInformation(
            "The challenge record at {RecordName} is visible at all {Count} configured " +
            "resolver(s).",
            recordName,
            servers.Count);

        return true;
    }

    /// <remarks>Nothing to remove: the operator created the record and removes it.</remarks>
    public Task RemoveAsync(string recordName, CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "The DNS TXT record at {RecordName} can now be deleted. A stale _acme-challenge " +
            "record is untidy and quietly advertises how this domain proves control.",
            recordName);

        return Task.CompletedTask;
    }
}
