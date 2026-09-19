using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Gathers the observations the identity checks judge.
/// </summary>
/// <remarks>
/// <para>
/// All I/O and no rules. <see cref="IdentityChecks"/> holds every decision and is pure, so the
/// interesting half of the Identity category is testable without a resolver; this half is
/// mechanical and its only real responsibility is to tell "did not answer" apart from "answered
/// with nothing" and pass that distinction through faithfully.
/// </para>
/// <para>
/// <b>That distinction is the whole reason the fact type uses null for one and an empty list for
/// the other.</b> A probe that collapsed them would turn every resolver outage into a
/// configuration failure, which is exactly the report a self-hosting operator cannot afford to
/// be given — they would go and change records that were already correct.
/// </para>
/// </remarks>
public sealed class IdentityProbe(IDnsDiagnosticsService dns)
{
    /// <summary>Looks up everything the identity checks need.</summary>
    /// <param name="hostname">The name this server calls itself.</param>
    /// <param name="publicAddress">The address mail leaves from, or null if it is not known.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<IdentityFacts> GatherAsync(
        DomainName hostname,
        IpAddressValue? publicAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        IReadOnlyList<IpAddressValue>? hostnameAddresses =
            await ResolveAddressesAsync(hostname.Value, cancellationToken).ConfigureAwait(false);

        if (publicAddress is null)
        {
            return new IdentityFacts(hostname, null, hostnameAddresses, null, EmptyForward);
        }

        DnsDiagnosticAnswer pointer = await dns
            .LookupPointerAsync(publicAddress, cancellationToken)
            .ConfigureAwait(false);

        if (!pointer.Answered)
        {
            return new IdentityFacts(hostname, publicAddress, hostnameAddresses, null, EmptyForward);
        }

        Dictionary<string, IReadOnlyList<IpAddressValue>> forward = [];

        foreach (string name in pointer.Values)
        {
            // A name that does not answer is left out of the dictionary rather than added with
            // an empty list: the checks read the difference as "no answer" against "resolves to
            // nothing", and the second is a finding while the first is not.
            if (await ResolveAddressesAsync(name, cancellationToken).ConfigureAwait(false) is { } addresses)
            {
                forward[name] = addresses;
            }
        }

        return new IdentityFacts(hostname, publicAddress, hostnameAddresses, pointer.Values, forward);
    }

    /// <summary>
    /// Both address families, or null when neither lookup answered.
    /// </summary>
    /// <remarks>
    /// <b>One family answering is enough to have an answer.</b> A great many networks have no
    /// IPv6 resolver path at all, so an AAAA query that times out while the A query succeeds
    /// says nothing about the operator's configuration — and treating the pair as unanswered
    /// would make the identity checks inconclusive on most of the internet.
    /// </remarks>
    private async Task<IReadOnlyList<IpAddressValue>?> ResolveAddressesAsync(
        string name,
        CancellationToken cancellationToken)
    {
        DnsDiagnosticAnswer v4 = await dns
            .LookupAsync(name, DnsDiagnosticRecordType.A, cancellationToken)
            .ConfigureAwait(false);

        DnsDiagnosticAnswer v6 = await dns
            .LookupAsync(name, DnsDiagnosticRecordType.Aaaa, cancellationToken)
            .ConfigureAwait(false);

        if (!v4.Answered && !v6.Answered)
        {
            return null;
        }

        List<IpAddressValue> addresses = [];

        foreach (string value in v4.Values.Concat(v6.Values))
        {
            if (IpAddressValue.TryParse(value, out IpAddressValue? address))
            {
                addresses.Add(address);
            }
        }

        return addresses;
    }

    private static readonly IReadOnlyDictionary<string, IReadOnlyList<IpAddressValue>> EmptyForward =
        new Dictionary<string, IReadOnlyList<IpAddressValue>>();
}
