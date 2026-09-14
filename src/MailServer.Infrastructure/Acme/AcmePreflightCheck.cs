using System.Net;
using System.Net.Sockets;
using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Platform;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Acme;

/// <summary>
/// Checks locally what the CA is about to check remotely.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists to protect a rate-limit slot.</b> A misconfiguration caught here costs
/// nothing; the same one discovered at the CA costs one of five failed validations per hostname
/// per hour, and five of those lock an operator out for the rest of the hour with no way to
/// undo it. Every check here is aimed at the two mistakes that account for nearly all failed
/// validations: DNS not pointing at this server, and inbound port 80 blocked upstream.
/// </para>
/// <para>
/// <b>A check that could not run never blocks.</b> If DNS resolution itself fails — no outbound
/// connectivity, a broken resolver — that is reported as a warning, not a refusal. Refusing on
/// the basis of a check that did not happen would make a local network fault look like a
/// misconfigured domain, and would block an operator whose setup is in fact correct.
/// </para>
/// <para>
/// <b>It cannot prove reachability from outside.</b> Nothing running on this machine can: the
/// question is whether a packet from the Internet arrives, and only something on the Internet
/// can answer it. The checks establish that the configuration is locally coherent, and the
/// documentation says plainly that verifying from outside the network is the operator's job.
/// </para>
/// </remarks>
internal sealed class AcmePreflightCheck(
    IServerIdentityProvider serverIdentity,
    IAcmeSettings settings,
    ILogger<AcmePreflightCheck> logger) : IAcmePreflightCheck
{
    private static readonly TimeSpan LookupTimeout = TimeSpan.FromSeconds(5);

    public async Task<PreflightReport> CheckAsync(
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        List<PreflightFinding> findings = [];

        foreach (DomainName identifier in identifiers)
        {
            if (identifier.Value.StartsWith("*.", StringComparison.Ordinal))
            {
                findings.Add(new PreflightFinding(
                    identifier,
                    challengeType == AcmeChallengeType.Dns01,
                    challengeType == AcmeChallengeType.Dns01
                        ? $"'{identifier}' is a wildcard and will be validated with DNS-01."
                        : $"'{identifier}' is a wildcard, which cannot be proved with HTTP-01. " +
                          "Use DNS-01 for wildcard identifiers.",

                    // Blocking, and knowably so without any network access: the CA will refuse
                    // this combination outright, so submitting it is a guaranteed wasted slot.
                    IsBlocking: true));

                continue;
            }

            findings.Add(await CheckDnsAsync(identifier, cancellationToken).ConfigureAwait(false));
        }

        if (challengeType == AcmeChallengeType.Http01)
        {
            findings.Add(CheckHttpListener(identifiers));
        }

        return new PreflightReport(findings);
    }

    /// <summary>
    /// Confirms the identifier resolves, and warns when it does not resolve to this server.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A name that does not resolve at all <b>blocks</b>: HTTP-01 validation against it cannot
    /// possibly succeed, so submitting the order spends a slot to learn something already
    /// known.
    /// </para>
    /// <para>
    /// A name that resolves to an address this machine does not hold only <b>warns</b>. That is
    /// the correct call and worth stating: behind NAT, a load balancer, or any reverse proxy,
    /// the public address is legitimately not one of this machine's local addresses, and
    /// blocking there would refuse a large share of correct deployments.
    /// </para>
    /// </remarks>
    private async Task<PreflightFinding> CheckDnsAsync(
        DomainName identifier,
        CancellationToken cancellationToken)
    {
        try
        {
            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            timeout.CancelAfter(LookupTimeout);

            IPAddress[] resolved = await System.Net.Dns
                .GetHostAddressesAsync(identifier.Value, timeout.Token)
                .ConfigureAwait(false);

            if (resolved.Length == 0)
            {
                return new PreflightFinding(
                    identifier,
                    false,
                    $"'{identifier}' does not resolve to any address. The certificate " +
                    "authority cannot validate a name that does not exist in public DNS.",
                    IsBlocking: true);
            }

            HashSet<string> localAddresses = await GetLocalAddressesAsync(cancellationToken)
                .ConfigureAwait(false);

            bool pointsHere = resolved.Any(a => localAddresses.Contains(a.ToString()));

            return new PreflightFinding(
                identifier,
                true,
                pointsHere
                    ? $"'{identifier}' resolves to an address on this server."
                    : $"'{identifier}' resolves to " +
                      string.Join(", ", resolved.Select(static a => a.ToString())) +
                      ", which is not an address on this server. That is expected behind NAT, " +
                      "a load balancer or a reverse proxy; verify from outside your network " +
                      "that the certificate authority can reach this server at that address.",
                IsBlocking: false);
        }
        catch (SocketException)
        {
            return new PreflightFinding(
                identifier,
                false,
                $"'{identifier}' does not resolve. Publish an A or AAAA record pointing at " +
                "this server, and allow time for it to propagate, before requesting a " +
                "certificate.",
                IsBlocking: true);
        }
        catch (Exception ex) when (ex is OperationCanceledException or InvalidOperationException)
        {
            // The check did not run. Reported, never blocking - see the class remarks.
            logger.LogWarning(
                "The DNS pre-flight check for {Identifier} could not be completed: {Reason}",
                identifier,
                ex.Message);

            return new PreflightFinding(
                identifier,
                false,
                $"The DNS check for '{identifier}' could not be completed, so it was skipped. " +
                "Issuance may still succeed.",
                IsBlocking: false);
        }
    }

    /// <summary>Reports whether this server is running the HTTP-01 endpoint at all.</summary>
    private PreflightFinding CheckHttpListener(IReadOnlyList<DomainName> identifiers)
    {
        DomainName first = identifiers[0];

        if (!settings.EnableHttpChallengeListener)
        {
            return new PreflightFinding(
                first,
                false,
                "HTTP-01 was selected but the challenge endpoint is disabled " +
                "(MailServer:Acme:EnableHttpChallengeListener). The certificate authority " +
                "would find nothing to fetch.",

                // Blocking and free to detect: the failure is certain and entirely local.
                IsBlocking: true);
        }

        return new PreflightFinding(
            first,
            true,
            $"The HTTP-01 challenge endpoint is enabled on port {settings.HttpChallengePort}. " +
            "It must be reachable from the Internet; nothing running on this machine can " +
            "confirm that, so verify it from outside your network.",
            IsBlocking: false);
    }

    /// <summary>Every address this machine holds, for comparison against a DNS answer.</summary>
    private async Task<HashSet<string>> GetLocalAddressesAsync(CancellationToken cancellationToken)
    {
        HashSet<string> addresses = new(StringComparer.OrdinalIgnoreCase);

        try
        {
            IPAddress[] local = await System.Net.Dns
                .GetHostAddressesAsync(System.Net.Dns.GetHostName(), cancellationToken)
                .ConfigureAwait(false);

            foreach (IPAddress address in local)
            {
                addresses.Add(address.ToString());
            }

            // The configured public address, when the operator has told us one. Behind NAT it
            // is the only address that will ever match a public DNS answer.
            if (serverIdentity.PublicIpAddress is { } publicAddress)
            {
                addresses.Add(publicAddress);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            logger.LogDebug("The local addresses of this machine could not be enumerated: {Reason}", ex.Message);
        }

        return addresses;
    }
}
