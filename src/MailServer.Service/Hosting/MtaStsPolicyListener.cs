using System.Net;
using System.Net.Sockets;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MailServer.Service.Hosting;

/// <summary>
/// Serves this server's MTA-STS policy over HTTPS.
/// </summary>
/// <remarks>
/// <para>
/// <b>One route, one media type, no redirects.</b> RFC 8461 §3.2 has senders fetch exactly
/// <c>https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</c>, and §3.3 says a sender "MUST NOT"
/// follow a redirect while fetching it. So there is nothing to gain from any other route and
/// something to lose from a redirect: this endpoint answers one path and 404s everything else.
/// </para>
/// <para>
/// <b>HTTPS is the requirement, not a preference.</b> §3.2 says the policy "MUST" be served with
/// a certificate valid for the <c>mta-sts</c> host, and §3.3 has senders discard a policy whose
/// certificate does not validate. That is the whole security model: the DNS TXT record at
/// <c>_mta-sts</c> is unauthenticated and only says a policy exists, and the policy's authority
/// comes from the certificate on the host serving it. Serving this over plain HTTP would publish
/// a file every sender ignores.
/// </para>
/// <para>
/// <b>Why a second web host rather than a route on the ACME one.</b> They differ in every
/// property that matters: ACME is plain HTTP on port 80 and exists for seconds at a time during
/// issuance, this is HTTPS on 443 and must answer whenever a sender looks. Sharing a host would
/// mean the MTA-STS policy stops being served whenever ACME is switched off, which is the kind
/// of coupling that shows up as a delivery failure weeks later.
/// </para>
/// <para>
/// <b>The certificate is selected per handshake, not captured at startup.</b> Certificates are
/// hot-reloaded elsewhere in this server, and an endpoint holding one from startup would go on
/// presenting a renewed-away certificate until the service restarted — for a policy whose entire
/// authority is that certificate.
/// </para>
/// </remarks>
public sealed class MtaStsPolicyListener(
    IMtaStsPolicySource policies,
    ITlsCertificateProvider certificates,
    IHealthRegistry health,
    ILogger<MtaStsPolicyListener> logger)
    : ResilientBackgroundService(health, logger)
{
    /// <summary>The one path this endpoint answers, from RFC 8461 §3.2.</summary>
    private const string PolicyPath = "/.well-known/mta-sts.txt";

    /// <summary>
    /// The media type §3.2 requires.
    /// </summary>
    /// <remarks>
    /// "with a Content-Type of text/plain". Senders are entitled to reject anything else, and
    /// a rejected policy is indistinguishable from no policy at all.
    /// </remarks>
    private const string PolicyContentType = "text/plain";

    private WebApplication? _app;

    public override string ComponentName => "MtaStsPolicy";

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        if (!policies.IsPublishing)
        {
            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Healthy,
                "MTA-STS publishing is disabled. Senders will use ordinary opportunistic TLS, " +
                "which is the default posture for most of the Internet.",
                DateTimeOffset.UtcNow));

            return;
        }

        MtaStsPolicy policy = policies.Current()!;
        string body = policy.Format();
        string id = policy.PolicyId();

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();

        // CreateSlimBuilder leaves HTTPS out of Kestrel deliberately - it is the trimming-
        // friendly builder, and most slim hosts sit behind a proxy that terminates TLS. This one
        // cannot: RFC 8461 §3.2 requires the policy to be served over HTTPS with a certificate
        // valid for the mta-sts host, so the support has to be put back explicitly.
        builder.WebHost.UseKestrelHttpsConfiguration();

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(IPAddress.Any, policies.Port, listen => listen.UseHttps(Certificate));

            if (IPv6IsUsable())
            {
                kestrel.Listen(IPAddress.IPv6Any, policies.Port, listen => listen.UseHttps(Certificate));
            }
            else
            {
                Logger.LogInformation(
                    "IPv6 is not available on this host, so the MTA-STS policy endpoint " +
                    "listens on IPv4 only. A sender reaching mta-sts.<domain> over IPv6 only " +
                    "will not find the policy.");
            }
        });

        _app = builder.Build();

        // The body is computed once, above. It cannot change while the process runs - the policy
        // source resolves it at construction - so recomputing it per request would only create
        // the possibility of serving something other than what the advertised id names.
        _app.MapGet(PolicyPath, () => Results.Text(body, PolicyContentType));

        try
        {
            await _app.StartAsync(stoppingToken).ConfigureAwait(false);

            Logger.LogInformation(
                "The MTA-STS policy endpoint is listening on port {Port} in {Mode} mode. For " +
                "senders to find it, DNS needs a _mta-sts TXT record reading \"v=STSv1; id={Id}\" " +
                "and an mta-sts.<domain> name resolving here with a trusted certificate.",
                policies.Port,
                policy.Mode,
                id);

            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Healthy,
                $"Serving a {policy.Mode} policy (id {id}) on port {policies.Port}.",
                DateTimeOffset.UtcNow));

            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Ordinary shutdown.
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            // Port 443 is the one most likely to be already taken, usually by IIS. A warning
            // rather than a fatal error for the same reason the ACME listener treats it that
            // way: mail keeps flowing, and a sender that cannot fetch a policy falls back to
            // opportunistic TLS rather than refusing to deliver.
            Logger.LogWarning(
                ex,
                "The MTA-STS policy endpoint could not bind port {Port}; another process is " +
                "probably using it. Senders will not find a policy and will fall back to " +
                "opportunistic TLS. Mail delivery is unaffected.",
                policies.Port);

            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Warning,
                $"Port {policies.Port} could not be bound, so no MTA-STS policy is being " +
                "served. Free the port, or disable MTA-STS publishing.",
                DateTimeOffset.UtcNow));
        }
        finally
        {
            if (_app is not null)
            {
                await _app.StopAsync(CancellationToken.None).ConfigureAwait(false);
                await _app.DisposeAsync().ConfigureAwait(false);
                _app = null;
            }
        }
    }

    /// <summary>
    /// Chooses the certificate for one handshake.
    /// </summary>
    /// <remarks>
    /// Per handshake rather than captured once, because certificates are hot-reloaded elsewhere
    /// in this server and an endpoint holding one from startup would go on presenting a
    /// renewed-away certificate until the service restarted — for a policy whose whole authority
    /// is that certificate. A null return fails the handshake, which is the right outcome: a
    /// sender that cannot validate the policy host discards the policy (§3.3) and falls back to
    /// opportunistic TLS rather than refusing to deliver.
    /// </remarks>
    private void Certificate(HttpsConnectionAdapterOptions https) =>
        https.ServerCertificateSelector =
            (_, hostname) => certificates.Select(hostname, CertificatePurpose.Https)!;

    /// <summary>
    /// True when this host can actually bind an IPv6 socket.
    /// </summary>
    /// <remarks>
    /// Probed rather than trusted, for the reason <see cref="AcmeChallengeListener"/> gives at
    /// length: <see cref="Socket.OSSupportsIPv6"/> reports what the framework was built for
    /// rather than what this kernel will accept, and the difference surfaces only as a bind
    /// failure that takes the whole endpoint down instead of just its IPv6 half.
    /// </remarks>
    private static bool IPv6IsUsable()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return false;
        }

        try
        {
            using Socket probe = new(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);

            probe.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));

            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
