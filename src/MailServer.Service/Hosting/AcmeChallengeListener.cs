using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Domain.Enums;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MailServer.Service.Hosting;

/// <summary>
/// Serves ACME HTTP-01 challenge responses on port 80.
/// </summary>
/// <remarks>
/// <para>
/// <b>This endpoint serves exactly one route and nothing else.</b> It is reachable from the
/// entire Internet without authentication — that is what makes HTTP-01 work — so it is a
/// deliberately tiny surface: one GET, a lookup in an in-memory dictionary, a plain-text
/// response. There is no static file serving, no directory browsing, no redirect, and no other
/// route registered. Every request that is not the challenge path gets 404 and is not logged.
/// </para>
/// <para>
/// <b>Plain HTTP, by protocol requirement.</b> RFC 8555 §8.3 specifies HTTP on port 80. That is
/// not a weakness: the challenge response is a token the CA already knows, and the security of
/// the exchange rests on the account key's signature rather than on the transport. Serving it
/// over TLS would also be circular, since obtaining the certificate is the point.
/// </para>
/// <para>
/// <b>Why a second host inside the service.</b> The mail server is a
/// <c>HostApplicationBuilder</c> and not a web application; it should not become one to publish
/// a few dozen bytes for a few seconds. A self-contained <see cref="WebApplication"/> owned by
/// this service keeps the web server optional, isolated, and off entirely when ACME is not in
/// use.
/// </para>
/// </remarks>
public sealed class AcmeChallengeListener(
    IHttpChallengeStore challenges,
    IAcmeSettings settings,
    IHealthRegistry health,
    ILogger<AcmeChallengeListener> logger)
    : ResilientBackgroundService(health, logger)
{
    /// <summary>The one path this endpoint answers, from RFC 8555 §8.3.</summary>
    private const string ChallengePath = "/.well-known/acme-challenge/{token}";

    /// <summary>
    /// Content type mandated for an HTTP-01 response.
    /// </summary>
    /// <remarks>
    /// RFC 8555 §8.3 says the CA should accept any type, but Let's Encrypt has historically
    /// been strict about it and the cost of being exact is nothing.
    /// </remarks>
    private const string ChallengeContentType = "application/octet-stream";

    private WebApplication? _app;

    public override string ComponentName => "AcmeChallenge";

    /// <summary>
    /// True when this host can actually bind an IPv6 socket.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Probed by binding a throwaway socket rather than trusting
    /// <see cref="Socket.OSSupportsIPv6"/>, which reports what the framework was built to
    /// support rather than what this kernel will accept. Container images routinely have IPv6
    /// compiled in and disabled, and the difference only shows up as a bind failure.
    /// </para>
    /// <para>
    /// It has to be a probe rather than a try/catch around <c>Listen</c>, because
    /// <c>Listen</c> only records the endpoint — Kestrel binds during <c>StartAsync</c>, by
    /// which point an unsupported family takes the whole endpoint down rather than just its
    /// IPv6 half.
    /// </para>
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

            // Port 0: the OS picks a free one, so the probe cannot collide with anything.
            probe.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));

            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        if (!settings.EnableHttpChallengeListener)
        {
            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Healthy,
                "The ACME HTTP-01 endpoint is disabled. DNS-01 does not need it; HTTP-01 " +
                "issuance will fail without it.",
                DateTimeOffset.UtcNow));

            return;
        }

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();

        // Bound explicitly rather than through configuration: this host exists to serve one
        // route on one port, and letting an unrelated setting change what an Internet-facing
        // endpoint listens on is not a flexibility worth having.
        //
        // Both families are bound separately, and IPv6 is optional. A dual-mode IPv6 socket
        // would be tidier, but it fails outright on a host with no IPv6 stack at all - which
        // container images frequently are - and taking down HTTP-01 on an IPv4-only machine to
        // gain tidiness is the wrong trade. IPv6 matters because Let's Encrypt validates over
        // it in preference when an AAAA record exists, so an endpoint that bound only IPv4
        // would fail validation for a correctly configured dual-stack domain.
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(IPAddress.Any, settings.HttpChallengePort);

            if (IPv6IsUsable())
            {
                kestrel.Listen(IPAddress.IPv6Any, settings.HttpChallengePort);
            }
            else
            {
                Logger.LogInformation(
                    "IPv6 is not available on this host, so the ACME challenge endpoint " +
                    "listens on IPv4 only. Validation of a domain with an AAAA record may " +
                    "fail, because the certificate authority prefers IPv6 when one exists.");
            }
        });

        _app = builder.Build();

        _app.MapGet(ChallengePath, (string token) =>
        {
            string? response = challenges.TryGet(token);

            // 404 for an unknown token, with no logging. Scanners probe this path constantly,
            // and logging each miss would fill the log with someone else's traffic.
            return response is null
                ? Results.NotFound()
                : Results.Text(response, ChallengeContentType);
        });

        try
        {
            await _app.StartAsync(stoppingToken).ConfigureAwait(false);

            Logger.LogInformation(
                "The ACME HTTP-01 challenge endpoint is listening on port {Port}. It serves " +
                "only /.well-known/acme-challenge/ and must be reachable from the Internet " +
                "for HTTP-01 issuance to succeed.",
                settings.HttpChallengePort);

            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Healthy,
                $"Listening on port {settings.HttpChallengePort}.",
                DateTimeOffset.UtcNow));

            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Ordinary shutdown.
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            // The common one: something else already has the port, usually IIS. Named as a
            // warning rather than a fatal error, because everything except HTTP-01 issuance
            // still works and DNS-01 is a complete alternative.
            //
            // SocketException as well as IOException: Kestrel surfaces a bind failure as
            // either depending on the cause, and letting one of them escape turns "port 80 is
            // busy" into a background service that crash-loops forever.
            Logger.LogWarning(
                ex,
                "The ACME HTTP-01 endpoint could not bind port {Port}; another process is " +
                "probably using it. HTTP-01 issuance will fail until that is resolved. " +
                "DNS-01 needs no inbound connectivity and is unaffected.",
                settings.HttpChallengePort);

            Health.Publish(new HealthReading(
                ComponentName,
                HealthState.Warning,
                $"Port {settings.HttpChallengePort} could not be bound, so HTTP-01 issuance " +
                "will fail. Use DNS-01, or free the port.",
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
}
