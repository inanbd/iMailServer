using MailServer.Application.Abstractions.Deliverability;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Builds this server's own MTA-STS policy from configuration, once.
/// </summary>
/// <remarks>
/// <para>
/// <b>Resolved at construction and then fixed.</b> The policy's <c>id</c> is a hash of its
/// content, and RFC 8461 §3.1 has senders re-fetch only when that id changes — so a source that
/// rebuilt the policy per request would be fine, but one that could return two different
/// policies for one advertised id would not. Building it once makes the served bytes and the
/// advertised id the same fact rather than two facts that have to agree.
/// </para>
/// <para>
/// <b>A misconfiguration disables publishing rather than failing the host.</b> Publishing is
/// opt-in and every other part of the server works without it; taking the whole service down
/// because an <c>mx</c> list was empty would turn a deliverability feature into an outage, which
/// is the exact failure mode <see cref="MtaStsOptions"/> exists to warn about.
/// </para>
/// </remarks>
public sealed class MtaStsPolicySource : IMtaStsPolicySource
{
    private readonly MtaStsPolicy? _policy;

    public MtaStsPolicySource(IOptions<MailServerOptions> options, ILogger<MtaStsPolicySource> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        MtaStsOptions configured = options.Value.Deliverability.MtaSts;

        Port = configured.Port;

        if (!configured.Enabled)
        {
            return;
        }

        try
        {
            _policy = MtaStsPolicy.Create(configured.Mode, configured.MxHosts, configured.MaxAgeSeconds);

            logger.LogInformation(
                "Publishing an MTA-STS policy in {Mode} mode for {Count} mx pattern(s), id {Id}. " +
                "Senders will not see it until _mta-sts TXT and the mta-sts. hostname are in DNS.",
                configured.Mode,
                _policy.MxPatterns.Count,
                _policy.PolicyId());
        }
        catch (ArgumentException ex)
        {
            logger.LogError(
                ex,
                "MTA-STS publishing is enabled but the policy is not valid, so nothing will be " +
                "served. Serving no policy is the safe outcome: senders fall back to ordinary " +
                "opportunistic TLS rather than refusing delivery.");
        }
    }

    public bool IsPublishing => _policy is not null;

    public int Port { get; }

    public MtaStsPolicy? Current() => _policy;
}
