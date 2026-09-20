using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>
/// The MTA-STS policy this server publishes for its own domain, if it publishes one.
/// </summary>
/// <remarks>
/// <para>
/// The counterpart of <see cref="IMtaStsPolicyFetcher"/>, which reads other domains' policies to
/// check them. This one answers what to serve. Keeping them apart matters because the two have
/// opposite trust postures: a fetched policy is somebody else's text and is treated as hostile
/// until parsed, while a served one is this server's own statement about where its mail may go.
/// </para>
/// <para>
/// An interface rather than the options type, so that the Service layer's endpoint depends on
/// "what should I serve" rather than on the shape of a configuration file, and so a test can
/// vary the policy without building a configuration tree.
/// </para>
/// </remarks>
public interface IMtaStsPolicySource
{
    /// <summary>Whether a policy should be served at all.</summary>
    bool IsPublishing { get; }

    /// <summary>
    /// The port the policy endpoint should listen on.
    /// </summary>
    /// <remarks>
    /// 443 in practice: RFC 8461 §3.2 fixes the URL senders fetch and §3.3 forbids following a
    /// redirect, so a policy anywhere else is one nobody reads.
    /// </remarks>
    int Port { get; }

    /// <summary>
    /// The policy to serve, or null when none is configured.
    /// </summary>
    /// <remarks>
    /// Null rather than an empty policy, because "publish nothing" and "publish
    /// <c>mode: none</c>" are different statements: §5 makes the second an active withdrawal
    /// that senders act on, and serving it by accident would tell every sender that already has
    /// a cached policy to stop enforcing it.
    /// </remarks>
    MtaStsPolicy? Current();
}
