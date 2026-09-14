using MailServer.Application.Abstractions.Certificates;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Certificates;

/// <summary>
/// Scoped per request: collects the intent to reload and performs it once, after commit.
/// </summary>
/// <remarks>
/// Scoped rather than singleton, so that two concurrent requests cannot have one's reload
/// satisfy the other's — each request reloads for its own committed change, and a request that
/// changed nothing never reloads at all.
/// </remarks>
internal sealed class TlsReloadCoordinator(
    ITlsCertificateProvider provider,
    ILogger<TlsReloadCoordinator> logger) : ITlsReloadCoordinator
{
    public bool ReloadRequested { get; private set; }

    public void RequestReload() => ReloadRequested = true;

    public async Task FlushAsync(CancellationToken cancellationToken)
    {
        if (!ReloadRequested)
        {
            return;
        }

        // Cleared before the reload, not after. If the reload throws, the behavior logs it and
        // the request still succeeds; leaving the flag set would make a retry of an unrelated
        // request in the same scope perform a second reload for a change already applied.
        ReloadRequested = false;

        logger.LogDebug("Reloading the TLS certificate snapshot after a committed change.");

        await provider.ReloadAsync(cancellationToken).ConfigureAwait(false);
    }
}
