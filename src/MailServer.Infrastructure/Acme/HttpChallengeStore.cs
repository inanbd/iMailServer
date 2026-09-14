using System.Collections.Concurrent;
using MailServer.Application.Abstractions.Acme;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Acme;

/// <summary>
/// In-memory store of HTTP-01 challenge responses.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not persisted. The token is valid for minutes, is useless to anyone without the
/// account key, and writing it to the database or to disk would create an artefact to clean up
/// — the exact hygiene problem publishing a challenge is supposed to avoid. A restart
/// mid-issuance loses the token, the order is retried, the CA issues a new one, and nothing is
/// left behind.
/// </para>
/// <para>
/// A hard cap on entries, because <see cref="Publish"/> is reachable only from an authenticated
/// issuance but <see cref="TryGet"/> is reachable from the public Internet. The cap means a bug
/// that fails to clean up cannot grow the dictionary without limit.
/// </para>
/// </remarks>
internal sealed class HttpChallengeStore(ILogger<HttpChallengeStore> logger) : IHttpChallengeStore
{
    /// <summary>
    /// Maximum concurrent published challenges.
    /// </summary>
    /// <remarks>
    /// A single order covers at most a hundred identifiers, and concurrent issuances are rare,
    /// so this is generous. It exists as a bound, not as a tuning parameter.
    /// </remarks>
    private const int MaxEntries = 256;

    private readonly ConcurrentDictionary<string, string> _responses =
        new(StringComparer.Ordinal);

    public int Count => _responses.Count;

    public void Publish(string token, string keyAuthorization)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyAuthorization);

        if (_responses.Count >= MaxEntries && !_responses.ContainsKey(token))
        {
            throw new InvalidOperationException(
                $"More than {MaxEntries} ACME challenges are published at once, which should " +
                "not happen. Challenge cleanup is failing somewhere.");
        }

        _responses[token] = keyAuthorization;

        // The count, never the token or the key authorisation. The token is the secret half of
        // a proof of control, and a log line carrying one invites it into a support thread.
        logger.LogDebug(
            "Published an HTTP-01 challenge response; {Count} now active.",
            _responses.Count);
    }

    /// <remarks>
    /// Returns null rather than throwing for an unknown token. This is reached from an
    /// unauthenticated public endpoint, and scanners probe
    /// <c>/.well-known/acme-challenge/</c> constantly; logging each miss at anything above
    /// Trace would fill the log with someone else's traffic.
    /// </remarks>
    public string? TryGet(string token) =>
        string.IsNullOrEmpty(token) ? null : _responses.GetValueOrDefault(token);

    public void Remove(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return;
        }

        if (_responses.TryRemove(token, out _))
        {
            logger.LogDebug(
                "Removed an HTTP-01 challenge response; {Count} remain.",
                _responses.Count);
        }
    }
}
