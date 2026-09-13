using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// In-memory administrative session store.
/// </summary>
/// <remarks>
/// <para>
/// <b>Sessions do not survive a service restart, deliberately.</b> A restart is either an
/// upgrade or an intervention; in both cases requiring administrators to re-authenticate is
/// the right outcome, and it bounds the useful life of a stolen token regardless of its
/// nominal expiry. It also avoids a database write on every request merely to slide an idle
/// timer — on a console that polls the dashboard every fifteen seconds, that would be a
/// steady stream of writes contending for SQLite's single writer.
/// </para>
/// <para>
/// Lockout state, by contrast, <i>is</i> persisted on the account, because clearing an
/// attacker's failure counter on restart would make lockout meaningless.
/// </para>
/// <para>
/// <b>Tokens are stored as SHA-256 hashes, never in plaintext.</b> SHA-256 rather than Argon2
/// is the right choice here and the reasoning is worth stating: a token is 256 bits of
/// cryptographically random data, so there is no dictionary to attack and no weak-password
/// problem to defend against. Paying Argon2's deliberate 100 ms cost on every single request
/// would be a self-inflicted denial of service for no security gain.
/// </para>
/// </remarks>
public sealed class AdminSessionManager : IAdminSessionManager
{
    /// <summary>Token length in bytes. 256 bits, unguessable.</summary>
    public const int TokenBytes = 32;

    /// <summary>
    /// Hard cap on concurrent sessions.
    /// </summary>
    /// <remarks>
    /// Bounds memory against a caller that authenticates in a loop. Well above any plausible
    /// number of real administration consoles.
    /// </remarks>
    public const int MaxConcurrentSessions = 128;

    private readonly ConcurrentDictionary<string, SessionEntry> _byTokenHash =
        new(StringComparer.Ordinal);

    private readonly ISecuritySettings _settings;
    private readonly IClock _clock;
    private readonly ILogger<AdminSessionManager> _logger;

    public AdminSessionManager(
        ISecuritySettings settings,
        IClock clock,
        ILogger<AdminSessionManager> logger)
    {
        _settings = settings;
        _clock = clock;
        _logger = logger;

        logger.LogInformation(
            "Administrative sessions expire after {IdleMinutes} minute(s) idle or " +
            "{AbsoluteHours} hour(s) absolute, and do not survive a service restart.",
            (int)settings.SessionIdleTimeout.TotalMinutes,
            (int)settings.SessionAbsoluteTimeout.TotalHours);
    }

    public Task<(AdminSession Session, string Token)> CreateAsync(
        string administrator,
        AdminPermission permissions,
        string? origin,
        bool mustChangePassword,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(administrator);

        // Opportunistic cleanup on the create path keeps the dictionary from accumulating
        // expired entries between housekeeping runs.
        PurgeExpiredCore();

        if (_byTokenHash.Count >= MaxConcurrentSessions)
        {
            // Evict the least recently active rather than refusing. Refusing would let an
            // attacker who can authenticate lock out every other administrator by simply
            // creating sessions.
            EvictOldest();
        }

        DateTimeOffset now = _clock.UtcNow;

        byte[] tokenBytes = RandomNumberGenerator.GetBytes(TokenBytes);
        string token = Convert.ToBase64String(tokenBytes);
        CryptographicOperations.ZeroMemory(tokenBytes);

        AdminSession session = new()
        {
            Id = AdminSessionId.New(),
            Administrator = administrator,
            Permissions = permissions,
            CreatedUtc = now,
            LastActivityUtc = now,
            AbsoluteExpiryUtc = now + _settings.SessionAbsoluteTimeout,
            Origin = origin,
            MustChangePassword = mustChangePassword,
        };

        _byTokenHash[HashToken(token)] = new SessionEntry(session);

        _logger.LogInformation(
            "Issued administrative session {SessionId} to {Administrator} from {Origin}.",
            session.Id,
            administrator,
            origin ?? "(unknown origin)");

        return Task.FromResult((session, token));
    }

    public Task<SessionValidationResult> ValidateAsync(
        string? token,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token))
        {
            return Task.FromResult(SessionValidationResult.Invalid(SessionValidationFailure.Missing));
        }

        string tokenHash = HashToken(token);

        if (!_byTokenHash.TryGetValue(tokenHash, out SessionEntry? entry))
        {
            return Task.FromResult(SessionValidationResult.Invalid(SessionValidationFailure.Unknown));
        }

        DateTimeOffset now = _clock.UtcNow;

        if (entry.IsRevoked)
        {
            _byTokenHash.TryRemove(tokenHash, out _);
            return Task.FromResult(SessionValidationResult.Invalid(SessionValidationFailure.Revoked));
        }

        if (now >= entry.Session.AbsoluteExpiryUtc)
        {
            _byTokenHash.TryRemove(tokenHash, out _);
            return Task.FromResult(SessionValidationResult.Invalid(SessionValidationFailure.Expired));
        }

        if (now - entry.Session.LastActivityUtc >= _settings.SessionIdleTimeout)
        {
            _byTokenHash.TryRemove(tokenHash, out _);

            _logger.LogInformation(
                "Session {SessionId} for {Administrator} expired through inactivity.",
                entry.Session.Id,
                entry.Session.Administrator);

            return Task.FromResult(
                SessionValidationResult.Invalid(SessionValidationFailure.IdleTimeout));
        }

        // Slide the idle window. Recorded on the entry rather than by replacing the dictionary
        // value, so concurrent requests on the same session do not race to overwrite each
        // other's timestamp.
        AdminSession slid = entry.Touch(now);

        return Task.FromResult(SessionValidationResult.Valid(slid));
    }

    public Task<bool> RevokeAsync(AdminSessionId sessionId, CancellationToken cancellationToken)
    {
        foreach (KeyValuePair<string, SessionEntry> pair in _byTokenHash)
        {
            if (pair.Value.Session.Id != sessionId)
            {
                continue;
            }

            _byTokenHash.TryRemove(pair.Key, out _);

            _logger.LogInformation("Revoked administrative session {SessionId}.", sessionId);

            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    public Task<bool> RevokeByTokenAsync(string? token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token))
        {
            return Task.FromResult(false);
        }

        return Task.FromResult(_byTokenHash.TryRemove(HashToken(token), out _));
    }

    public Task<int> RevokeAllAsync(CancellationToken cancellationToken)
    {
        int count = _byTokenHash.Count;

        _byTokenHash.Clear();

        if (count > 0)
        {
            _logger.LogWarning("Revoked all {SessionCount} administrative session(s).", count);
        }

        return Task.FromResult(count);
    }

    public Task<IReadOnlyList<AdminSession>> GetActiveAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset now = _clock.UtcNow;

        IReadOnlyList<AdminSession> active =
        [
            .. _byTokenHash.Values
                .Where(e => !e.IsRevoked && IsLive(e.Session, now))
                .Select(e => e.Session)
        ];

        return Task.FromResult(active);
    }

    public Task<int> PurgeExpiredAsync(CancellationToken cancellationToken) =>
        Task.FromResult(PurgeExpiredCore());

    private int PurgeExpiredCore()
    {
        DateTimeOffset now = _clock.UtcNow;
        int removed = 0;

        foreach (KeyValuePair<string, SessionEntry> pair in _byTokenHash)
        {
            if (pair.Value.IsRevoked || !IsLive(pair.Value.Session, now))
            {
                if (_byTokenHash.TryRemove(pair.Key, out _))
                {
                    removed++;
                }
            }
        }

        return removed;
    }

    private bool IsLive(AdminSession session, DateTimeOffset now) =>
        now < session.AbsoluteExpiryUtc &&
        now - session.LastActivityUtc < _settings.SessionIdleTimeout;

    private void EvictOldest()
    {
        KeyValuePair<string, SessionEntry> oldest = _byTokenHash
            .OrderBy(p => p.Value.Session.LastActivityUtc)
            .FirstOrDefault();

        if (oldest.Key is not null && _byTokenHash.TryRemove(oldest.Key, out _))
        {
            _logger.LogWarning(
                "The session limit of {Limit} was reached; the least recently used session " +
                "{SessionId} was evicted.",
                MaxConcurrentSessions,
                oldest.Value.Session.Id);
        }
    }

    /// <summary>
    /// Hashes a token for use as the dictionary key.
    /// </summary>
    /// <remarks>
    /// Keying on the hash rather than the token means a memory dump of this process yields no
    /// usable credential, and a future decision to persist sessions cannot accidentally write
    /// live tokens to disk.
    /// </remarks>
    private static string HashToken(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>
    /// Mutable wrapper so the idle timer can slide without replacing the dictionary entry.
    /// </summary>
    private sealed class SessionEntry(AdminSession session)
    {
        private AdminSession _session = session;

        public AdminSession Session => _session;

        public bool IsRevoked { get; private set; }

        public AdminSession Touch(DateTimeOffset now)
        {
            AdminSession updated = _session with { LastActivityUtc = now };
            _session = updated;
            return updated;
        }

        public void Revoke() => IsRevoked = true;
    }
}
