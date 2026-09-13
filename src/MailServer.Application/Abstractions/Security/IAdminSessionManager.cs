using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Security;

/// <summary>
/// An established administrative session. Contains no token.
/// </summary>
/// <remarks>
/// The raw token is returned exactly once, from <see cref="IAdminSessionManager.CreateAsync"/>,
/// and is never stored or re-readable. Everything that describes a session afterwards — the
/// active-sessions list, the audit trail, this type — carries the id, never the credential.
/// </remarks>
public sealed record AdminSession
{
    public required AdminSessionId Id { get; init; }

    /// <summary>The administrator this session authenticates.</summary>
    public required string Administrator { get; init; }

    public required AdminPermission Permissions { get; init; }

    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>Last time a request used this session, for idle expiry.</summary>
    public required DateTimeOffset LastActivityUtc { get; init; }

    /// <summary>
    /// Hard expiry, regardless of activity.
    /// </summary>
    /// <remarks>
    /// A sliding window alone means a console left open on an unattended desktop stays
    /// authenticated indefinitely. The absolute expiry bounds that.
    /// </remarks>
    public required DateTimeOffset AbsoluteExpiryUtc { get; init; }

    /// <summary>Where the session was established from, for the active-sessions list.</summary>
    public string? Origin { get; init; }

    /// <summary>True when the password must be changed before anything else is permitted.</summary>
    public bool MustChangePassword { get; init; }
}

/// <summary>Why a session token was rejected.</summary>
public enum SessionValidationFailure
{
    /// <summary>The session is valid.</summary>
    None = 0,

    /// <summary>No token was presented.</summary>
    Missing = 1,

    /// <summary>The token does not correspond to any session.</summary>
    Unknown = 2,

    /// <summary>The session passed its idle timeout.</summary>
    IdleTimeout = 3,

    /// <summary>The session passed its absolute expiry.</summary>
    Expired = 4,

    /// <summary>The session was revoked, by sign-out, by a password change, or administratively.</summary>
    Revoked = 5,
}

/// <summary>The outcome of validating a presented token.</summary>
/// <param name="Session">The session, when valid.</param>
/// <param name="Failure">Why it was rejected, when invalid.</param>
public readonly record struct SessionValidationResult(
    AdminSession? Session,
    SessionValidationFailure Failure)
{
    public bool IsValid => Session is not null && Failure == SessionValidationFailure.None;

    public static SessionValidationResult Valid(AdminSession session) =>
        new(session, SessionValidationFailure.None);

    public static SessionValidationResult Invalid(SessionValidationFailure failure) =>
        new(null, failure);
}

/// <summary>
/// Issues, validates and revokes administrative sessions.
/// </summary>
/// <remarks>
/// <para>
/// <b>Sessions are held in memory and do not survive a service restart.</b> That is a
/// deliberate security posture, not an omission. A restart is either an upgrade or an
/// intervention; in both cases requiring administrators to re-authenticate is correct, and it
/// means a stolen token has a bounded useful life regardless of its expiry. It also avoids a
/// database write on every single request merely to slide an idle timer.
/// </para>
/// <para>
/// Lockout state, by contrast, <i>is</i> persisted on the account — otherwise restarting the
/// service would clear an attacker's failure counter.
/// </para>
/// <para>
/// <b>Tokens are stored hashed.</b> The manager keeps a SHA-256 of each token, never the token
/// itself, so a memory dump or a future decision to persist sessions does not hand over live
/// credentials. SHA-256 rather than Argon2 is correct here: the token is 256 bits of
/// cryptographically random data, so there is no dictionary to attack and no reason to pay a
/// deliberate cost on every request.
/// </para>
/// </remarks>
public interface IAdminSessionManager
{
    /// <summary>
    /// Creates a session and returns the raw token.
    /// </summary>
    /// <returns>
    /// The session and its raw token. The token is returned <b>once</b>; it is not recoverable
    /// afterwards.
    /// </returns>
    Task<(AdminSession Session, string Token)> CreateAsync(
        string administrator,
        AdminPermission permissions,
        string? origin,
        bool mustChangePassword,
        CancellationToken cancellationToken);

    /// <summary>
    /// Validates a token and, when valid, slides its idle timer.
    /// </summary>
    Task<SessionValidationResult> ValidateAsync(string? token, CancellationToken cancellationToken);

    /// <summary>Revokes one session. Returns false when it was not present.</summary>
    Task<bool> RevokeAsync(AdminSessionId sessionId, CancellationToken cancellationToken);

    /// <summary>Revokes the session identified by a raw token, for sign-out.</summary>
    Task<bool> RevokeByTokenAsync(string? token, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes every session.
    /// </summary>
    /// <remarks>
    /// Called when the master password changes. A password change whose purpose is to lock out
    /// an intruder achieves nothing if the intruder's existing session keeps working.
    /// </remarks>
    Task<int> RevokeAllAsync(CancellationToken cancellationToken);

    /// <summary>Currently valid sessions, for the active-sessions screen.</summary>
    Task<IReadOnlyList<AdminSession>> GetActiveAsync(CancellationToken cancellationToken);

    /// <summary>Drops sessions that have expired. Called periodically by the housekeeping worker.</summary>
    Task<int> PurgeExpiredAsync(CancellationToken cancellationToken);
}
