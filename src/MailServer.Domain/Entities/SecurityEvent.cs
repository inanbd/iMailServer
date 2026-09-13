using MailServer.Domain.Enums;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// An immutable record of a security-relevant occurrence.
/// </summary>
/// <remarks>
/// <para>
/// Separate from <see cref="AuditRecord"/> by design. The audit trail answers "who changed
/// what" and is written inside the transaction that made the change. This answers "what
/// happened to the security posture" and is written out of band, because the events worth
/// recording — a refused sign-in, an invalid session token, a protocol violation — have no
/// transaction to join and frequently occur when nothing is being changed at all.
/// </para>
/// <para>
/// The volumes differ by orders of magnitude too: a brute-force run produces thousands of
/// security events and zero audit records. Mixing them would make the audit trail unreadable
/// precisely when it matters most.
/// </para>
/// <para>
/// <b>Never records a credential.</b> Not the attempted password, not the presented session
/// token, not the recovery key. A failed sign-in records that one occurred and from where;
/// storing what was tried would turn this table into a dictionary of near-miss passwords.
/// </para>
/// </remarks>
public sealed class SecurityEvent : Entity<SecurityEventId>
{
    public SecurityEvent(
        SecurityEventId id,
        DateTimeOffset timestampUtc,
        SecurityEventType eventType,
        string? subject,
        string? origin,
        string description,
        string machineName,
        CorrelationId correlationId) : base(id)
    {
        TimestampUtc = timestampUtc;
        EventType = eventType;
        Subject = subject;
        Origin = origin;
        Description = description;
        MachineName = machineName;
        CorrelationId = correlationId;
    }

    public DateTimeOffset TimestampUtc { get; }

    public SecurityEventType EventType { get; }

    /// <summary>
    /// Who the event concerns — an administrator name, or null when unknown.
    /// </summary>
    /// <remarks>
    /// Null for a failed sign-in against an account that does not exist. Recording the
    /// attempted name would be useful, but it is attacker-controlled text that would then be
    /// rendered in an admin UI, so it is deliberately not stored.
    /// </remarks>
    public string? Subject { get; }

    /// <summary>Where it came from: a client description or an IP address.</summary>
    public string? Origin { get; }

    /// <summary>Human-readable summary. Contains no credential.</summary>
    public string Description { get; }

    public string MachineName { get; }

    /// <summary>Joins this event to the log lines and audit records for the same operation.</summary>
    public CorrelationId CorrelationId { get; }

    /// <summary>
    /// True for events that warrant an operator's attention rather than merely a record.
    /// </summary>
    /// <remarks>
    /// Drives escalation to the Windows Event Log and the dashboard. A successful sign-in is
    /// recorded but not alarming; a lockout or a forged session token is both.
    /// </remarks>
    public bool IsAlarming => EventType is
        SecurityEventType.AdminAccountLockedOut or
        SecurityEventType.AdminSignInBlockedByLockout or
        SecurityEventType.MasterPasswordResetWithRecoveryKey or
        SecurityEventType.RecoveryKeyRejected or
        SecurityEventType.InvalidSessionPresented or
        SecurityEventType.IpcProtocolViolation;

    public static SecurityEvent Create(
        DateTimeOffset timestampUtc,
        SecurityEventType eventType,
        string? subject,
        string? origin,
        string description,
        string machineName,
        CorrelationId correlationId) =>
        new(SecurityEventId.New(),
            timestampUtc,
            eventType,
            subject,
            origin,
            description,
            machineName,
            correlationId);
}
