using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Events;

/// <summary>The master password was established for the first time.</summary>
public sealed record MasterPasswordCreatedEvent(
    AdminAccountId AccountId,
    string Administrator,
    DateTimeOffset OccurredUtc) : IDomainEvent;

/// <summary>
/// The master password changed.
/// </summary>
/// <remarks>
/// Consumers must revoke every existing session. A password change whose purpose is to lock
/// out an intruder is pointless if the intruder's session token keeps working.
/// </remarks>
public sealed record MasterPasswordChangedEvent(
    AdminAccountId AccountId,
    string Administrator,
    bool ViaRecoveryKey,
    DateTimeOffset OccurredUtc) : IDomainEvent;

/// <summary>Repeated authentication failures locked the account.</summary>
public sealed record AdminAccountLockedOutEvent(
    AdminAccountId AccountId,
    int ConsecutiveFailures,
    DateTimeOffset LockedOutUntilUtc,
    DateTimeOffset OccurredUtc) : IDomainEvent;

/// <summary>
/// A new recovery key was issued, superseding any previous one.
/// </summary>
public sealed record RecoveryKeyIssuedEvent(
    AdminAccountId AccountId,
    DateTimeOffset OccurredUtc) : IDomainEvent;
