using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Events;

/// <summary>A mail domain was added to the server.</summary>
public sealed record MailDomainCreatedEvent(
    DomainId DomainId,
    DomainName Name,
    DateTimeOffset OccurredUtc) : IDomainEvent;

/// <summary>A mail domain began accepting mail.</summary>
public sealed record MailDomainEnabledEvent(
    DomainId DomainId,
    DomainName Name,
    DateTimeOffset OccurredUtc) : IDomainEvent;

/// <summary>A mail domain stopped accepting mail.</summary>
public sealed record MailDomainDisabledEvent(
    DomainId DomainId,
    DomainName Name,
    DateTimeOffset OccurredUtc) : IDomainEvent;

/// <summary>
/// A mail domain's outbound identity changed. Consumers must re-check DNS, because the
/// SPF record and the HELO name almost certainly need updating too.
/// </summary>
public sealed record MailDomainHostnameChangedEvent(
    DomainId DomainId,
    DomainName Name,
    DomainName? PreviousHostname,
    DomainName NewHostname,
    DateTimeOffset OccurredUtc) : IDomainEvent;

/// <summary>A mail domain was removed from the server.</summary>
public sealed record MailDomainDeletedEvent(
    DomainId DomainId,
    DomainName Name,
    DateTimeOffset OccurredUtc) : IDomainEvent;
