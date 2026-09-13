using MailServer.Domain.Enums;
using MailServer.Domain.Events;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// A mail domain hosted by this server: the aggregate root that owns its mailboxes,
/// aliases, DKIM keys and delivery policy.
/// </summary>
/// <remarks>
/// <para>
/// Named <c>MailDomain</c> rather than <c>Domain</c> to avoid colliding with
/// <see cref="System.AppDomain"/>-adjacent naming and with the <c>Domain</c> namespace
/// segment, both of which make for genuinely confusing code at the call site.
/// </para>
/// <para>
/// <b>The domain name is immutable.</b> Renaming a mail domain is not an edit: every
/// mailbox address, every DKIM DNS record, every SPF record and every message already
/// delivered refers to the old name. The supported operation is "add the new domain, add
/// aliases, migrate, remove the old one", and modelling it as an immutable field is what
/// stops a well-meaning UI from offering a rename that would silently strand mail.
/// </para>
/// </remarks>
public sealed class MailDomain : AggregateRoot<DomainId>
{
    /// <summary>
    /// Rehydration constructor for the persistence layer.
    /// </summary>
    /// <remarks>
    /// Internal-by-convention: it is public because the persistence assembly is separate,
    /// but it deliberately performs no invariant checks beyond null guards, because data
    /// already in the database is by definition already committed. Re-validating here would
    /// make a schema change or a hand-edited row unloadable, which turns a small problem
    /// into an outage.
    /// </remarks>
    public MailDomain(
        DomainId id,
        DomainName name,
        DomainStatus status,
        DomainName? mailHostname,
        DkimSelector? activeDkimSelector,
        CatchAllPolicy catchAllPolicy,
        EmailAddress? catchAllMailbox,
        QuotaBytes defaultMailboxQuota,
        QuotaBytes domainQuota,
        long maxMessageSizeBytes,
        bool requireTlsForOutbound,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(name);

        Name = name;
        Status = status;
        MailHostname = mailHostname;
        ActiveDkimSelector = activeDkimSelector;
        CatchAllPolicy = catchAllPolicy;
        CatchAllMailbox = catchAllMailbox;
        DefaultMailboxQuota = defaultMailboxQuota;
        DomainQuota = domainQuota;
        MaxMessageSizeBytes = maxMessageSizeBytes;
        RequireTlsForOutbound = requireTlsForOutbound;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
    }

    /// <summary>The domain name. Immutable for the lifetime of the aggregate.</summary>
    public DomainName Name { get; }

    /// <summary>Lifecycle state.</summary>
    public DomainStatus Status { get; private set; }

    /// <summary>
    /// The outbound identity for this domain: the name used in EHLO, in the MX record, and
    /// the name a TLS certificate must cover. Null until configured, which is why a domain
    /// starts <see cref="DomainStatus.Pending"/> and cannot be enabled without it.
    /// </summary>
    public DomainName? MailHostname { get; private set; }

    /// <summary>The DKIM selector currently used for signing, if any.</summary>
    public DkimSelector? ActiveDkimSelector { get; private set; }

    /// <summary>What to do with mail for an unknown local recipient.</summary>
    public CatchAllPolicy CatchAllPolicy { get; private set; }

    /// <summary>
    /// Destination when <see cref="CatchAllPolicy"/> is
    /// <see cref="Enums.CatchAllPolicy.DeliverToCatchAll"/>.
    /// </summary>
    public EmailAddress? CatchAllMailbox { get; private set; }

    /// <summary>Quota applied to new mailboxes unless overridden.</summary>
    public QuotaBytes DefaultMailboxQuota { get; private set; }

    /// <summary>Ceiling on the total storage consumed by every mailbox in this domain.</summary>
    public QuotaBytes DomainQuota { get; private set; }

    /// <summary>Largest message accepted for this domain, in bytes. Advertised via SMTP SIZE.</summary>
    public long MaxMessageSizeBytes { get; private set; }

    /// <summary>
    /// When true, outbound mail from this domain must be delivered over TLS. If the remote
    /// server offers no usable TLS, delivery FAILS rather than silently falling back to
    /// plaintext. A security policy that downgrades itself is not a security policy.
    /// </summary>
    public bool RequireTlsForOutbound { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    /// <summary>True when this domain may accept and send mail right now.</summary>
    public bool IsOperational => Status == DomainStatus.Active;

    /// <summary>
    /// Creates a new hosted domain in <see cref="DomainStatus.Pending"/>.
    /// </summary>
    /// <remarks>
    /// New domains are deliberately not active. DNS has not propagated, DKIM has not been
    /// generated, and the certificate may not cover the hostname yet. Starting active would
    /// mean sending mail that fails authentication at every major receiver - which damages
    /// the sending IP's reputation in a way that takes weeks to undo.
    /// </remarks>
    public static MailDomain Create(
        DomainId id,
        DomainName name,
        DateTimeOffset nowUtc,
        DomainName? mailHostname = null,
        QuotaBytes? defaultMailboxQuota = null,
        long maxMessageSizeBytes = DefaultMaxMessageSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (maxMessageSizeBytes < MinimumMaxMessageSizeBytes)
        {
            throw new DomainRuleViolationException(
                "domain.max_message_size.too_small",
                $"The maximum message size must be at least " +
                $"{QuotaBytes.FormatBytes(MinimumMaxMessageSizeBytes)}.");
        }

        MailDomain domain = new(
            id,
            name,
            DomainStatus.Pending,
            mailHostname,
            activeDkimSelector: null,
            CatchAllPolicy.Reject,
            catchAllMailbox: null,
            defaultMailboxQuota ?? QuotaBytes.FromGigabytes(5),
            QuotaBytes.Unlimited,
            maxMessageSizeBytes,
            requireTlsForOutbound: false,
            nowUtc,
            modifiedUtc: null);

        domain.Raise(new MailDomainCreatedEvent(id, name, nowUtc));
        return domain;
    }

    /// <summary>Default maximum message size: 35 MiB, comfortably above the common 25 MB limit.</summary>
    public const long DefaultMaxMessageSizeBytes = 35L * 1024 * 1024;

    /// <summary>
    /// Floor on the maximum message size. Below this the server would reject ordinary mail
    /// with attachments, which looks to the sender like an outage.
    /// </summary>
    public const long MinimumMaxMessageSizeBytes = 64L * 1024;

    /// <summary>
    /// Brings the domain into service.
    /// </summary>
    /// <exception cref="DomainRuleViolationException">
    /// The domain has no mail hostname, or is pending deletion.
    /// </exception>
    public void Enable(DateTimeOffset nowUtc)
    {
        if (Status == DomainStatus.PendingDeletion)
        {
            throw new DomainRuleViolationException(
                "domain.enable.pending_deletion",
                $"Domain '{Name}' is scheduled for deletion and cannot be enabled. " +
                "Cancel the deletion first.");
        }

        if (MailHostname is null)
        {
            throw new DomainRuleViolationException(
                "domain.enable.no_hostname",
                $"Domain '{Name}' has no mail hostname. Mail sent from a domain with no " +
                "outbound identity fails SPF, DKIM alignment and reverse-DNS checks at " +
                "every major receiver, so the domain cannot be enabled without one.");
        }

        if (Status == DomainStatus.Active)
        {
            return;
        }

        Status = DomainStatus.Active;
        Touch(nowUtc);
        Raise(new MailDomainEnabledEvent(Id, Name, nowUtc));
    }

    /// <summary>
    /// Takes the domain out of service. Mailboxes and stored mail are retained.
    /// </summary>
    public void Disable(DateTimeOffset nowUtc)
    {
        if (Status is DomainStatus.Disabled or DomainStatus.PendingDeletion)
        {
            return;
        }

        Status = DomainStatus.Disabled;
        Touch(nowUtc);
        Raise(new MailDomainDisabledEvent(Id, Name, nowUtc));
    }

    /// <summary>
    /// Marks the domain for removal. Deletion is deferred so that queued mail drains and so
    /// that an accidental deletion is recoverable inside the retention window.
    /// </summary>
    public void MarkForDeletion(DateTimeOffset nowUtc)
    {
        if (Status == DomainStatus.PendingDeletion)
        {
            return;
        }

        Status = DomainStatus.PendingDeletion;
        Touch(nowUtc);
        Raise(new MailDomainDeletedEvent(Id, Name, nowUtc));
    }

    /// <summary>
    /// Sets the outbound identity. Changing it on a live domain is significant: DNS, SPF
    /// and the TLS certificate all reference this name, so the event is raised to prompt a
    /// re-check.
    /// </summary>
    public void SetMailHostname(DomainName hostname, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        if (MailHostname == hostname)
        {
            return;
        }

        DomainName? previous = MailHostname;
        MailHostname = hostname;
        Touch(nowUtc);
        Raise(new MailDomainHostnameChangedEvent(Id, Name, previous, hostname, nowUtc));
    }

    /// <summary>Assigns the selector used for outbound DKIM signing.</summary>
    public void SetActiveDkimSelector(DkimSelector? selector, DateTimeOffset nowUtc)
    {
        ActiveDkimSelector = selector;
        Touch(nowUtc);
    }

    /// <summary>
    /// Sets the unknown-recipient policy.
    /// </summary>
    /// <exception cref="DomainRuleViolationException">
    /// A catch-all destination is required but missing, or belongs to another domain.
    /// </exception>
    public void SetCatchAllPolicy(
        CatchAllPolicy policy,
        EmailAddress? catchAllMailbox,
        DateTimeOffset nowUtc)
    {
        if (policy == CatchAllPolicy.DeliverToCatchAll)
        {
            if (catchAllMailbox is null)
            {
                throw new DomainRuleViolationException(
                    "domain.catchall.destination_required",
                    "A catch-all destination mailbox is required when the catch-all policy " +
                    "is DeliverToCatchAll.");
            }

            // Routing a catch-all off-domain would turn this server into a forwarder for
            // every dictionary attack aimed at the domain.
            if (catchAllMailbox.Domain != Name)
            {
                throw new DomainRuleViolationException(
                    "domain.catchall.foreign_destination",
                    $"The catch-all mailbox '{catchAllMailbox}' must belong to '{Name}'.");
            }
        }

        CatchAllPolicy = policy;
        CatchAllMailbox = policy == CatchAllPolicy.DeliverToCatchAll ? catchAllMailbox : null;
        Touch(nowUtc);
    }

    /// <summary>Sets the storage quotas applied to this domain and its new mailboxes.</summary>
    public void SetQuotas(QuotaBytes defaultMailboxQuota, QuotaBytes domainQuota, DateTimeOffset nowUtc)
    {
        if (!domainQuota.IsUnlimited &&
            !defaultMailboxQuota.IsUnlimited &&
            defaultMailboxQuota.Bytes > domainQuota.Bytes)
        {
            throw new DomainRuleViolationException(
                "domain.quota.mailbox_exceeds_domain",
                $"The default mailbox quota ({defaultMailboxQuota}) cannot exceed the " +
                $"domain quota ({domainQuota}).");
        }

        DefaultMailboxQuota = defaultMailboxQuota;
        DomainQuota = domainQuota;
        Touch(nowUtc);
    }

    /// <summary>Sets the largest message this domain accepts.</summary>
    public void SetMaxMessageSize(long maxMessageSizeBytes, DateTimeOffset nowUtc)
    {
        if (maxMessageSizeBytes < MinimumMaxMessageSizeBytes)
        {
            throw new DomainRuleViolationException(
                "domain.max_message_size.too_small",
                $"The maximum message size must be at least " +
                $"{QuotaBytes.FormatBytes(MinimumMaxMessageSizeBytes)}.");
        }

        MaxMessageSizeBytes = maxMessageSizeBytes;
        Touch(nowUtc);
    }

    /// <summary>Requires (or stops requiring) TLS for outbound mail from this domain.</summary>
    public void SetRequireTlsForOutbound(bool require, DateTimeOffset nowUtc)
    {
        RequireTlsForOutbound = require;
        Touch(nowUtc);
    }

    /// <summary>
    /// True when this domain should accept mail for <paramref name="recipient"/>.
    /// Address-level routing (which mailbox, which alias) is a separate decision.
    /// </summary>
    public bool AcceptsMailFor(EmailAddress recipient)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        return IsOperational && recipient.Domain == Name;
    }

    private void Touch(DateTimeOffset nowUtc) => ModifiedUtc = nowUtc;
}
