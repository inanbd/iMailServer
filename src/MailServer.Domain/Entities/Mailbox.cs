using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// A mailbox: an address that accepts mail, stores it, and can be logged into.
/// </summary>
/// <remarks>
/// <para>
/// <b>The address is immutable.</b> Renaming a mailbox is not an edit — every message already
/// delivered carries the old address in its envelope and headers, every correspondent has it,
/// and every device is configured with it. The supported operation is "create the new address,
/// alias the old one to it, migrate, then remove the alias when nothing uses it". Modelling
/// the address as immutable is what stops a well-meaning UI offering a rename that would
/// silently strand mail.
/// </para>
/// <para>
/// <b>It holds no password.</b> Credentials are a separate entity with their own lifecycle,
/// because a mailbox can outlive several passwords and because a password change must not need
/// the whole aggregate loaded and rewritten.
/// </para>
/// <para>
/// <b>Storage used is maintained by delivery, not computed here.</b> Summing message sizes on
/// every quota check would make the cheapest question in the system — "is this mailbox full" —
/// a table scan, and that question is asked on every RCPT TO.
/// </para>
/// </remarks>
public sealed class Mailbox : AggregateRoot<MailboxId>
{
    /// <summary>Rehydration constructor for the persistence layer.</summary>
    /// <remarks>
    /// Null guards only. A row already in the database is already committed, and re-validating
    /// it here would make a mailbox unloadable after a rule tightened — which would take mail
    /// delivery down for an account that is merely non-conforming.
    /// </remarks>
    public Mailbox(
        MailboxId id,
        DomainId domainId,
        EmailAddress address,
        string localPart,
        string? displayName,
        MailboxStatus status,
        QuotaBytes quota,
        long storageUsedBytes,
        long maxMessageSizeBytes,
        MailboxAccess access,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc,
        DateTimeOffset? lastLoginUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(localPart);

        DomainId = domainId;
        Address = address;
        LocalPart = localPart;
        DisplayName = displayName;
        Status = status;
        Quota = quota;
        StorageUsedBytes = storageUsedBytes;
        MaxMessageSizeBytes = maxMessageSizeBytes;
        Access = access;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
        LastLoginUtc = lastLoginUtc;
    }

    public DomainId DomainId { get; }

    /// <summary>The full address. Immutable for the lifetime of the mailbox.</summary>
    public EmailAddress Address { get; }

    /// <summary>The local-part exactly as the administrator typed it, for display.</summary>
    /// <remarks>
    /// Kept alongside the normalised address because <c>J.Smith@example.com</c> and
    /// <c>j.smith@example.com</c> are the same mailbox but only one of them is how its owner
    /// writes their own name.
    /// </remarks>
    public string LocalPart { get; }

    public string? DisplayName { get; private set; }

    public MailboxStatus Status { get; private set; }

    /// <summary>
    /// Storage ceiling. <see cref="QuotaBytes.Unlimited"/> means inherit the domain default.
    /// </summary>
    /// <remarks>
    /// Zero-means-inherit rather than a nullable column, matching the schema written in
    /// migration 0001. The consequence worth knowing: a mailbox cannot be explicitly unlimited
    /// while its domain has a quota — see <see cref="EffectiveQuota"/>.
    /// </remarks>
    public QuotaBytes Quota { get; private set; }

    /// <summary>Bytes currently stored, maintained by delivery and expunge.</summary>
    public long StorageUsedBytes { get; private set; }

    /// <summary>Largest accepted message, or 0 to inherit the domain default.</summary>
    public long MaxMessageSizeBytes { get; private set; }

    public MailboxAccess Access { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    public DateTimeOffset? LastLoginUtc { get; private set; }

    /// <summary>True when this mailbox will accept delivery right now.</summary>
    /// <remarks>
    /// Suspended mailboxes accept mail: the suspension stops logins, not delivery. Rejecting
    /// mail would announce the suspension to every sender, which for a compromised account is
    /// the wrong thing to broadcast.
    /// </remarks>
    public bool AcceptsMail => Status is MailboxStatus.Active or MailboxStatus.Suspended;

    /// <summary>True when a credential for this mailbox may be used to log in.</summary>
    public bool AllowsLogin => Status == MailboxStatus.Active;

    /// <summary>
    /// The quota actually in force, given the domain's default.
    /// </summary>
    /// <remarks>
    /// Resolved here rather than at each call site, because "0 means inherit" is the kind of
    /// rule that gets reimplemented slightly differently in the delivery path and the admin UI
    /// and then disagrees about whether a mailbox is full.
    /// </remarks>
    public QuotaBytes EffectiveQuota(QuotaBytes domainDefault) =>
        Quota.IsUnlimited ? domainDefault : Quota;

    /// <summary>The largest message this mailbox accepts, given the domain's default.</summary>
    public long EffectiveMaxMessageSize(long domainDefault) =>
        MaxMessageSizeBytes == 0 ? domainDefault : MaxMessageSizeBytes;

    /// <summary>
    /// True when storing <paramref name="messageBytes"/> more would exceed the quota.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Checked <i>before</i> accepting a message rather than after storing it. Accepting mail
    /// that takes a mailbox over quota and then bouncing it means the sender has been told the
    /// message was accepted; the correct answer is to refuse it at RCPT TO with 452, which
    /// tells the sending server to retry later and keeps the message in <i>their</i> queue.
    /// </para>
    /// <para>
    /// Deliberately takes the domain default rather than reading it, so the caller cannot
    /// forget that inheritance exists.
    /// </para>
    /// </remarks>
    public bool WouldExceedQuota(long messageBytes, QuotaBytes domainDefault) =>
        EffectiveQuota(domainDefault).WouldBeExceededBy(StorageUsedBytes, messageBytes);

    /// <summary>How full the mailbox is, as a percentage of its effective quota.</summary>
    public double QuotaPercentageUsed(QuotaBytes domainDefault) =>
        EffectiveQuota(domainDefault).PercentageUsed(StorageUsedBytes);

    /// <summary>Creates a mailbox in <see cref="MailboxStatus.Active"/>.</summary>
    /// <exception cref="DomainRuleViolationException">
    /// The address does not belong to the domain, or a limit is negative.
    /// </exception>
    public static Mailbox Create(
        DomainId domainId,
        EmailAddress address,
        MailDomain domain,
        string? displayName,
        QuotaBytes quota,
        MailboxAccess access,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(domain);

        // The one check that cannot be left to a foreign key: a mailbox row pointing at the
        // wrong domain would be addressable at a name this server does not host, and the
        // resulting mail would be accepted and then undeliverable.
        if (address.Domain != domain.Name)
        {
            throw new DomainRuleViolationException(
                "mailbox.address.wrong_domain",
                $"'{address.Value}' is not an address in '{domain.Name}'. A mailbox belongs to " +
                "exactly one hosted domain, and its address must be in that domain.");
        }

        if (access == MailboxAccess.None)
        {
            throw new DomainRuleViolationException(
                "mailbox.access.none",
                $"'{address.Value}' would have no access protocols enabled, so nobody could " +
                "read its mail or send from it. Disable the mailbox instead if that is the " +
                "intent — it says so plainly and can be reversed.");
        }

        return new Mailbox(
            MailboxId.New(),
            domainId,
            address,
            address.LocalPart,
            string.IsNullOrWhiteSpace(displayName) ? null : displayName.Trim(),
            MailboxStatus.Active,
            quota,
            storageUsedBytes: 0,
            maxMessageSizeBytes: 0,
            access,
            createdUtc: now,
            modifiedUtc: null,
            lastLoginUtc: null);
    }

    public void SetDisplayName(string? displayName, DateTimeOffset now)
    {
        DisplayName = string.IsNullOrWhiteSpace(displayName) ? null : displayName.Trim();
        ModifiedUtc = now;
    }

    public void SetStatus(MailboxStatus status, DateTimeOffset now)
    {
        Status = status;
        ModifiedUtc = now;
    }

    /// <summary>
    /// Changes the storage ceiling.
    /// </summary>
    /// <remarks>
    /// A quota below current usage is permitted, deliberately. Refusing it would leave an
    /// operator unable to act on a mailbox that is already too large, which is exactly when
    /// they most need to. The mailbox simply accepts no more mail until it is under the new
    /// limit, and the UI shows it over quota.
    /// </remarks>
    public void SetQuota(QuotaBytes quota, DateTimeOffset now)
    {
        Quota = quota;
        ModifiedUtc = now;
    }

    public void SetMaxMessageSize(long maxMessageSizeBytes, DateTimeOffset now)
    {
        if (maxMessageSizeBytes < 0)
        {
            throw new DomainRuleViolationException(
                "mailbox.max_message_size.negative",
                "The maximum message size cannot be negative. Use 0 to inherit the domain's.");
        }

        MaxMessageSizeBytes = maxMessageSizeBytes;
        ModifiedUtc = now;
    }

    /// <exception cref="DomainRuleViolationException">No protocol would be left enabled.</exception>
    public void SetAccess(MailboxAccess access, DateTimeOffset now)
    {
        if (access == MailboxAccess.None)
        {
            throw new DomainRuleViolationException(
                "mailbox.access.none",
                $"'{Address.Value}' would have no access protocols enabled. Disable the " +
                "mailbox instead if that is the intent.");
        }

        Access = access;
        ModifiedUtc = now;
    }

    /// <summary>True when this mailbox may use <paramref name="protocol"/> right now.</summary>
    /// <remarks>
    /// Combines the flag with the status, because a caller asking "may this login proceed"
    /// needs both and checking them separately is how a suspended account keeps working over
    /// one protocol.
    /// </remarks>
    public bool AllowsAccess(MailboxAccess protocol) =>
        AllowsLogin && (Access & protocol) == protocol;

    public void RecordLogin(DateTimeOffset now) => LastLoginUtc = now;

    /// <summary>Adds to the recorded storage usage after a delivery.</summary>
    public void AddStorage(long bytes, DateTimeOffset now)
    {
        if (bytes < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(bytes),
                bytes,
                "Use ReleaseStorage to account for a deletion.");
        }

        StorageUsedBytes += bytes;
        ModifiedUtc = now;
    }

    /// <summary>Subtracts from the recorded storage usage after an expunge.</summary>
    /// <remarks>
    /// Clamped at zero rather than allowed to go negative. The counter is maintained
    /// incrementally, so a missed increment somewhere would otherwise turn into a negative
    /// total that reports every mailbox as empty — a quota that silently stops applying is
    /// worse than one that is slightly high until the next recount.
    /// </remarks>
    public void ReleaseStorage(long bytes, DateTimeOffset now)
    {
        if (bytes < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(bytes),
                bytes,
                "Use AddStorage to account for a delivery.");
        }

        StorageUsedBytes = Math.Max(0, StorageUsedBytes - bytes);
        ModifiedUtc = now;
    }

    /// <summary>Replaces the recorded usage with a freshly counted figure.</summary>
    /// <remarks>
    /// The repair path for the incremental counter above. Milestone 13's maintenance tooling
    /// recounts from the message store; this is how the result gets back in.
    /// </remarks>
    public void ResetStorage(long actualBytes, DateTimeOffset now)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(actualBytes);

        StorageUsedBytes = actualBytes;
        ModifiedUtc = now;
    }
}
