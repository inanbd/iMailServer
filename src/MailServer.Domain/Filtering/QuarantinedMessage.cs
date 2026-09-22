using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Filtering;

/// <summary>Where a held message has got to.</summary>
public enum QuarantineStatus
{
    /// <summary>Held, and delivered to nobody.</summary>
    Held = 0,

    /// <summary>An operator decided it was legitimate, and it was delivered.</summary>
    Released = 1,

    /// <summary>An operator decided it was not, and the content was removed.</summary>
    Discarded = 2,
}

/// <summary>
/// One message the filter held rather than delivered.
/// </summary>
/// <remarks>
/// <para>
/// <b>The content is not copied here.</b> The message is already in the store and the
/// <c>Messages</c> row already names it; this carries the verdict and the state, and a release
/// reads the same file an ordinary delivery would have. Copying would double what a held
/// message costs on disk and create a second copy nothing else knows to delete.
/// </para>
/// <para>
/// <b>Resolving does not remove the row.</b> A released message leaves behind a record of what
/// was held and who let it through, which outlives the message being expunged from the mailbox
/// it was released into. An operator asking "did we release that?" six months later has an
/// answer.
/// </para>
/// </remarks>
public sealed class QuarantinedMessage : Entity<QuarantinedMessageId>
{
    private readonly List<FilterSignal> _signals;

    private QuarantinedMessage(
        QuarantinedMessageId id,
        StoredMessageId messageId,
        EmailAddress? reversePath,
        IpAddressValue remoteAddress,
        double score,
        string summary,
        IReadOnlyList<FilterSignal> signals,
        DateTimeOffset quarantinedUtc,
        DateTimeOffset expiresUtc)
        : base(id)
    {
        MessageId = messageId;
        ReversePath = reversePath;
        RemoteAddress = remoteAddress;
        Score = score;
        Summary = summary;
        _signals = [.. signals];
        QuarantinedUtc = quarantinedUtc;
        ExpiresUtc = expiresUtc;
        Status = QuarantineStatus.Held;
    }

    /// <summary>The held message.</summary>
    public StoredMessageId MessageId { get; }

    /// <summary>The envelope sender, or null for the null reverse path.</summary>
    public EmailAddress? ReversePath { get; }

    /// <summary>The peer that delivered it.</summary>
    public IpAddressValue RemoteAddress { get; }

    /// <summary>What the checks summed to.</summary>
    public double Score { get; }

    /// <summary>The one-line verdict, as it read when the message was held.</summary>
    public string Summary { get; }

    /// <summary>Why it was held, in the order the checks produced the reasons.</summary>
    public IReadOnlyList<FilterSignal> Signals => _signals;

    /// <summary>When it was held.</summary>
    public DateTimeOffset QuarantinedUtc { get; }

    /// <summary>When a retention sweep may remove it.</summary>
    /// <remarks>
    /// Fixed at hold time rather than computed on read, so that changing the retention setting
    /// does not retroactively expire what is already held — an operator who shortens it should
    /// not find yesterday's quarantine gone.
    /// </remarks>
    public DateTimeOffset ExpiresUtc { get; }

    /// <summary>Held, released or discarded.</summary>
    public QuarantineStatus Status { get; private set; }

    /// <summary>When the hold was resolved. Null while it is held.</summary>
    public DateTimeOffset? ResolvedUtc { get; private set; }

    /// <summary>Which administrator resolved it. Null while it is held.</summary>
    public string? ResolvedBy { get; private set; }

    /// <summary>Whether this is still waiting for somebody to decide.</summary>
    public bool IsHeld => Status == QuarantineStatus.Held;

    /// <summary>Holds a message.</summary>
    public static QuarantinedMessage Create(
        StoredMessageId messageId,
        EmailAddress? reversePath,
        IpAddressValue remoteAddress,
        FilterVerdict verdict,
        DateTimeOffset now,
        TimeSpan retention)
    {
        ArgumentNullException.ThrowIfNull(verdict);

        if (retention <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(retention), retention, "Quarantine retention must be a positive period.");
        }

        return new QuarantinedMessage(
            QuarantinedMessageId.New(),
            messageId,
            reversePath,
            remoteAddress,
            verdict.Score,
            verdict.Summarise(),
            verdict.Signals,
            now,
            now + retention);
    }

    /// <summary>Rebuilds one from its stored row.</summary>
    public static QuarantinedMessage Rehydrate(
        QuarantinedMessageId id,
        StoredMessageId messageId,
        EmailAddress? reversePath,
        IpAddressValue remoteAddress,
        double score,
        string summary,
        IReadOnlyList<FilterSignal> signals,
        DateTimeOffset quarantinedUtc,
        DateTimeOffset expiresUtc,
        QuarantineStatus status,
        DateTimeOffset? resolvedUtc,
        string? resolvedBy)
    {
        QuarantinedMessage message = new(
            id, messageId, reversePath, remoteAddress, score, summary, signals, quarantinedUtc, expiresUtc)
        {
            Status = status,
            ResolvedUtc = resolvedUtc,
            ResolvedBy = resolvedBy,
        };

        return message;
    }

    /// <summary>Marks it released by an administrator.</summary>
    /// <remarks>
    /// <b>The state changes before the delivery is attempted, not after.</b> A release that
    /// delivered first and recorded second would, if it crashed in between, leave a held row
    /// whose message is already in somebody's inbox — and the next operator to look would
    /// release it again. The other ordering's worst case is a row saying released for a message
    /// that did not arrive, which is visible and fixable.
    /// </remarks>
    public void Release(string by, DateTimeOffset now) => Resolve(QuarantineStatus.Released, by, now);

    /// <summary>Marks it discarded by an administrator.</summary>
    public void Discard(string by, DateTimeOffset now) => Resolve(QuarantineStatus.Discarded, by, now);

    private void Resolve(QuarantineStatus status, string by, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(by);

        if (Status != QuarantineStatus.Held)
        {
            // Not idempotent on purpose. Two operators resolving the same message differently is
            // a thing they need to know happened, and a silent second write would hide it —
            // along with which of the two decisions actually took effect.
            throw new InvalidOperationException(
                $"This message was already {Status.ToString().ToLowerInvariant()} at {ResolvedUtc:u}.");
        }

        Status = status;
        ResolvedBy = by;
        ResolvedUtc = now;
    }
}
