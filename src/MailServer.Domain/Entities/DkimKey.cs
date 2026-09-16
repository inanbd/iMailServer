using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// One DKIM signing key for one domain, at one selector, somewhere in its rotation lifecycle.
/// </summary>
/// <remarks>
/// <para>
/// <b>This aggregate holds no private key material</b> — the same separation
/// <see cref="Certificate"/> makes for TLS keys, for the same reason: a domain object carrying
/// key bytes puts them into every object graph that touches this aggregate's metadata (an admin
/// UI list, an audit record, a log line rendering it). <see cref="Id"/> is itself the lookup key
/// the private-key store (an Application-layer abstraction, added alongside the RSA signer) uses
/// to find the DPAPI-protected key material — there is exactly one key blob per
/// <see cref="DkimKey"/>, so no separate location value object is needed the way
/// <see cref="Certificate"/> needs one to distinguish several possible physical stores.
/// </para>
/// <para>
/// <see cref="PublicKeyBase64"/> is not secret — it is the exact value this key's DNS TXT record
/// publishes in its <c>p=</c> tag — so it lives on the aggregate directly, the same way a
/// certificate's SANs do.
/// </para>
/// <para>
/// <b>Status is persisted and explicitly transitioned, not derived from the clock</b> — see
/// <see cref="DkimKeyStatus"/>'s own remarks. The rotation runbook in <c>docs/DKIM.md</c> is
/// exactly the sequence <see cref="Generate"/> → <see cref="Publish"/> → <see cref="Activate"/>
/// → <see cref="Retire"/> enforces: a key cannot sign before it has been published (unpropagated
/// keys produce unverifiable signatures) and cannot be retired except from a state where it was
/// actually in use for something.
/// </para>
/// <para>
/// <b>"At most one Active key per domain" is not this aggregate's invariant to enforce.</b> It
/// spans every <see cref="DkimKey"/> row for a <see cref="DomainId"/> plus
/// <c>MailDomain.ActiveDkimSelector</c> — a cross-aggregate concern that belongs to the
/// application-layer command that coordinates both, not to one aggregate acting alone.
/// </para>
/// </remarks>
public sealed class DkimKey : AggregateRoot<DkimKeyId>
{
    /// <summary>
    /// RFC 6376 does not mandate a minimum, but 1024-bit RSA is now considered breakable by a
    /// well-resourced attacker and several major receivers (Gmail among them) reject it outright.
    /// This product never generates, and refuses to register, anything shorter.
    /// </summary>
    public const int MinimumRsaKeyLengthBits = 2048;

    /// <summary>Rehydration constructor for the persistence layer.</summary>
    /// <remarks>
    /// Null guards only, for the same reason as <see cref="Certificate"/>'s: a row already
    /// committed must remain loadable even if a later version of this code would refuse to
    /// create it fresh (a tightened minimum key length, say).
    /// </remarks>
    public DkimKey(
        DkimKeyId id,
        DomainId domainId,
        DkimSelector selector,
        DkimKeyAlgorithm algorithm,
        string publicKeyBase64,
        int keyLengthBits,
        DkimKeyStatus status,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc,
        DateTimeOffset? publishedUtc,
        DateTimeOffset? activatedUtc,
        DateTimeOffset? retiredUtc,
        DateTimeOffset? safeToDeleteAfterUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(publicKeyBase64);

        DomainId = domainId;
        Selector = selector;
        Algorithm = algorithm;
        PublicKeyBase64 = publicKeyBase64;
        KeyLengthBits = keyLengthBits;
        Status = status;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
        PublishedUtc = publishedUtc;
        ActivatedUtc = activatedUtc;
        RetiredUtc = retiredUtc;
        SafeToDeleteAfterUtc = safeToDeleteAfterUtc;
    }

    /// <summary>The domain this key signs for.</summary>
    public DomainId DomainId { get; }

    /// <summary>Locates this key's public half in DNS: <c>{Selector}._domainkey.{domain}</c>.</summary>
    public DkimSelector Selector { get; }

    public DkimKeyAlgorithm Algorithm { get; }

    /// <summary>
    /// The exact value this key's DNS TXT record publishes as its <c>p=</c> tag. Not secret.
    /// </summary>
    public string PublicKeyBase64 { get; }

    public int KeyLengthBits { get; }

    public DkimKeyStatus Status { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    public DateTimeOffset? PublishedUtc { get; private set; }

    public DateTimeOffset? ActivatedUtc { get; private set; }

    public DateTimeOffset? RetiredUtc { get; private set; }

    /// <summary>
    /// When it becomes safe to remove this key's DNS record and discard its private key — set
    /// on <see cref="Retire"/> to <c>now + graceWindow</c>. Null until then.
    /// </summary>
    public DateTimeOffset? SafeToDeleteAfterUtc { get; private set; }

    /// <summary>
    /// True once <see cref="SafeToDeleteAfterUtc"/> has passed. A cleanup job's signal to
    /// actually remove the DNS record and delete the private key — this aggregate only tracks
    /// the fact, it does not act on it.
    /// </summary>
    public bool IsSafeToDelete(DateTimeOffset now) =>
        Status == DkimKeyStatus.Retired && SafeToDeleteAfterUtc is { } t && now >= t;

    /// <summary>Records a freshly generated key pair's metadata. Status starts at <see cref="DkimKeyStatus.Generated"/>.</summary>
    /// <remarks>
    /// The key pair itself — the RSA operation, and encrypting the private half through
    /// <c>ISecretProtector</c> — happens in Infrastructure before this is called; this method
    /// only records what was generated. See the aggregate's own remarks for why the private key
    /// never passes through here.
    /// </remarks>
    /// <exception cref="DomainRuleViolationException">
    /// The algorithm is not one this product can sign with yet, the key is shorter than
    /// <see cref="MinimumRsaKeyLengthBits"/>, or the public key value is empty.
    /// </exception>
    public static DkimKey Generate(
        DomainId domainId,
        DkimSelector selector,
        DkimKeyAlgorithm algorithm,
        string publicKeyBase64,
        int keyLengthBits,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeyBase64);

        if (algorithm != DkimKeyAlgorithm.RsaSha256)
        {
            throw new DomainRuleViolationException(
                "dkim_key.algorithm_not_implemented",
                $"'{algorithm}' is a recognised DKIM algorithm but this product only signs with " +
                $"{DkimKeyAlgorithm.RsaSha256} in this milestone. Ed25519 is reserved for a " +
                "later, secondary-signature addition alongside RSA, never as a replacement for " +
                "it, per docs/DKIM.md.");
        }

        if (keyLengthBits < MinimumRsaKeyLengthBits)
        {
            throw new DomainRuleViolationException(
                "dkim_key.key_too_short",
                $"A {keyLengthBits}-bit RSA key is shorter than the {MinimumRsaKeyLengthBits}-bit " +
                "minimum this product enforces. Major receivers now reject signatures from keys " +
                "shorter than this outright, so accepting one here would produce a key that " +
                "cannot reliably sign anything.");
        }

        return new DkimKey(
            DkimKeyId.New(),
            domainId,
            selector,
            algorithm,
            publicKeyBase64,
            keyLengthBits,
            DkimKeyStatus.Generated,
            createdUtc: now,
            modifiedUtc: null,
            publishedUtc: null,
            activatedUtc: null,
            retiredUtc: null,
            safeToDeleteAfterUtc: null);
    }

    /// <summary>Records that this key's DNS TXT record has been published.</summary>
    /// <exception cref="DomainRuleViolationException">The key is not <see cref="DkimKeyStatus.Generated"/>.</exception>
    public void Publish(DateTimeOffset now)
    {
        RequireStatus(DkimKeyStatus.Generated, nameof(Publish));

        Status = DkimKeyStatus.Published;
        PublishedUtc = now;
        ModifiedUtc = now;
    }

    /// <summary>
    /// Starts signing outbound mail with this key.
    /// </summary>
    /// <remarks>
    /// Callers are expected to have already verified DNS propagation from several resolvers, per
    /// the rotation runbook in <c>docs/DKIM.md</c> — this method has no way to check that itself
    /// and does not pretend to; it only records the operator's (or automation's) decision that
    /// propagation is confirmed.
    /// </remarks>
    /// <exception cref="DomainRuleViolationException">The key is not <see cref="DkimKeyStatus.Published"/>.</exception>
    public void Activate(DateTimeOffset now)
    {
        RequireStatus(DkimKeyStatus.Published, nameof(Activate));

        Status = DkimKeyStatus.Active;
        ActivatedUtc = now;
        ModifiedUtc = now;
    }

    /// <summary>
    /// Stops this key from being used for new signatures and starts its grace window.
    /// </summary>
    /// <remarks>
    /// Never deletes anything — the DNS record and the private key both survive until
    /// <see cref="IsSafeToDelete"/> is true, because mail signed moments before retirement can
    /// still be in transit and must still verify when it arrives.
    /// </remarks>
    /// <exception cref="DomainRuleViolationException">
    /// The key has never been published (retiring it means nothing) or is already retired.
    /// </exception>
    public void Retire(TimeSpan graceWindow, DateTimeOffset now)
    {
        if (Status is not (DkimKeyStatus.Published or DkimKeyStatus.Active))
        {
            throw new DomainRuleViolationException(
                "dkim_key.invalid_transition",
                $"Cannot retire a key with status '{Status}'. Only a key that is " +
                $"{DkimKeyStatus.Published} or {DkimKeyStatus.Active} has anything to retire " +
                "from — a key still Generated was never published, and a key already Retired " +
                "has already gone through this transition.");
        }

        if (graceWindow < TimeSpan.Zero)
        {
            throw new DomainRuleViolationException(
                "dkim_key.negative_grace_window",
                "The retirement grace window cannot be negative — it exists to keep the DNS " +
                "record and private key available while mail signed moments ago is still in " +
                "transit, and a negative value would delete both before this call returns.");
        }

        Status = DkimKeyStatus.Retired;
        RetiredUtc = now;
        SafeToDeleteAfterUtc = now + graceWindow;
        ModifiedUtc = now;
    }

    private void RequireStatus(DkimKeyStatus required, string operation)
    {
        if (Status != required)
        {
            throw new DomainRuleViolationException(
                "dkim_key.invalid_transition",
                $"Cannot {operation} a key with status '{Status}'; it must be '{required}'. " +
                "DKIM key rotation is a fixed sequence (Generated -> Published -> Active -> " +
                "Retired) and this call would skip a step.");
        }
    }
}
