using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// One certificate issuance attempt, from request to outcome.
/// </summary>
/// <remarks>
/// <para>
/// Persisted rather than held in memory for the duration of a request, for three reasons that
/// each cost something real if ignored:
/// </para>
/// <list type="number">
///   <item><description><b>Rate limiting needs history.</b> The limit that actually bites is
///   five failed validations per hostname per hour, and a counter that resets on restart would
///   let a crash-loop burn an operator's quota with no record of why.</description></item>
///   <item><description><b>DNS-01 outlives a request.</b> Manual DNS-01 can take an operator an
///   hour to publish a record. The order has to survive that, and a service restart in the
///   middle of it.</description></item>
///   <item><description><b>Failures need explaining.</b> "Issuance failed" a week ago is
///   unanswerable without the identifiers, the challenge type and the CA's own error
///   text.</description></item>
/// </list>
/// <para>
/// The order holds no key material. The certificate's private key is generated at finalisation
/// and goes straight to the certificate store.
/// </para>
/// </remarks>
public sealed class AcmeOrder : AggregateRoot<AcmeOrderId>
{
    private readonly List<DomainName> _identifiers;

    /// <summary>Rehydration constructor for the persistence layer.</summary>
    public AcmeOrder(
        AcmeOrderId id,
        AcmeAccountId accountId,
        IEnumerable<DomainName> identifiers,
        AcmeChallengeType challengeType,
        AcmeOrderStatus status,
        string? orderUrl,
        CertificateId? issuedCertificateId,
        string? lastError,
        int attemptCount,
        DateTimeOffset? lastAttemptUtc,
        DateTimeOffset? completedUtc,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        AccountId = accountId;
        _identifiers = [.. identifiers];
        ChallengeType = challengeType;
        Status = status;
        OrderUrl = orderUrl;
        IssuedCertificateId = issuedCertificateId;
        LastError = lastError;
        AttemptCount = attemptCount;
        LastAttemptUtc = lastAttemptUtc;
        CompletedUtc = completedUtc;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
    }

    public AcmeAccountId AccountId { get; }

    /// <summary>The hostnames this order covers.</summary>
    public IReadOnlyList<DomainName> Identifiers => _identifiers;

    public AcmeChallengeType ChallengeType { get; }

    public AcmeOrderStatus Status { get; private set; }

    /// <summary>The order's URL at the CA. Null until submitted.</summary>
    public string? OrderUrl { get; private set; }

    /// <summary>The certificate this order produced, once it succeeded.</summary>
    public CertificateId? IssuedCertificateId { get; private set; }

    /// <summary>
    /// The CA's error, or a local refusal, in terms an operator can act on.
    /// </summary>
    /// <remarks>
    /// Never an exception dump. ACME errors carry a structured problem document whose detail
    /// field is written for humans; that is what belongs here. A stack trace would bury the one
    /// useful sentence and risks carrying request content into a column that gets rendered.
    /// </remarks>
    public string? LastError { get; private set; }

    /// <summary>How many times issuance has been attempted for this order.</summary>
    public int AttemptCount { get; private set; }

    public DateTimeOffset? LastAttemptUtc { get; private set; }

    public DateTimeOffset? CompletedUtc { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    /// <summary>True when this order is finished, successfully or not.</summary>
    public bool IsTerminal =>
        Status is AcmeOrderStatus.Valid or AcmeOrderStatus.Invalid or AcmeOrderStatus.Abandoned;

    /// <summary>
    /// True when this attempt reached the CA and could have consumed quota.
    /// </summary>
    /// <remarks>
    /// The distinction the rate limiter depends on. An order refused locally by pre-flight or
    /// by the limiter itself never reached the CA, so counting it would make the server
    /// progressively more reluctant to do something that has cost nothing.
    /// </remarks>
    public bool ConsumedCaQuota => OrderUrl is not null;

    /// <summary>
    /// A stable key for the identifier set, for the duplicate-certificate limit.
    /// </summary>
    /// <remarks>
    /// Sorted, so that ordering the hostnames differently does not look like a different
    /// certificate — the CA's duplicate limit is on the identifier <i>set</i>, and a server
    /// that thought otherwise would submit five "different" orders and hit the limit anyway.
    /// </remarks>
    public string IdentifierSetKey => BuildIdentifierSetKey(_identifiers);

    /// <summary>Builds the same key from a candidate list, before an order exists.</summary>
    public static string BuildIdentifierSetKey(IEnumerable<DomainName> identifiers)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        return string.Join(
            ',',
            identifiers.Select(static i => i.Value).OrderBy(static v => v, StringComparer.Ordinal));
    }

    /// <summary>Creates a local order, not yet submitted.</summary>
    public static AcmeOrder Create(
        AcmeAccountId accountId,
        IEnumerable<DomainName> identifiers,
        AcmeChallengeType challengeType,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(identifiers);

        List<DomainName> list = [.. identifiers];

        if (list.Count == 0)
        {
            throw new DomainRuleViolationException(
                "acme.order.no_identifiers",
                "An order must cover at least one hostname.");
        }

        if (accountId.IsEmpty)
        {
            throw new DomainRuleViolationException(
                "acme.order.no_account",
                "An order must be placed against a registered ACME account.");
        }

        return new AcmeOrder(
            AcmeOrderId.New(),
            accountId,
            list,
            challengeType,
            AcmeOrderStatus.Created,
            orderUrl: null,
            issuedCertificateId: null,
            lastError: null,
            attemptCount: 0,
            lastAttemptUtc: null,
            completedUtc: null,
            createdUtc: now,
            modifiedUtc: null);
    }

    /// <summary>Records that the CA has accepted the order.</summary>
    public void MarkSubmitted(string orderUrl, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orderUrl);

        OrderUrl = orderUrl;
        Status = AcmeOrderStatus.Pending;
        AttemptCount++;
        LastAttemptUtc = now;
        ModifiedUtc = now;
    }

    /// <summary>Advances the order's state as reported by the CA.</summary>
    /// <exception cref="DomainRuleViolationException">The order has already finished.</exception>
    public void Advance(AcmeOrderStatus status, DateTimeOffset now)
    {
        if (IsTerminal)
        {
            throw new DomainRuleViolationException(
                "acme.order.already_terminal",
                $"Order {Id} is already {Status} and cannot be advanced. Issuance attempts are " +
                "immutable once finished, so the rate-limit history they form stays accurate.");
        }

        Status = status;
        ModifiedUtc = now;
    }

    /// <summary>Records a successful issuance.</summary>
    public void MarkIssued(CertificateId certificateId, DateTimeOffset now)
    {
        Status = AcmeOrderStatus.Valid;
        IssuedCertificateId = certificateId;
        LastError = null;
        CompletedUtc = now;
        ModifiedUtc = now;
    }

    /// <summary>Records a failure reported by the CA.</summary>
    /// <remarks>
    /// Distinct from <see cref="Abandon"/>: this one reached the CA and consumed a
    /// failed-validation slot, which is what the rate limiter must count.
    /// </remarks>
    public void MarkFailed(string reason, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        Status = AcmeOrderStatus.Invalid;
        LastError = reason;
        CompletedUtc = now;
        ModifiedUtc = now;
    }

    /// <summary>
    /// Records a local refusal — pre-flight, rate limiting, or an operator cancelling.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="MarkFailed"/> because the CA never saw it. It consumed no
    /// quota and says nothing about the identifiers, so the rate limiter must not count it;
    /// treating the two alike would make a server that refused an order locally progressively
    /// more reluctant to do the thing that cost nothing.
    /// </remarks>
    public void Abandon(string reason, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        Status = AcmeOrderStatus.Abandoned;
        LastError = reason;
        CompletedUtc = now;
        ModifiedUtc = now;
    }
}
