using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// A TLS certificate known to this server: its identity, its coverage, where it came from and
/// where its private key lives.
/// </summary>
/// <remarks>
/// <para>
/// <b>This aggregate holds no key material and no certificate bytes.</b> It is the metadata
/// the server reasons about — subject, issuer, SANs, validity window, source, thumbprint — and
/// a <i>reference</i> to where the real certificate is kept. The bytes live in the Windows
/// certificate store or in a DPAPI-protected PFX; they are loaded when a handshake needs them
/// and are never held in the domain model.
/// </para>
/// <para>
/// That separation is the point. A domain object carrying an <c>X509Certificate2</c> would put
/// a private key into every object graph that touches certificate metadata — the admin UI's
/// list view, an audit record, a log line rendering the aggregate. Rule 105's "no private keys
/// in logs" is far easier to guarantee when the key is not in the object in the first place.
/// </para>
/// <para>
/// The validity window is stored rather than re-parsed from the certificate on every query.
/// The dashboard asks "what expires soonest" constantly, and answering it by loading and
/// parsing every certificate in the store would make a cheap question expensive.
/// </para>
/// </remarks>
public sealed class Certificate : AggregateRoot<CertificateId>
{
    private readonly List<CertificateSubjectName> _subjectAlternativeNames;

    /// <summary>
    /// Rehydration constructor for the persistence layer.
    /// </summary>
    /// <remarks>
    /// Null guards only, for the same reason as <see cref="MailDomain"/>: a row already in the
    /// database is already committed, and re-validating it here would make a certificate that
    /// has since expired — or one whose SAN list a later version parses differently —
    /// unloadable. An unloadable certificate row is an outage; a certificate the model reports
    /// as <see cref="CertificateStatus.Expired"/> is a dashboard entry.
    /// </remarks>
    public Certificate(
        CertificateId id,
        CertificateThumbprint thumbprint,
        string subject,
        string issuer,
        string serialNumber,
        IEnumerable<CertificateSubjectName> subjectAlternativeNames,
        CertificateSource source,
        CertificateKeyLocation keyLocation,
        DateTimeOffset notBeforeUtc,
        DateTimeOffset notAfterUtc,
        bool autoRenew,
        bool isRenewing,
        DateTimeOffset? lastRenewalUtc,
        string? lastRenewalError,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(serialNumber);
        ArgumentNullException.ThrowIfNull(subjectAlternativeNames);
        ArgumentNullException.ThrowIfNull(keyLocation);

        Thumbprint = thumbprint;
        Subject = subject;
        Issuer = issuer;
        SerialNumber = serialNumber;
        _subjectAlternativeNames = [.. subjectAlternativeNames];
        Source = source;
        KeyLocation = keyLocation;
        NotBeforeUtc = notBeforeUtc;
        NotAfterUtc = notAfterUtc;
        AutoRenew = autoRenew;
        IsRenewing = isRenewing;
        LastRenewalUtc = lastRenewalUtc;
        LastRenewalError = lastRenewalError;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
    }

    /// <summary>The certificate's thumbprint: its identity everywhere outside this database.</summary>
    public CertificateThumbprint Thumbprint { get; }

    /// <summary>Distinguished name of the subject, as issued.</summary>
    public string Subject { get; }

    /// <summary>Distinguished name of the issuer. Equal to <see cref="Subject"/> when self-signed.</summary>
    public string Issuer { get; }

    /// <summary>Serial number in hexadecimal, for correlating with a CA's records.</summary>
    public string SerialNumber { get; }

    /// <summary>
    /// Every hostname this certificate covers, from its subjectAltName extension.
    /// </summary>
    /// <remarks>
    /// The common name is deliberately not consulted for coverage. RFC 6125 deprecated CN-based
    /// name matching and every current client ignores it, so a certificate whose hostname
    /// appears only in the CN does not in practice cover that hostname. Treating it as covered
    /// here would mean the server reported Healthy while clients showed warnings.
    /// </remarks>
    public IReadOnlyList<CertificateSubjectName> SubjectAlternativeNames => _subjectAlternativeNames;

    public CertificateSource Source { get; }

    /// <summary>Where the certificate and its private key actually live.</summary>
    public CertificateKeyLocation KeyLocation { get; private set; }

    public DateTimeOffset NotBeforeUtc { get; }

    public DateTimeOffset NotAfterUtc { get; }

    /// <summary>
    /// Whether the lifecycle service should renew this automatically.
    /// </summary>
    /// <remarks>
    /// Always false for an imported PFX and for a Windows-store certificate: this server did
    /// not obtain those and has no means to obtain a replacement. Offering auto-renew for them
    /// would be a switch that silently does nothing, which is worse than no switch.
    /// </remarks>
    public bool AutoRenew { get; private set; }

    /// <summary>True while a renewal attempt is in flight.</summary>
    public bool IsRenewing { get; private set; }

    public DateTimeOffset? LastRenewalUtc { get; private set; }

    /// <summary>
    /// Why the last renewal attempt failed, or null if the last attempt succeeded.
    /// </summary>
    /// <remarks>
    /// Kept on the aggregate so the UI can show it next to the certificate rather than asking
    /// the operator to correlate a dashboard warning with a log search. Never contains key
    /// material: the callers write a description, not an exception dump.
    /// </remarks>
    public string? LastRenewalError { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    /// <summary>True when this certificate is not publicly trusted and will cause client warnings.</summary>
    public bool IsSelfSigned => Source == CertificateSource.SelfSigned;

    /// <summary>Whole days until expiry; negative once expired.</summary>
    public int DaysRemaining(DateTimeOffset now) =>
        (int)Math.Floor((NotAfterUtc - now).TotalDays);

    /// <summary>True when <paramref name="now"/> lies inside the validity window.</summary>
    public bool IsCurrentlyValid(DateTimeOffset now) =>
        now >= NotBeforeUtc && now < NotAfterUtc;

    /// <summary>
    /// True when any subjectAltName entry covers <paramref name="hostname"/>.
    /// </summary>
    /// <remarks>
    /// The common name is deliberately not consulted. RFC 6125 deprecated CN-based name
    /// matching and current clients ignore it, so treating a CN-only hostname as covered would
    /// make this server report Healthy while clients showed warnings. Wildcard semantics live
    /// in <see cref="CertificateSubjectName.Matches"/>.
    /// </remarks>
    public bool Covers(DomainName hostname)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        foreach (CertificateSubjectName san in _subjectAlternativeNames)
        {
            if (san.Matches(hostname))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Derives the status from the certificate, the clock, and the hostnames it is bound to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Order matters, and it runs worst-first. An expired certificate that also fails to cover
    /// its hostname should report <see cref="CertificateStatus.Expired"/>, because that is the
    /// fault to fix; reporting the name mismatch would send the operator to re-issue with
    /// different SANs and discover the expiry afterwards.
    /// </para>
    /// <para>
    /// <paramref name="chainIsTrusted"/> is supplied by the caller rather than computed here.
    /// Chain building needs the platform trust store and the network, neither of which belongs
    /// in a domain model with no dependencies outside the BCL.
    /// </para>
    /// </remarks>
    public CertificateStatus GetStatus(
        DateTimeOffset now,
        CertificateRenewalPolicy policy,
        IReadOnlyCollection<DomainName>? boundHostnames = null,
        bool chainIsTrusted = true)
    {
        ArgumentNullException.ThrowIfNull(policy);

        if (now >= NotAfterUtc)
        {
            return CertificateStatus.Expired;
        }

        if (now < NotBeforeUtc)
        {
            return CertificateStatus.Invalid;
        }

        if (boundHostnames is not null)
        {
            foreach (DomainName hostname in boundHostnames)
            {
                if (!Covers(hostname))
                {
                    return CertificateStatus.HostnameMismatch;
                }
            }
        }

        if (!chainIsTrusted)
        {
            return CertificateStatus.Untrusted;
        }

        if (IsRenewing)
        {
            return CertificateStatus.Renewing;
        }

        return DaysRemaining(now) <= policy.RenewalWindowDays
            ? CertificateStatus.ExpiringSoon
            : CertificateStatus.Healthy;
    }

    /// <summary>Registers metadata for a newly obtained certificate.</summary>
    /// <exception cref="DomainRuleViolationException">
    /// The certificate covers no hostnames, or its validity window is inverted.
    /// </exception>
    public static Certificate Register(
        CertificateThumbprint thumbprint,
        string subject,
        string issuer,
        string serialNumber,
        IEnumerable<CertificateSubjectName> subjectAlternativeNames,
        CertificateSource source,
        CertificateKeyLocation keyLocation,
        DateTimeOffset notBeforeUtc,
        DateTimeOffset notAfterUtc,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentNullException.ThrowIfNull(subjectAlternativeNames);
        ArgumentNullException.ThrowIfNull(keyLocation);

        List<CertificateSubjectName> sans = [.. subjectAlternativeNames];

        if (sans.Count == 0)
        {
            throw new DomainRuleViolationException(
                "certificate.no_subject_alternative_names",
                "A certificate with no subjectAltName entries covers no hostname that any " +
                "current client will accept, so it cannot be used for TLS. RFC 6125 " +
                "deprecated common-name matching and clients no longer fall back to it.");
        }

        if (notAfterUtc <= notBeforeUtc)
        {
            throw new DomainRuleViolationException(
                "certificate.validity_window_inverted",
                "The certificate's notAfter is not after its notBefore, so it is valid for no " +
                "period at all.");
        }

        return new Certificate(
            CertificateId.New(),
            thumbprint,
            subject,
            issuer,
            serialNumber ?? string.Empty,
            sans,
            source,
            keyLocation,
            notBeforeUtc,
            notAfterUtc,
            // Only sources this server can actually re-obtain may auto-renew. See AutoRenew.
            autoRenew: source == CertificateSource.Acme,
            isRenewing: false,
            lastRenewalUtc: null,
            lastRenewalError: null,
            createdUtc: now,
            modifiedUtc: null);
    }

    /// <summary>Turns automatic renewal on or off.</summary>
    /// <exception cref="DomainRuleViolationException">
    /// The source is one this server cannot renew on its own.
    /// </exception>
    public void SetAutoRenew(bool enabled, DateTimeOffset now)
    {
        if (enabled && Source is not CertificateSource.Acme)
        {
            throw new DomainRuleViolationException(
                "certificate.auto_renew.unsupported_source",
                $"A certificate from '{Source}' cannot be renewed automatically, because this " +
                "server did not obtain it and has no way to obtain a replacement. Enabling " +
                "the setting would produce a switch that silently does nothing while the " +
                "certificate expires.");
        }

        AutoRenew = enabled;
        ModifiedUtc = now;
    }

    /// <summary>Marks a renewal attempt as started.</summary>
    public void BeginRenewal(DateTimeOffset now)
    {
        IsRenewing = true;
        ModifiedUtc = now;
    }

    /// <summary>Records a successful renewal.</summary>
    /// <remarks>
    /// The replacement certificate is a <i>new</i> aggregate with its own thumbprint and
    /// validity window; this only closes out the attempt on the outgoing one. Mutating the
    /// thumbprint in place would make the audit trail unable to say which certificate was
    /// actually serving at a given time.
    /// </remarks>
    public void CompleteRenewal(DateTimeOffset now)
    {
        IsRenewing = false;
        LastRenewalUtc = now;
        LastRenewalError = null;
        ModifiedUtc = now;
    }

    /// <summary>
    /// Records a failed renewal attempt. The certificate is retained exactly as it was.
    /// </summary>
    /// <remarks>
    /// There is deliberately no method to replace a failed certificate with a self-signed one.
    /// See <see cref="CertificateRenewalPolicy.MayDowngradeToSelfSignedOnRenewalFailure"/> —
    /// the absence is the policy.
    /// </remarks>
    public void FailRenewal(string reason, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        IsRenewing = false;
        LastRenewalError = reason;
        ModifiedUtc = now;
    }

    /// <summary>Points the aggregate at a new physical location for the same certificate.</summary>
    public void RelocateKey(CertificateKeyLocation location, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(location);

        KeyLocation = location;
        ModifiedUtc = now;
    }
}
