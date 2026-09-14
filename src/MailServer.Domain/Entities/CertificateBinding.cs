using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// Maps a hostname and a set of services to the certificate that should be presented for them.
/// </summary>
/// <remarks>
/// <para>
/// The binding is what the TLS handshake resolves against: a client connects, offers an SNI
/// hostname, and the server needs to answer "which certificate" in microseconds. Keeping that
/// as an explicit, queryable mapping — rather than scanning every certificate's SAN list on
/// each handshake — is what makes the answer cheap and, more importantly, predictable when two
/// certificates both cover the same name.
/// </para>
/// <para>
/// A binding is a separate entity from <see cref="Certificate"/> because the lifetimes differ.
/// A certificate is replaced every 60–90 days; the binding that says "mail.example.com is
/// served by whatever currently covers it" outlives many certificates. Renewal therefore
/// repoints one binding instead of rewriting configuration.
/// </para>
/// </remarks>
public sealed class CertificateBinding : Entity<CertificateBindingId>
{
    /// <summary>Rehydration constructor for the persistence layer.</summary>
    public CertificateBinding(
        CertificateBindingId id,
        DomainName hostname,
        CertificateId certificateId,
        CertificatePurpose purpose,
        bool isDefault,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        Hostname = hostname;
        CertificateId = certificateId;
        Purpose = purpose;
        IsDefault = isDefault;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
    }

    /// <summary>The SNI hostname this binding answers for.</summary>
    public DomainName Hostname { get; }

    public CertificateId CertificateId { get; private set; }

    /// <summary>Which services present this certificate.</summary>
    public CertificatePurpose Purpose { get; private set; }

    /// <summary>
    /// True for the binding used when a client offers no SNI hostname, or one nothing matches.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A default is not optional. SNI is an extension, and a handshake that arrives without it
    /// still has to be answered — returning no certificate aborts the connection with an error
    /// the remote MTA reports as a TLS failure rather than as a configuration problem.
    /// </para>
    /// <para>
    /// Older MTAs in particular still connect without SNI, and inbound mail from them is
    /// exactly the traffic a mail server cannot afford to drop.
    /// </para>
    /// </remarks>
    public bool IsDefault { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    /// <summary>True when this binding applies to <paramref name="purpose"/>.</summary>
    public bool AppliesTo(CertificatePurpose purpose) => (Purpose & purpose) == purpose;

    /// <summary>Creates a binding.</summary>
    /// <exception cref="DomainRuleViolationException">No purpose was selected.</exception>
    public static CertificateBinding Create(
        DomainName hostname,
        CertificateId certificateId,
        CertificatePurpose purpose,
        bool isDefault,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        if (purpose == CertificatePurpose.None)
        {
            throw new DomainRuleViolationException(
                "certificate_binding.no_purpose",
                $"The binding for '{hostname}' selects no service, so it would never be " +
                "consulted during a handshake.");
        }

        if (certificateId.IsEmpty)
        {
            throw new DomainRuleViolationException(
                "certificate_binding.no_certificate",
                $"The binding for '{hostname}' does not name a certificate.");
        }

        return new CertificateBinding(
            CertificateBindingId.New(),
            hostname,
            certificateId,
            purpose,
            isDefault,
            now,
            modifiedUtc: null);
    }

    /// <summary>
    /// Points this binding at a different certificate — the operation renewal performs.
    /// </summary>
    /// <remarks>
    /// Repointing is an update to one row, which is what makes hot reload possible: the
    /// provider rebuilds its snapshot from the bindings and swaps it atomically. Nothing
    /// restarts and no listener is reconfigured.
    /// </remarks>
    public void PointAt(CertificateId certificateId, DateTimeOffset now)
    {
        if (certificateId.IsEmpty)
        {
            throw new DomainRuleViolationException(
                "certificate_binding.no_certificate",
                $"The binding for '{Hostname}' cannot be pointed at an empty certificate id.");
        }

        CertificateId = certificateId;
        ModifiedUtc = now;
    }

    public void SetPurpose(CertificatePurpose purpose, DateTimeOffset now)
    {
        if (purpose == CertificatePurpose.None)
        {
            throw new DomainRuleViolationException(
                "certificate_binding.no_purpose",
                $"The binding for '{Hostname}' would select no service.");
        }

        Purpose = purpose;
        ModifiedUtc = now;
    }

    public void SetDefault(bool isDefault, DateTimeOffset now)
    {
        IsDefault = isDefault;
        ModifiedUtc = now;
    }
}
