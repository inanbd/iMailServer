namespace MailServer.Domain.Enums;

/// <summary>Which ACME directory an account is registered against.</summary>
/// <remarks>
/// <para>
/// Staging and production are <b>separate accounts with separate keys</b>. An account
/// registered against one is meaningless to the other, which is why this is part of the
/// account's identity rather than a setting that can be flipped.
/// </para>
/// <para>
/// Persisted as an integer, so the values are fixed.
/// </para>
/// </remarks>
public enum AcmeDirectory
{
    /// <summary>
    /// Let's Encrypt staging. Issues certificates that are <b>not publicly trusted</b>.
    /// </summary>
    /// <remarks>
    /// The default for a new installation, deliberately. An operator fixing DNS while retrying
    /// against production can exhaust the five-duplicates-per-week limit in an afternoon and
    /// then wait a week; staging has far looser limits and costs nothing to get wrong.
    /// </remarks>
    LetsEncryptStaging = 0,

    /// <summary>Let's Encrypt production. Publicly trusted, and rate-limited accordingly.</summary>
    LetsEncryptProduction = 1,

    /// <summary>Another ACME CA, identified by an explicit directory URL.</summary>
    Custom = 2,
}

/// <summary>How ownership of an identifier is proved to the CA.</summary>
public enum AcmeChallengeType
{
    /// <summary>
    /// The CA fetches a token over plain HTTP from
    /// <c>http://&lt;host&gt;/.well-known/acme-challenge/&lt;token&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Needs inbound TCP 80 reachable from the Internet, which is the usual stumbling block.
    /// It cannot prove control of a wildcard.
    /// </remarks>
    Http01 = 0,

    /// <summary>
    /// A TXT record at <c>_acme-challenge.&lt;host&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Needs no inbound connectivity at all, and is the only challenge that can prove control
    /// of a wildcard identifier. The cost is that it needs DNS write access, whether through a
    /// provider API or by hand.
    /// </remarks>
    Dns01 = 1,
}

/// <summary>Where an issuance attempt has got to.</summary>
/// <remarks>
/// Mirrors RFC 8555 §7.1.6 order states, plus the two local states that exist because this
/// server persists an order across restarts and needs to distinguish "we have not started" and
/// "we gave up" from anything the CA would report.
/// </remarks>
public enum AcmeOrderStatus
{
    /// <summary>Created locally; not yet submitted to the CA.</summary>
    Created = 0,

    /// <summary>The CA has the order and is waiting for authorisations to be satisfied.</summary>
    Pending = 1,

    /// <summary>Challenges are published and the CA has been asked to validate.</summary>
    Validating = 2,

    /// <summary>Every identifier is authorised; the order is ready to finalise.</summary>
    Ready = 3,

    /// <summary>The CSR has been submitted and the CA is issuing.</summary>
    Processing = 4,

    /// <summary>The certificate has been issued and downloaded.</summary>
    Valid = 5,

    /// <summary>The CA rejected the order, or an authorisation failed.</summary>
    Invalid = 6,

    /// <summary>
    /// Abandoned locally — a pre-flight refusal, a rate-limit refusal, or an operator
    /// cancelling. Distinct from <see cref="Invalid"/> because the CA never saw it, so it
    /// consumed no quota and reflects nothing about the identifiers.
    /// </summary>
    Abandoned = 7,
}
