namespace MailServer.Domain.Deliverability;

/// <summary>
/// Why a sender's TLS session to this domain failed. RFC 8460 §4.3's result types.
/// </summary>
/// <remarks>
/// <b>These are the sender's findings about us, which is what makes them worth having.</b> Every
/// other TLS check in this product looks at the certificate this server presents from the inside.
/// A result type here is what a real sender's validator concluded from the outside, after a real
/// handshake — the difference between "our certificate chain looks fine locally" and "Google
/// could not build a path to it".
/// </remarks>
public enum TlsFailureResult
{
    /// <summary>A type this version does not know. §4.3 is extensible.</summary>
    Unknown = 0,

    /// <summary>The receiving MX did not offer STARTTLS.</summary>
    StartTlsNotSupported = 1,

    /// <summary>The certificate did not match the MX hostname.</summary>
    CertificateHostMismatch = 2,

    /// <summary>The certificate had expired.</summary>
    CertificateExpired = 3,

    /// <summary>No trust path could be built to the certificate.</summary>
    CertificateNotTrusted = 4,

    /// <summary>A validation failure §4.3 does not name more precisely.</summary>
    ValidationFailure = 5,

    /// <summary>A TLSA record was present and unusable.</summary>
    TlsaInvalid = 6,

    /// <summary>DNSSEC validation failed for the recipient domain.</summary>
    DnssecInvalid = 7,

    /// <summary>The sender required DANE and found none.</summary>
    DaneRequired = 8,

    /// <summary>The MTA-STS policy could not be fetched.</summary>
    StsPolicyFetchError = 9,

    /// <summary>The MTA-STS policy was fetched and would not parse.</summary>
    StsPolicyInvalid = 10,

    /// <summary>The MTA-STS policy host's certificate did not validate.</summary>
    StsWebpkiInvalid = 11,
}

/// <summary>One failure a sender grouped and counted. RFC 8460 §4.4.</summary>
/// <param name="Result">What went wrong.</param>
/// <param name="RawResultType">The type exactly as the sender wrote it, for one this version does not know.</param>
/// <param name="SendingMtaIp">The sender's address, when it gave one.</param>
/// <param name="ReceivingMxHostname">The host of ours it was talking to.</param>
/// <param name="FailedSessionCount">How many sessions failed this way.</param>
public sealed record TlsFailureDetail(
    TlsFailureResult Result,
    string? RawResultType,
    string? SendingMtaIp,
    string? ReceivingMxHostname,
    long FailedSessionCount);

/// <summary>One policy's results within a report. RFC 8460 §4.2.</summary>
/// <param name="PolicyType"><c>sts</c>, <c>tlsa</c> or <c>no-policy-found</c>.</param>
/// <param name="PolicyDomain">The domain the policy was for.</param>
/// <param name="SuccessfulSessionCount">Sessions that negotiated TLS as the policy required.</param>
/// <param name="FailedSessionCount">Sessions that did not.</param>
/// <param name="Failures">The breakdown, when the sender supplied one.</param>
public sealed record TlsReportPolicy(
    string? PolicyType,
    string? PolicyDomain,
    long SuccessfulSessionCount,
    long FailedSessionCount,
    IReadOnlyList<TlsFailureDetail> Failures);

/// <summary>
/// One RFC 8460 TLS report, as a sender sent it.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is somebody else's account of us, and it is treated as data rather than as a
/// finding.</b> A report is unauthenticated: anyone who can reach the <c>rua</c> address can
/// send one, and nothing in RFC 8460 proves the organisation named actually sent it. So a report
/// is worth reading and worth acting on when several independent senders agree, and is never on
/// its own grounds for this server to change a policy. The same caution
/// <c>docs/DMARC.md</c> applies to an inbound authentication header applies here, for the same
/// reason: it is a claim from outside.
/// </para>
/// <para>
/// <b>What makes it valuable anyway</b> is that it is the only feedback channel in the product
/// that reports a real handshake from a real sender. A certificate that validates perfectly on
/// this host and fails at Google is invisible to every other check here, and is exactly what
/// this reports.
/// </para>
/// </remarks>
/// <param name="OrganizationName">Who says they sent it. A claim.</param>
/// <param name="ContactInfo">Their contact address. A claim.</param>
/// <param name="ReportId">Their identifier for it, for de-duplication.</param>
/// <param name="StartDate">Start of the period it covers.</param>
/// <param name="EndDate">End of the period it covers.</param>
/// <param name="Policies">The per-policy results.</param>
public sealed record TlsReport(
    string? OrganizationName,
    string? ContactInfo,
    string? ReportId,
    DateTimeOffset? StartDate,
    DateTimeOffset? EndDate,
    IReadOnlyList<TlsReportPolicy> Policies)
{
    /// <summary>Sessions across every policy that negotiated TLS as required.</summary>
    public long SuccessfulSessionCount => Policies.Sum(p => p.SuccessfulSessionCount);

    /// <summary>Sessions across every policy that did not.</summary>
    public long FailedSessionCount => Policies.Sum(p => p.FailedSessionCount);

    /// <summary>Every session the report accounts for.</summary>
    public long TotalSessionCount => SuccessfulSessionCount + FailedSessionCount;

    /// <summary>
    /// The share of sessions that succeeded, or null when the report accounts for none.
    /// </summary>
    /// <remarks>
    /// Null rather than 1.0 for an empty report, because "every session succeeded" and "there
    /// were no sessions" are different things and a report covering a quiet period should not
    /// read as a clean bill of health.
    /// </remarks>
    public double? SuccessRate => TotalSessionCount == 0
        ? null
        : (double)SuccessfulSessionCount / TotalSessionCount;

    /// <summary>
    /// The failures, worst first, with each result type's sessions added up.
    /// </summary>
    /// <remarks>
    /// <b>Grouped by result type rather than listed as sent.</b> A sender reports per MX host
    /// and per sending address, so one expired certificate arrives as a dozen entries that are
    /// all the same problem. An operator needs to know which problem to fix first, and that is
    /// the one costing the most sessions.
    /// </remarks>
    public IReadOnlyList<TlsFailureSummary> FailuresByImpact() =>
    [
        .. Policies
            .SelectMany(p => p.Failures)
            .GroupBy(f => f.Result)
            .Select(g => new TlsFailureSummary(
                g.Key,
                g.Sum(f => f.FailedSessionCount),
                [.. g.Select(f => f.ReceivingMxHostname)
                    .Where(h => !string.IsNullOrWhiteSpace(h))
                    .Select(h => h!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Order(StringComparer.OrdinalIgnoreCase)]))
            .OrderByDescending(s => s.FailedSessionCount)
            .ThenBy(s => s.Result),
    ];

    /// <summary>
    /// What to tell an operator about this report in one sentence.
    /// </summary>
    /// <remarks>
    /// Written here rather than in a UI because the phrasing carries a judgement — which number
    /// leads, and whether a period with no sessions is reported as success — and two callers
    /// phrasing it independently would eventually disagree about a report they are both looking
    /// at.
    /// </remarks>
    public string Summarise()
    {
        string who = string.IsNullOrWhiteSpace(OrganizationName) ? "An unnamed sender" : OrganizationName;

        if (TotalSessionCount == 0)
        {
            return $"{who} reported no sessions for this period.";
        }

        if (FailedSessionCount == 0)
        {
            return $"{who} reported {SuccessfulSessionCount} session(s), all of which negotiated TLS successfully.";
        }

        TlsFailureSummary worst = FailuresByImpact().FirstOrDefault()
            ?? new TlsFailureSummary(TlsFailureResult.Unknown, FailedSessionCount, []);

        return
            $"{who} reported {FailedSessionCount} failed session(s) out of {TotalSessionCount}. " +
            $"The largest cause was {NameOf(worst.Result)} ({worst.FailedSessionCount} session(s)).";
    }

    /// <summary>The wire name RFC 8460 §4.3 gives a result type.</summary>
    public static string NameOf(TlsFailureResult result) => result switch
    {
        TlsFailureResult.StartTlsNotSupported => "starttls-not-supported",
        TlsFailureResult.CertificateHostMismatch => "certificate-host-mismatch",
        TlsFailureResult.CertificateExpired => "certificate-expired",
        TlsFailureResult.CertificateNotTrusted => "certificate-not-trusted",
        TlsFailureResult.ValidationFailure => "validation-failure",
        TlsFailureResult.TlsaInvalid => "tlsa-invalid",
        TlsFailureResult.DnssecInvalid => "dnssec-invalid",
        TlsFailureResult.DaneRequired => "dane-required",
        TlsFailureResult.StsPolicyFetchError => "sts-policy-fetch-error",
        TlsFailureResult.StsPolicyInvalid => "sts-policy-invalid",
        TlsFailureResult.StsWebpkiInvalid => "sts-webpki-invalid",
        _ => "unknown",
    };

    /// <summary>
    /// Reads RFC 8460 §4.3's wire name into a result type.
    /// </summary>
    /// <remarks>
    /// An unrecognised name becomes <see cref="TlsFailureResult.Unknown"/> rather than a
    /// refusal, and the raw text is kept alongside it. §4.3's list is extensible, and a report
    /// that named one new type is still telling the truth about everything else in it —
    /// discarding the whole report over a type this version has not heard of would throw away
    /// the failures it also counted.
    /// </remarks>
    public static TlsFailureResult ReadResult(string? wireName) => wireName?.Trim().ToLowerInvariant() switch
    {
        "starttls-not-supported" => TlsFailureResult.StartTlsNotSupported,
        "certificate-host-mismatch" => TlsFailureResult.CertificateHostMismatch,
        "certificate-expired" => TlsFailureResult.CertificateExpired,
        "certificate-not-trusted" => TlsFailureResult.CertificateNotTrusted,
        "validation-failure" => TlsFailureResult.ValidationFailure,
        "tlsa-invalid" => TlsFailureResult.TlsaInvalid,
        "dnssec-invalid" => TlsFailureResult.DnssecInvalid,
        "dane-required" => TlsFailureResult.DaneRequired,
        "sts-policy-fetch-error" => TlsFailureResult.StsPolicyFetchError,
        "sts-policy-invalid" => TlsFailureResult.StsPolicyInvalid,
        "sts-webpki-invalid" => TlsFailureResult.StsWebpkiInvalid,
        _ => TlsFailureResult.Unknown,
    };

    /// <summary>
    /// What a result type means for this server, and what to do about it.
    /// </summary>
    /// <remarks>
    /// <b>Several of these are not this server's fault, and saying so matters.</b>
    /// <c>dane-required</c> and <c>dnssec-invalid</c> are about a sender's policy and the
    /// recipient domain's DNSSEC, and an operator who read every result type as a defect in
    /// their own configuration would go looking for a problem that is not there.
    /// </remarks>
    public static string RemedyFor(TlsFailureResult result) => result switch
    {
        TlsFailureResult.StartTlsNotSupported =>
            "A sender reached an MX of yours that did not offer STARTTLS. Check that every host " +
            "in your MX records is this server, and that its inbound listener has a certificate.",

        TlsFailureResult.CertificateHostMismatch =>
            "The certificate presented did not cover the MX hostname the sender connected to. " +
            "Add that hostname to the certificate's subject alternative names.",

        TlsFailureResult.CertificateExpired =>
            "The certificate had expired when the sender connected. Check renewal is running; " +
            "this is the failure automatic renewal exists to prevent.",

        TlsFailureResult.CertificateNotTrusted =>
            "The sender could not build a trust path to your certificate. A self-signed " +
            "certificate produces this, and so does a missing intermediate in the chain served.",

        TlsFailureResult.ValidationFailure =>
            "The sender's validation failed for a reason it did not name more precisely. Check " +
            "the certificate and the chain served on port 25.",

        TlsFailureResult.TlsaInvalid =>
            "A TLSA record for your MX did not match the certificate served. Publish a TLSA " +
            "record matching the current key, or remove it.",

        TlsFailureResult.DnssecInvalid =>
            "The sender's DNSSEC validation of your domain failed. This is a DNS problem rather " +
            "than a mail one, and it is with your zone's signing.",

        TlsFailureResult.DaneRequired =>
            "The sender requires DANE and found no usable TLSA record. This is that sender's " +
            "policy rather than a defect here; publish TLSA records if you want their mail.",

        TlsFailureResult.StsPolicyFetchError =>
            "A sender could not fetch your MTA-STS policy. Check that mta-sts.<domain> resolves " +
            "and serves /.well-known/mta-sts.txt over HTTPS with a trusted certificate.",

        TlsFailureResult.StsPolicyInvalid =>
            "Your MTA-STS policy was fetched and would not parse. Check the served file against " +
            "RFC 8461 section 3.2.",

        TlsFailureResult.StsWebpkiInvalid =>
            "The certificate on your MTA-STS policy host did not validate. Senders discard a " +
            "policy they cannot authenticate, so the policy is having no effect.",

        _ =>
            "The sender reported a result type this version does not recognise. The raw type is " +
            "kept on the failure detail.",
    };
}

/// <summary>One result type's total impact across a report.</summary>
/// <param name="Result">What went wrong.</param>
/// <param name="FailedSessionCount">Sessions lost to it.</param>
/// <param name="ReceivingMxHostnames">The hosts of ours it happened on.</param>
public sealed record TlsFailureSummary(
    TlsFailureResult Result,
    long FailedSessionCount,
    IReadOnlyList<string> ReceivingMxHostnames);
