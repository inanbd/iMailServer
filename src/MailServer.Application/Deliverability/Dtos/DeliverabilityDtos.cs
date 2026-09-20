using MailServer.Domain.Enums;

namespace MailServer.Application.Deliverability.Dtos;

/// <summary>One check's result, as the admin surface shows it.</summary>
/// <remarks>
/// A DTO rather than the domain record because this crosses a process boundary: the IPC layer
/// serialises what it is given, and a domain type carrying behaviour and value objects would
/// couple the wire format to the model's shape. The fields are the ones
/// <c>docs/Deliverability.md</c> promises — "Every check returns <c>Pass</c> / <c>Warn</c> /
/// <c>Fail</c> / <c>Inconclusive</c> <b>with evidence</b>: the record actually found, the value
/// expected, the resolver used, the TTL observed."
/// </remarks>
public sealed record DeliverabilityCheckDto
{
    public required string Id { get; init; }

    public required string Category { get; init; }

    public required string Title { get; init; }

    public required int Weight { get; init; }

    public required string Outcome { get; init; }

    public required string Detail { get; init; }

    public string? Expected { get; init; }

    public string? Found { get; init; }

    public string? Source { get; init; }

    public int? TtlSeconds { get; init; }

    /// <summary>What to do about it. Null only when the outcome is a pass or was not measured.</summary>
    public string? Remedy { get; init; }

    /// <summary>
    /// Whether an operator has to act on this check.
    /// </summary>
    /// <remarks>
    /// Carried rather than derived from <see cref="Outcome"/> by whatever is drawing the list,
    /// because the rule has one subtlety that a reader re-deriving it tends to get wrong:
    /// <c>Inconclusive</c> needs attention. It means the check could not be made, so it is not
    /// evidence that anything is correct, and grouping it with the passes would report a
    /// configuration as verified that nobody verified. See
    /// <c>DeliverabilityCheck.NeedsAttention</c>, which is where the rule lives.
    /// </remarks>
    public required bool NeedsAttention { get; init; }
}

/// <summary>One category's contribution to the score.</summary>
public sealed record DeliverabilityCategoryDto
{
    public required string Category { get; init; }

    public required int Weight { get; init; }

    /// <summary>How much of <see cref="Weight"/> was actually judged.</summary>
    public required double Judged { get; init; }

    public required double Earned { get; init; }
}

/// <summary>A readiness report.</summary>
/// <remarks>
/// <b><see cref="Readiness"/> leads, not <see cref="Score"/>.</b> The verdict is the worst
/// outcome present and never the arithmetic, because a comfortable number beside a failing check
/// is exactly the report that gets skimmed. <see cref="Score"/> is null when nothing could be
/// judged, and <see cref="Summary"/> always states the real denominator.
/// </remarks>
public sealed record DeliverabilityReportDto
{
    public required string Readiness { get; init; }

    public required double? Score { get; init; }

    public required string Summary { get; init; }

    public required DateTimeOffset ProducedAt { get; init; }

    public required IReadOnlyList<DeliverabilityCategoryDto> Categories { get; init; }

    public required IReadOnlyList<DeliverabilityCheckDto> Checks { get; init; }
}

/// <summary>One hop of a pasted message's trace.</summary>
public sealed record TraceHopDto
{
    /// <summary>The EHLO name. A claim.</summary>
    public string? GreetedName { get; init; }

    /// <summary>The name in the TCP-info comment, when the hop did a reverse lookup.</summary>
    public string? ObservedName { get; init; }

    /// <summary>
    /// The address in brackets.
    /// </summary>
    /// <remarks>
    /// The one field here the hop that wrote it could not have been lied to about: RFC 5321 §4.4
    /// annotates <c>TCP-info</c> "Information derived by server from TCP connection not client
    /// EHLO".
    /// </remarks>
    public string? ObservedAddress { get; init; }

    public string? By { get; init; }

    public string? With { get; init; }

    public string? For { get; init; }

    public DateTimeOffset? Timestamp { get; init; }

    /// <summary>Seconds since the hop below. May be negative; see the report's own remarks.</summary>
    public double? DelaySeconds { get; init; }

    /// <summary>True when a clause keyword repeats, so no reading of this hop is authoritative.</summary>
    public required bool Ambiguous { get; init; }
}

/// <summary>One signature, and what its selector turned out to publish.</summary>
public sealed record AnalysedSignatureDto
{
    public string? Selector { get; init; }

    public string? Domain { get; init; }

    public string? Algorithm { get; init; }

    public required IReadOnlyList<string> SignedHeaders { get; init; }

    public DateTimeOffset? SignedAt { get; init; }

    public DateTimeOffset? Expires { get; init; }

    public long? BodyLengthLimit { get; init; }

    /// <summary>What the selector's key lookup found.</summary>
    public required string KeyState { get; init; }

    public int? KeyBits { get; init; }

    public string? Diagnostic { get; init; }
}

/// <summary>A pasted header block, read and checked.</summary>
/// <remarks>
/// <b>There is no DKIM pass or fail here, and that is deliberate.</b> A pasted block has no body,
/// so no body hash can be checked — see <see cref="DkimCouldAlign"/>.
/// </remarks>
public sealed record HeaderAnalysisDto
{
    public string? From { get; init; }

    public string? ReturnPath { get; init; }

    public string? ReplyTo { get; init; }

    public required IReadOnlyList<string> ListUnsubscribe { get; init; }

    public required bool OneClickUnsubscribe { get; init; }

    public required IReadOnlyList<TraceHopDto> Trace { get; init; }

    public double? TotalTransitSeconds { get; init; }

    public required IReadOnlyList<AnalysedSignatureDto> Signatures { get; init; }

    /// <summary>The SPF result this server computed, not one read off the message.</summary>
    public string? Spf { get; init; }

    public string? SpfDomain { get; init; }

    public string? SpfAddress { get; init; }

    /// <summary>True when the address came from the message's own trace rather than the caller.</summary>
    public required bool SpfAddressFromTrace { get; init; }

    public string? SpfDiagnostic { get; init; }

    public string? DmarcRecord { get; init; }

    public string? DmarcPolicy { get; init; }

    public required bool SpfAligned { get; init; }

    /// <summary>
    /// A signature with a published key names a domain that aligns with <c>From</c>.
    /// </summary>
    /// <remarks>
    /// Named for what it means. Whether that signature verifies needs the body, so this is the
    /// most a header block can support.
    /// </remarks>
    public required bool DkimCouldAlign { get; init; }

    /// <summary>Everything worth pointing out, in the order it was found.</summary>
    public required IReadOnlyList<HeaderObservationDto> Observations { get; init; }
}

/// <summary>Something the analysis found worth saying.</summary>
public sealed record HeaderObservationDto
{
    public required string Id { get; init; }

    public required string Text { get; init; }
}

/// <summary>One record an operator should publish.</summary>
/// <remarks>
/// <see cref="Placement"/> is carried on every record rather than left to the caller to infer
/// from the name, because the one record that is not the operator's to publish is also the one
/// most often published into the wrong zone with no effect — see <c>docs/DNS.md</c>.
/// </remarks>
public sealed record DnsRecordDto
{
    /// <summary>The record's fully qualified owner name, without a trailing dot.</summary>
    public required string Name { get; init; }

    /// <summary>The record type, as a zone file writes it: <c>A</c>, <c>MX</c>, <c>TXT</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>
    /// The record's data.
    /// </summary>
    /// <remarks>
    /// For a <c>TXT</c> record these are the character-strings of one record and are
    /// concatenated by whoever reads it; for anything else they are separate records sharing an
    /// owner name. Rendering the two the same way would publish two addresses as one.
    /// </remarks>
    public required IReadOnlyList<string> Values { get; init; }

    /// <summary>Whose zone it belongs in: <c>OwnZone</c> or <c>IpOwner</c>.</summary>
    public required string Placement { get; init; }

    /// <summary>What breaks without it.</summary>
    public required string Purpose { get; init; }

    /// <summary>Whether it improves a working configuration rather than being required.</summary>
    public required bool IsOptional { get; init; }
}

/// <summary>Something true about a plan that no record in it discharges.</summary>
public sealed record DnsPlanCaveatDto
{
    public required string Subject { get; init; }

    public required string Text { get; init; }
}

/// <summary>Everything an operator should publish for one domain.</summary>
public sealed record DnsPlanDto
{
    /// <summary>In the order they should be worked through.</summary>
    public required IReadOnlyList<DnsRecordDto> Records { get; init; }

    /// <summary>Obligations no record in the plan discharges.</summary>
    public required IReadOnlyList<DnsPlanCaveatDto> Caveats { get; init; }

    /// <summary>
    /// The same records as zone-file lines, for an operator who would rather paste than click.
    /// </summary>
    /// <remarks>
    /// Owner names are absolute and records the operator cannot publish are commented out, so
    /// the text can be pasted into a zone whole — see <c>DnsRecordPlan.ToZoneText</c>.
    /// </remarks>
    public required string ZoneText { get; init; }
}

/// <summary>What one delivery test observed.</summary>
/// <remarks>
/// <b>The transcript carries no message content and no credential.</b> It is the command and
/// reply lines only — see <c>SmtpTranscript</c> — so an operator can paste it into a support
/// ticket without pasting somebody's mail along with it.
/// </remarks>
public sealed record DeliveryTestDto
{
    /// <summary>Whether the remote accepted the message.</summary>
    public required bool Succeeded { get; init; }

    /// <summary>The address the probe was sent to.</summary>
    public required string Recipient { get; init; }

    /// <summary>The <c>Message-ID</c> on the probe, so it can be found at the far end.</summary>
    public required string MessageId { get; init; }

    /// <summary>The exchanger chosen, or null when none could be resolved.</summary>
    public string? MxHost { get; init; }

    /// <summary>That exchanger's preference, for comparing against the DNS plan.</summary>
    public int? MxPreference { get; init; }

    /// <summary>The address actually connected to.</summary>
    public string? RemoteAddress { get; init; }

    /// <summary>The negotiated protocol, or null when the session stayed in plaintext.</summary>
    public string? TlsProtocol { get; init; }

    /// <summary>The negotiated cipher suite.</summary>
    public string? TlsCipher { get; init; }

    /// <summary>The remote's certificate subject, as presented.</summary>
    public string? PeerCertificateSubject { get; init; }

    /// <summary>The remote's certificate issuer.</summary>
    public string? PeerCertificateIssuer { get; init; }

    /// <summary>
    /// The selector the probe was signed with, or null when it was not signed — which is itself
    /// the finding, since a receiver will report an unsigned message as <c>dkim=none</c>.
    /// </summary>
    public string? DkimSelector { get; init; }

    /// <summary>The remote's final reply code.</summary>
    public int? ReplyCode { get; init; }

    /// <summary>Its enhanced status code, when it sent one.</summary>
    public string? EnhancedStatus { get; init; }

    /// <summary>Its final reply text.</summary>
    public string? ReplyText { get; init; }

    /// <summary>What went wrong, when the test could not complete.</summary>
    public string? ErrorDetail { get; init; }

    /// <summary>How long the whole attempt took.</summary>
    public required long ElapsedMilliseconds { get; init; }

    /// <summary>The conversation, command and reply.</summary>
    public required IReadOnlyList<string> Transcript { get; init; }
}

/// <summary>One result type's total impact across a TLS report.</summary>
public sealed record TlsFailureSummaryDto
{
    /// <summary>The RFC 8460 §4.3 wire name, so an operator can look it up.</summary>
    public required string ResultType { get; init; }

    public required long FailedSessionCount { get; init; }

    /// <summary>The hosts of ours it happened on.</summary>
    public required IReadOnlyList<string> ReceivingMxHostnames { get; init; }

    /// <summary>
    /// What it means here and what to do about it.
    /// </summary>
    /// <remarks>
    /// Several result types are not this server's fault — <c>dane-required</c> is the sender's
    /// policy, <c>dnssec-invalid</c> is the zone's signing — and the remedy says so, because an
    /// operator reading every entry as a defect in their own configuration would go looking for
    /// a problem that is not there.
    /// </remarks>
    public required string Remedy { get; init; }
}

/// <summary>What one submitted TLS report said.</summary>
/// <remarks>
/// <b>Everything here is a claim from outside.</b> A report is unauthenticated: anyone who can
/// reach the <c>rua</c> address can send one, and nothing in RFC 8460 proves the organisation
/// named actually sent it. It is worth reading, and worth acting on when several independent
/// senders agree; it is never on its own grounds to change a policy.
/// </remarks>
public sealed record TlsReportDto
{
    /// <summary>Who says they sent it.</summary>
    public string? OrganizationName { get; init; }

    public string? ContactInfo { get; init; }

    /// <summary>Their identifier for it, for de-duplication.</summary>
    public string? ReportId { get; init; }

    public DateTimeOffset? StartDate { get; init; }

    public DateTimeOffset? EndDate { get; init; }

    public required long SuccessfulSessionCount { get; init; }

    public required long FailedSessionCount { get; init; }

    /// <summary>
    /// The share of sessions that negotiated TLS, or null when the report covers none.
    /// </summary>
    /// <remarks>
    /// Null rather than 1.0 for an empty report: "every session succeeded" and "there were no
    /// sessions" are different, and a quiet period should not read as a clean bill of health.
    /// </remarks>
    public double? SuccessRate { get; init; }

    /// <summary>The failures, worst first, with each result type's sessions added up.</summary>
    public required IReadOnlyList<TlsFailureSummaryDto> Failures { get; init; }

    /// <summary>The one-sentence verdict.</summary>
    public required string Summary { get; init; }
}
