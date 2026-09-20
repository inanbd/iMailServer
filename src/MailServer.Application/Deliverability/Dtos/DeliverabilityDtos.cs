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
