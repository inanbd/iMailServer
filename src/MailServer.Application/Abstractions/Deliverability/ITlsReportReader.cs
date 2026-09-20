using MailServer.Domain.Deliverability;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>
/// Reads an RFC 8460 TLS report, or explains why the text is not one.
/// </summary>
/// <remarks>
/// <para>
/// The parsing lives behind this port rather than in the Domain because RFC 8460 §3 makes the
/// report JSON, and <c>MailServer.Domain</c> carries no package reference and no dependency
/// beyond the narrow BCL surface <c>ArchitectureTests</c> allows — <c>System.Text.Json</c> is
/// not on that list. The same division <c>RawMessageHeaders</c> made for MIME: the model and the
/// rules are Domain, and whatever needs a library to decode a wire format is not.
/// </para>
/// <para>
/// <b>Reports are unauthenticated.</b> Anyone who can reach the <c>rua</c> address can send one,
/// and nothing in RFC 8460 proves the organisation named in it sent it. So everything this
/// returns is a claim from outside, to be read and corroborated rather than acted on alone —
/// see <see cref="TlsReport"/>'s own remarks.
/// </para>
/// </remarks>
public interface ITlsReportReader
{
    /// <summary>Reads a report, or says why it is not one.</summary>
    /// <param name="json">The report's JSON, already decompressed.</param>
    /// <param name="report">The report, when it parsed.</param>
    /// <param name="error">Why it did not, when it did not.</param>
    bool TryRead(string? json, out TlsReport? report, out string? error);
}
