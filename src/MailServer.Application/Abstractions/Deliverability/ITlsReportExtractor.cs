using MailServer.Domain.Deliverability;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>
/// Pulls an RFC 8460 report out of the message a sender delivered it in.
/// </summary>
/// <remarks>
/// Separate from <see cref="ITlsReportReader"/>, which reads the JSON once it is in hand. The
/// split is worth keeping: the reader is a parser over text an operator can also paste in by
/// hand, and this is the part that deals with MIME, transfer encodings and compression — three
/// layers whose sizes a stranger chooses, and which therefore need bounding rather than
/// parsing.
/// </remarks>
public interface ITlsReportExtractor
{
    /// <summary>Finds and reads the report a message carries, if it carries one.</summary>
    /// <param name="message">The stored message, headers and all.</param>
    /// <param name="report">The report, when one was found.</param>
    /// <param name="error">Why none was, including what each candidate part failed on.</param>
    bool TryExtract(ReadOnlyMemory<byte> message, out TlsReport? report, out string? error);
}
