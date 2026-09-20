using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>What one delivery test observed, whether it succeeded or not.</summary>
/// <param name="Succeeded">Whether the remote accepted the message.</param>
/// <param name="Recipient">The address the probe was sent to.</param>
/// <param name="MessageId">The <c>Message-ID</c> put on the probe, so it can be found at the far end.</param>
/// <param name="MxHost">The exchanger chosen, or null when none could be resolved.</param>
/// <param name="MxPreference">That exchanger's preference, for comparing with the DNS plan.</param>
/// <param name="RemoteAddress">The address actually connected to.</param>
/// <param name="TlsProtocol">The negotiated protocol, or null when the session stayed in plaintext.</param>
/// <param name="TlsCipher">The negotiated cipher suite.</param>
/// <param name="PeerCertificateSubject">The remote's certificate subject, as presented.</param>
/// <param name="PeerCertificateIssuer">The remote's certificate issuer.</param>
/// <param name="DkimSelector">The selector the probe was signed with, or null when it was not signed.</param>
/// <param name="ReplyCode">The remote's final reply code.</param>
/// <param name="EnhancedStatus">Its enhanced status code, when it sent one.</param>
/// <param name="ReplyText">Its final reply text.</param>
/// <param name="ErrorDetail">What went wrong, when the test could not complete.</param>
/// <param name="Elapsed">How long the whole attempt took.</param>
/// <param name="Transcript">The conversation, command and reply — never message content.</param>
public sealed record DeliveryTestResult(
    bool Succeeded,
    EmailAddress Recipient,
    string MessageId,
    string? MxHost,
    int? MxPreference,
    IpAddressValue? RemoteAddress,
    string? TlsProtocol,
    string? TlsCipher,
    string? PeerCertificateSubject,
    string? PeerCertificateIssuer,
    string? DkimSelector,
    int? ReplyCode,
    string? EnhancedStatus,
    string? ReplyText,
    string? ErrorDetail,
    TimeSpan Elapsed,
    IReadOnlyList<string> Transcript);

/// <summary>
/// Sends one real message to an address an operator nominates, and records what happened.
/// </summary>
/// <remarks>
/// <para>
/// <b>The one check in this product whose answer comes from somebody else.</b> Every other
/// deliverability check reports this server's opinion of its own configuration: the DNS it
/// published, the certificate it presents, the policy it serves. Those can all be perfect while
/// mail still fails, because what decides that is a receiver this server does not control.
/// Sending to a real mailbox and reading the <c>Authentication-Results</c> header the receiver
/// adds is the receiver's own verdict, which is worth more than any number of local checks.
/// </para>
/// <para>
/// <b>It goes down the production path, deliberately.</b> The same outbound client, the same MX
/// resolution, the same DKIM signing as ordinary mail — because a test that used a parallel code
/// path would prove that the parallel path works. What it adds is a transcript and a stopwatch.
/// </para>
/// <para>
/// <b>Sending real mail is an outward-facing act.</b> One call puts one message in somebody's
/// mailbox from this server's IP, and a caller looping it is indistinguishable from a
/// mail-bombing tool at the receiving end. Rate limiting belongs at the call site — see the IPC
/// command — not here.
/// </para>
/// </remarks>
public interface IDeliveryTestService
{
    /// <summary>Sends one probe and reports the whole conversation.</summary>
    /// <param name="from">The address to send from; must be one this server is authoritative for.</param>
    /// <param name="to">The address to send to.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task<DeliveryTestResult> RunAsync(
        EmailAddress from,
        EmailAddress to,
        CancellationToken cancellationToken);
}
