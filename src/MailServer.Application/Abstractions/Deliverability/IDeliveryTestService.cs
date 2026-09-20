using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Deliverability;

/// <summary>
/// Sends one real message to an address an operator nominates, and records what happened.
/// </summary>
/// <remarks>
/// <para>
/// <b>The only thing in the readiness subsystem that sends mail to a third party.</b> The report
/// reads DNS, the analyser reads pasted text, the DNS wizard reads configuration; this one
/// connects to somebody else's mail server and delivers a message. That is why it is a command
/// rather than a query, and why the permission it asks for is the one that already governs
/// making this server send mail rather than the one that governs reading dashboards.
/// </para>
/// <para>
/// <b>One message per call, to one address.</b> There is no recipient list and no repeat count,
/// because the value of the feature is one conversation an operator reads — and anything that
/// took a list would be a tool for sending unsolicited mail from an authenticated session.
/// </para>
/// <para>
/// Sending to a large provider and reading the <c>Authentication-Results</c> header it adds is
/// the fastest honest answer to "is my setup correct?", because it is the receiver's own verdict
/// rather than this server's opinion of it. See <c>docs/Deliverability.md</c>.
/// </para>
/// </remarks>
public interface IDeliveryTestService
{
    /// <summary>Runs the test.</summary>
    Task<DeliveryTestOutcome> RunAsync(DeliveryTestRequest request, CancellationToken cancellationToken);
}

/// <summary>What an operator has to decide before a delivery test can run.</summary>
/// <param name="Sender">
/// The address to send from, which is also the envelope sender. Required rather than defaulted:
/// it decides which domain's SPF, DKIM and DMARC the receiver judges, so a default would test a
/// domain nobody asked about.
/// </param>
/// <param name="Recipient">The address to send to. A mailbox the operator can read.</param>
/// <param name="RequireTls">
/// When true, the attempt fails rather than sending in plaintext if STARTTLS cannot be
/// negotiated to a trusted, matching certificate. Off by default, because the ordinary question
/// is "does my mail arrive" and answering it with a policy failure the operator did not ask for
/// would hide the answer.
/// </param>
public sealed record DeliveryTestRequest(
    EmailAddress Sender,
    EmailAddress Recipient,
    bool RequireTls = false);
