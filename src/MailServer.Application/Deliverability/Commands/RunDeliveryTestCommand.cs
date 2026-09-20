using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Exceptions;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Deliverability.Commands;

/// <summary>
/// Sends one real message to an address the operator nominates, and returns the conversation.
/// </summary>
/// <remarks>
/// <para>
/// <b>A command, not a query, and the only thing in this subsystem that is.</b> The report reads
/// DNS, the analyser reads pasted text and the DNS wizard reads configuration; this one connects
/// to somebody else's mail server and delivers a message. Calling it a query would put an
/// outward-facing side effect behind the word "read".
/// </para>
/// <para>
/// <b><see cref="AdminPermission.ManageQueue"/> rather than
/// <see cref="AdminPermission.ViewServerState"/>.</b> Its siblings ask for the latter because
/// they only look; this one makes the server send mail to a third party, and the permission that
/// already governs exactly that power is the queue one — retrying a queued item causes a send in
/// the same way. Asking for the dashboard permission instead would let anyone who can read a
/// graph send mail from the operator's domain, and adding a permission of its own would say this
/// is a power the existing set does not already cover. It is.
/// </para>
/// <para>
/// <b>One message, one recipient, no repeat count.</b> Anything that took a list would be a tool
/// for sending unsolicited mail from an authenticated session, and the feature's value is one
/// conversation an operator reads.
/// </para>
/// <para>
/// Not <see cref="ITransactionalRequest"/>: it writes one message to the store and removes it
/// again, and the thing in between is a network conversation with a stranger. Holding a database
/// transaction open across that would pin a connection for as long as a remote MX cares to take.
/// </para>
/// </remarks>
public sealed record RunDeliveryTestCommand : ICommand<DeliveryTestDto>, IAuthorizedRequest
{
    /// <summary>
    /// The address to send from, which is also the envelope sender.
    /// </summary>
    /// <remarks>
    /// Required rather than defaulted: it decides which domain's SPF, DKIM and DMARC the
    /// receiver is about to judge, so a default would test a domain nobody asked about.
    /// </remarks>
    public required string Sender { get; init; }

    /// <summary>The address to send to. A mailbox the operator can read.</summary>
    public required string Recipient { get; init; }

    /// <summary>
    /// Fail rather than send in plaintext if STARTTLS cannot reach a trusted, matching
    /// certificate.
    /// </summary>
    /// <remarks>
    /// Off by default, because the ordinary question is "does my mail arrive" and answering it
    /// with a policy failure the operator did not ask for would hide the answer.
    /// </remarks>
    public bool RequireTls { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageQueue;
}

internal sealed class RunDeliveryTestCommandHandler(IDeliveryTestService tests)
    : IRequestHandler<RunDeliveryTestCommand, DeliveryTestDto>
{
    public async Task<DeliveryTestDto> Handle(
        RunDeliveryTestCommand request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Dictionary<string, string[]> failures = [];

        if (!EmailAddress.TryParse(request.Sender, out EmailAddress? sender))
        {
            failures[nameof(request.Sender)] = [$"'{request.Sender}' is not an email address."];
        }

        if (!EmailAddress.TryParse(request.Recipient, out EmailAddress? recipient))
        {
            failures[nameof(request.Recipient)] = [$"'{request.Recipient}' is not an email address."];
        }

        if (failures.Count > 0)
        {
            throw new ValidationFailedException(failures);
        }

        DeliveryTestOutcome outcome = await tests
            .RunAsync(
                new DeliveryTestRequest(sender!, recipient!, request.RequireTls),
                cancellationToken)
            .ConfigureAwait(false);

        return Map(outcome);
    }

    internal static DeliveryTestDto Map(DeliveryTestOutcome outcome) => new()
    {
        Outcome = outcome.Outcome.ToString(),
        Sender = outcome.Sender.Value,
        Recipient = outcome.Recipient.Value,
        MessageId = outcome.MessageId,
        Candidates = [.. outcome.Candidates.Select(h => new MailExchangerDto
        {
            Hostname = h.Hostname,
            Preference = h.Preference,
        })],
        Attempts = [.. outcome.Attempts.Select(Map)],
        LatencyMilliseconds = outcome.Latency?.TotalMilliseconds,
        Diagnostic = outcome.Diagnostic,
    };

    private static DeliveryAttemptDto Map(DeliveryTestAttempt attempt) => new()
    {
        Hostname = attempt.Host.Hostname,
        Preference = attempt.Host.Preference,
        Outcome = attempt.Outcome.ToString(),
        Diagnostic = attempt.Diagnostic,
        Banner = attempt.Transcript.Banner,
        Capabilities = attempt.Transcript.Capabilities,
        LastStage = attempt.Transcript.LastStage?.ToString(),
        FinalReplyCode = attempt.Transcript.FinalReply?.Code,
        FinalReplyText = attempt.Transcript.FinalReply?.Text,
        Steps = [.. attempt.Transcript.Timed.Select(t => new DeliveryStepDto
        {
            Stage = t.Step.Stage.ToString(),
            Sent = t.Step.Sent,
            ReplyCode = t.Step.Reply?.Code,
            ReplyText = t.Step.Reply?.Text,
            ReplyContinuations = t.Step.Reply?.ContinuationLines ?? [],
            Detail = t.Step.Detail,
            ElapsedMilliseconds = t.Elapsed.TotalMilliseconds,
        })],
        Transcript = attempt.Transcript.Render(),
    };
}
