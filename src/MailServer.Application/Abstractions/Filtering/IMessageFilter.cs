using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Filtering;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Filtering;

/// <summary>What the filter is asked about.</summary>
/// <param name="Message">The message, already committed to the store.</param>
/// <param name="ReversePath">The envelope sender, or null for the null reverse path.</param>
/// <param name="RemoteAddress">The peer that delivered it.</param>
/// <param name="RecipientCount">How many recipients the envelope carried.</param>
/// <param name="Authentication">What SPF, DKIM and DMARC concluded.</param>
/// <param name="ReceivedUtc">When this server accepted it.</param>
public sealed record MessageFilterRequest(
    StoredMessage Message,
    EmailAddress? ReversePath,
    IpAddressValue RemoteAddress,
    int RecipientCount,
    MessageAuthenticationFacts Authentication,
    DateTimeOffset ReceivedUtc);

/// <summary>
/// The facts every check shares, assembled once per message.
/// </summary>
/// <remarks>
/// <b>Parsed once, because each parse is work a stranger asked for.</b> Five checks that each
/// read the headers and walked the MIME tree would multiply the per-message cost of a hostile
/// message by five, on the delivery path — and would give two checks different answers if the
/// parsers ever disagreed.
/// </remarks>
/// <param name="Request">What was asked.</param>
/// <param name="Headers">
/// The header block, or null when the message has no locatable header/body boundary. Null is a
/// finding rather than a reason to skip: see <c>MessageFilterPipeline</c>.
/// </param>
/// <param name="Attachments">Every part that named itself or declared a disposition.</param>
/// <param name="ContentWasRead">
/// Whether the body was actually available. False when the message was larger than the filter
/// will read, which every check that needs the body must report rather than pass silently.
/// </param>
/// <param name="OpenContentAsync">
/// Opens the stored message for a check that needs the bytes themselves. Each call yields a
/// fresh stream the caller disposes.
/// </param>
public sealed record MessageFilterContext(
    MessageFilterRequest Request,
    RawMessageHeaders? Headers,
    IReadOnlyList<AttachmentDescriptor> Attachments,
    bool ContentWasRead,
    Func<CancellationToken, ValueTask<Stream>> OpenContentAsync)
{
    /// <summary>The envelope facts, as the heuristics want them.</summary>
    public EnvelopeFacts Envelope => new(Request.RecipientCount, Request.ReceivedUtc);
}

/// <summary>What one check concluded.</summary>
/// <param name="Signals">Its signals, which may be empty.</param>
/// <param name="Floor">
/// An action the score must not soften. <see cref="FilterAction.Accept"/> — the default — means
/// the check is content to be weighed against everything else.
/// </param>
public sealed record SpamCheckResult(
    IReadOnlyList<FilterSignal> Signals,
    FilterAction Floor = FilterAction.Accept)
{
    /// <summary>A check that found nothing.</summary>
    public static SpamCheckResult Nothing { get; } = new([]);

    /// <summary>A check that found things, none of them decisive on its own.</summary>
    public static SpamCheckResult Weigh(IReadOnlyList<FilterSignal> signals) => new(signals);
}

/// <summary>
/// One question the filter asks about a message.
/// </summary>
/// <remarks>
/// <para>
/// <b>A check never decides; it reports.</b> It returns signals, and the policy turns the sum
/// into an action. The one exception is <see cref="SpamCheckResult.Floor"/>, for the two
/// conclusions no weighting should be able to overturn — malware found, and an attachment the
/// operator blocked outright.
/// </para>
/// <para>
/// <b>A check that throws is a bug in the check, not a verdict about the message.</b> The
/// pipeline catches, logs and carries on without it. The alternative is that one malformed
/// message plus one unhandled edge case stops mail flowing, which is a worse failure than the
/// spam the check would have caught.
/// </para>
/// </remarks>
public interface ISpamCheck
{
    /// <summary>A stable name, for logs and for turning the check off.</summary>
    string Name { get; }

    /// <summary>Whether this check needs the message body.</summary>
    /// <remarks>
    /// Checks that do not are run even on a message too large to read, so an oversized message
    /// still gets its headers and its authentication results weighed.
    /// </remarks>
    bool NeedsContent { get; }

    /// <summary>Inspects the message.</summary>
    Task<SpamCheckResult> InspectAsync(MessageFilterContext context, CancellationToken cancellationToken);
}

/// <summary>Runs the checks and applies the policy.</summary>
public interface IMessageFilter
{
    /// <summary>Whether filtering is switched on at all.</summary>
    bool IsEnabled { get; }

    /// <summary>Reaches a verdict about one message.</summary>
    Task<FilterVerdict> EvaluateAsync(MessageFilterRequest request, CancellationToken cancellationToken);
}
