using MailServer.Application.Abstractions.Filtering;
using MailServer.Domain.Filtering;

namespace MailServer.Infrastructure.Filtering.Checks;

/// <summary>
/// Refuses attachments a recipient's desktop would run.
/// </summary>
/// <remarks>
/// <para>
/// <b>Quarantines rather than scores.</b> An executable in the mail is not evidence about how
/// spam-like a message is; it is a thing that should not reach a mailbox. Expressing it as a
/// large weight would work until an operator tuned a threshold, and then it would silently
/// stop working.
/// </para>
/// <para>
/// <b>A message too large to read is reported, never passed.</b> The alternative is that the
/// way past the attachment policy is to make the message big, which is the one bypass an
/// attacker does not have to be clever to find.
/// </para>
/// </remarks>
public sealed class AttachmentSpamCheck(AttachmentPolicy policy) : ISpamCheck
{
    /// <summary>What a blocked attachment contributes, alongside the floor it sets.</summary>
    /// <remarks>
    /// A score as well as a floor so that the number an operator sees on the verdict reflects
    /// why it was held. The floor is what actually decides it.
    /// </remarks>
    public const double BlockedAttachmentScore = 10.0;

    /// <summary>What an unexaminable message contributes.</summary>
    /// <remarks>
    /// Weighed rather than floored: a legitimate large message exists, and holding every one
    /// of them for an operator would make the quarantine useless within a week. It is enough
    /// on its own to junk the message, which is the honest answer to "this was not checked".
    /// </remarks>
    public const double NotExaminedScore = 5.0;

    /// <inheritdoc />
    public string Name => "Attachments";

    /// <inheritdoc />
    public bool NeedsContent => true;

    /// <inheritdoc />
    public Task<SpamCheckResult> InspectAsync(
        MessageFilterContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.ContentWasRead)
        {
            return Task.FromResult(SpamCheckResult.Weigh([
                FilterSignal.Create(
                    "ATTACHMENTS_NOT_EXAMINED",
                    NotExaminedScore,
                    "The message was too large to examine its attachments."),
            ]));
        }

        IReadOnlyList<AttachmentFinding> findings = policy.Inspect(context.Attachments);

        if (findings.Count == 0)
        {
            return Task.FromResult(SpamCheckResult.Nothing);
        }

        // One signal per finding, because an operator releasing a message needs to know which
        // attachment they are releasing — a single "3 blocked attachments" signal makes that a
        // question they have to open the message to answer.
        List<FilterSignal> signals = [.. findings.Select(f => FilterSignal.Create(
            "BLOCKED_ATTACHMENT",
            BlockedAttachmentScore / findings.Count,
            $"{f.FileName}: {f.Reason}"))];

        return Task.FromResult(new SpamCheckResult(signals, FilterAction.Quarantine));
    }
}
