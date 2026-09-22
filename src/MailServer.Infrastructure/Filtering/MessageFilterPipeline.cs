using MailServer.Application.Abstractions.Filtering;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Filtering;
using MailServer.Domain.Imap;
using MailServer.Infrastructure.Dkim;
using MailServer.Domain.Mail;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Filtering;

/// <summary>
/// The pipeline's bounds on what one message may ask this server to do.
/// </summary>
/// <remarks>
/// Their own type because a primary constructor's defaults cannot name constants on the class
/// being declared, and these are worth stating as defaults rather than duplicating as literals
/// at every construction site.
/// </remarks>
public static class FilterLimits
{
    /// <summary>How much of a message's start is read looking for the header boundary.</summary>
    public const int MaxHeaderBytes = 256 * 1024;

    /// <summary>
    /// The largest message whose body the pipeline will parse.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The MIME tree is built in memory, so this bounds what one message can ask this server to
    /// allocate. A message over it still gets its headers and its authentication results
    /// weighed, and the checks that needed the body say they did not see it — see
    /// <c>AttachmentSpamCheck</c>. Silently passing an oversized message would make "send it
    /// big" the bypass.
    /// </para>
    /// <para>
    /// <b>Reading a message whole departs from <c>IMessageStore</c>'s stated position</b> —
    /// "none of them needs the whole message resident" — and does so for the same reason
    /// <c>ImapCommandProcessor</c> does: <c>ImapMimeTree.Parse</c> needs the octets contiguous,
    /// and a streaming MIME parser would be a second implementation of a structure IMAP
    /// already has one of. What is different here is who is asking. IMAP reads a message
    /// because an authenticated user asked for that message; the filter reads every message a
    /// stranger delivers. That is what <see cref="MaxConcurrentContentReads"/> is for.
    /// </para>
    /// </remarks>
    public const long MaxContentBytes = 32 * 1024 * 1024;

    /// <summary>
    /// How many messages may be resident in the filter at once.
    /// </summary>
    /// <remarks>
    /// <b>The per-message bound is not a bound on anything by itself.</b> A hundred concurrent
    /// inbound connections each delivering a message just under
    /// <see cref="MaxContentBytes"/> is three gigabytes, and every one of those connections is
    /// free for anyone who can reach port 25. Multiplied out, this gate is what actually caps
    /// the filter's memory: four times 32 MB, rather than "as many as the listener will
    /// accept" times 32 MB.
    /// </b>
    /// <para>
    /// Waiting is the right behaviour when it is reached, not skipping. A message that waited
    /// is delayed; a message that skipped the filter is unfiltered mail delivered because the
    /// server was busy, which is a bypass anyone can trigger by being busy at it.
    /// </para>
    /// </remarks>
    public const int MaxConcurrentContentReads = 4;
}

/// <summary>
/// Runs every check over one message and applies the policy to what they found.
/// </summary>
/// <remarks>
/// <para>
/// <b>Reads the message once.</b> The header block is parsed once and the MIME tree walked
/// once, and every check is handed the result. Five checks that each opened the file would
/// multiply what a hostile message costs by five, on the delivery path.
/// </para>
/// <para>
/// <b>Fails open, like the authentication step above it.</b> A check that throws is dropped
/// with a warning and the rest run; a pipeline that throws returns
/// <see cref="FilterVerdict.Clean"/>. A filter whose own bug stops mail flowing is a worse
/// failure than the spam it would have caught, and this server's operator is far more likely
/// to notice mail that arrived wrongly than mail that never arrived at all.
/// </para>
/// <para>
/// <b>There is no per-check timeout.</b> The checks that touch the network are the block-list
/// one, whose provider already bounds itself, and the malware one, whose scanner owns its own
/// deadline — wrapping a second timeout around either would mean two timeouts disagreeing
/// about what happened. The delivery path's own cancellation token is passed through and is
/// what actually stops a slow check.
/// </para>
/// </remarks>
public sealed class MessageFilterPipeline(
    IEnumerable<ISpamCheck> checks,
    IMessageStore messageStore,
    FilterPolicy policy,
    ILogger<MessageFilterPipeline> logger,
    bool enabled = true,
    int maxHeaderBytes = FilterLimits.MaxHeaderBytes,
    long maxContentBytes = FilterLimits.MaxContentBytes) : IMessageFilter, IDisposable
{
    private readonly List<ISpamCheck> _checks = [.. checks];

    /// <summary>Caps how much of the filter's per-message memory can exist at once.</summary>
    private readonly SemaphoreSlim _contentGate = new(
        FilterLimits.MaxConcurrentContentReads, FilterLimits.MaxConcurrentContentReads);

    /// <inheritdoc />
    public bool IsEnabled => enabled;

    /// <inheritdoc />
    public async Task<FilterVerdict> EvaluateAsync(
        MessageFilterRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!enabled || _checks.Count == 0)
        {
            return FilterVerdict.Clean;
        }

        try
        {
            MessageFilterContext context = await BuildContextAsync(request, cancellationToken)
                .ConfigureAwait(false);

            List<FilterSignal> signals = [];
            FilterAction floor = FilterAction.Accept;

            foreach (ISpamCheck check in _checks)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Every check runs, including one that needs a body the context does not have:
                // a check that needs content is the one that has to say the content was not
                // available. Skipping it is what would make an oversized message look clean.
                SpamCheckResult result;

                try
                {
                    result = await check.InspectAsync(context, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(
                        ex,
                        "Spam check {Check} failed on message {MessageId}; it was not counted.",
                        check.Name,
                        request.Message.Id.Value);

                    continue;
                }

                signals.AddRange(result.Signals);

                if (result.Floor > floor)
                {
                    floor = result.Floor;
                }
            }

            FilterVerdict verdict = FilterVerdict.Create(signals, policy, floor);

            if (verdict.Action != FilterAction.Accept)
            {
                logger.LogInformation(
                    "Message {MessageId} was {Action}: {Summary}",
                    request.Message.Id.Value,
                    verdict.Action,
                    verdict.Summarise());
            }

            return verdict;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex, "Filtering failed for message {MessageId}; it was delivered unfiltered.", request.Message.Id.Value);

            return FilterVerdict.Clean;
        }
    }

    /// <summary>Reads the message once and parses what the checks need.</summary>
    private async Task<MessageFilterContext> BuildContextAsync(
        MessageFilterRequest request,
        CancellationToken cancellationToken)
    {
        RawMessageHeaders? headers = null;
        IReadOnlyList<AttachmentDescriptor> attachments = [];
        bool contentWasRead = false;

        if (request.Message.SizeBytes <= maxContentBytes)
        {
            // Held across the parse rather than only the read: the MIME tree references the
            // same buffer, so releasing at the end of the read would let the next message in
            // while this one's octets were still resident, and the cap would count the wrong
            // thing.
            await _contentGate.WaitAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                byte[] content = await ReadAllAsync(request.Message.Id, cancellationToken).ConfigureAwait(false);

                contentWasRead = true;

                RawMessageHeaders.TryParse(content, out headers, out _);
                attachments = DescribeAttachments(content, request.Message.Id);
            }
            finally
            {
                _contentGate.Release();
            }
        }
        else
        {
            // Over the bound, so only the start is read — enough for the structural checks,
            // which is better than giving an oversized message no examination at all.
            await using Stream stream = await messageStore
                .OpenReadAsync(request.Message.Id, cancellationToken)
                .ConfigureAwait(false);

            headers = await MessageHeaderReader
                .TryReadHeadersAsync(stream, maxHeaderBytes, cancellationToken)
                .ConfigureAwait(false);

            logger.LogInformation(
                "Message {MessageId} is {Size} bytes and was not examined beyond its headers.",
                request.Message.Id.Value,
                request.Message.SizeBytes);
        }

        return new MessageFilterContext(
            request,
            headers,
            attachments,
            contentWasRead,
            ct => messageStore.OpenReadAsync(request.Message.Id, ct));
    }

    /// <summary>Walks the MIME tree and describes every part that names itself.</summary>
    /// <remarks>
    /// A malformed message is not an exceptional condition on this path — it is the ordinary
    /// case for the mail this check exists to catch. A tree that will not parse yields no
    /// attachments, and <c>HeaderHeuristicSpamCheck</c> is what notices the message was
    /// malformed.
    /// </remarks>
    private IReadOnlyList<AttachmentDescriptor> DescribeAttachments(
        ReadOnlyMemory<byte> content,
        Domain.ValueObjects.StoredMessageId messageId)
    {
        try
        {
            ImapBodyPart root = ImapMimeTree.Parse(content);
            List<AttachmentDescriptor> found = [];

            Walk(root, found);

            return found;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogDebug(ex, "Message {MessageId}'s MIME structure could not be walked.", messageId.Value);

            return [];
        }
    }

    private static void Walk(ImapBodyPart part, List<AttachmentDescriptor> found)
    {
        // The tree's own depth and part-count bounds (ImapMimeTree.MaxDepth, MaxPartCount) are
        // enforced during the parse, so anything reaching here is already bounded. The
        // attachment policy applies its own bound on how many it will examine.
        if (MimeFileName.IsAttachment(part))
        {
            found.Add(MimeFileName.Describe(part));
        }

        foreach (ImapBodyPart child in part.Children)
        {
            Walk(child, found);
        }

        if (part.Message is not null)
        {
            Walk(part.Message, found);
        }
    }

    /// <inheritdoc />
    public void Dispose() => _contentGate.Dispose();

    private async Task<byte[]> ReadAllAsync(
        Domain.ValueObjects.StoredMessageId messageId,
        CancellationToken cancellationToken)
    {
        await using Stream stream = await messageStore
            .OpenReadAsync(messageId, cancellationToken)
            .ConfigureAwait(false);

        using MemoryStream buffer = new();

        await stream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);

        return buffer.ToArray();
    }
}
