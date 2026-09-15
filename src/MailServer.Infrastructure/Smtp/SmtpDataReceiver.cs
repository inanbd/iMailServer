using System.Buffers;
using System.Text;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Smtp;

/// <summary>How receiving a message ended.</summary>
public enum SmtpDataOutcome
{
    /// <summary>The message arrived complete and is stored.</summary>
    Accepted = 0,

    /// <summary>The message exceeded the size limit. The session survives.</summary>
    TooLarge = 1,

    /// <summary>The message exceeded the limit by so much that the session was abandoned.</summary>
    TooLargeAndUnrecoverable = 2,

    /// <summary>The peer stopped sending.</summary>
    Timeout = 3,

    /// <summary>The peer disconnected mid-message.</summary>
    ConnectionClosed = 4,

    /// <summary>Storage failed. Transient, so the sender retries.</summary>
    StorageFailure = 5,
}

/// <summary>What happened, what to say, and what was stored.</summary>
/// <param name="Outcome">How it ended.</param>
/// <param name="Reply">The reply to send. Null when the peer is already gone.</param>
/// <param name="Message">The stored message, when one was committed.</param>
/// <param name="RawByteCount">Octets the peer sent, which is what the limit is charged against.</param>
public sealed record SmtpDataResult(
    SmtpDataOutcome Outcome,
    SmtpReply? Reply,
    StoredMessage? Message,
    long RawByteCount)
{
    /// <summary>Whether the connection should be closed rather than continued.</summary>
    public bool ShouldCloseConnection => Outcome is
        SmtpDataOutcome.TooLargeAndUnrecoverable or
        SmtpDataOutcome.ConnectionClosed or
        SmtpDataOutcome.Timeout;
}

/// <summary>
/// Reads a <c>DATA</c> body from the wire into the message store.
/// </summary>
/// <remarks>
/// <para>
/// Fixed-size buffers, rented once per message, from first octet to last. Nothing here grows
/// with the size of the message: a thirty-megabyte message and a thirty-byte one allocate the
/// same. That is what makes the size limit a policy decision rather than the thing standing
/// between the server and an out-of-memory kill.
/// </para>
/// <para>
/// <b>Over-size is a bounded overrun, not an unbounded one.</b> RFC 5321 §4.5.3.1.9 wants the
/// server to keep reading to the end-of-data marker so it can answer 552 and carry on, which is
/// far more useful to the sender than a dropped connection. Reading to the marker without a
/// limit is exactly the unbounded read rule 105 forbids, so the overrun has its own budget:
/// past it the session is abandoned. A peer therefore cannot turn "your message is too big" into
/// free bandwidth.
/// </para>
/// </remarks>
public sealed class SmtpDataReceiver(IMessageStore store, ILogger<SmtpDataReceiver> logger)
{
    /// <summary>
    /// How far past the limit a peer may run before the connection is dropped.
    /// </summary>
    /// <remarks>
    /// Enough for a sender that genuinely miscounted to finish its message and receive a proper
    /// 552; not enough to be worth abusing. A peer that wants to push more than this has stopped
    /// trying to deliver mail.
    /// </remarks>
    public const long MaxOverrunBytes = 1024 * 1024;

    /// <summary>Largest trace header this server will prepend.</summary>
    /// <remarks>
    /// Every field in the header is sanitised and length-bounded, so the real figure is far
    /// below this. The cap exists so the storage ceiling can be computed before the header
    /// is built, and so a future header that grew without anyone noticing fails loudly.
    /// </remarks>
    public const long MaxPreambleBytes = 8 * 1024;

    /// <summary>Receives one message.</summary>
    /// <param name="reader">The connection reader, positioned just after the 354 reply.</param>
    /// <param name="buildPreamble">
    /// Builds the octets stored ahead of the body — the <c>Received:</c> header — given the
    /// identifier the message will be stored under. A factory rather than a string because the
    /// header names that identifier, and it does not exist until the write begins.
    /// <para>
    /// The preamble is counted against storage but not against the peer's size budget: the peer
    /// did not send it and must not be charged for it, or a message exactly at the limit would
    /// be refused because of a header this server added to it.
    /// </para>
    /// </param>
    /// <param name="maxSizeBytes">The effective size limit for this message.</param>
    /// <param name="chunkTimeout">Longest wait for the next octets. Bounds slowloris inside DATA.</param>
    public async ValueTask<SmtpDataResult> ReceiveAsync(
        SmtpLineReader reader,
        Func<StoredMessageId, string> buildPreamble,
        long maxSizeBytes,
        TimeSpan chunkTimeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(buildPreamble);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxSizeBytes);

        // Sized from the reader's own window, which is bounded by the line limit. The receiver
        // never asks for more than the reader can hold, so no path here grows with the message.
        byte[] output = ArrayPool<byte>.Shared.Rent(
            SmtpDataDecoder.MaxOutputFor(reader.MaxLineOctets + 2));

        SmtpDataDecoder decoder = new();

        // The writer's own ceiling allows for the header this server prepends, so that storage
        // never refuses a message the peer kept within its budget. Sized from the cap the header
        // builder is itself bounded by rather than from the header, because the writer has to
        // exist before the header that names it can be built.
        long storageCeiling = maxSizeBytes + MaxPreambleBytes + MaxOverrunBytes;

        await using IMessageWriter writer = await store
            .BeginWriteAsync(storageCeiling, cancellationToken)
            .ConfigureAwait(false);

        bool exceededLimit = false;

        try
        {
            byte[] preamble = Encoding.UTF8.GetBytes(buildPreamble(writer.Id));

            if (preamble.Length > MaxPreambleBytes)
            {
                // The trace header is built from bounded, sanitised fields, so this is a caller
                // bug rather than something a peer can provoke. Refusing is still better than
                // quietly eating into the peer's size budget.
                throw new InvalidOperationException(
                    $"The trace header is {preamble.Length} octets, above the {MaxPreambleBytes}-octet cap.");
            }

            await writer.WriteAsync(preamble, cancellationToken).ConfigureAwait(false);

            while (true)
            {
                SmtpReadResult read = await reader
                    .FillAsync(chunkTimeout, cancellationToken)
                    .ConfigureAwait(false);

                switch (read.Status)
                {
                    case SmtpReadStatus.Timeout:
                        return new SmtpDataResult(
                            SmtpDataOutcome.Timeout, SmtpReplies.Timeout(), null, decoder.RawByteCount);

                    case SmtpReadStatus.EndOfStream:
                        // No marker, so no message. An incomplete body must never be delivered:
                        // the sender will retry, and a truncated copy delivered now becomes a
                        // duplicate of the complete one that follows.
                        return new SmtpDataResult(
                            SmtpDataOutcome.ConnectionClosed, null, null, decoder.RawByteCount);
                }

                bool complete = decoder.Decode(
                    reader.BufferedInput.Span,
                    output,
                    out int consumed,
                    out int produced);

                // Exactly what belonged to the message, and not one octet more. With PIPELINING
                // the next command shares a packet with the end-of-data marker, and consuming it
                // here would lose it - the session would then sit waiting for a command the peer
                // has already sent.
                reader.Consume(consumed);

                if (!exceededLimit && decoder.RawByteCount > maxSizeBytes)
                {
                    // Stop storing, keep reading to the marker so the session can survive.
                    exceededLimit = true;

                    logger.LogInformation(
                        "Message exceeded the {Limit}-byte limit at {Received} bytes; discarding and continuing to the end-of-data marker.",
                        maxSizeBytes,
                        decoder.RawByteCount);
                }

                if (!exceededLimit && produced > 0)
                {
                    await writer
                        .WriteAsync(output.AsMemory(0, produced), cancellationToken)
                        .ConfigureAwait(false);
                }

                if (complete)
                {
                    if (exceededLimit)
                    {
                        return new SmtpDataResult(
                            SmtpDataOutcome.TooLarge,
                            SmtpReplies.MessageTooLarge(maxSizeBytes),
                            null,
                            decoder.RawByteCount);
                    }

                    StoredMessage stored = await writer.CommitAsync(cancellationToken).ConfigureAwait(false);

                    return new SmtpDataResult(
                        SmtpDataOutcome.Accepted,
                        null,
                        stored,
                        decoder.RawByteCount);
                }

                if (exceededLimit && decoder.RawByteCount > maxSizeBytes + MaxOverrunBytes)
                {
                    // The overrun budget is spent. Say why, then go.
                    return new SmtpDataResult(
                        SmtpDataOutcome.TooLargeAndUnrecoverable,
                        SmtpReplies.MessageTooLarge(maxSizeBytes),
                        null,
                        decoder.RawByteCount);
                }
            }
        }
        catch (MessageTooLargeException ex)
        {
            // The store's own ceiling, which sits above the protocol limit. Reaching it means
            // the protocol check let something through, so it is logged rather than swallowed.
            logger.LogWarning(
                ex,
                "The message store refused a message at {Bytes} bytes; the protocol limit was {Limit}.",
                ex.AttemptedBytes,
                maxSizeBytes);

            return new SmtpDataResult(
                SmtpDataOutcome.TooLargeAndUnrecoverable,
                SmtpReplies.MessageTooLarge(maxSizeBytes),
                null,
                decoder.RawByteCount);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Transient on purpose. A full or failing disk is this server's problem, and a 4xx
            // leaves the message in the sender's queue where it can still be delivered once the
            // problem is fixed. A 5xx here would destroy mail to save a retry.
            logger.LogError(ex, "Storing a message failed; the sender will be asked to retry.");

            return new SmtpDataResult(
                SmtpDataOutcome.StorageFailure,
                SmtpReplies.LocalError("the message could not be stored"),
                null,
                decoder.RawByteCount);
        }
        finally
        {
            // Clear before returning: these buffers held message content, and the next renter is
            // a different message on a different connection.
            ArrayPool<byte>.Shared.Return(output, clearArray: true);
        }
    }
}
