using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Deliverability;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>Where the message store lives, so its volume can be measured.</summary>
/// <remarks>
/// An abstraction of one property because the alternative is this probe reaching into the
/// persistence configuration, and a diagnostic tool that had its own idea of where messages are
/// stored would be measuring a volume nobody writes to.
/// </remarks>
public interface IMessageStoreLocation
{
    /// <summary>The directory messages are written to.</summary>
    string Path { get; }
}

/// <summary>
/// <see cref="IMessageStoreLocation"/> over the configured data root.
/// </summary>
/// <remarks>
/// The same <c>Storage.DataRoot</c> <c>FileSystemMessageStore</c> writes under, read from the
/// same options — so the volume this reports on is the volume messages actually land on, however
/// an operator has configured it.
/// </remarks>
public sealed class ConfiguredMessageStoreLocation(string path) : IMessageStoreLocation
{
    /// <inheritdoc />
    public string Path { get; } = path;
}

/// <summary>What free space a volume has, so the real one can be swapped out in a test.</summary>
public interface IVolumeMeasure
{
    /// <summary>Free and total bytes for the volume holding a path, or null if it cannot be read.</summary>
    (long Free, long Total)? Measure(string path);
}

/// <summary><see cref="IVolumeMeasure"/> over the real filesystem.</summary>
public sealed class DriveVolumeMeasure : IVolumeMeasure
{
    /// <inheritdoc />
    public (long Free, long Total)? Measure(string path)
    {
        try
        {
            DriveInfo drive = new(System.IO.Path.GetPathRoot(System.IO.Path.GetFullPath(path)) ?? path);

            return drive.IsReady ? (drive.AvailableFreeSpace, drive.TotalSize) : null;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            // Null rather than an exception: a volume that cannot be read leaves the check
            // unjudged, which is the honest answer and not a reason to fail the whole report.
            return null;
        }
    }
}

/// <summary>
/// Gathers the observations the operations checks judge.
/// </summary>
/// <remarks>
/// The probe that looks inward. The others ask DNS and the internet what they can see of this
/// server; this one reads the queue, the disk and the clock, and asks the server one question
/// over SMTP — whether it will relay for a stranger.
/// </remarks>
public sealed class OperationsProbe(
    IOutboundQueueRepository queue,
    IClock clock,
    IVolumeMeasure volume,
    IMessageStoreLocation store,
    ITimeReference? timeReference = null)
{
    /// <summary>
    /// How far back the bounce rate looks.
    /// </summary>
    /// <remarks>
    /// A week: long enough to gather the fifty deliveries
    /// <see cref="OperationsChecks.MinimumDeliveriesForRate"/> asks for on a quiet server, and
    /// short enough that a problem fixed a month ago is not still being reported.
    /// </remarks>
    public static readonly TimeSpan BounceWindow = TimeSpan.FromDays(7);

    /// <summary>Looks up everything the operations checks need.</summary>
    /// <param name="relayTest">
    /// The open-relay self-test's result, or null when one was not run. Passed in rather than
    /// run here because it is the one part of this probe that opens a connection, and a caller
    /// that cannot reach the listener — or should not, on a host where port 25 is not this
    /// server's — must be able to leave it out.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<OperationsFacts> GatherAsync(
        OpenRelayResult? relayTest,
        CancellationToken cancellationToken)
    {
        QueueDepth depth = await queue.GetDepthAsync(cancellationToken).ConfigureAwait(false);

        DeliveryOutcomeCounts counts = await queue
            .GetOutcomeCountsAsync(clock.UtcNow - BounceWindow, cancellationToken)
            .ConfigureAwait(false);

        (long Free, long Total)? disk = volume.Measure(store.Path);

        TimeSpan? skew = timeReference is null
            ? null
            : await timeReference.GetSkewAsync(cancellationToken).ConfigureAwait(false);

        return new OperationsFacts(
            // A test that did not complete is null, not false. "The listener refused the
            // connection" says nothing about what it does with one it accepts, and reporting
            // that as "not an open relay" would be the most dangerous false pass in the report.
            relayTest is { Ran: true } ? relayTest.Relayed : null,
            relayTest?.Source,
            depth.Pending,
            depth.OldestPendingUtc is { } oldest ? clock.UtcNow - oldest : null,
            counts.Delivered + counts.Bounced,
            counts.Bounced,
            disk?.Free,
            disk?.Total,
            skew);
    }
}
