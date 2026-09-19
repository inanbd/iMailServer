using System.Globalization;

namespace MailServer.Domain.Deliverability;

/// <summary>What the operations probe observed about the running server.</summary>
/// <param name="RelaysForStrangers">
/// Whether the server accepted an unauthenticated message from an outside address to an outside
/// address, or null when no self-test was run.
/// </param>
/// <param name="QueuePending">Messages waiting to go out, or null when the queue was not read.</param>
/// <param name="OldestPendingAge">How long the oldest of them has waited, or null.</param>
/// <param name="RecentDeliveries">Delivery outcomes recorded in the window, or null.</param>
/// <param name="RecentBounces">How many of those were permanent failures.</param>
/// <param name="FreeDiskBytes">Free space on the message store's volume, or null.</param>
/// <param name="TotalDiskBytes">The volume's size, or null.</param>
/// <param name="ClockSkew">
/// How far this server's clock is from an external reference, or null when none was consulted.
/// Positive means this server is ahead.
/// </param>
public sealed record OperationsFacts(
    bool? RelaysForStrangers,
    int? QueuePending,
    TimeSpan? OldestPendingAge,
    int? RecentDeliveries,
    int? RecentBounces,
    long? FreeDiskBytes,
    long? TotalDiskBytes,
    TimeSpan? ClockSkew);

/// <summary>
/// The Operations category: the running server rather than what it publishes.
/// </summary>
/// <remarks>
/// <b>Five points, the lightest, and it contains the single worst finding in the report.</b> An
/// open relay is not a five-point problem; it is a server that will be found by a scanner within
/// hours, used to send spam, and blocklisted everywhere before anybody notices. The weight is
/// low because the readiness verdict — <see cref="DeliverabilityReadiness"/> — is the worst
/// outcome present and never the arithmetic, so a failure here makes the whole report *Not
/// ready* whatever the number says. That is the design working as intended, and it is why the
/// UI leads with the verdict.
/// </remarks>
public static class OperationsChecks
{
    /// <summary>The open-relay check's id.</summary>
    public const string NotAnOpenRelayId = "operations.not-an-open-relay";

    /// <summary>The queue-health check's id.</summary>
    public const string QueueHealthId = "operations.queue-health";

    /// <summary>The bounce-rate check's id.</summary>
    public const string BounceRateId = "operations.bounce-rate";

    /// <summary>The disk-space check's id.</summary>
    public const string DiskSpaceId = "operations.disk-space";

    /// <summary>The clock-skew check's id.</summary>
    public const string ClockSkewId = "operations.clock-skew";

    /// <summary>Above this, the outbound queue is not draining.</summary>
    public static readonly TimeSpan QueueWarningAge = TimeSpan.FromHours(4);

    /// <summary>Above this, mail is close to timing out in senders' queues.</summary>
    public static readonly TimeSpan QueueFailureAge = TimeSpan.FromHours(24);

    /// <summary>
    /// Above this share of recent deliveries bouncing, receivers start treating the sender as a
    /// list problem rather than a correspondent.
    /// </summary>
    public const double BounceWarningRate = 0.02;

    /// <summary>Above this, the pattern is indistinguishable from sending to a purchased list.</summary>
    public const double BounceFailureRate = 0.05;

    /// <summary>
    /// The fewest deliveries a bounce rate is worth computing from.
    /// </summary>
    /// <remarks>
    /// Two bounces out of three messages is 67% and means nothing at all. A rate reported from a
    /// handful of deliveries is noise presented as a measurement, and an operator who has just
    /// installed the server would see a catastrophic-looking number on their first day.
    /// </remarks>
    public const int MinimumDeliveriesForRate = 50;

    /// <summary>Below this share free, the volume is close to refusing mail.</summary>
    public const double DiskWarningFree = 0.15;

    /// <summary>Below this, it is about to.</summary>
    public const double DiskFailureFree = 0.05;

    /// <summary>
    /// Beyond this, a skewed clock starts breaking things that depend on time.
    /// </summary>
    /// <remarks>
    /// DKIM signatures carrying <c>x=</c>, certificate validity windows, and the <c>Received</c>
    /// timestamps a receiver uses to judge a message's route all assume the clock is roughly
    /// right. Spam filters have long treated a message dated in the future as a signal.
    /// </remarks>
    public static readonly TimeSpan ClockWarningSkew = TimeSpan.FromSeconds(30);

    /// <summary>Beyond this, it already has.</summary>
    public static readonly TimeSpan ClockFailureSkew = TimeSpan.FromMinutes(5);

    /// <summary>Judges a set of observations. Pure.</summary>
    public static IReadOnlyList<DeliverabilityCheck> Evaluate(OperationsFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        return
        [
            NotAnOpenRelay(facts),
            QueueHealth(facts),
            BounceRate(facts),
            DiskSpace(facts),
            ClockSkew(facts),
        ];
    }

    /// <summary>
    /// The server does not relay for strangers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The one finding in this report that is an emergency.</b> An open relay is found by a
    /// scanner within hours of being exposed, and by the time the operator notices, the address
    /// is on every list and the domain's reputation is gone. Everything else here can wait until
    /// tomorrow.
    /// </para>
    /// <para>
    /// The remedy says to take the listener off the network rather than to adjust a setting,
    /// because while it is reachable it is being used.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck NotAnOpenRelay(OperationsFacts facts)
    {
        const string Id = NotAnOpenRelayId;
        const string Title = "The server is not an open relay";
        const int Weight = 3;

        if (facts.RelaysForStrangers is not { } relays)
        {
            return Unmeasured(Id, Title, Weight, "No relay self-test was run.");
        }

        DeliverabilityEvidence evidence = new(
            "An unauthenticated message to an outside address is refused",
            relays ? "accepted" : "refused");

        return relays
            ? Fail(
                Id,
                Title,
                Weight,
                "This server accepted an unauthenticated message from an outside address to an " +
                "outside address. It is an open relay. Scanners find these within hours; by the " +
                "time it shows up as a delivery problem, the address is on every blocklist and " +
                "the domain's reputation is gone.",
                evidence,
                "Take the port 25 listener off the public network now, before changing anything " +
                "else. While it is reachable it is being used. Then require authentication for " +
                "any recipient this server is not the final destination for.")
            : Pass(
                Id,
                Title,
                Weight,
                "An unauthenticated message to an outside address was refused.",
                evidence);
    }

    /// <summary>
    /// The outbound queue is draining.
    /// </summary>
    /// <remarks>
    /// Judged on the age of the oldest message rather than on the depth. A queue of ten thousand
    /// that clears in a minute is a busy server; a queue of one that has been there since
    /// yesterday is a broken one, and only the age tells them apart.
    /// </remarks>
    private static DeliverabilityCheck QueueHealth(OperationsFacts facts)
    {
        const string Id = QueueHealthId;
        const string Title = "The outbound queue is draining";
        const int Weight = 2;

        if (facts.QueuePending is not { } pending)
        {
            return Unmeasured(Id, Title, Weight, "The outbound queue was not read.");
        }

        if (pending == 0)
        {
            return Pass(
                Id,
                Title,
                Weight,
                "Nothing is waiting to go out.",
                new DeliverabilityEvidence("An outbound queue that drains", "empty"));
        }

        if (facts.OldestPendingAge is not { } age)
        {
            return Unmeasured(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{pending} message(s) are waiting, but how long the oldest has waited is " +
                    $"not known — and depth alone says nothing."));
        }

        DeliverabilityEvidence evidence = new(
            $"Nothing waiting longer than {Hours(QueueWarningAge)} hours",
            string.Create(
                CultureInfo.InvariantCulture,
                $"{pending} waiting, oldest {Hours(age)} hours"));

        if (age >= QueueFailureAge)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"The oldest queued message has been waiting {Hours(age)} hours. Senders' own " +
                "retry windows are measured in days, so mail is now at risk of being returned " +
                "rather than delayed.",
                evidence,
                "Look at the delivery attempt history for the destinations that are failing — a " +
                "queue this old is usually one domain refusing, not a general fault.");
        }

        return age >= QueueWarningAge
            ? Warn(
                Id,
                Title,
                Weight,
                $"The oldest queued message has been waiting {Hours(age)} hours.",
                evidence,
                "Check which destinations are deferring. A single slow domain is normal; a " +
                "rising oldest-age across many is not.")
            : Pass(
                Id,
                Title,
                Weight,
                $"{pending} message(s) waiting, the oldest for {Hours(age)} hours.",
                evidence);
    }

    /// <summary>
    /// Recent deliveries are mostly arriving.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A bounce rate is how receivers decide whether a sender has a list or a correspondence.
    /// Above a few per cent the pattern is indistinguishable from sending to addresses that were
    /// never opted in, and reputation systems respond to the pattern rather than to the intent.
    /// </para>
    /// <para>
    /// <b>Not computed below <see cref="MinimumDeliveriesForRate"/> deliveries.</b> Two bounces
    /// out of three is 67% and means nothing; an operator on their first day would otherwise be
    /// shown a catastrophic number generated by their own test messages.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck BounceRate(OperationsFacts facts)
    {
        const string Id = BounceRateId;
        const string Title = "Recent mail is being accepted";
        const int Weight = 2;

        if (facts.RecentDeliveries is not { } deliveries || facts.RecentBounces is not { } bounces)
        {
            return Unmeasured(Id, Title, Weight, "No delivery history was read.");
        }

        if (deliveries < MinimumDeliveriesForRate)
        {
            return Unmeasured(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Only {deliveries} recent deliveries — too few for a rate to mean anything. " +
                    $"At least {MinimumDeliveriesForRate} are needed."));
        }

        double rate = (double)bounces / deliveries;

        DeliverabilityEvidence evidence = new(
            $"Under {Percent(BounceWarningRate)}% of deliveries bouncing",
            string.Create(
                CultureInfo.InvariantCulture,
                $"{bounces} of {deliveries} ({rate * 100:0.0}%)"));

        if (rate >= BounceFailureRate)
        {
            return Fail(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{rate * 100:0.0}% of recent deliveries bounced permanently. Receivers read " +
                    $"that pattern as mail to addresses that were never opted in, whatever the " +
                    $"intent, and reputation follows the pattern."),
                evidence,
                "Read the bounce reasons. Unknown recipients point at a stale address list; " +
                "policy rejections point at this report's other findings.");
        }

        return rate >= BounceWarningRate
            ? Warn(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{rate * 100:0.0}% of recent deliveries bounced permanently."),
                evidence,
                "Remove addresses that have bounced permanently — retrying them is what turns a " +
                "bounce rate into a reputation problem.")
            : Pass(
                Id,
                Title,
                Weight,
                string.Create(CultureInfo.InvariantCulture, $"{rate * 100:0.0}% of recent deliveries bounced."),
                evidence);
    }

    /// <summary>
    /// There is room to accept mail.
    /// </summary>
    /// <remarks>
    /// A full volume is a deliverability problem rather than an operations one: a server that
    /// cannot write a message returns a temporary failure, senders retry for days, and the mail
    /// is eventually returned to people who will not try again.
    /// </remarks>
    private static DeliverabilityCheck DiskSpace(OperationsFacts facts)
    {
        const string Id = DiskSpaceId;
        const string Title = "There is room to accept mail";
        const int Weight = 2;

        if (facts.FreeDiskBytes is not { } free ||
            facts.TotalDiskBytes is not { } total ||
            total <= 0)
        {
            return Unmeasured(Id, Title, Weight, "The message store's volume was not measured.");
        }

        double share = (double)free / total;

        DeliverabilityEvidence evidence = new(
            $"At least {Percent(DiskWarningFree)}% free",
            string.Create(
                CultureInfo.InvariantCulture,
                $"{Gigabytes(free)} GB free of {Gigabytes(total)} GB ({share * 100:0.0}%)"));

        if (share < DiskFailureFree)
        {
            return Fail(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Only {share * 100:0.0}% of the message store's volume is free. A server " +
                    $"that cannot write a message defers it, senders retry for days, and the " +
                    $"mail is returned to people who will not try again."),
                evidence,
                "Free space now. Then set a retention policy, or move the message store to a " +
                "larger volume.");
        }

        return share < DiskWarningFree
            ? Warn(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{share * 100:0.0}% of the message store's volume is free."),
                evidence,
                "Plan for more space before it becomes urgent.")
            : Pass(
                Id,
                Title,
                Weight,
                string.Create(CultureInfo.InvariantCulture, $"{share * 100:0.0}% of the volume is free."),
                evidence);
    }

    /// <summary>
    /// The clock is roughly right.
    /// </summary>
    /// <remarks>
    /// The check whose consequences are least obvious. A skewed clock invalidates DKIM signatures
    /// carrying <c>x=</c>, makes a freshly issued certificate look not-yet-valid, and dates
    /// <c>Received</c> headers wrongly — which spam filters have treated as a signal for as long
    /// as there have been spam filters. None of it looks like a clock problem from the outside.
    /// </remarks>
    private static DeliverabilityCheck ClockSkew(OperationsFacts facts)
    {
        const string Id = ClockSkewId;
        const string Title = "This server's clock is correct";
        const int Weight = 1;

        if (facts.ClockSkew is not { } skew)
        {
            return Unmeasured(Id, Title, Weight, "No external time reference was consulted.");
        }

        TimeSpan magnitude = skew.Duration();
        string direction = skew > TimeSpan.Zero ? "ahead of" : "behind";

        DeliverabilityEvidence evidence = new(
            $"Within {ClockWarningSkew.TotalSeconds:0} seconds of the reference",
            string.Create(
                CultureInfo.InvariantCulture,
                $"{magnitude.TotalSeconds:0.0} seconds {direction} the reference"));

        if (magnitude >= ClockFailureSkew)
        {
            return Fail(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"This server's clock is {magnitude.TotalSeconds:0} seconds {direction} the " +
                    $"reference. That is enough to invalidate DKIM signatures with an expiry, " +
                    $"make a new certificate look not-yet-valid, and date Received headers " +
                    $"wrongly — none of which looks like a clock problem from the outside."),
                evidence,
                "Enable NTP. On systemd hosts that is `timedatectl set-ntp true`.");
        }

        return magnitude >= ClockWarningSkew
            ? Warn(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"This server's clock is {magnitude.TotalSeconds:0.0} seconds {direction} the " +
                    $"reference."),
                evidence,
                "Check that NTP is running and reaching a server.")
            : Pass(
                Id,
                Title,
                Weight,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"The clock is within {magnitude.TotalSeconds:0.0} seconds of the reference."),
                evidence);
    }

    // -------------------------------------------------------------------------------------------
    // Shared.
    // -------------------------------------------------------------------------------------------

    private static string Hours(TimeSpan span) =>
        span.TotalHours.ToString("0.#", CultureInfo.InvariantCulture);

    private static string Percent(double share) =>
        (share * 100).ToString("0.#", CultureInfo.InvariantCulture);

    private static string Gigabytes(long bytes) =>
        (bytes / 1024d / 1024d / 1024d).ToString("0.#", CultureInfo.InvariantCulture);

    private static DeliverabilityCheck Pass(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence) =>
        new(id, DeliverabilityCategory.Operations, title, weight, DeliverabilityOutcome.Pass, detail, evidence);

    private static DeliverabilityCheck Warn(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Operations, title, weight, DeliverabilityOutcome.Warn, detail, evidence, remedy);

    private static DeliverabilityCheck Fail(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Operations, title, weight, DeliverabilityOutcome.Fail, detail, evidence, remedy);

    private static DeliverabilityCheck Unmeasured(string id, string title, int weight, string detail) =>
        new(id, DeliverabilityCategory.Operations, title, weight, DeliverabilityOutcome.Inconclusive, detail);
}
