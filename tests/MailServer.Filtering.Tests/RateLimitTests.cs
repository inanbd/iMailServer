using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Filtering;

namespace MailServer.Filtering.Tests;

/// <summary>A clock the test moves by hand.</summary>
internal sealed class ManualClock(DateTimeOffset start) : IClock
{
    private DateTimeOffset _now = start;

    public DateTimeOffset UtcNow => _now;

    public long GetTimestamp() => _now.UtcTicks;

    public TimeSpan GetElapsedTime(long startingTimestamp) =>
        TimeSpan.FromTicks(_now.UtcTicks - startingTimestamp);

    public Task DelayAsync(TimeSpan span, CancellationToken cancellationToken)
    {
        _now += span;
        return Task.CompletedTask;
    }

    public void Advance(TimeSpan span) => _now += span;
}

public sealed class SmtpAbusePolicyTests
{
    private static SmtpAbuseVerdict Evaluate(int rejectedCommands = 0, int rejectedRecipients = 0) =>
        SmtpAbusePolicy.Default.Evaluate(new SmtpSessionConduct(rejectedCommands, rejectedRecipients));

    [Fact]
    public void Leaves_a_well_behaved_session_alone() => Evaluate().ShouldBe(SmtpAbuseVerdict.Continue);

    /// <summary>
    /// A misconfigured client collects a handful of refusals. The limit is well past that, so
    /// reaching it means something is wrong rather than that somebody was unlucky — a limit
    /// that occasionally drops a real sender is one an operator turns off.
    /// </summary>
    [Fact]
    public void Tolerates_a_client_that_gets_a_few_things_wrong()
    {
        Evaluate(rejectedCommands: 5).ShouldBe(SmtpAbuseVerdict.Continue);
        Evaluate(rejectedRecipients: 12).ShouldBe(SmtpAbuseVerdict.Continue);
    }

    [Fact]
    public void Closes_a_session_issuing_bad_commands() =>
        Evaluate(rejectedCommands: SmtpAbusePolicy.Default.MaxRejectedCommands)
            .ShouldBe(SmtpAbuseVerdict.TooManyRejectedCommands);

    /// <summary>A great many refused recipients on one connection is a dictionary walk.</summary>
    [Fact]
    public void Closes_a_session_walking_the_directory() =>
        Evaluate(rejectedRecipients: SmtpAbusePolicy.Default.MaxRejectedRecipients)
            .ShouldBe(SmtpAbuseVerdict.TooManyRejectedRecipients);

    /// <summary>
    /// Harvesting is the less ambiguous of the two — a client can collect refused commands by
    /// misreading a grammar, but nothing legitimate walks a directory.
    /// </summary>
    [Fact]
    public void Reports_harvesting_when_a_session_trips_both() =>
        Evaluate(rejectedCommands: 100, rejectedRecipients: 100)
            .ShouldBe(SmtpAbuseVerdict.TooManyRejectedRecipients);

    /// <summary>
    /// The message must not tell a harvester how many guesses they get per connection — the
    /// one piece of information that makes the limit easy to work around.
    /// </summary>
    [Theory]
    [InlineData(SmtpAbuseVerdict.TooManyRejectedCommands)]
    [InlineData(SmtpAbuseVerdict.TooManyRejectedRecipients)]
    public void Says_the_same_vague_thing_whatever_the_limit_was(SmtpAbuseVerdict verdict)
    {
        string diagnostic = SmtpAbusePolicy.DiagnosticFor(verdict);

        diagnostic.ShouldBe("Too many errors on this connection.");
        diagnostic.ShouldNotContain("recipient");
        diagnostic.ShouldNotContain("auth");
    }

    [Fact]
    public void An_operator_can_tighten_the_limits()
    {
        SmtpAbusePolicy strict = new() { MaxRejectedCommands = 2 };

        strict.Evaluate(new SmtpSessionConduct(2, 0))
            .ShouldBe(SmtpAbuseVerdict.TooManyRejectedCommands);
    }
}

public sealed class InboundRateLimiterTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);

    private static IpAddressValue Address(int last = 7) => IpAddressValue.Parse($"198.51.100.{last}");

    private static InboundRateLimiter Build(
        ManualClock clock, int connections = 3, int messages = 5, int windowMinutes = 60) =>
        new(clock, new InboundRateLimits(connections, messages, TimeSpan.FromMinutes(windowMinutes)));

    [Fact]
    public void Allows_traffic_within_the_allowance()
    {
        InboundRateLimiter limiter = Build(new ManualClock(Start));

        for (int i = 0; i < 3; i++)
        {
            limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.Allowed);
        }
    }

    [Fact]
    public void Refuses_a_connection_past_the_allowance()
    {
        InboundRateLimiter limiter = Build(new ManualClock(Start));

        for (int i = 0; i < 3; i++)
        {
            limiter.RecordConnection(Address());
        }

        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.TooManyConnections);
    }

    [Fact]
    public void Refuses_a_message_past_the_allowance()
    {
        InboundRateLimiter limiter = Build(new ManualClock(Start));

        for (int i = 0; i < 5; i++)
        {
            limiter.RecordMessage(Address()).ShouldBe(InboundRateOutcome.Allowed);
        }

        limiter.RecordMessage(Address()).ShouldBe(InboundRateOutcome.TooManyMessages);
    }

    /// <summary>
    /// The complement to the concurrency cap, which a peer that connects, sends and disconnects
    /// never reaches however fast it goes.
    /// </summary>
    [Fact]
    public void Counts_sequential_connections_not_just_concurrent_ones()
    {
        ManualClock clock = new(Start);
        InboundRateLimiter limiter = Build(clock);

        for (int i = 0; i < 3; i++)
        {
            clock.Advance(TimeSpan.FromSeconds(30));
            limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.Allowed);
        }

        clock.Advance(TimeSpan.FromSeconds(30));
        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.TooManyConnections);
    }

    /// <summary>One address exhausting its allowance must not affect anybody else.</summary>
    [Fact]
    public void Counts_each_address_separately()
    {
        InboundRateLimiter limiter = Build(new ManualClock(Start));

        for (int i = 0; i < 10; i++)
        {
            limiter.RecordConnection(Address(1));
        }

        limiter.RecordConnection(Address(2)).ShouldBe(InboundRateOutcome.Allowed);
    }

    [Fact]
    public void Starts_a_new_window_once_the_old_one_runs_out()
    {
        ManualClock clock = new(Start);
        InboundRateLimiter limiter = Build(clock);

        for (int i = 0; i < 4; i++)
        {
            limiter.RecordConnection(Address());
        }

        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.TooManyConnections);

        clock.Advance(TimeSpan.FromMinutes(61));

        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.Allowed);
    }

    [Fact]
    public void Connections_and_messages_are_counted_separately()
    {
        InboundRateLimiter limiter = Build(new ManualClock(Start));

        for (int i = 0; i < 4; i++)
        {
            limiter.RecordConnection(Address());
        }

        limiter.RecordMessage(Address()).ShouldBe(InboundRateOutcome.Allowed);
    }

    [Fact]
    public void Sweeping_drops_counters_whose_window_has_passed()
    {
        ManualClock clock = new(Start);
        InboundRateLimiter limiter = Build(clock);

        limiter.RecordConnection(Address(1));
        limiter.RecordConnection(Address(2));

        limiter.TrackedAddresses.ShouldBe(2);

        clock.Advance(TimeSpan.FromMinutes(61));

        limiter.Sweep().ShouldBe(2);
        limiter.TrackedAddresses.ShouldBe(0);
    }

    [Fact]
    public void Sweeping_keeps_a_counter_whose_window_is_still_open()
    {
        ManualClock clock = new(Start);
        InboundRateLimiter limiter = Build(clock);

        limiter.RecordConnection(Address(1));

        clock.Advance(TimeSpan.FromMinutes(5));

        limiter.Sweep().ShouldBe(0);
        limiter.TrackedAddresses.ShouldBe(1);
    }

    // ---- Connections that prove who they are -----------------------------------------------

    [Fact]
    public void A_forgiven_connection_no_longer_counts()
    {
        // An office's mail clients behind one address: every one signs in, so the allowance
        // is never spent however many of them there are.
        InboundRateLimiter limiter = Build(new ManualClock(Start), connections: 1);

        for (int i = 0; i < 10; i++)
        {
            limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.Allowed);
            limiter.ForgiveConnection(Address());
        }
    }

    [Fact]
    public void Only_the_connections_that_sign_in_are_forgiven()
    {
        // A guessing run never signs in, so it spends the allowance exactly as before.
        InboundRateLimiter limiter = Build(new ManualClock(Start), connections: 2);

        limiter.RecordConnection(Address());
        limiter.ForgiveConnection(Address());

        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.Allowed);
        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.Allowed);
        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.TooManyConnections);
    }

    [Fact]
    public void Forgiveness_never_builds_credit()
    {
        // Below zero would let an address bank sign-ins against a flood later in the window.
        InboundRateLimiter limiter = Build(new ManualClock(Start), connections: 1);

        limiter.RecordConnection(Address());

        for (int i = 0; i < 5; i++)
        {
            limiter.ForgiveConnection(Address());
        }

        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.Allowed);
        limiter.RecordConnection(Address()).ShouldBe(InboundRateOutcome.TooManyConnections);
    }

    [Fact]
    public void Forgiving_an_address_the_limiter_is_not_tracking_remembers_nothing()
    {
        InboundRateLimiter limiter = Build(new ManualClock(Start));

        limiter.ForgiveConnection(Address(99));

        limiter.TrackedAddresses.ShouldBe(0);
    }

    [Fact]
    public void Forgiveness_does_not_touch_the_message_count()
    {
        InboundRateLimiter limiter = Build(new ManualClock(Start), messages: 1);

        limiter.RecordConnection(Address());
        limiter.RecordMessage(Address());
        limiter.ForgiveConnection(Address());

        limiter.RecordMessage(Address()).ShouldBe(InboundRateOutcome.TooManyMessages);
    }
}

/// <summary>
/// The limiter's own resource bounds. A rate limiter keyed by source address, with no cap on
/// how many addresses it will remember, is a memory-exhaustion vector reachable by anyone with
/// a botnet or a spoofable network — the defence becoming the vulnerability.
/// </summary>
public sealed class InboundRateLimiterResourceTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Never_tracks_more_addresses_than_its_cap()
    {
        InboundRateLimiter limiter = new(new ManualClock(Start));

        for (int i = 0; i < InboundRateLimiter.MaxTrackedAddresses + 5_000; i++)
        {
            limiter.RecordConnection(IpAddressValue.Parse(Fabricate(i)));
        }

        limiter.TrackedAddresses.ShouldBeLessThanOrEqualTo(InboundRateLimiter.MaxTrackedAddresses);
    }

    /// <summary>
    /// And when the table is full it admits rather than refuses. An over-full table means this
    /// server has lost track; refusing mail on the strength of a fact it does not have would
    /// turn a flood from one set of addresses into an outage for everybody else.
    /// </summary>
    [Fact]
    public void Admits_an_address_it_has_no_room_to_count()
    {
        InboundRateLimiter limiter = new(
            new ManualClock(Start), new InboundRateLimits(1, 1, TimeSpan.FromHours(1)));

        for (int i = 0; i < InboundRateLimiter.MaxTrackedAddresses + 100; i++)
        {
            limiter.RecordConnection(IpAddressValue.Parse(Fabricate(i)));
        }

        // A brand-new address the table has no room for. Its first connection is allowed,
        // where a counted address's second would not be.
        limiter.RecordConnection(IpAddressValue.Parse("203.0.113.254"))
            .ShouldBe(InboundRateOutcome.Allowed);
    }

    /// <summary>A flood leaves nothing behind once its window has passed.</summary>
    [Fact]
    public void Releases_everything_a_flood_allocated()
    {
        ManualClock clock = new(Start);
        InboundRateLimiter limiter = new(clock);

        for (int i = 0; i < 5_000; i++)
        {
            limiter.RecordConnection(IpAddressValue.Parse(Fabricate(i)));
        }

        limiter.TrackedAddresses.ShouldBe(5_000);

        clock.Advance(TimeSpan.FromHours(2));
        limiter.Sweep();

        limiter.TrackedAddresses.ShouldBe(0);
    }

    /// <summary>Counting from many threads at once must not lose or double a count.</summary>
    [Fact]
    public void Counts_correctly_under_concurrent_connections()
    {
        InboundRateLimiter limiter = new(
            new ManualClock(Start), new InboundRateLimits(1_000, 1_000, TimeSpan.FromHours(1)));

        IpAddressValue address = IpAddressValue.Parse("198.51.100.7");

        Parallel.For(0, 1_000, _ => limiter.RecordConnection(address));

        // The thousandth was the last one allowed, so the next must not be.
        limiter.RecordConnection(address).ShouldBe(InboundRateOutcome.TooManyConnections);
    }

    /// <summary>A distinct address per index, to fill the table with.</summary>
    private static string Fabricate(int i) => $"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}";
}
