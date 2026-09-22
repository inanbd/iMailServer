using System.Collections.Concurrent;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Filtering;

/// <summary>What an address is allowed, per window.</summary>
/// <param name="MaxConnections">Connections one address may open in a window.</param>
/// <param name="MaxMessages">Messages one address may deliver in a window.</param>
/// <param name="Window">How long the counts cover.</param>
public sealed record InboundRateLimits(int MaxConnections, int MaxMessages, TimeSpan Window)
{
    /// <summary>
    /// The default allowance.
    /// </summary>
    /// <remarks>
    /// Set from what a real exchanger does rather than from what feels safe. A large provider
    /// delivering a backlog opens connections in bursts and reuses each for several messages,
    /// so the message allowance is well above the connection one; both are far above anything
    /// a correspondent generates and far below what a delivery run of junk needs.
    /// </remarks>
    public static InboundRateLimits Default { get; } = new(120, 600, TimeSpan.FromHours(1));
}

/// <summary>What the limiter decided.</summary>
public enum InboundRateOutcome
{
    /// <summary>Within the allowance.</summary>
    Allowed = 0,

    /// <summary>Too many connections from this address in the window.</summary>
    TooManyConnections = 1,

    /// <summary>Too many messages from this address in the window.</summary>
    TooManyMessages = 2,
}

/// <summary>
/// Bounds how much one address may do over time, as opposed to at once.
/// </summary>
/// <remarks>
/// <para>
/// <b>The complement to <c>SmtpConnectionLimiter</c>, which bounds concurrency and nothing
/// else.</b> A peer that opens one connection, delivers, disconnects and repeats never exceeds
/// a concurrency cap however fast it goes. That is the shape of most junk delivery and of the
/// cheapest denial of service against a mail server, and only a rate limit sees it.
/// </para>
/// <para>
/// <b>In memory, not in the database.</b> A row written per inbound connection would make the
/// limiter an amplifier for the attack it exists to stop: one packet from a stranger becoming
/// one write here. The cost is that the counts are per process and reset on restart, which is
/// the right trade for abuse mitigation — the limit exists to make a flood expensive, not to
/// keep a ledger.
/// </para>
/// <para>
/// <b>The table of addresses is itself bounded, and that is not a detail.</b> A limiter keyed
/// by source address, with no cap on how many addresses it will remember, is a memory
/// exhaustion vector that anyone with a botnet or a spoofable network can reach — the defence
/// becoming the vulnerability. <see cref="MaxTrackedAddresses"/> caps it, and reaching the cap
/// admits the connection rather than refusing it: an over-full table means this server has
/// lost track, and refusing mail on the strength of a fact it does not have would turn a
/// flood from one set of addresses into an outage for everybody else.
/// </para>
/// <para>
/// <b>A fixed window, not a sliding one.</b> A sliding window needs a timestamp per event, so
/// an address at its limit would cost memory proportional to the limit rather than a single
/// counter. The cost is that a peer can send two windows' worth across a boundary; against
/// limits set this far above legitimate traffic, that is not the case worth paying for.
/// </para>
/// <para>Thread-safe; one instance serves every listener.</para>
/// </remarks>
public sealed class InboundRateLimiter(IClock clock, InboundRateLimits? limits = null)
{
    /// <summary>
    /// The most source addresses counted at once.
    /// </summary>
    /// <remarks>
    /// Ten thousand entries is a few hundred kilobytes and is far more distinct exchangers than
    /// any single installation hears from in an hour. It exists to bound the table, not to be
    /// reached in ordinary operation.
    /// </remarks>
    public const int MaxTrackedAddresses = 10_000;

    private readonly ConcurrentDictionary<string, Counter> _counters = new(StringComparer.Ordinal);
    private readonly InboundRateLimits _limits = limits ?? InboundRateLimits.Default;

    /// <summary>The allowance in force.</summary>
    public InboundRateLimits Limits => _limits;

    /// <summary>How many addresses are currently counted.</summary>
    public int TrackedAddresses => _counters.Count;

    /// <summary>Counts a connection from this address, and says whether it is within the allowance.</summary>
    public InboundRateOutcome RecordConnection(IpAddressValue address)
    {
        ArgumentNullException.ThrowIfNull(address);

        Counter? counter = Track(address);

        if (counter is null)
        {
            return InboundRateOutcome.Allowed;
        }

        lock (counter)
        {
            RollIfElapsed(counter);

            counter.Connections++;

            return counter.Connections > _limits.MaxConnections
                ? InboundRateOutcome.TooManyConnections
                : InboundRateOutcome.Allowed;
        }
    }

    /// <summary>Counts a message from this address, and says whether it is within the allowance.</summary>
    public InboundRateOutcome RecordMessage(IpAddressValue address)
    {
        ArgumentNullException.ThrowIfNull(address);

        Counter? counter = Track(address);

        if (counter is null)
        {
            return InboundRateOutcome.Allowed;
        }

        lock (counter)
        {
            RollIfElapsed(counter);

            counter.Messages++;

            return counter.Messages > _limits.MaxMessages
                ? InboundRateOutcome.TooManyMessages
                : InboundRateOutcome.Allowed;
        }
    }

    /// <summary>
    /// Drops counters whose window has passed.
    /// </summary>
    /// <remarks>
    /// Called on a timer rather than on every request. Sweeping inline would make each
    /// connection pay for every address the server has ever heard from, which is the cost
    /// profile the limiter exists to avoid.
    /// </remarks>
    public int Sweep()
    {
        DateTimeOffset now = clock.UtcNow;
        int removed = 0;

        foreach (KeyValuePair<string, Counter> entry in _counters)
        {
            bool stale;

            lock (entry.Value)
            {
                stale = now - entry.Value.WindowStarted >= _limits.Window;
            }

            if (stale && _counters.TryRemove(entry))
            {
                removed++;
            }
        }

        return removed;
    }

    /// <summary>
    /// Finds or creates this address's counter, or null when the table is full.
    /// </summary>
    /// <remarks>
    /// The check is on the way in rather than under a lock over the whole table: a check that
    /// serialised every connection behind one lock would be a bottleneck on the delivery path,
    /// and the cap only has to be approximately right — a handful of entries over it while two
    /// threads race costs nothing, where a lock on every inbound connection costs throughput on
    /// every inbound connection.
    /// </remarks>
    private Counter? Track(IpAddressValue address)
    {
        string key = address.ToString();

        if (_counters.TryGetValue(key, out Counter? existing))
        {
            return existing;
        }

        return _counters.Count >= MaxTrackedAddresses
            ? null
            : _counters.GetOrAdd(key, _ => new Counter { WindowStarted = clock.UtcNow });
    }

    /// <summary>Starts a new window if the old one has run out. Caller holds the counter's lock.</summary>
    private void RollIfElapsed(Counter counter)
    {
        DateTimeOffset now = clock.UtcNow;

        if (now - counter.WindowStarted < _limits.Window)
        {
            return;
        }

        counter.WindowStarted = now;
        counter.Connections = 0;
        counter.Messages = 0;
    }

    private sealed class Counter
    {
        public DateTimeOffset WindowStarted { get; set; }

        public int Connections { get; set; }

        public int Messages { get; set; }
    }
}
