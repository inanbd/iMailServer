using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;
using MailServer.Application.Abstractions.Time;

namespace MailServer.Deliverability.Tests;

/// <summary>A clock the test moves by hand, and a delay that records instead of waiting.</summary>
internal sealed class TestThrottleClock(DateTimeOffset? start = null) : IClock
{
    private DateTimeOffset _now = start ?? new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Every span the throttle asked to wait for, in order.</summary>
    public List<TimeSpan> Waits { get; } = [];

    public DateTimeOffset UtcNow => _now;

    public long GetTimestamp() => _now.UtcTicks;

    public TimeSpan GetElapsedTime(long startingTimestamp) =>
        TimeSpan.FromTicks(_now.UtcTicks - startingTimestamp);

    public void Advance(TimeSpan span) => _now += span;

    /// <summary>
    /// Records the wait and advances the clock by it, rather than sleeping.
    /// </summary>
    /// <remarks>
    /// Advancing is what makes this honest: the code under test reads the clock again after the
    /// delay, and a fake that stood still would let a throttle that never waits pass.
    /// </remarks>
    public Task DelayAsync(TimeSpan span, CancellationToken cancellationToken)
    {
        Waits.Add(span);
        Advance(span);

        return Task.CompletedTask;
    }
}

public sealed class DnsBlockListProviderTests
{
    private static readonly IpAddressValue Address = IpAddressValue.Parse("203.0.113.10");
    private static readonly DomainName Domain = DomainName.Parse("example.com");

    private const string Zone = "bl.example.net";
    private const string DomainZone = "dbl.example.net";

    /// <summary>A list whose RFC 5782 §5 test entries answer correctly.</summary>
    private static ScriptedDiagnosticsService Healthy(string zone = Zone) =>
        new ScriptedDiagnosticsService()
            .With($"2.0.0.127.{zone}", DnsDiagnosticRecordType.A, "127.0.0.2");

    private static DnsBlockListProvider Provider(
        ScriptedDiagnosticsService dns,
        TestThrottleClock? clock = null,
        ReputationListSubject subject = ReputationListSubject.Address,
        string zone = Zone)
    {
        TestThrottleClock c = clock ?? new TestThrottleClock();

        return new DnsBlockListProvider(dns, [new ReputationList(zone, subject)], c, c.DelayAsync);
    }

    // ---------------------------------------------------------------------------------------
    // The query name.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The octets are reversed, and the reverse-DNS suffix is not carried over.
    /// </summary>
    /// <remarks>
    /// RFC 5782 §2.1 builds the name "by reversing the order of the components of the dotted text
    /// representation of the IP address, and appending the domain name of the DNSxL". The
    /// <c>in-addr.arpa</c> suffix belongs to reverse DNS and not to a list's zone — leaving it on
    /// would query a name no list serves, and every address would come back clean.
    /// </remarks>
    [Fact]
    public void The_query_name_reverses_the_octets_without_the_arpa_suffix()
    {
        DnsBlockListProvider.ReversedOctets(Address).ShouldBe("10.113.0.203");

        DnsBlockListProvider.ReversedOctets(IpAddressValue.Parse("2001:db8::1"))
            .ShouldNotContain("arpa");
    }

    /// <summary>The list is asked about the reversed address under its own zone.</summary>
    [Fact]
    public async Task The_list_is_asked_about_the_reversed_address()
    {
        ScriptedDiagnosticsService dns = Healthy();

        await Provider(dns).CheckAddressAsync(Address, CancellationToken.None);

        dns.Asked.ShouldContain(($"10.113.0.203.{Zone}", DnsDiagnosticRecordType.A));
    }

    /// <summary>A domain list is asked about the domain as it stands.</summary>
    [Fact]
    public async Task A_domain_list_is_asked_about_the_domain_itself()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With($"TEST.{DomainZone}", DnsDiagnosticRecordType.A, "127.0.0.2");

        await Provider(dns, subject: ReputationListSubject.Domain, zone: DomainZone)
            .CheckDomainAsync(Domain, CancellationToken.None);

        dns.Asked.ShouldContain(($"example.com.{DomainZone}", DnsDiagnosticRecordType.A));
    }

    // ---------------------------------------------------------------------------------------
    // Listings.
    // ---------------------------------------------------------------------------------------

    /// <summary>An A record at the query name is a listing; its value is the code.</summary>
    [Fact]
    public async Task An_a_record_at_the_query_name_is_a_listing()
    {
        ScriptedDiagnosticsService dns = Healthy()
            .With($"10.113.0.203.{Zone}", DnsDiagnosticRecordType.A, "127.0.0.4");

        ReputationListing listing = (await Provider(dns)
            .CheckAddressAsync(Address, CancellationToken.None)).Single();

        listing.Listed.ShouldBeTrue();
        listing.Codes.ShouldBe(["127.0.0.4"]);
        listing.Health.ShouldBe(ReputationListHealth.Healthy);
    }

    /// <summary>No A record is not a listing.</summary>
    [Fact]
    public async Task No_a_record_is_not_a_listing()
    {
        ReputationListing listing = (await Provider(Healthy())
            .CheckAddressAsync(Address, CancellationToken.None)).Single();

        listing.Listed.ShouldBeFalse();
        listing.Health.ShouldBe(ReputationListHealth.Healthy);
    }

    /// <summary>
    /// The TXT record is read only for a listing, and carried as the reason.
    /// </summary>
    /// <remarks>
    /// RFC 5782 §2.1: the TXT record "describes the reason that the IP address is listed". Asking
    /// for it when the address is not listed would double this provider's query count against
    /// volunteer-run infrastructure to learn nothing.
    /// </remarks>
    [Fact]
    public async Task The_reason_is_read_only_for_a_listing()
    {
        ScriptedDiagnosticsService listed = Healthy()
            .With($"10.113.0.203.{Zone}", DnsDiagnosticRecordType.A, "127.0.0.2")
            .With($"10.113.0.203.{Zone}", DnsDiagnosticRecordType.Txt, "Dynamic address range");

        ReputationListing listing = (await Provider(listed)
            .CheckAddressAsync(Address, CancellationToken.None)).Single();

        listing.Reason.ShouldBe("Dynamic address range");

        ScriptedDiagnosticsService clean = Healthy();

        await Provider(clean).CheckAddressAsync(Address, CancellationToken.None);

        clean.Asked.ShouldNotContain(($"10.113.0.203.{Zone}", DnsDiagnosticRecordType.Txt));
    }

    // ---------------------------------------------------------------------------------------
    // The self-test.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A list that lists 127.0.0.1 is answering wrongly, and is not asked about the real address.
    /// </summary>
    /// <remarks>
    /// RFC 5782 §5: "IPv4-based DNSxLs MUST NOT contain an entry for 127.0.0.1." A list that
    /// returns one is answering "listed" for everything, which is what being cut off looks
    /// like. Asking it about the operator's address would spend a query to obtain noise.
    /// </remarks>
    [Fact]
    public async Task A_list_that_lists_the_must_not_entry_is_unreliable()
    {
        ScriptedDiagnosticsService dns = Healthy()
            .With($"1.0.0.127.{Zone}", DnsDiagnosticRecordType.A, "127.0.0.2")
            .With($"10.113.0.203.{Zone}", DnsDiagnosticRecordType.A, "127.0.0.2");

        ReputationListing listing = (await Provider(dns)
            .CheckAddressAsync(Address, CancellationToken.None)).Single();

        listing.Health.ShouldBe(ReputationListHealth.Unreliable);
        listing.Listed.ShouldBeFalse();

        dns.Asked.ShouldNotContain(($"10.113.0.203.{Zone}", DnsDiagnosticRecordType.A));
    }

    /// <summary>
    /// A list that does not carry 127.0.0.2 is not answering this server.
    /// </summary>
    /// <remarks>
    /// §5: it "MUST contain an entry for 127.0.0.2 for testing purposes." A zone that answers
    /// nothing at all reports as silent rather than as clean, because "nobody listed you" and
    /// "nobody answered" are different facts and only one is good news.
    /// </remarks>
    [Fact]
    public async Task A_list_missing_the_test_entry_is_not_answering()
    {
        ReputationListing listing = (await Provider(new ScriptedDiagnosticsService())
            .CheckAddressAsync(Address, CancellationToken.None)).Single();

        listing.Health.ShouldBe(ReputationListHealth.NotAnswering);

        ReputationFacts facts = new(Domain, Address, [listing], null);

        ReputationChecks.Evaluate(facts)
            .Single(c => c.Id == ReputationChecks.IpNotListedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>A domain list is self-tested with RFC 2606's reserved names, per §5.</summary>
    [Fact]
    public async Task A_domain_list_is_self_tested_with_the_reserved_names()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With($"TEST.{DomainZone}", DnsDiagnosticRecordType.A, "127.0.0.2");

        await Provider(dns, subject: ReputationListSubject.Domain, zone: DomainZone)
            .CheckDomainAsync(Domain, CancellationToken.None);

        dns.Asked.ShouldContain(($"TEST.{DomainZone}", DnsDiagnosticRecordType.A));
        dns.Asked.ShouldContain(($"INVALID.{DomainZone}", DnsDiagnosticRecordType.A));
    }

    // ---------------------------------------------------------------------------------------
    // Caching and rate limiting — an obligation, not an optimisation.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A second check within the cache lifetime asks the list nothing.
    /// </summary>
    /// <remarks>
    /// <c>docs/Deliverability.md</c>: "Naïve DNSBL querying from a busy MTA gets you blocked by
    /// the DNSBL operator and is an abuse of volunteer infrastructure." An admin page that
    /// re-ran this report on every refresh would do exactly that.
    /// </remarks>
    [Fact]
    public async Task A_repeated_check_is_served_from_the_cache()
    {
        ScriptedDiagnosticsService dns = Healthy();
        TestThrottleClock clock = new();
        DnsBlockListProvider provider = Provider(dns, clock);

        await provider.CheckAddressAsync(Address, CancellationToken.None);

        int first = dns.Asked.Count;

        await provider.CheckAddressAsync(Address, CancellationToken.None);

        dns.Asked.Count.ShouldBe(first);
    }

    /// <summary>Past the cache lifetime the list is asked again.</summary>
    [Fact]
    public async Task Past_the_cache_lifetime_the_list_is_asked_again()
    {
        ScriptedDiagnosticsService dns = Healthy();
        TestThrottleClock clock = new();
        DnsBlockListProvider provider = Provider(dns, clock);

        await provider.CheckAddressAsync(Address, CancellationToken.None);

        int first = dns.Asked.Count;

        clock.Advance(DnsBlockListProvider.CacheLifetime + TimeSpan.FromSeconds(1));

        await provider.CheckAddressAsync(Address, CancellationToken.None);

        dns.Asked.Count.ShouldBeGreaterThan(first);
    }

    /// <summary>
    /// Two queries to the same list are spaced out.
    /// </summary>
    /// <remarks>
    /// The self-test alone is two queries per list, and a check with a listing is two more. The
    /// throttle is what keeps that from arriving as a burst.
    /// </remarks>
    [Fact]
    public async Task Queries_to_one_list_are_spaced_out()
    {
        ScriptedDiagnosticsService dns = Healthy()
            .With($"10.113.0.203.{Zone}", DnsDiagnosticRecordType.A, "127.0.0.2");

        TestThrottleClock clock = new();

        await Provider(dns, clock).CheckAddressAsync(Address, CancellationToken.None);

        // Four queries to one zone: the two test entries, the address, and its TXT reason. The
        // first goes out at once and each of the rest waits, so three waits of the full interval.
        dns.Asked.Count.ShouldBe(4);
        clock.Waits.Count.ShouldBe(3);
        clock.Waits.ShouldAllBe(w => w == DnsBlockListProvider.MinimumInterval);
    }

    /// <summary>The lists this provider will query are named, so the report can say which.</summary>
    [Fact]
    public void The_configured_lists_are_reported()
    {
        Provider(Healthy()).Lists.ShouldBe([Zone]);
    }

    /// <summary>
    /// With no list configured, nothing is asked of anybody.
    /// </summary>
    /// <remarks>
    /// Querying a third party about the operator's own address is a request this server makes on
    /// their behalf to an organisation they have not chosen. It happens only once they name the
    /// lists.
    /// </remarks>
    [Fact]
    public async Task With_no_list_configured_nothing_is_queried()
    {
        ScriptedDiagnosticsService dns = new();

        TestThrottleClock clock = new();

        DnsBlockListProvider provider = new(dns, [], clock, clock.DelayAsync);

        (await provider.CheckAddressAsync(Address, CancellationToken.None)).ShouldBeEmpty();
        (await provider.CheckDomainAsync(Domain, CancellationToken.None)).ShouldBeEmpty();

        dns.Asked.ShouldBeEmpty();
    }

    /// <summary>An address list is not asked about a domain, or the reverse.</summary>
    [Fact]
    public async Task A_list_is_only_asked_about_what_it_lists()
    {
        ScriptedDiagnosticsService dns = Healthy();

        (await Provider(dns).CheckDomainAsync(Domain, CancellationToken.None)).ShouldBeEmpty();

        dns.Asked.ShouldBeEmpty();
    }
}
