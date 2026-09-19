using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

public sealed class DnsProbeTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");
    private static readonly DomainName Hostname = DomainName.Parse("mail.example.com");

    private const string Issuer = "letsencrypt.org";

    private static Task<DnsFacts> Gather(ScriptedDiagnosticsService dns, string? issuer = Issuer) =>
        new DnsProbe(dns).GatherAsync(Domain, Hostname, issuer, CancellationToken.None);

    // ---------------------------------------------------------------------------------------
    // MX records.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An MX value arrives as <c>preference host</c> and is split back into the two.
    /// </summary>
    /// <remarks>
    /// The rendering is <c>DnsDiagnosticsService</c>'s, chosen so an operator sees the same text
    /// the DNS panel shows. Splitting it back is this probe's job, and getting the halves the
    /// wrong way round would put a host name where a preference belongs in every finding.
    /// </remarks>
    [Fact]
    public async Task An_mx_value_is_split_into_preference_and_host()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Mx, "10 mail.example.com", "20 mx2.example.com")
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10")
            .With("mx2.example.com", DnsDiagnosticRecordType.A, "198.51.100.7");

        DnsFacts facts = await Gather(dns);

        IReadOnlyList<MxTarget> mx = facts.MxRecords.ShouldNotBeNull();

        mx.Count.ShouldBe(2);
        mx[0].Preference.ShouldBe(10);
        mx[0].Host.ShouldBe("mail.example.com");
        mx[1].Preference.ShouldBe(20);
        mx[1].Host.ShouldBe("mx2.example.com");
    }

    /// <summary>Each target's addresses are attached to that target.</summary>
    [Fact]
    public async Task Each_mx_targets_addresses_are_attached_to_it()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Mx, "10 mail.example.com")
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10")
            .With("mail.example.com", DnsDiagnosticRecordType.Aaaa, "2001:db8::10");

        DnsFacts facts = await Gather(dns);

        MxTarget target = facts.MxRecords.ShouldNotBeNull().Single();

        target.Addresses.ShouldNotBeNull().Select(a => a.ToString())
            .ShouldBe(["203.0.113.10", "2001:db8::10"]);
    }

    /// <summary>
    /// A malformed MX value is not carried as a route.
    /// </summary>
    /// <remarks>
    /// Inventing a preference for something that did not parse would put a record in the report
    /// that DNS never returned, and the operator would go looking for it in their zone.
    /// </remarks>
    [Fact]
    public async Task A_malformed_mx_value_is_left_out()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Mx, "not-an-mx", "10 mail.example.com")
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10");

        DnsFacts facts = await Gather(dns);

        facts.MxRecords.ShouldNotBeNull().Single().Host.ShouldBe("mail.example.com");
    }

    /// <summary>
    /// The null MX is carried through without a lookup on it.
    /// </summary>
    /// <remarks>
    /// RFC 7505's "." names no host. Querying it would put a lookup for the root in the report
    /// and invite an operator to fix something that is not broken.
    /// </remarks>
    [Fact]
    public async Task The_null_mx_is_carried_without_being_resolved()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Mx, "0 .");

        DnsFacts facts = await Gather(dns);

        MxTarget target = facts.MxRecords.ShouldNotBeNull().Single();

        target.IsNull.ShouldBeTrue();
        dns.Asked.ShouldNotContain((".", DnsDiagnosticRecordType.A));

        DnsChecks.Evaluate(facts)
            .Single(c => c.Id == DnsChecks.MxPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>A CNAME at an MX target is noticed.</summary>
    [Fact]
    public async Task A_cname_at_an_mx_target_is_noticed()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Mx, "10 mail.example.com")
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10")
            .With("mail.example.com", DnsDiagnosticRecordType.Cname, "real.example.net");

        DnsFacts facts = await Gather(dns);

        facts.MxRecords.ShouldNotBeNull().Single().IsAlias.ShouldBeTrue();

        DnsChecks.Evaluate(facts)
            .Single(c => c.Id == DnsChecks.MxNotAliasId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>The MX answer's TTL is carried, since the TTL check judges it.</summary>
    [Fact]
    public async Task The_mx_ttl_is_carried_through()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .WithTtl("example.com", DnsDiagnosticRecordType.Mx, TimeSpan.FromSeconds(60), "10 mail.example.com")
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10");

        DnsFacts facts = await Gather(dns);

        facts.MxTtl.ShouldBe(TimeSpan.FromSeconds(60));

        DnsChecks.Evaluate(facts)
            .Single(c => c.Id == DnsChecks.TtlSanityId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    // ---------------------------------------------------------------------------------------
    // Answered against not answered.
    // ---------------------------------------------------------------------------------------

    /// <summary>A domain with no MX answers with an empty list, which is a fact.</summary>
    [Fact]
    public async Task A_domain_with_no_mx_yields_an_empty_list()
    {
        DnsFacts facts = await Gather(new ScriptedDiagnosticsService());

        facts.MxRecords.ShouldNotBeNull().ShouldBeEmpty();

        DnsChecks.Evaluate(facts)
            .Single(c => c.Id == DnsChecks.MxPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>An MX lookup that did not answer yields null, and nothing is judged.</summary>
    [Fact]
    public async Task An_unanswered_mx_lookup_yields_null()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .WithNoAnswer("example.com", DnsDiagnosticRecordType.Mx);

        DnsFacts facts = await Gather(dns);

        facts.MxRecords.ShouldBeNull();

        DnsChecks.Evaluate(facts)
            .Single(c => c.Id == DnsChecks.MxPublishedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// A target whose address lookups both failed yields null addresses, not none.
    /// </summary>
    /// <remarks>
    /// The difference between "this host has no address record" — a fault the operator must fix
    /// — and "the resolver did not answer", which is not about their configuration at all.
    /// </remarks>
    [Fact]
    public async Task An_mx_target_whose_lookups_failed_yields_null_addresses()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Mx, "10 mail.example.com")
            .WithNoAnswer("mail.example.com", DnsDiagnosticRecordType.A)
            .WithNoAnswer("mail.example.com", DnsDiagnosticRecordType.Aaaa);

        DnsFacts facts = await Gather(dns);

        facts.MxRecords.ShouldNotBeNull().Single().Addresses.ShouldBeNull();
    }

    /// <summary>
    /// One address family answering is an answer.
    /// </summary>
    /// <remarks>
    /// The same reasoning as <c>IdentityProbe</c>: a great many networks have no IPv6 resolver
    /// path, so treating a timed-out AAAA as "did not answer" would leave the MX checks
    /// inconclusive on most of the internet.
    /// </remarks>
    [Fact]
    public async Task One_address_family_answering_is_enough()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Mx, "10 mail.example.com")
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10")
            .WithNoAnswer("mail.example.com", DnsDiagnosticRecordType.Aaaa);

        DnsFacts facts = await Gather(dns);

        facts.MxRecords.ShouldNotBeNull().Single().Addresses.ShouldNotBeNull().Count.ShouldBe(1);
    }

    // ---------------------------------------------------------------------------------------
    // CAA.
    // ---------------------------------------------------------------------------------------

    /// <summary>A CAA record at the domain itself is found.</summary>
    [Fact]
    public async Task A_caa_record_at_the_domain_is_found()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Caa, "0 issue \"letsencrypt.org\"");

        DnsFacts facts = await Gather(dns);

        facts.CaaRecords.ShouldBe(["0 issue \"letsencrypt.org\""]);
    }

    /// <summary>
    /// The walk continues up the tree until it finds a set.
    /// </summary>
    /// <remarks>
    /// RFC 8659 §3's worked example: "CAA('X.Y.Z.') = Empty; domain = Parent('X.Y.Z.') = 'Y.Z.'"
    /// and onwards. A probe that asked only at the domain would report "no restriction" for a
    /// domain whose parent forbids the issuer — the exact case where a restriction was published
    /// once, at the registered domain, and forgotten.
    /// </remarks>
    [Fact]
    public async Task The_caa_walk_climbs_to_a_parent()
    {
        DnsProbe probe = new(new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Caa, "0 issue \"digicert.com\""));

        DnsFacts facts = await probe.GatherAsync(
            DomainName.Parse("mail.sub.example.com"),
            Hostname,
            Issuer,
            CancellationToken.None);

        facts.CaaRecords.ShouldBe(["0 issue \"digicert.com\""]);

        DnsChecks.Evaluate(facts)
            .Single(c => c.Id == DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    /// <summary>
    /// The nearest set wins; the walk stops at it.
    /// </summary>
    /// <remarks>
    /// §3 returns the first non-empty set found on the way up, so a permissive record at the
    /// subdomain overrides a restrictive one at the parent rather than being merged with it.
    /// </remarks>
    [Fact]
    public async Task The_nearest_caa_set_stops_the_walk()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("sub.example.com", DnsDiagnosticRecordType.Caa, "0 issue \"letsencrypt.org\"")
            .With("example.com", DnsDiagnosticRecordType.Caa, "0 issue \"digicert.com\"");

        DnsFacts facts = await new DnsProbe(dns).GatherAsync(
            DomainName.Parse("sub.example.com"),
            Hostname,
            Issuer,
            CancellationToken.None);

        facts.CaaRecords.ShouldBe(["0 issue \"letsencrypt.org\""]);
        dns.Asked.ShouldNotContain(("example.com", DnsDiagnosticRecordType.Caa));
    }

    /// <summary>A completed walk that found nothing is an empty list, which means unrestricted.</summary>
    [Fact]
    public async Task A_completed_caa_walk_that_found_nothing_is_an_empty_list()
    {
        DnsFacts facts = await Gather(new ScriptedDiagnosticsService());

        facts.CaaRecords.ShouldNotBeNull().ShouldBeEmpty();

        DnsChecks.Evaluate(facts)
            .Single(c => c.Id == DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// A walk in which nothing answered is null, not an empty set.
    /// </summary>
    /// <remarks>
    /// "No CAA record restricts issuance" is a conclusion, and it must not be drawn from a
    /// resolver that said nothing — the check would pass a domain whose CAA forbids the issuer.
    /// </remarks>
    [Fact]
    public async Task A_caa_walk_where_nothing_answered_is_null()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .WithNoAnswer("example.com", DnsDiagnosticRecordType.Caa)
            .WithNoAnswer("com", DnsDiagnosticRecordType.Caa);

        DnsFacts facts = await Gather(dns);

        facts.CaaRecords.ShouldBeNull();

        DnsChecks.Evaluate(facts)
            .Single(c => c.Id == DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>The walk is bounded, whatever name it is handed.</summary>
    [Fact]
    public async Task The_caa_walk_is_bounded()
    {
        ScriptedDiagnosticsService dns = new();

        string deep = string.Join(".", Enumerable.Range(0, 40).Select(i => $"l{i}"));

        await new DnsProbe(dns).GatherAsync(
            DomainName.Parse(deep),
            Hostname,
            Issuer,
            CancellationToken.None);

        dns.Asked.Count(a => a.Type == DnsDiagnosticRecordType.Caa)
            .ShouldBe(DnsProbe.MaxCaaAncestors);
    }
}
