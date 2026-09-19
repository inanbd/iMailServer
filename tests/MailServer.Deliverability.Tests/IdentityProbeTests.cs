using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>A resolver that answers from a script, so the probe's wiring can be tested.</summary>
internal sealed class ScriptedDiagnosticsService : IDnsDiagnosticsService
{
    private readonly Dictionary<(string Name, DnsDiagnosticRecordType Type), DnsDiagnosticAnswer> _answers =
        new();

    /// <summary>Every lookup the probe made, in order.</summary>
    public List<(string Name, DnsDiagnosticRecordType Type)> Asked { get; } = [];

    public ScriptedDiagnosticsService With(
        string name,
        DnsDiagnosticRecordType type,
        params string[] values)
    {
        _answers[(name, type)] = DnsDiagnosticAnswer.Success(values);
        return this;
    }

    /// <summary>Scripts a lookup that does not answer — a timeout or SERVFAIL.</summary>
    public ScriptedDiagnosticsService WithNoAnswer(string name, DnsDiagnosticRecordType type)
    {
        _answers[(name, type)] = DnsDiagnosticAnswer.Temporary("scripted timeout");
        return this;
    }

    public Task<DnsDiagnosticAnswer> LookupAsync(
        string name,
        DnsDiagnosticRecordType type,
        CancellationToken cancellationToken)
    {
        Asked.Add((name, type));

        // Anything not scripted answers with nothing, which is a fact rather than a failure.
        return Task.FromResult(_answers.TryGetValue((name, type), out DnsDiagnosticAnswer? answer)
            ? answer
            : DnsDiagnosticAnswer.Success([]));
    }

    public Task<DnsDiagnosticAnswer> LookupPointerAsync(
        IpAddressValue address,
        CancellationToken cancellationToken) =>
        LookupAsync(address.ToReverseDnsName(), DnsDiagnosticRecordType.Ptr, cancellationToken);
}

public sealed class IdentityProbeTests
{
    private static readonly DomainName Hostname = DomainName.Parse("mail.example.com");
    private static readonly IpAddressValue Sender = IpAddressValue.Parse("203.0.113.10");

    private const string ReverseName = "10.113.0.203.in-addr.arpa";

    private static Task<IdentityFacts> GatherAsync(
        ScriptedDiagnosticsService dns,
        IpAddressValue? address = null) =>
        new IdentityProbe(dns).GatherAsync(Hostname, address ?? Sender, CancellationToken.None);

    /// <summary>A correct configuration gathers facts that pass every check.</summary>
    [Fact]
    public async Task A_correct_configuration_gathers_passing_facts()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10")
            .With(ReverseName, DnsDiagnosticRecordType.Ptr, "mail.example.com");

        IdentityFacts facts = await GatherAsync(dns);

        IdentityChecks.Evaluate(facts)
            .ShouldAllBe(c => c.Outcome == DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// The probe's one real responsibility: telling "did not answer" apart from "answered with
    /// nothing". Collapsing them would turn every resolver outage into a configuration failure,
    /// and send an operator to change records that were already correct.
    /// </summary>
    [Fact]
    public async Task A_lookup_that_did_not_answer_is_not_an_empty_answer()
    {
        ScriptedDiagnosticsService unanswered = new ScriptedDiagnosticsService()
            .WithNoAnswer("mail.example.com", DnsDiagnosticRecordType.A)
            .WithNoAnswer("mail.example.com", DnsDiagnosticRecordType.Aaaa)
            .WithNoAnswer(ReverseName, DnsDiagnosticRecordType.Ptr);

        IdentityFacts facts = await GatherAsync(unanswered);

        facts.HostnameAddresses.ShouldBeNull();
        facts.PointerNames.ShouldBeNull();

        // An empty answer is a different thing, and a finding.
        IdentityFacts empty = await GatherAsync(new ScriptedDiagnosticsService());

        empty.HostnameAddresses.ShouldNotBeNull().ShouldBeEmpty();
        empty.PointerNames.ShouldNotBeNull().ShouldBeEmpty();
    }

    /// <summary>
    /// One address family answering is enough. A great many networks have no IPv6 resolver path,
    /// so an AAAA timeout alongside a successful A query says nothing about the configuration —
    /// and treating the pair as unanswered would make these checks inconclusive on most of the
    /// internet.
    /// </summary>
    [Fact]
    public async Task One_address_family_answering_is_an_answer()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10")
            .WithNoAnswer("mail.example.com", DnsDiagnosticRecordType.Aaaa)
            .With(ReverseName, DnsDiagnosticRecordType.Ptr, "mail.example.com");

        IdentityFacts facts = await GatherAsync(dns);

        facts.HostnameAddresses.ShouldNotBeNull().Select(a => a.Value).ShouldBe(["203.0.113.10"]);
    }

    /// <summary>Both families are gathered, so a v6-only server is not reported as unresolvable.</summary>
    [Fact]
    public async Task Both_address_families_are_gathered()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10")
            .With("mail.example.com", DnsDiagnosticRecordType.Aaaa, "2001:db8::1");

        IdentityFacts facts = await GatherAsync(dns);

        facts.HostnameAddresses.ShouldNotBeNull()
            .Select(a => a.Value)
            .ShouldBe(["203.0.113.10", "2001:db8::1"]);
    }

    /// <summary>
    /// A PTR name whose forward lookup did not answer is left out of the dictionary, not added
    /// with an empty list: the checks read the difference, and only one of the two is a finding.
    /// </summary>
    [Fact]
    public async Task A_pointer_name_that_did_not_resolve_is_absent_rather_than_empty()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With(ReverseName, DnsDiagnosticRecordType.Ptr, "silent.example.com", "empty.example.com")
            .WithNoAnswer("silent.example.com", DnsDiagnosticRecordType.A)
            .WithNoAnswer("silent.example.com", DnsDiagnosticRecordType.Aaaa);

        IdentityFacts facts = await GatherAsync(dns);

        facts.PointerForwardAddresses.ContainsKey("silent.example.com").ShouldBeFalse();
        facts.PointerForwardAddresses["empty.example.com"].ShouldBeEmpty();
    }

    /// <summary>
    /// With no sending address there is no reverse lookup to make, and the probe does not invent
    /// one.
    /// </summary>
    [Fact]
    public async Task Without_a_sending_address_no_reverse_lookup_is_attempted()
    {
        ScriptedDiagnosticsService dns = new();

        IdentityFacts facts = await new IdentityProbe(dns)
            .GatherAsync(Hostname, null, CancellationToken.None);

        facts.PublicAddress.ShouldBeNull();
        facts.PointerNames.ShouldBeNull();
        dns.Asked.ShouldNotContain(a => a.Type == DnsDiagnosticRecordType.Ptr);
    }

    /// <summary>
    /// The reverse name is built from the address, so a caller never has to know the difference
    /// between in-addr.arpa and the nibble-reversed ip6.arpa form.
    /// </summary>
    [Fact]
    public async Task The_reverse_name_is_built_from_the_address()
    {
        ScriptedDiagnosticsService v4 = new();
        await GatherAsync(v4);

        v4.Asked.ShouldContain((ReverseName, DnsDiagnosticRecordType.Ptr));

        ScriptedDiagnosticsService v6 = new();
        await GatherAsync(v6, IpAddressValue.Parse("2001:db8::1"));

        v6.Asked.ShouldContain(a =>
            a.Type == DnsDiagnosticRecordType.Ptr && a.Name.EndsWith("ip6.arpa", StringComparison.Ordinal));
    }

    /// <summary>A value that is not an address is dropped rather than crashing the probe.</summary>
    [Fact]
    public async Task A_malformed_address_record_is_ignored()
    {
        ScriptedDiagnosticsService dns = new ScriptedDiagnosticsService()
            .With("mail.example.com", DnsDiagnosticRecordType.A, "not-an-address", "203.0.113.10");

        IdentityFacts facts = await GatherAsync(dns);

        facts.HostnameAddresses.ShouldNotBeNull().Select(a => a.Value).ShouldBe(["203.0.113.10"]);
    }
}
