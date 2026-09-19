using System.Globalization;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>
/// What the identity probe observed, so that judging it needs no resolver.
/// </summary>
/// <remarks>
/// <para>
/// Gathering and judging are separate for the reason the protocol handlers separate transport
/// from decisions: every rule below is then testable against a hand-written set of facts, and
/// the rules are where the subtlety is. A resolver that had to be mocked to test "the PTR name
/// resolves back to the sending address" would make the interesting half of this file the hard
/// half to cover.
/// </para>
/// <para>
/// A null field means the lookup did not answer, which
/// <see cref="DeliverabilityOutcome.Inconclusive"/> exists for. An empty list means it answered
/// and there was nothing there, which is a finding.
/// </para>
/// </remarks>
/// <param name="Hostname">
/// The name this server calls itself — <c>MailServer:Server:Hostname</c>, which is what it sends
/// in EHLO and what its certificate should name.
/// </param>
/// <param name="PublicAddress">
/// The address mail actually leaves from, or null when it could not be determined. Not the same
/// as an address the hostname resolves to: a server behind NAT, or one with several addresses,
/// sends from one of them and a receiver's PTR check looks at that one.
/// </param>
/// <param name="HostnameAddresses">
/// The addresses <paramref name="Hostname"/> resolves to, or null when the lookup did not answer.
/// </param>
/// <param name="PointerNames">
/// The names <paramref name="PublicAddress"/>'s PTR records give, or null when the lookup did not
/// answer.
/// </param>
/// <param name="PointerForwardAddresses">
/// For each PTR name, the addresses it resolves forward to. A name missing from the dictionary
/// is one whose forward lookup did not answer.
/// </param>
public sealed record IdentityFacts(
    DomainName Hostname,
    IpAddressValue? PublicAddress,
    IReadOnlyList<IpAddressValue>? HostnameAddresses,
    IReadOnlyList<string>? PointerNames,
    IReadOnlyDictionary<string, IReadOnlyList<IpAddressValue>> PointerForwardAddresses);

/// <summary>
/// The Identity category: does this server look, to a receiver, like what it claims to be?
/// </summary>
/// <remarks>
/// <para>
/// <c>docs/DNS.md</c> is blunt about why this category exists and why it is weighted as heavily
/// as it is: "<b>Major receivers reject or spam-folder mail from IPs without correct FCrDNS.</b>
/// It is not optional, it cannot be fixed in your own DNS zone, and it is the single most common
/// reason a self-hosted server cannot deliver to Gmail. If your provider will not set a PTR
/// record, you cannot run a public mail server on that IP — no amount of correct SPF, DKIM or
/// DMARC compensates."
/// </para>
/// <para>
/// That last sentence is why the remedies here name the IP's owner rather than the operator's
/// DNS panel. A PTR record lives in the reverse zone, which belongs to whoever assigned the
/// address; telling an operator to "add a PTR record" sends them somewhere they have no
/// authority, and they will conclude the tool is wrong.
/// </para>
/// </remarks>
public static class IdentityChecks
{
    /// <summary>The check ids, so a caller can refer to one without repeating a string.</summary>
    public const string HostnameResolvesId = "identity.hostname-resolves";

    /// <summary>The PTR check's id.</summary>
    public const string PointerId = "identity.ptr";

    /// <summary>The forward-confirmed reverse DNS check's id.</summary>
    public const string ForwardConfirmedId = "identity.fcrdns";

    /// <summary>The EHLO-agreement check's id.</summary>
    public const string HeloMatchesPointerId = "identity.ehlo-matches-ptr";

    /// <summary>Judges a set of observations. Pure: same facts, same checks, every time.</summary>
    public static IReadOnlyList<DeliverabilityCheck> Evaluate(IdentityFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        return
        [
            HostnameResolves(facts),
            Pointer(facts),
            ForwardConfirmed(facts),
            HeloMatchesPointer(facts),
        ];
    }

    /// <summary>
    /// The name this server calls itself resolves to an address.
    /// </summary>
    /// <remarks>
    /// A hostname that resolves to nothing fails every downstream expectation at once: the MX
    /// target cannot point at it usefully, a receiver doing a forward lookup on the EHLO name
    /// finds nothing, and the certificate names something that does not exist.
    /// </remarks>
    private static DeliverabilityCheck HostnameResolves(IdentityFacts facts)
    {
        const string Id = HostnameResolvesId;
        const string Title = "The server's hostname resolves";

        if (facts.HostnameAddresses is not { } addresses)
        {
            return Unmeasured(Id, Title, weight: 1, $"No answer for {facts.Hostname.Value}.");
        }

        DeliverabilityEvidence evidence = new(
            $"An A or AAAA record for {facts.Hostname.Value}",
            addresses.Count == 0 ? null : string.Join(", ", addresses.Select(a => a.Value)));

        return addresses.Count == 0
            ? new DeliverabilityCheck(
                Id,
                DeliverabilityCategory.Identity,
                Title,
                1,
                DeliverabilityOutcome.Fail,
                $"{facts.Hostname.Value} has no address record, so nothing a receiver looks up " +
                "about this server will resolve.",
                evidence,
                $"Publish an A record (or AAAA) for {facts.Hostname.Value} pointing at this " +
                "server's public address.")
            : new DeliverabilityCheck(
                Id,
                DeliverabilityCategory.Identity,
                Title,
                1,
                DeliverabilityOutcome.Pass,
                $"{facts.Hostname.Value} resolves to {addresses.Count} address(es).",
                evidence);
    }

    /// <summary>
    /// The sending address has a PTR record.
    /// </summary>
    /// <remarks>
    /// Weighted highest in the category, because <c>docs/DNS.md</c> makes it the thing that
    /// cannot be compensated for. The remedy names the address's owner: the reverse zone is
    /// theirs, not the operator's.
    /// </remarks>
    private static DeliverabilityCheck Pointer(IdentityFacts facts)
    {
        const string Id = PointerId;
        const string Title = "The sending address has a PTR record";
        const int Weight = 3;

        if (facts.PublicAddress is not { } address)
        {
            return Unmeasured(
                Id,
                Title,
                Weight,
                "This server's public sending address could not be determined, so its reverse " +
                "DNS could not be looked up.");
        }

        if (facts.PointerNames is not { } names)
        {
            return Unmeasured(Id, Title, Weight, $"No answer for {address.ToReverseDnsName()}.");
        }

        DeliverabilityEvidence evidence = new(
            $"A PTR record at {address.ToReverseDnsName()}",
            names.Count == 0 ? null : string.Join(", ", names));

        return names.Count == 0
            ? new DeliverabilityCheck(
                Id,
                DeliverabilityCategory.Identity,
                Title,
                Weight,
                DeliverabilityOutcome.Fail,
                $"{address.Value} has no reverse DNS. Major receivers reject or spam-folder " +
                "mail from addresses without it, and no amount of correct SPF, DKIM or DMARC " +
                "compensates.",
                evidence,
                "Ask whoever assigned this address — your hosting provider, datacentre or ISP — " +
                $"to publish a PTR record for {address.Value} naming {facts.Hostname.Value}. " +
                "This cannot be fixed in your own DNS zone. If they will not, this address " +
                "cannot be used to run a public mail server.")
            : new DeliverabilityCheck(
                Id,
                DeliverabilityCategory.Identity,
                Title,
                Weight,
                DeliverabilityOutcome.Pass,
                $"{address.Value} reverses to {string.Join(", ", names)}.",
                evidence);
    }

    /// <summary>
    /// The PTR name resolves forward to the same address.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>docs/DNS.md</c>: "Forward-Confirmed reverse DNS means the PTR for your sending IP
    /// resolves to a name, and that name resolves back to the same IP."
    /// </para>
    /// <para>
    /// <b>One confirming name is enough.</b> An address may legitimately have several PTR
    /// records, and a receiver checking FCrDNS is satisfied by finding one that round-trips.
    /// Requiring all of them to round-trip would fail a correct configuration.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck ForwardConfirmed(IdentityFacts facts)
    {
        const string Id = ForwardConfirmedId;
        const string Title = "Reverse DNS is forward-confirmed";
        const int Weight = 3;

        if (facts.PublicAddress is not { } address)
        {
            return Unmeasured(
                Id,
                Title,
                Weight,
                "This server's public sending address could not be determined.");
        }

        if (facts.PointerNames is not { } names || names.Count == 0)
        {
            // Nothing to confirm, and the PTR check above has already said so. Reporting this
            // as a second failure would charge an operator twice for one missing record.
            return Unmeasured(
                Id,
                Title,
                Weight,
                "There is no PTR record to confirm; see the reverse DNS check.");
        }

        List<string> confirmed = [];
        bool anyUnresolved = false;

        foreach (string name in names)
        {
            if (!facts.PointerForwardAddresses.TryGetValue(name, out IReadOnlyList<IpAddressValue>? forward))
            {
                anyUnresolved = true;
                continue;
            }

            if (forward.Contains(address))
            {
                confirmed.Add(name);
            }
        }

        DeliverabilityEvidence evidence = new(
            $"A name in {string.Join(", ", names)} resolving back to {address.Value}",
            confirmed.Count > 0 ? string.Join(", ", confirmed) : Describe(facts, names));

        if (confirmed.Count > 0)
        {
            return new DeliverabilityCheck(
                Id,
                DeliverabilityCategory.Identity,
                Title,
                Weight,
                DeliverabilityOutcome.Pass,
                $"{confirmed[0]} resolves back to {address.Value}.",
                evidence);
        }

        // Every forward lookup failed to answer: that is a resolver problem, not the operator's.
        return anyUnresolved && facts.PointerForwardAddresses.Count == 0
            ? Unmeasured(
                Id,
                Title,
                Weight,
                "The PTR name's forward lookup did not answer, so the round trip could not be " +
                "confirmed.")
            : new DeliverabilityCheck(
                Id,
                DeliverabilityCategory.Identity,
                Title,
                Weight,
                DeliverabilityOutcome.Fail,
                $"{address.Value} reverses to {string.Join(", ", names)}, but no such name " +
                "resolves back to it. Receivers treat that as an unconfirmed identity.",
                evidence,
                $"Publish an A or AAAA record for {names[0]} pointing at {address.Value}, or ask " +
                "the address's owner to correct the PTR record to a name that already does.");
    }

    /// <summary>
    /// The EHLO name, the PTR name and the certificate name are the same name.
    /// </summary>
    /// <remarks>
    /// <c>docs/DNS.md</c>: "The EHLO name, the PTR record, the TLS certificate SAN and the MX
    /// target must all agree." This checks the first two against each other; the certificate is
    /// the TLS category's business and the MX target is the DNS category's, so each pair is
    /// reported where an operator would look for it.
    /// </remarks>
    private static DeliverabilityCheck HeloMatchesPointer(IdentityFacts facts)
    {
        const string Id = HeloMatchesPointerId;
        const string Title = "The EHLO name matches the PTR record";
        const int Weight = 2;

        if (facts.PointerNames is not { } names || names.Count == 0)
        {
            return Unmeasured(
                Id,
                Title,
                Weight,
                "There is no PTR record to compare the EHLO name against.");
        }

        // DNS names are case-insensitive and a PTR record conventionally carries a trailing dot.
        bool matches = names.Any(n =>
            string.Equals(Normalise(n), facts.Hostname.Value, StringComparison.OrdinalIgnoreCase));

        DeliverabilityEvidence evidence = new(
            facts.Hostname.Value,
            string.Join(", ", names));

        return matches
            ? new DeliverabilityCheck(
                Id,
                DeliverabilityCategory.Identity,
                Title,
                Weight,
                DeliverabilityOutcome.Pass,
                $"This server greets as {facts.Hostname.Value} and its address reverses to the " +
                "same name.",
                evidence)
            : new DeliverabilityCheck(
                Id,
                DeliverabilityCategory.Identity,
                Title,
                Weight,
                DeliverabilityOutcome.Warn,
                $"This server greets as {facts.Hostname.Value} but its address reverses to " +
                $"{string.Join(", ", names)}. Some receivers score the disagreement against you.",
                evidence,
                $"Either set MailServer:Server:Hostname to {Normalise(names[0])}, or ask the " +
                $"address's owner to change the PTR record to {facts.Hostname.Value}. They must " +
                "also match the certificate's subject name.");
    }

    /// <summary>A check that could not be made, which is never a finding about the operator.</summary>
    private static DeliverabilityCheck Unmeasured(string id, string title, int weight, string detail) =>
        new(id, DeliverabilityCategory.Identity, title, weight, DeliverabilityOutcome.Inconclusive, detail);

    /// <summary>What the forward lookups actually produced, for the evidence.</summary>
    private static string Describe(IdentityFacts facts, IReadOnlyList<string> names)
    {
        List<string> parts = [];

        foreach (string name in names)
        {
            parts.Add(facts.PointerForwardAddresses.TryGetValue(name, out IReadOnlyList<IpAddressValue>? forward)
                ? string.Create(
                    CultureInfo.InvariantCulture,
                    $"{name} -> {(forward.Count == 0 ? "nothing" : string.Join("/", forward.Select(a => a.Value)))}")
                : $"{name} -> no answer");
        }

        return string.Join("; ", parts);
    }

    /// <summary>Strips the trailing dot a PTR record conventionally carries.</summary>
    private static string Normalise(string name) => name.TrimEnd('.');
}
