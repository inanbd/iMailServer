using System.Globalization;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>
/// One MX record, and what its target turned out to be.
/// </summary>
/// <param name="Preference">The preference number. Lower is preferred (RFC 5321 §5.1).</param>
/// <param name="Host">The exchange, without its trailing root label.</param>
/// <param name="Addresses">
/// The addresses the exchange resolves to, or null when the lookup did not answer. An empty list
/// means it answered with none, which is a finding.
/// </param>
/// <param name="IsAlias">Whether a CNAME was found at the exchange.</param>
public sealed record MxTarget(
    int Preference,
    string Host,
    IReadOnlyList<IpAddressValue>? Addresses,
    bool IsAlias)
{
    /// <summary>
    /// Whether this is RFC 7505's null MX.
    /// </summary>
    /// <remarks>
    /// RFC 7505 §3: "To indicate that a domain does not accept email, it advertises a single MX
    /// RR […] consisting of preference number 0 and a zero-length label, written in master files
    /// as '.', as the exchange domain[…] Since '.' is not a valid host name, a null MX record
    /// cannot be confused with an ordinary MX record."
    /// </remarks>
    public bool IsNull => Host.Length == 0 || Host == ".";
}

/// <summary>What the DNS probe observed about a domain's mail routing.</summary>
/// <param name="Domain">The domain being judged.</param>
/// <param name="Hostname">The name this server calls itself.</param>
/// <param name="MxRecords">The MX records, or null when the lookup did not answer.</param>
/// <param name="MxTtl">The smallest TTL in the MX answer, or null if unknown.</param>
/// <param name="CaaRecords">
/// The relevant CAA RRset — already walked up the tree per RFC 8659 §3 — or null when no lookup
/// answered. An empty list means the walk completed and found nothing, which CAA defines as
/// unrestricted.
/// </param>
/// <param name="AcmeIssuerDomain">
/// The issuer this server renews its certificate from, or null when it does not use ACME. Null
/// leaves the CAA check unjudged rather than guessing a CA.
/// </param>
public sealed record DnsFacts(
    DomainName Domain,
    DomainName Hostname,
    IReadOnlyList<MxTarget>? MxRecords,
    TimeSpan? MxTtl,
    IReadOnlyList<string>? CaaRecords,
    string? AcmeIssuerDomain);

/// <summary>
/// The DNS category: whether mail addressed to this domain can be routed to this server.
/// </summary>
/// <remarks>
/// <b>Distinct from Identity, which asks the reverse question.</b> Identity judges whether
/// receivers will accept what this server sends; these checks judge whether anything arrives.
/// The two share a resolver and nothing else, and a server can pass one completely while failing
/// the other — a common enough state that keeping the findings separate is the whole point.
/// </remarks>
public static class DnsChecks
{
    /// <summary>The MX-published check's id.</summary>
    public const string MxPublishedId = "dns.mx-published";

    /// <summary>The MX-resolves check's id.</summary>
    public const string MxResolvesId = "dns.mx-resolves";

    /// <summary>The MX-not-an-alias check's id.</summary>
    public const string MxNotAliasId = "dns.mx-not-alias";

    /// <summary>The MX-redundancy check's id.</summary>
    public const string MxRedundancyId = "dns.mx-redundancy";

    /// <summary>The MX-points-here check's id.</summary>
    public const string MxPointsHereId = "dns.mx-points-here";

    /// <summary>The TTL-sanity check's id.</summary>
    public const string TtlSanityId = "dns.ttl-sanity";

    /// <summary>The CAA-allows-issuer check's id.</summary>
    public const string CaaAllowsIssuerId = "dns.caa-allows-issuer";

    /// <summary>
    /// Below this, an MX TTL costs every receiver a lookup per message without buying anything
    /// back. Operational judgement, not a rule — see <see cref="TtlSanity"/>.
    /// </summary>
    public static readonly TimeSpan MinimumSensibleTtl = TimeSpan.FromMinutes(5);

    /// <summary>Above this, a correction takes more than a day to become visible.</summary>
    public static readonly TimeSpan MaximumSensibleTtl = TimeSpan.FromDays(1);

    /// <summary>Judges a set of observations. Pure.</summary>
    public static IReadOnlyList<DeliverabilityCheck> Evaluate(DnsFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        // The null MX is a statement about the whole domain rather than one route into it, so
        // every MX check reads it the same way: there is no mail service here to judge.
        IReadOnlyList<MxTarget>? routes = facts.MxRecords
            ?.Where(mx => !mx.IsNull)
            .ToList();

        return
        [
            MxPublished(facts),
            MxResolves(facts, routes),
            MxNotAlias(facts, routes),
            MxRedundancy(routes),
            MxPointsHere(facts, routes),
            TtlSanity(facts),
            CaaAllowsIssuer(facts),
        ];
    }

    // -------------------------------------------------------------------------------------------
    // MX.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The domain publishes an MX record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>No MX is not "no mail", and the check says which it is.</b> RFC 5321 §5.1: "If an empty
    /// list of MXs is returned, the address is treated as if it was associated with an implicit
    /// MX RR, with a preference of 0, pointing to that host." So a domain with an A record and no
    /// MX does receive mail — at whatever that A record points to, which for a great many domains
    /// is a web server that will refuse it. The finding is therefore a warning about a fragile
    /// arrangement rather than a failure, and the remedy says what to publish.
    /// </para>
    /// <para>
    /// A null MX is different in kind: RFC 7505 makes it an explicit refusal, so a server being
    /// assessed for delivering mail to a domain that has published one is a contradiction the
    /// operator needs told about plainly.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck MxPublished(DnsFacts facts)
    {
        const string Id = MxPublishedId;
        const string Title = "The domain publishes an MX record";
        const int Weight = 4;

        if (facts.MxRecords is not { } records)
        {
            return Unmeasured(Id, Title, Weight, $"No MX answer for {facts.Domain.Value}.");
        }

        DeliverabilityEvidence evidence = new(
            $"At least one MX record at {facts.Domain.Value}",
            records.Count == 0 ? null : string.Join(", ", records.Select(Describe)));

        if (records.Any(mx => mx.IsNull))
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"{facts.Domain.Value} publishes a null MX, which RFC 7505 defines as \"this " +
                "domain does not accept email\". Senders will bounce mail to it immediately, " +
                "whatever this server is configured to do.",
                evidence,
                "Remove the \"0 .\" MX record and publish one naming this server, or leave it in " +
                "place if the domain is genuinely send-only.");
        }

        return records.Count == 0
            ? Warn(
                Id,
                Title,
                Weight,
                $"{facts.Domain.Value} publishes no MX record, so senders fall back to RFC 5321 " +
                "§5.1's implicit MX and deliver to the domain's own address record. Mail " +
                "arrives only if whatever that name points at accepts SMTP.",
                evidence,
                $"Publish an MX record such as \"10 {facts.Hostname.Value}\" so mail is routed " +
                "deliberately rather than by fallback.")
            : Pass(
                Id,
                Title,
                Weight,
                $"{records.Count} MX record(s) published.",
                evidence);
    }

    /// <summary>
    /// Every MX target resolves to an address.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §5.1: "When a domain name associated with an MX RR is looked up and the
    /// associated data field obtained, the data field of that response MUST contain a domain
    /// name. That domain name, when queried, MUST return at least one address record (e.g., A or
    /// AAAA RR) that gives the IP address of the SMTP server to which the message should be
    /// directed."
    /// </remarks>
    private static DeliverabilityCheck MxResolves(DnsFacts facts, IReadOnlyList<MxTarget>? routes)
    {
        const string Id = MxResolvesId;
        const string Title = "Every MX target resolves to an address";
        const int Weight = 4;

        if (routes is not { Count: > 0 })
        {
            return Unmeasured(Id, Title, Weight, "There is no MX target to resolve.");
        }

        List<string> dead = [.. routes.Where(mx => mx.Addresses is { Count: 0 }).Select(mx => mx.Host)];
        bool anyUnanswered = routes.Any(mx => mx.Addresses is null);

        DeliverabilityEvidence evidence = new(
            "An A or AAAA record at every MX target",
            dead.Count > 0 ? $"{string.Join(", ", dead)} resolve to nothing" : "all targets resolve");

        if (dead.Count > 0)
        {
            return dead.Count == routes.Count
                ? Fail(
                    Id,
                    Title,
                    Weight,
                    "No MX target resolves to an address, so no sender can reach this domain at " +
                    "all.",
                    evidence,
                    $"Publish an A or AAAA record for {dead[0]}, or correct the MX to name a " +
                    "host that has one.")
                : Warn(
                    Id,
                    Title,
                    Weight,
                    $"{dead.Count} of {routes.Count} MX targets resolve to nothing. Senders will " +
                    "fall through to the others, so mail still arrives — after a delay on every " +
                    "message that tries the dead one first.",
                    evidence,
                    $"Publish an address record for {string.Join(" and ", dead)}, or remove " +
                    "those MX records.");
        }

        return anyUnanswered
            ? Unmeasured(Id, Title, Weight, "An MX target's address lookup did not answer.")
            : Pass(Id, Title, Weight, $"All {routes.Count} MX target(s) resolve.", evidence);
    }

    /// <summary>
    /// No MX target is a CNAME.
    /// </summary>
    /// <remarks>
    /// RFC 2181 §10.3: "The domain name used as the value of a NS resource record, or part of the
    /// value of a MX resource record must not be an alias[…] This domain name must have as its
    /// value one or more address records[…] It can also have other RRs, but never a CNAME RR."
    /// RFC 5321 §5.1 puts the consequence in senders' terms: "Any other response, specifically
    /// including a value that will return a CNAME record when queried, lies outside the scope of
    /// this Standard." Outside the scope means each sender decides for itself, so an aliased MX
    /// works with most of them and fails with some, intermittently and without pattern.
    /// </remarks>
    private static DeliverabilityCheck MxNotAlias(DnsFacts facts, IReadOnlyList<MxTarget>? routes)
    {
        const string Id = MxNotAliasId;
        const string Title = "No MX target is a CNAME";
        const int Weight = 2;

        if (routes is not { Count: > 0 })
        {
            return Unmeasured(Id, Title, Weight, "There is no MX target to check.");
        }

        List<string> aliases = [.. routes.Where(mx => mx.IsAlias).Select(mx => mx.Host)];

        DeliverabilityEvidence evidence = new(
            "An address record, not a CNAME, at every MX target",
            aliases.Count > 0 ? $"{string.Join(", ", aliases)} is an alias" : "no aliases");

        return aliases.Count > 0
            ? Fail(
                Id,
                Title,
                Weight,
                $"{string.Join(" and ", aliases)} is a CNAME. RFC 2181 §10.3 forbids it, and the " +
                "practical result is that some senders deliver and others do not — the failure " +
                "is intermittent and looks like anything but a DNS problem.",
                evidence,
                $"Replace the CNAME at {aliases[0]} with the A and AAAA records it points to, or " +
                "point the MX at a name that has them.")
            : Pass(Id, Title, Weight, "No MX target is an alias.", evidence);
    }

    /// <summary>
    /// There is somewhere for mail to go when the first choice is down.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §5.1: "the SMTP client SHOULD try at least two addresses." A single MX pointing
    /// at a single address means every hour this server is down is an hour of mail sitting in
    /// other people's queues — recoverable, since senders retry, but only for as long as their
    /// retry windows last. A SHOULD, so this warns.
    /// </remarks>
    private static DeliverabilityCheck MxRedundancy(IReadOnlyList<MxTarget>? routes)
    {
        const string Id = MxRedundancyId;
        const string Title = "Mail has more than one route in";
        const int Weight = 1;

        if (routes is not { Count: > 0 })
        {
            return Unmeasured(Id, Title, Weight, "There is no MX record to count routes from.");
        }

        int addresses = routes.Sum(mx => mx.Addresses?.Count ?? 0);

        DeliverabilityEvidence evidence = new(
            "At least two MX targets, or one with two addresses",
            string.Create(
                CultureInfo.InvariantCulture,
                $"{routes.Count} target(s), {addresses} address(es)"));

        return routes.Count > 1 || addresses > 1
            ? Pass(Id, Title, Weight, "There is more than one way in.", evidence)
            : Warn(
                Id,
                Title,
                Weight,
                "There is a single MX target with a single address, so any outage stops mail " +
                "arriving. Senders retry, but only for as long as their own retry windows last.",
                evidence,
                "Publish a second MX at a higher preference number, pointing at a host that " +
                "queues mail while this one is down.");
    }

    /// <summary>
    /// The domain's mail is routed to this server.
    /// </summary>
    /// <remarks>
    /// <b>A warning rather than a failure, because putting something in front is a real
    /// architecture.</b> A filtering service or a relay that forwards inbound mail here is
    /// deliberate and correct, and this check cannot tell it apart from an operator who has set
    /// up a mail server and never pointed the domain at it. What it can do is say which
    /// arrangement the DNS describes, and let the operator recognise their own.
    /// </remarks>
    private static DeliverabilityCheck MxPointsHere(DnsFacts facts, IReadOnlyList<MxTarget>? routes)
    {
        const string Id = MxPointsHereId;
        const string Title = "The domain's mail is routed to this server";
        const int Weight = 2;

        if (routes is not { Count: > 0 })
        {
            return Unmeasured(Id, Title, Weight, "There is no MX record to compare against.");
        }

        string self = Normalise(facts.Hostname.Value);
        bool here = routes.Any(mx => Normalise(mx.Host) == self);

        DeliverabilityEvidence evidence = new(
            $"An MX naming {facts.Hostname.Value}",
            string.Join(", ", routes.Select(Describe)));

        return here
            ? Pass(Id, Title, Weight, $"An MX record names {facts.Hostname.Value}.", evidence)
            : Warn(
                Id,
                Title,
                Weight,
                $"No MX record for {facts.Domain.Value} names {facts.Hostname.Value}. Inbound " +
                "mail goes elsewhere — which is correct if a filtering service or relay sits in " +
                "front, and is the whole fault if nothing does.",
                evidence,
                $"If nothing should be in front of this server, publish \"10 " +
                $"{facts.Hostname.Value}\" and remove the records that name something else.");
    }

    // -------------------------------------------------------------------------------------------
    // TTL and CAA.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The MX TTL is in a range that serves the operator.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The one check here with no RFC behind it, and it says so in its own detail.</b> RFC
    /// 2181 §8 settles what a TTL <i>is</i> — "an unsigned number, with a minimum value of 0, and
    /// a maximum value of 2147483647" — and nothing more; every value in that range conforms.
    /// What is left is a trade the operator is making whether or not they know it, between the
    /// lookups a short TTL costs and the time a long one adds before a correction takes effect.
    /// </para>
    /// <para>
    /// So both ends warn and neither fails, and the text names the consequence rather than
    /// quoting a rule that does not exist. An operator mid-migration wants a low TTL and should
    /// not be told they are wrong; they should be told what it costs, and left to decide.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck TtlSanity(DnsFacts facts)
    {
        const string Id = TtlSanityId;
        const string Title = "The MX TTL is a sensible length";
        const int Weight = 1;

        if (facts.MxTtl is not { } ttl)
        {
            return Unmeasured(Id, Title, Weight, "No TTL was observed for the MX record.");
        }

        DeliverabilityEvidence evidence = new(
            $"Between {Seconds(MinimumSensibleTtl)} and {Seconds(MaximumSensibleTtl)} seconds",
            $"{Seconds(ttl)} seconds",
            Ttl: ttl);

        const string Note = "No RFC sets a range; this is a trade-off, not a rule.";

        if (ttl < MinimumSensibleTtl)
        {
            return Warn(
                Id,
                Title,
                Weight,
                $"The MX TTL is {Seconds(ttl)} seconds, so every receiver re-queries it " +
                "constantly. That is the right setting while you are moving the record and a " +
                $"standing cost afterwards. {Note}",
                evidence,
                $"Raise it to {Seconds(MinimumSensibleTtl)} seconds or more once the record has " +
                "settled.");
        }

        return ttl > MaximumSensibleTtl
            ? Warn(
                Id,
                Title,
                Weight,
                $"The MX TTL is {Seconds(ttl)} seconds, so a correction to this record takes " +
                $"more than a day to reach everyone. {Note}",
                evidence,
                $"Lower it to {Seconds(MaximumSensibleTtl)} seconds or less, and lower it " +
                "further a day before you plan to change the record.")
            : Pass(
                Id,
                Title,
                Weight,
                $"The MX TTL is {Seconds(ttl)} seconds.",
                evidence);
    }

    /// <summary>
    /// CAA does not forbid the CA this server renews from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A mail check because of what it breaks: a renewal the CA refuses ends in an expired
    /// certificate, and an expired certificate ends STARTTLS, MTA-STS and every receiver that
    /// requires them. The failure surfaces sixty days after the record was published, by which
    /// time nobody connects the two.
    /// </para>
    /// <para>
    /// RFC 8659 §4: "Before issuing a certificate, a compliant CA MUST check for publication of a
    /// Relevant RRset. If such an RRset exists, a CA MUST NOT issue a certificate unless the CA
    /// determines that either (1) the certificate request is consistent with the applicable CAA
    /// RRset or (2) an exception specified in the relevant CP or CPS applies." And §4.2 on the
    /// empty value: "FQDN owners can use an issue Property Tag with no issuer-domain-name to
    /// request no issuance."
    /// </para>
    /// <para>
    /// <b>No CAA records is a pass, not a gap.</b> §4 is explicit that a restriction only exists
    /// where an RRset does, so treating absence as a finding would tell most of the internet to
    /// publish a record they do not need.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck CaaAllowsIssuer(DnsFacts facts)
    {
        const string Id = CaaAllowsIssuerId;
        const string Title = "CAA permits this server's certificate issuer";
        const int Weight = 1;

        if (facts.AcmeIssuerDomain is not { Length: > 0 } issuer)
        {
            return Unmeasured(
                Id,
                Title,
                Weight,
                "This server does not renew its certificate from a known issuer, so there is no " +
                "issuer to check CAA against.");
        }

        if (facts.CaaRecords is not { } records)
        {
            return Unmeasured(Id, Title, Weight, "No CAA answer.");
        }

        List<string> issuePermissions = [.. records
            .Select(ParseIssueValue)
            .Where(v => v is not null)
            .Select(v => v!)];

        DeliverabilityEvidence evidence = new(
            $"No CAA restriction, or one naming {issuer}",
            records.Count == 0 ? "no CAA records" : string.Join(", ", records));

        if (issuePermissions.Count == 0)
        {
            return Pass(
                Id,
                Title,
                Weight,
                records.Count == 0
                    ? "No CAA record restricts issuance, so any CA may issue."
                    : "The CAA records present do not restrict issuance.",
                evidence);
        }

        // §4.2's ";" - an issue tag with no issuer-domain-name - forbids every CA, this one
        // included, so it is not a name that can be matched but a refusal to be reported.
        if (issuePermissions.All(p => p.Length == 0))
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"CAA forbids all certificate issuance for {facts.Domain.Value}, so renewal will " +
                "fail and the certificate will expire. STARTTLS and MTA-STS go with it.",
                evidence,
                $"Replace the empty issue value with \"issue \\\"{issuer}\\\"\", or remove the " +
                "CAA record.");
        }

        return issuePermissions.Any(p => Normalise(p) == Normalise(issuer))
            ? Pass(Id, Title, Weight, $"CAA permits {issuer} to issue.", evidence)
            : Fail(
                Id,
                Title,
                Weight,
                $"CAA restricts issuance to {string.Join(", ", issuePermissions.Where(p => p.Length > 0))} " +
                $"and this server renews from {issuer}, so renewal will fail and the certificate " +
                "will expire. The failure arrives whenever the certificate next comes up for " +
                "renewal, long after the record was published.",
                evidence,
                $"Add \"0 issue \\\"{issuer}\\\"\" to the CAA record set for {facts.Domain.Value}.");
    }

    /// <summary>
    /// The issuer name in a CAA <c>issue</c> record, or null when the record is not one.
    /// </summary>
    /// <remarks>
    /// The record arrives rendered as <c>flags tag "value"</c>. Only <c>issue</c> is read:
    /// <c>issuewild</c> governs wildcard certificates, which this server does not request, and
    /// <c>iodef</c> restricts nothing at all — §4 says an RRset "contains no Property Tags that
    /// restrict issuance (for instance, if it contains only iodef Property Tags […])" does not
    /// restrict issuance.
    /// </remarks>
    private static string? ParseIssueValue(string record)
    {
        string[] parts = record.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length < 2 || !parts[1].Equals("issue", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string value = parts.Length == 3 ? parts[2].Trim().Trim('"') : string.Empty;

        // §4.2: issue-value = *WSP [issuer-domain-name *WSP] [";" *WSP [parameters *WSP]] - the
        // parameters after a semicolon are for the CA, and say nothing about who may issue.
        int semicolon = value.IndexOf(';', StringComparison.Ordinal);

        return (semicolon >= 0 ? value[..semicolon] : value).Trim();
    }

    // -------------------------------------------------------------------------------------------
    // Shared.
    // -------------------------------------------------------------------------------------------

    private static string Describe(MxTarget mx) => string.Create(
        CultureInfo.InvariantCulture,
        $"{mx.Preference} {(mx.IsNull ? "." : mx.Host)}");

    /// <summary>A duration as whole seconds, which is the unit a DNS panel shows.</summary>
    private static string Seconds(TimeSpan ttl) =>
        ((long)ttl.TotalSeconds).ToString(CultureInfo.InvariantCulture);

    /// <summary>A host name in the form two of them can be compared in.</summary>
    private static string Normalise(string host) => host.TrimEnd('.').ToLowerInvariant();

    private static DeliverabilityCheck Pass(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence) =>
        new(id, DeliverabilityCategory.Dns, title, weight, DeliverabilityOutcome.Pass, detail, evidence);

    private static DeliverabilityCheck Warn(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Dns, title, weight, DeliverabilityOutcome.Warn, detail, evidence, remedy);

    private static DeliverabilityCheck Fail(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Dns, title, weight, DeliverabilityOutcome.Fail, detail, evidence, remedy);

    private static DeliverabilityCheck Unmeasured(string id, string title, int weight, string detail) =>
        new(id, DeliverabilityCategory.Dns, title, weight, DeliverabilityOutcome.Inconclusive, detail);
}
