using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>
/// Whether a list's answers can be believed, per RFC 5782 §5's test entries.
/// </summary>
/// <remarks>
/// <b>The most consequential enum in this category.</b> A DNSBL queried through a public
/// resolver, or from an address that has exceeded a free-use quota, commonly answers "listed"
/// for every query it is given. Reporting that as a listing would send an operator to file
/// delisting requests with half a dozen organisations for a problem they do not have — and the
/// answers look identical to a real listing unless the test entries are asked about too.
/// </remarks>
public enum ReputationListHealth
{
    /// <summary>The list was not tested.</summary>
    Unknown = 0,

    /// <summary>
    /// The list answered RFC 5782 §5's test entries correctly.
    /// </summary>
    /// <remarks>
    /// §5: "IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes. IPv4-based
    /// DNSxLs MUST NOT contain an entry for 127.0.0.1."
    /// </remarks>
    Healthy = 1,

    /// <summary>The list did not answer at all, so it says nothing either way.</summary>
    NotAnswering = 2,

    /// <summary>
    /// The list answered, but wrongly — it listed 127.0.0.1, or did not list 127.0.0.2.
    /// </summary>
    /// <remarks>
    /// Almost always this server's queries being refused rather than the list being broken: a
    /// public resolver, or a quota. Either way its answers about a real address cannot be
    /// distinguished from noise.
    /// </remarks>
    Unreliable = 3,
}

/// <summary>One list's answer about one identity.</summary>
/// <param name="Provider">The list's zone, as an operator would recognise it.</param>
/// <param name="Listed">Whether the identity was listed.</param>
/// <param name="Codes">
/// The A-record values returned. RFC 5782 §2.1: "The contents of the A record MUST NOT be used as
/// an IP address" — they are the list's own sublist codes, carried so an operator can look up
/// what the list means by them.
/// </param>
/// <param name="Reason">
/// The TXT record, which §2.1 says "describes the reason that the IP address is listed" — the
/// one part of a listing an operator can usually act on directly.
/// </param>
/// <param name="Health">Whether this list's answers can be believed at all.</param>
public sealed record ReputationListing(
    string Provider,
    bool Listed,
    IReadOnlyList<string> Codes,
    string? Reason,
    ReputationListHealth Health);

/// <summary>What the reputation probe observed.</summary>
/// <param name="Domain">The domain being judged.</param>
/// <param name="Address">The address mail leaves from, or null when it is not known.</param>
/// <param name="IpListings">Answers about the address, or null when none were sought.</param>
/// <param name="DomainListings">Answers about the domain, or null when none were sought.</param>
public sealed record ReputationFacts(
    DomainName Domain,
    IpAddressValue? Address,
    IReadOnlyList<ReputationListing>? IpListings,
    IReadOnlyList<ReputationListing>? DomainListings);

/// <summary>
/// The Reputation category: what the public lists say about this server.
/// </summary>
/// <remarks>
/// <para>
/// Ten points, the second lowest, and deliberately so. Everything else in this report is
/// something the operator controls and can verify before sending a single message; a blocklist
/// entry is somebody else's judgement, arrives after the fact, and is often about the previous
/// tenant of an address rather than about them at all.
/// </para>
/// <para>
/// <b>Every listing is checked against the list's own health before it is believed.</b> See
/// <see cref="ReputationListHealth"/> — the failure mode this guards against produces answers
/// indistinguishable from real listings, and acting on them wastes an operator's time with
/// several organisations at once.
/// </para>
/// </remarks>
public static class ReputationChecks
{
    /// <summary>The IP-not-listed check's id.</summary>
    public const string IpNotListedId = "reputation.ip-not-listed";

    /// <summary>The domain-not-listed check's id.</summary>
    public const string DomainNotListedId = "reputation.domain-not-listed";

    /// <summary>The lists-usable check's id.</summary>
    public const string ListsUsableId = "reputation.lists-usable";

    /// <summary>Judges a set of observations. Pure.</summary>
    public static IReadOnlyList<DeliverabilityCheck> Evaluate(ReputationFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        return
        [
            IpNotListed(facts),
            DomainNotListed(facts),
            ListsUsable(facts),
        ];
    }

    /// <summary>
    /// The sending address is not on a blocklist.
    /// </summary>
    /// <remarks>
    /// The heaviest check here, because a listed sending address is the one reputation problem
    /// that stops mail outright rather than sorting it into a spam folder — and unlike the rest
    /// of this report, the remedy is a request to somebody else that may take days.
    /// </remarks>
    private static DeliverabilityCheck IpNotListed(ReputationFacts facts)
    {
        const string Id = IpNotListedId;
        const string Title = "The sending address is not blocklisted";
        const int Weight = 6;

        if (facts.Address is not { } address)
        {
            return Unmeasured(Id, Title, Weight, "The address mail leaves from is not known.");
        }

        if (facts.IpListings is not { } listings)
        {
            return Unmeasured(Id, Title, Weight, "No list was queried about the address.");
        }

        return Judge(Id, Title, Weight, listings, address.ToString(), "address");
    }

    /// <summary>
    /// The domain is not on a blocklist.
    /// </summary>
    /// <remarks>
    /// Lighter than the address check because a domain listing more often reflects something
    /// hosted at the domain than the mail server itself — and because the remedy usually begins
    /// with finding what that is.
    /// </remarks>
    private static DeliverabilityCheck DomainNotListed(ReputationFacts facts)
    {
        const string Id = DomainNotListedId;
        const string Title = "The domain is not blocklisted";
        const int Weight = 3;

        if (facts.DomainListings is not { } listings)
        {
            return Unmeasured(Id, Title, Weight, "No list was queried about the domain.");
        }

        return Judge(Id, Title, Weight, listings, facts.Domain.Value, "domain");
    }

    /// <summary>
    /// Judges the listings from lists that can be believed.
    /// </summary>
    /// <remarks>
    /// A listing from an unhealthy list is not evidence of anything and is left out entirely.
    /// It is not silently dropped either: <see cref="ListsUsable"/> reports the list's state,
    /// so an operator sees "three lists could not be queried reliably" rather than a clean bill
    /// of health from lists that never answered.
    /// </remarks>
    private static DeliverabilityCheck Judge(
        string id,
        string title,
        int weight,
        IReadOnlyList<ReputationListing> listings,
        string subject,
        string noun)
    {
        List<ReputationListing> believable =
            [.. listings.Where(l => l.Health is ReputationListHealth.Healthy)];

        if (believable.Count == 0)
        {
            return Unmeasured(
                id,
                title,
                weight,
                listings.Count == 0
                    ? $"No list was queried about the {noun}."
                    : $"None of the {listings.Count} list(s) queried answered reliably.");
        }

        List<ReputationListing> hits = [.. believable.Where(l => l.Listed)];

        DeliverabilityEvidence evidence = new(
            $"Not listed on any of the {believable.Count} list(s) queried",
            hits.Count == 0
                ? $"not listed on {string.Join(", ", believable.Select(l => l.Provider))}"
                : string.Join("; ", hits.Select(Describe)));

        if (hits.Count == 0)
        {
            return Pass(
                id,
                title,
                weight,
                $"{subject} is not listed on any of the {believable.Count} list(s) queried.",
                evidence);
        }

        string reasons = string.Join(
            " ",
            hits.Where(h => h.Reason is { Length: > 0 }).Select(h => h.Reason));

        return Fail(
            id,
            title,
            weight,
            $"{subject} is listed on {string.Join(", ", hits.Select(h => h.Provider))}. " +
            (reasons.Length > 0
                ? $"The list gives the reason as: {reasons}"
                : "The list gives no reason."),
            evidence,
            $"Follow each list's own delisting process. Find and fix what caused the listing " +
            "first — a delisting granted while the cause remains is usually followed by a " +
            "longer one.");
    }

    /// <summary>
    /// The lists queried are answering the way RFC 5782 says they must.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §5: "IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes. IPv4-based
    /// DNSxLs MUST NOT contain an entry for 127.0.0.1." A list that gets either wrong is not
    /// answering this server's queries properly, and the overwhelmingly likely reason is this
    /// server's own resolver — a public one, or one that has exceeded a free-use quota.
    /// </para>
    /// <para>
    /// <b>This check is about the report, not about the server.</b> Its weight is one, and the
    /// finding's remedy points at the resolver rather than at the mail configuration, because
    /// nothing the operator publishes can change it.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck ListsUsable(ReputationFacts facts)
    {
        const string Id = ListsUsableId;
        const string Title = "The reputation lists answered reliably";
        const int Weight = 1;

        List<ReputationListing> all =
        [
            .. facts.IpListings ?? [],
            .. facts.DomainListings ?? [],
        ];

        if (all.Count == 0)
        {
            return Unmeasured(Id, Title, Weight, "No list was queried.");
        }

        List<string> unreliable =
            [.. all.Where(l => l.Health is ReputationListHealth.Unreliable).Select(l => l.Provider)];

        List<string> silent =
            [.. all.Where(l => l.Health is ReputationListHealth.NotAnswering).Select(l => l.Provider)];

        int healthy = all.Count(l => l.Health is ReputationListHealth.Healthy);

        DeliverabilityEvidence evidence = new(
            $"All {all.Count} list(s) answering RFC 5782 §5's test entries correctly",
            $"{healthy} of {all.Count} answering correctly");

        if (unreliable.Count > 0)
        {
            return Warn(
                Id,
                Title,
                Weight,
                $"{string.Join(", ", unreliable.Distinct())} answered RFC 5782 §5's test entries " +
                "wrongly, so anything they say about this server cannot be told apart from " +
                "noise and has been left out of the report. This is almost always the resolver " +
                "rather than the list.",
                evidence,
                "Query the lists through your own resolver rather than a public one, and check " +
                "whether you have exceeded a free-use quota.");
        }

        return silent.Count > 0
            ? Warn(
                Id,
                Title,
                Weight,
                $"{string.Join(", ", silent.Distinct())} did not answer, so the report says " +
                "nothing about what they think.",
                evidence,
                "Retry later. If it persists, check whether the list still exists — abandoned " +
                "DNSBLs have been known to resolve every query, or none.")
            : Pass(Id, Title, Weight, $"All {all.Count} list(s) answered correctly.", evidence);
    }

    private static string Describe(ReputationListing listing) =>
        listing.Codes.Count == 0
            ? $"listed on {listing.Provider}"
            : $"listed on {listing.Provider} ({string.Join(", ", listing.Codes)})";

    private static DeliverabilityCheck Pass(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence) =>
        new(id, DeliverabilityCategory.Reputation, title, weight, DeliverabilityOutcome.Pass, detail, evidence);

    private static DeliverabilityCheck Warn(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Reputation, title, weight, DeliverabilityOutcome.Warn, detail, evidence, remedy);

    private static DeliverabilityCheck Fail(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Reputation, title, weight, DeliverabilityOutcome.Fail, detail, evidence, remedy);

    private static DeliverabilityCheck Unmeasured(string id, string title, int weight, string detail) =>
        new(id, DeliverabilityCategory.Reputation, title, weight, DeliverabilityOutcome.Inconclusive, detail);
}
