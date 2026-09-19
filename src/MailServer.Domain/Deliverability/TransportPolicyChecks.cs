using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Deliverability;

/// <summary>Why a policy resource could not be read.</summary>
public enum MtaStsFetchOutcome
{
    /// <summary>No fetch was attempted.</summary>
    NotAttempted = 0,

    /// <summary>The resource was retrieved.</summary>
    Fetched = 1,

    /// <summary>The policy host did not answer, or the request failed before any response.</summary>
    Unreachable = 2,

    /// <summary>The host answered, but not with a policy — a 404, a redirect to a login page.</summary>
    NotFound = 3,

    /// <summary>
    /// The TLS handshake with the policy host failed.
    /// </summary>
    /// <remarks>
    /// Its own outcome because RFC 8461 §3.3 makes it fatal and unambiguous: senders "MUST
    /// validate the TLS certificate", so a policy host with a bad certificate publishes nothing
    /// at all — while looking, from a browser that clicked through the warning, entirely fine.
    /// </remarks>
    TlsFailed = 4,

    /// <summary>
    /// The resource was served with a media type other than <c>text/plain</c>.
    /// </summary>
    /// <remarks>
    /// §3.2: "senders SHOULD validate that the media type is 'text/plain' to guard against cases
    /// where web servers allow untrusted users to host non-text content".
    /// </remarks>
    WrongMediaType = 5,
}

/// <summary>What the transport-policy probe observed.</summary>
/// <param name="Domain">The domain being judged.</param>
/// <param name="MxHosts">
/// The MX hosts the policy must cover, or null when they are not known. Judging a policy's
/// <c>mx</c> list against nothing would pass a policy that names no host this domain uses.
/// </param>
/// <param name="StsTxtRecords">
/// The TXT records at <c>_mta-sts.domain</c>, or null when the lookup did not answer.
/// </param>
/// <param name="PolicyOutcome">How the fetch of the policy resource went.</param>
/// <param name="PolicyText">The resource's content when it was fetched, and null otherwise.</param>
/// <param name="TlsRptTxtRecords">
/// The TXT records at <c>_smtp._tls.domain</c>, or null when the lookup did not answer.
/// </param>
public sealed record TransportPolicyFacts(
    DomainName Domain,
    IReadOnlyList<string>? MxHosts,
    IReadOnlyList<string>? StsTxtRecords,
    MtaStsFetchOutcome PolicyOutcome,
    string? PolicyText,
    IReadOnlyList<string>? TlsRptTxtRecords);

/// <summary>
/// MTA-STS and TLS-RPT: the six points of the TLS category that live in DNS and HTTPS rather
/// than in a certificate.
/// </summary>
/// <remarks>
/// <b>These are the checks that turn the rest of the category from advice into a commitment.</b>
/// Without MTA-STS a sender that cannot get a valid TLS session simply delivers in clear text or
/// gives up quietly, and either way the receiving operator learns nothing. RFC 8461 §5's enforce
/// mode is what makes a downgrade visible, and RFC 8460 is what makes it visible <i>to the
/// receiver</i> rather than only to the sender.
/// </remarks>
public static class TransportPolicyChecks
{
    /// <summary>The MTA-STS record check's id.</summary>
    public const string MtaStsRecordId = "tls.mta-sts-record";

    /// <summary>The MTA-STS policy check's id.</summary>
    public const string MtaStsPolicyId = "tls.mta-sts-policy";

    /// <summary>The TLS-RPT check's id.</summary>
    public const string TlsReportingId = "tls.tls-rpt";

    /// <summary>
    /// Below this, a <c>max_age</c> defeats the point of caching the policy.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.2: "To mitigate the risks of attacks at policy refresh time, it is expected
    /// that this value typically be in the range of weeks or greater." A policy refetched daily
    /// gives an attacker who can block the fetch a fresh opening every day.
    /// </remarks>
    public const long MinimumSensibleMaxAge = 604_800;

    /// <summary>Judges a set of observations. Pure.</summary>
    public static IReadOnlyList<DeliverabilityCheck> Evaluate(TransportPolicyFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        IReadOnlyList<string>? stsTexts = SelectVersioned(facts.StsTxtRecords, "v=STSv1");

        return
        [
            MtaStsRecord(facts, stsTexts),
            Policy(facts, stsTexts),
            TlsReporting(facts),
        ];
    }

    /// <summary>
    /// The <c>_mta-sts</c> TXT record is published, and there is exactly one.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.1: "If multiple TXT records for '_mta-sts' are returned by the resolver,
    /// records that do not begin with 'v=STSv1;' are discarded. If the number of resulting
    /// records is not one, or if the resulting record is syntactically invalid, senders MUST
    /// assume the recipient domain does not have an available MTA-STS Policy and skip the
    /// remaining steps of policy discovery." So two records is not a duplicate but a withdrawal:
    /// every sender behaves as though the domain published nothing.
    /// </remarks>
    private static DeliverabilityCheck MtaStsRecord(
        TransportPolicyFacts facts,
        IReadOnlyList<string>? texts)
    {
        const string Id = MtaStsRecordId;
        const string Title = "An MTA-STS record is published";
        const int Weight = 2;

        string name = $"_mta-sts.{facts.Domain.Value}";

        if (texts is null)
        {
            return Unmeasured(Id, Title, Weight, $"No TXT answer for {name}.");
        }

        DeliverabilityEvidence evidence = new(
            $"One v=STSv1 TXT record at {name}",
            texts.Count == 0 ? null : string.Join(" | ", texts));

        if (texts.Count == 0)
        {
            return Warn(
                Id,
                Title,
                Weight,
                $"{facts.Domain.Value} publishes no MTA-STS record, so a sender that cannot " +
                "establish a valid TLS session has no instruction and will usually deliver in " +
                "clear text instead. Nothing about that is visible from this side.",
                evidence,
                $"Publish \"v=STSv1; id=<a short unique string>\" at {name}, and serve a policy " +
                $"at https://mta-sts.{facts.Domain.Value}/.well-known/mta-sts.txt.");
        }

        if (texts.Count > 1)
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"{name} publishes {texts.Count} MTA-STS records. RFC 8461 §3.1 makes senders " +
                "treat that as no policy at all, so the effect is the same as publishing none " +
                "— while the record on screen suggests otherwise.",
                evidence,
                "Delete all but one.");
        }

        // §3.1: "The TXT record MUST begin with the sts-version field" and the id "MUST uniquely
        // identify a given instance of a policy, such that senders can determine when the policy
        // has been updated". Without it senders cannot tell a revision from the cached copy.
        return HasTag(texts[0], "id")
            ? Pass(Id, Title, Weight, "One MTA-STS record is published.", evidence)
            : Fail(
                Id,
                Title,
                Weight,
                "The MTA-STS record has no id tag, which RFC 8461 §3.1 requires. Senders cannot " +
                "tell a revised policy from the one they cached, so a correction may never be " +
                "picked up.",
                evidence,
                "Add \"id=\" with a short unique string — a timestamp such as 20260919T120000 is " +
                "conventional — and change it whenever you change the policy.");
    }

    /// <summary>
    /// The policy resource is served, parses, covers the MX hosts, and asks for something.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A published record with no reachable policy is worse than neither.</b> §3.1 sends every
    /// sender to fetch the resource; a record that promises one and does not deliver spends a
    /// request per sender per refresh and buys nothing, and the operator sees a correctly
    /// published TXT record and concludes MTA-STS is on.
    /// </para>
    /// <para>
    /// The mode is graded rather than judged pass or fail. §5 makes only <c>enforce</c> protect
    /// anything, but <c>testing</c> is the mode the RFC's own deployment advice starts from and
    /// it cannot lose mail — so it warns, and the remedy names the step rather than the fault.
    /// </para>
    /// </remarks>
    private static DeliverabilityCheck Policy(TransportPolicyFacts facts, IReadOnlyList<string>? texts)
    {
        const string Id = MtaStsPolicyId;
        const string Title = "The MTA-STS policy is served and enforcing";
        const int Weight = 2;

        string url = $"https://mta-sts.{facts.Domain.Value}/.well-known/mta-sts.txt";

        // No record means no policy discovery happens at all, so there is nothing here to judge
        // that the record check has not already reported.
        if (texts is { Count: 0 })
        {
            return Unmeasured(Id, Title, Weight, "There is no MTA-STS record, so no policy is fetched.");
        }

        if (facts.PolicyOutcome is MtaStsFetchOutcome.NotAttempted || texts is null)
        {
            return Unmeasured(Id, Title, Weight, "The policy resource was not fetched.");
        }

        DeliverabilityEvidence bad = new($"A text/plain STSv1 policy at {url}", null);

        switch (facts.PolicyOutcome)
        {
            case MtaStsFetchOutcome.Unreachable:
                return Fail(
                    Id,
                    Title,
                    Weight,
                    $"{facts.Domain.Value} publishes an MTA-STS record but {url} cannot be " +
                    "reached, so every sender that follows the record gets nothing. The record " +
                    "looks correct from the DNS side, which is why this goes unnoticed.",
                    bad with { Found = "unreachable" },
                    $"Serve the policy at {url}, or remove the _mta-sts record until you do.");

            case MtaStsFetchOutcome.NotFound:
                return Fail(
                    Id,
                    Title,
                    Weight,
                    $"{url} does not serve a policy. A record promising one that is not there " +
                    "costs every sender a request per refresh and buys nothing.",
                    bad with { Found = "no policy at that path" },
                    $"Serve the policy file at exactly {url}; the path is fixed by RFC 8461 §3.2.");

            case MtaStsFetchOutcome.TlsFailed:
                return Fail(
                    Id,
                    Title,
                    Weight,
                    "The policy host's TLS certificate is not valid, so no sender will read the " +
                    "policy. A browser that clicks through the warning shows the file perfectly, " +
                    "which is why this one is so easily missed.",
                    bad with { Found = "the policy host's certificate is not valid" },
                    $"Install a valid certificate for mta-sts.{facts.Domain.Value}. It needs one " +
                    "of its own; the mail server's certificate does not cover it.");

            case MtaStsFetchOutcome.WrongMediaType:
                return Fail(
                    Id,
                    Title,
                    Weight,
                    "The policy is served with the wrong media type. RFC 8461 §3.2 has senders " +
                    "validate it is text/plain, so the policy is ignored although the file " +
                    "itself is correct.",
                    bad with { Found = "a media type other than text/plain" },
                    "Serve the file as text/plain — a web server guessing from the .txt " +
                    "extension usually does this already, so check for an override.");

            default:
                break;
        }

        if (!MtaStsPolicy.TryParse(facts.PolicyText, out MtaStsPolicy? policy, out string? error))
        {
            return Fail(
                Id,
                Title,
                Weight,
                $"The policy at {url} does not parse: {error} Senders discard it, so the domain " +
                "has no policy.",
                bad with { Found = facts.PolicyText is { Length: > 0 } ? "a policy that does not parse" : "an empty policy" },
                "Correct the policy file; it needs version, mode, at least one mx and max_age.");
        }

        string found =
            $"mode={policy.Mode.ToString().ToLowerInvariant()}, mx: {string.Join(", ", policy.MxPatterns)}";

        DeliverabilityEvidence evidence = new($"A text/plain STSv1 policy at {url}", found);

        // A policy whose mx list omits a host the domain's MX names is the one MTA-STS failure
        // that loses mail outright: in enforce mode senders must not deliver to that host, and
        // the domain is telling them to use it.
        if (facts.MxHosts is { Count: > 0 } hosts)
        {
            List<string> uncovered = [.. hosts.Where(h => !policy.Covers(h))];

            if (uncovered.Count > 0)
            {
                return Fail(
                    Id,
                    Title,
                    Weight,
                    $"The policy does not cover {string.Join(" or ", uncovered)}, which the " +
                    "domain's MX records name. In enforce mode senders must not deliver to a " +
                    "host the policy omits, so that mail is refused rather than downgraded.",
                    evidence,
                    $"Add \"mx: {uncovered[0]}\" to the policy, on a line of its own.");
            }
        }

        if (policy.Mode is MtaStsMode.None)
        {
            return Warn(
                Id,
                Title,
                Weight,
                "The policy's mode is none, which RFC 8461 §5 defines as \"Sending MTAs should " +
                "treat the Policy Domain as though it does not have any active policy\". That " +
                "is how a policy is withdrawn, and it protects nothing.",
                evidence,
                "Set mode to testing, and to enforce once the TLS-RPT reports show senders " +
                "validating successfully.");
        }

        if (policy.Mode is MtaStsMode.Testing)
        {
            return Warn(
                Id,
                Title,
                Weight,
                "The policy's mode is testing, so failures are reported and the message is " +
                "delivered anyway. That is the right first step and it protects nothing yet.",
                evidence,
                "Move to enforce once the TLS-RPT reports show senders validating successfully.");
        }

        return policy.MaxAgeSeconds < MinimumSensibleMaxAge
            ? Warn(
                Id,
                Title,
                Weight,
                $"The policy is enforcing, but max_age is {policy.MaxAgeSeconds} seconds. RFC " +
                "8461 §3.2 expects \"weeks or greater\", because an attacker who can block the " +
                "refetch gets a fresh opening every time the cache expires.",
                evidence with { Found = $"{found}, max_age={policy.MaxAgeSeconds}" },
                $"Raise max_age to {MinimumSensibleMaxAge} or more once you are confident in the " +
                "policy.")
            : Pass(Id, Title, Weight, "The policy is served and enforcing.", evidence);
    }

    /// <summary>
    /// TLS-RPT is published, so failures are reported back.
    /// </summary>
    /// <remarks>
    /// RFC 8460 §3: the record lives at <c>_smtp._tls</c> and its <c>rua</c> is "A URI specifying
    /// the endpoint to which aggregate information about policy validation results should be
    /// sent". Without it, a sender that fails to establish a valid TLS session reports the
    /// failure to nobody, and the receiving operator has no way to learn that MTA-STS is
    /// rejecting their own mail — which is the one thing that makes moving to enforce safe.
    /// </remarks>
    private static DeliverabilityCheck TlsReporting(TransportPolicyFacts facts)
    {
        const string Id = TlsReportingId;
        const string Title = "TLS-RPT reports are requested";
        const int Weight = 2;

        string name = $"_smtp._tls.{facts.Domain.Value}";

        IReadOnlyList<string>? texts = SelectVersioned(facts.TlsRptTxtRecords, "v=TLSRPTv1");

        if (texts is null)
        {
            return Unmeasured(Id, Title, Weight, $"No TXT answer for {name}.");
        }

        DeliverabilityEvidence evidence = new(
            $"A v=TLSRPTv1 record with a rua= tag at {name}",
            texts.Count == 0 ? null : string.Join(" | ", texts));

        if (texts.Count == 0)
        {
            return Warn(
                Id,
                Title,
                Weight,
                $"{facts.Domain.Value} publishes no TLS-RPT record, so a sender that cannot " +
                "negotiate TLS with this server reports it to nobody. Moving MTA-STS to enforce " +
                "without these reports is done blind.",
                evidence,
                $"Publish \"v=TLSRPTv1; rua=mailto:tlsrpt@{facts.Domain.Value}\" at {name}.");
        }

        return HasTag(texts[0], "rua")
            ? Pass(Id, Title, Weight, "TLS-RPT aggregate reports are requested.", evidence)
            : Warn(
                Id,
                Title,
                Weight,
                "The TLS-RPT record has no rua tag, so it names nowhere to send reports and no " +
                "report is ever sent.",
                evidence,
                $"Add rua=mailto:<an address you read> — or an https: endpoint, which RFC 8460 " +
                "§3 also allows.");
    }

    // -------------------------------------------------------------------------------------------
    // Shared.
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The records beginning with a version tag, the whole token matched.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.1: "records that do not begin with 'v=STSv1;' are discarded". A prefix match
    /// would keep a hypothetical "v=STSv10" too, so the terminator is checked — the same shape
    /// as RFC 7208 §4.5's rule about "v=spf10".
    /// </remarks>
    private static IReadOnlyList<string>? SelectVersioned(IReadOnlyList<string>? texts, string version)
    {
        if (texts is null)
        {
            return null;
        }

        List<string> matching = [];

        foreach (string text in texts)
        {
            string trimmed = text.TrimStart();

            if (!trimmed.StartsWith(version, StringComparison.Ordinal))
            {
                continue;
            }

            string rest = trimmed[version.Length..];

            if (rest.Length == 0 || rest[0] is ';' or ' ')
            {
                matching.Add(text);
            }
        }

        return matching;
    }

    /// <summary>Whether a semicolon-separated tag list carries a named tag with a value.</summary>
    private static bool HasTag(string record, string tag)
    {
        foreach (string part in record.Split(';'))
        {
            int equals = part.IndexOf('=', StringComparison.Ordinal);

            if (equals < 0)
            {
                continue;
            }

            if (part[..equals].Trim().Equals(tag, StringComparison.OrdinalIgnoreCase) &&
                part[(equals + 1)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static DeliverabilityCheck Pass(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence) =>
        new(id, DeliverabilityCategory.Tls, title, weight, DeliverabilityOutcome.Pass, detail, evidence);

    private static DeliverabilityCheck Warn(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Tls, title, weight, DeliverabilityOutcome.Warn, detail, evidence, remedy);

    private static DeliverabilityCheck Fail(
        string id, string title, int weight, string detail, DeliverabilityEvidence evidence, string remedy) =>
        new(id, DeliverabilityCategory.Tls, title, weight, DeliverabilityOutcome.Fail, detail, evidence, remedy);

    private static DeliverabilityCheck Unmeasured(string id, string title, int weight, string detail) =>
        new(id, DeliverabilityCategory.Tls, title, weight, DeliverabilityOutcome.Inconclusive, detail);
}
