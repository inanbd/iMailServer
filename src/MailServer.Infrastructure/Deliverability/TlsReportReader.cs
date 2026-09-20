using System.Globalization;
using System.Text.Json;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Domain.Deliverability;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Reads RFC 8460 §4's report JSON into the domain model.
/// </summary>
/// <remarks>
/// <para>
/// <b>Lenient about everything except being JSON with policies in it.</b> These reports come
/// from other people's implementations, and the ones that matter — Google, Microsoft — each
/// differ in small ways from the ABNF: a count sent as a string, a date without a timezone, a
/// field the RFC marks optional simply absent. A parser that refused any of those would report
/// the senders who matter most as sending malformed reports, which is the opposite of useful.
/// What it will not do is invent: a count it cannot read is zero and a field it cannot read is
/// null, never a guess.
/// </para>
/// <para>
/// <b>Bounded.</b> A report arrives from outside and nothing about its size is this server's
/// choice, so the document is capped before it is parsed rather than after.
/// </para>
/// </remarks>
public sealed class TlsReportReader : ITlsReportReader
{
    /// <summary>
    /// The largest report this will read.
    /// </summary>
    /// <remarks>
    /// Real reports from large senders run to a few hundred kilobytes when a domain has many
    /// MX hosts and a busy period. Four megabytes is far past that and still a bound on
    /// something a stranger chose the size of.
    /// </remarks>
    public const int MaxJsonLength = 4 * 1024 * 1024;

    public bool TryRead(string? json, out TlsReport? report, out string? error)
    {
        report = null;
        error = null;

        if (string.IsNullOrWhiteSpace(json))
        {
            error = "the report is empty.";
            return false;
        }

        if (json.Length > MaxJsonLength)
        {
            error = $"the report is larger than the {MaxJsonLength} character limit.";
            return false;
        }

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            error = $"the report is not valid JSON: {ex.Message}";
            return false;
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                error = "the report's top level is not an object.";
                return false;
            }

            // §4.1 makes policies the one thing a report is actually for. Everything else is
            // provenance, and a report without it is carrying no information at all.
            if (!root.TryGetProperty("policies", out JsonElement policies) ||
                policies.ValueKind != JsonValueKind.Array)
            {
                error = "the report has no policies array.";
                return false;
            }

            (DateTimeOffset? start, DateTimeOffset? end) = ReadDateRange(root);

            report = new TlsReport(
                Text(root, "organization-name"),
                Text(root, "contact-info"),
                Text(root, "report-id"),
                start,
                end,
                [.. policies.EnumerateArray().Select(ReadPolicy)]);

            return true;
        }
    }

    private static TlsReportPolicy ReadPolicy(JsonElement element)
    {
        string? policyType = null;
        string? policyDomain = null;

        if (element.TryGetProperty("policy", out JsonElement policy) &&
            policy.ValueKind == JsonValueKind.Object)
        {
            policyType = Text(policy, "policy-type");
            policyDomain = Text(policy, "policy-domain");
        }

        long successes = 0;
        long failures = 0;

        if (element.TryGetProperty("summary", out JsonElement summary) &&
            summary.ValueKind == JsonValueKind.Object)
        {
            successes = Count(summary, "total-successful-session-count");
            failures = Count(summary, "total-failure-session-count");
        }

        List<TlsFailureDetail> details = [];

        if (element.TryGetProperty("failure-details", out JsonElement failureDetails) &&
            failureDetails.ValueKind == JsonValueKind.Array)
        {
            details.AddRange(failureDetails.EnumerateArray().Select(ReadFailure));
        }

        return new TlsReportPolicy(policyType, policyDomain, successes, failures, details);
    }

    private static TlsFailureDetail ReadFailure(JsonElement element)
    {
        string? raw = Text(element, "result-type");

        return new TlsFailureDetail(
            TlsReport.ReadResult(raw),
            raw,
            Text(element, "sending-mta-ip"),
            Text(element, "receiving-mx-hostname"),
            Count(element, "failed-session-count"));
    }

    private static (DateTimeOffset? Start, DateTimeOffset? End) ReadDateRange(JsonElement root)
    {
        if (!root.TryGetProperty("date-range", out JsonElement range) ||
            range.ValueKind != JsonValueKind.Object)
        {
            return (null, null);
        }

        return (Timestamp(range, "start-datetime"), Timestamp(range, "end-datetime"));
    }

    private static string? Text(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>
    /// Reads a session count.
    /// </summary>
    /// <remarks>
    /// <b>A string is accepted as well as a number, because senders send both.</b> RFC 8460
    /// §4.4's ABNF has these as integers, and implementations in the wild quote them. Refusing
    /// the quoted form would mean discarding whole reports over a pair of quotation marks. An
    /// unreadable value is zero rather than a guess: a count that cannot be read is not evidence
    /// of any particular number of failures.
    /// </remarks>
    private static long Count(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value))
        {
            return 0;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long number))
        {
            return number < 0 ? 0 : number;
        }

        if (value.ValueKind == JsonValueKind.String &&
            long.TryParse(value.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out long parsed))
        {
            return parsed;
        }

        return 0;
    }

    private static DateTimeOffset? Timestamp(JsonElement parent, string name) =>
        Text(parent, name) is { Length: > 0 } text &&
        DateTimeOffset.TryParse(
            text,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out DateTimeOffset value)
            ? value
            : null;
}
