using MailServer.Domain.Deliverability;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// Reading RFC 8460 TLS reports, and saying what they mean.
/// </summary>
/// <remarks>
/// These arrive from other people's implementations, so the parser's leniency is as much the
/// subject here as its correctness: a reader that refused Google's quoted counts would report
/// the sender that matters most as sending malformed reports.
/// </remarks>
public sealed class TlsReportTests
{
    private static readonly TlsReportReader Reader = new();

    /// <summary>RFC 8460 §4.6's own example, trimmed to the fields that carry information.</summary>
    private const string RfcExample = """
        {
          "organization-name": "Company-X",
          "date-range": {
            "start-datetime": "2016-04-01T00:00:00Z",
            "end-datetime": "2016-04-01T23:59:59Z"
          },
          "contact-info": "sts-reporting@company-x.example",
          "report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
          "policies": [{
            "policy": {
              "policy-type": "sts",
              "policy-domain": "company-y.example"
            },
            "summary": {
              "total-successful-session-count": 5326,
              "total-failure-session-count": 303
            },
            "failure-details": [{
              "result-type": "certificate-expired",
              "sending-mta-ip": "2001:db8:abcd:0012::1",
              "receiving-mx-hostname": "mx1.mail.company-y.example",
              "failed-session-count": 100
            }, {
              "result-type": "starttls-not-supported",
              "sending-mta-ip": "2001:db8:abcd:0013::1",
              "receiving-mx-hostname": "mx2.mail.company-y.example",
              "failed-session-count": 203
            }]
          }]
        }
        """;

    private static TlsReport Read(string json)
    {
        Reader.TryRead(json, out TlsReport? report, out string? error).ShouldBeTrue(error);
        return report.ShouldNotBeNull();
    }

    private static string Reject(string? json)
    {
        Reader.TryRead(json, out TlsReport? report, out string? error).ShouldBeFalse();
        report.ShouldBeNull();
        return error.ShouldNotBeNull();
    }

    [Fact]
    public void The_rfc_example_reads_back_whole()
    {
        TlsReport report = Read(RfcExample);

        report.OrganizationName.ShouldBe("Company-X");
        report.ContactInfo.ShouldBe("sts-reporting@company-x.example");
        report.ReportId.ShouldBe("5065427c-23d3-47ca-b6e0-946ea0e8c4be");
        report.StartDate!.Value.Year.ShouldBe(2016);
        report.SuccessfulSessionCount.ShouldBe(5326);
        report.FailedSessionCount.ShouldBe(303);
        report.TotalSessionCount.ShouldBe(5629);
        report.Policies.ShouldHaveSingleItem().PolicyDomain.ShouldBe("company-y.example");
    }

    /// <summary>
    /// A sender reports per MX host and per sending address, so one expired certificate arrives
    /// as several entries that are the same problem. The operator needs to know which problem
    /// costs the most, which means adding them up and sorting.
    /// </summary>
    [Fact]
    public void Failures_are_grouped_by_result_type_and_ordered_by_impact()
    {
        IReadOnlyList<TlsFailureSummary> failures = Read(RfcExample).FailuresByImpact();

        failures.Count.ShouldBe(2);
        failures[0].Result.ShouldBe(TlsFailureResult.StartTlsNotSupported);
        failures[0].FailedSessionCount.ShouldBe(203);
        failures[1].Result.ShouldBe(TlsFailureResult.CertificateExpired);
        failures[1].FailedSessionCount.ShouldBe(100);
    }

    [Fact]
    public void Grouping_adds_up_the_same_result_across_hosts_and_keeps_every_host()
    {
        TlsReport report = Read("""
            {
              "policies": [{
                "summary": { "total-failure-session-count": 30 },
                "failure-details": [
                  { "result-type": "certificate-expired", "receiving-mx-hostname": "mx1.example.com", "failed-session-count": 10 },
                  { "result-type": "certificate-expired", "receiving-mx-hostname": "mx2.example.com", "failed-session-count": 20 }
                ]
              }]
            }
            """);

        TlsFailureSummary summary = report.FailuresByImpact().ShouldHaveSingleItem();

        summary.Result.ShouldBe(TlsFailureResult.CertificateExpired);
        summary.FailedSessionCount.ShouldBe(30);
        summary.ReceivingMxHostnames.ShouldBe(["mx1.example.com", "mx2.example.com"]);
    }

    /// <summary>
    /// §4.3's list is extensible. A report naming one type this version has not heard of is
    /// still telling the truth about everything else in it, so the type is kept raw rather than
    /// the report discarded.
    /// </summary>
    [Fact]
    public void An_unknown_result_type_is_kept_rather_than_rejecting_the_report()
    {
        TlsReport report = Read("""
            {
              "policies": [{
                "summary": { "total-successful-session-count": 5, "total-failure-session-count": 2 },
                "failure-details": [
                  { "result-type": "some-future-type", "failed-session-count": 2 }
                ]
              }]
            }
            """);

        TlsFailureDetail detail = report.Policies.ShouldHaveSingleItem().Failures.ShouldHaveSingleItem();

        detail.Result.ShouldBe(TlsFailureResult.Unknown);
        detail.RawResultType.ShouldBe("some-future-type");
        report.SuccessfulSessionCount.ShouldBe(5);
    }

    /// <summary>
    /// The ABNF has these as integers and implementations in the wild quote them. Refusing the
    /// quoted form would discard whole reports over a pair of quotation marks.
    /// </summary>
    [Fact]
    public void A_count_sent_as_a_string_is_read()
    {
        TlsReport report = Read("""
            {
              "policies": [{
                "summary": {
                  "total-successful-session-count": "1200",
                  "total-failure-session-count": "7"
                }
              }]
            }
            """);

        report.SuccessfulSessionCount.ShouldBe(1200);
        report.FailedSessionCount.ShouldBe(7);
    }

    /// <summary>
    /// A count that cannot be read is zero rather than a guess: it is not evidence of any
    /// particular number of failures.
    /// </summary>
    [Theory]
    [InlineData("\"not a number\"")]
    [InlineData("null")]
    [InlineData("-5")]
    [InlineData("{}")]
    public void An_unreadable_count_is_zero(string value)
    {
        TlsReport report = Read($$"""
            { "policies": [{ "summary": { "total-failure-session-count": {{value}} } }] }
            """);

        report.FailedSessionCount.ShouldBe(0);
    }

    [Theory]
    [InlineData(null, "empty")]
    [InlineData("", "empty")]
    [InlineData("   ", "empty")]
    [InlineData("not json at all", "valid JSON")]
    [InlineData("[1, 2, 3]", "top level")]
    [InlineData("{}", "policies")]
    [InlineData("{\"policies\": \"nope\"}", "policies")]
    public void A_document_that_is_not_a_report_is_refused_with_a_reason(string? json, string expected) =>
        Reject(json).ShouldContain(expected);

    /// <summary>A report from outside must not decide how much memory this server holds.</summary>
    [Fact]
    public void An_oversized_report_is_refused_before_it_is_parsed() =>
        Reject(new string('x', TlsReportReader.MaxJsonLength + 1)).ShouldContain("limit");

    // ---- What it means ------------------------------------------------------------------------

    /// <summary>
    /// "Every session succeeded" and "there were no sessions" are different things, and a quiet
    /// period must not read as a clean bill of health.
    /// </summary>
    [Fact]
    public void A_report_covering_no_sessions_has_no_success_rate()
    {
        TlsReport report = Read("""{ "policies": [] }""");

        report.TotalSessionCount.ShouldBe(0);
        report.SuccessRate.ShouldBeNull();
        report.Summarise().ShouldContain("no sessions");
    }

    [Fact]
    public void A_clean_report_says_so()
    {
        TlsReport report = Read("""
            {
              "organization-name": "Google Inc.",
              "policies": [{ "summary": { "total-successful-session-count": 400 } }]
            }
            """);

        report.SuccessRate.ShouldBe(1.0);
        report.Summarise().ShouldContain("Google Inc.");
        report.Summarise().ShouldContain("all of which");
    }

    /// <summary>The summary leads with the failure that costs the most, because that is what to fix first.</summary>
    [Fact]
    public void A_failing_report_names_the_largest_cause()
    {
        string summary = Read(RfcExample).Summarise();

        summary.ShouldContain("303 failed session(s) out of 5629");
        summary.ShouldContain("starttls-not-supported");
    }

    [Fact]
    public void An_unnamed_sender_is_described_rather_than_left_blank() =>
        Read("""{ "policies": [{ "summary": { "total-successful-session-count": 1 } }] }""")
            .Summarise()
            .ShouldStartWith("An unnamed sender");

    /// <summary>
    /// Every result type needs a remedy, including the ones that are not this server's fault —
    /// an operator reading dane-required as a defect in their own configuration would go looking
    /// for a problem that is not there.
    /// </summary>
    [Theory]
    [InlineData(TlsFailureResult.StartTlsNotSupported)]
    [InlineData(TlsFailureResult.CertificateHostMismatch)]
    [InlineData(TlsFailureResult.CertificateExpired)]
    [InlineData(TlsFailureResult.CertificateNotTrusted)]
    [InlineData(TlsFailureResult.ValidationFailure)]
    [InlineData(TlsFailureResult.TlsaInvalid)]
    [InlineData(TlsFailureResult.DnssecInvalid)]
    [InlineData(TlsFailureResult.DaneRequired)]
    [InlineData(TlsFailureResult.StsPolicyFetchError)]
    [InlineData(TlsFailureResult.StsPolicyInvalid)]
    [InlineData(TlsFailureResult.StsWebpkiInvalid)]
    [InlineData(TlsFailureResult.Unknown)]
    public void Every_result_type_has_a_name_and_a_remedy(TlsFailureResult result)
    {
        TlsReport.NameOf(result).ShouldNotBeNullOrWhiteSpace();
        TlsReport.RemedyFor(result).ShouldNotBeNullOrWhiteSpace();
    }

    /// <summary>The wire names must round-trip, or a report's own vocabulary stops matching ours.</summary>
    [Theory]
    [InlineData(TlsFailureResult.StartTlsNotSupported)]
    [InlineData(TlsFailureResult.CertificateHostMismatch)]
    [InlineData(TlsFailureResult.CertificateExpired)]
    [InlineData(TlsFailureResult.CertificateNotTrusted)]
    [InlineData(TlsFailureResult.ValidationFailure)]
    [InlineData(TlsFailureResult.TlsaInvalid)]
    [InlineData(TlsFailureResult.DnssecInvalid)]
    [InlineData(TlsFailureResult.DaneRequired)]
    [InlineData(TlsFailureResult.StsPolicyFetchError)]
    [InlineData(TlsFailureResult.StsPolicyInvalid)]
    [InlineData(TlsFailureResult.StsWebpkiInvalid)]
    public void Result_type_names_round_trip(TlsFailureResult result) =>
        TlsReport.ReadResult(TlsReport.NameOf(result)).ShouldBe(result);

    [Theory]
    [InlineData("CERTIFICATE-EXPIRED")]
    [InlineData("  certificate-expired  ")]
    public void Result_type_reading_tolerates_case_and_space(string wire) =>
        TlsReport.ReadResult(wire).ShouldBe(TlsFailureResult.CertificateExpired);
}
