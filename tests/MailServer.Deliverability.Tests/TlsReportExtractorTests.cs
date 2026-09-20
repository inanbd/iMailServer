using System.IO.Compression;
using System.Text;
using MailServer.Domain.Deliverability;
using MailServer.Infrastructure.Deliverability;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// Getting a report out of the message a sender delivered it in.
/// </summary>
/// <remarks>
/// Three layers whose sizes a stranger chooses — the MIME part, the transfer encoding, the
/// compression — so the bounds are as much the subject here as the happy path.
/// </remarks>
public sealed class TlsReportExtractorTests
{
    private static readonly TlsReportExtractor Extractor = new(new TlsReportReader());

    private const string ReportJson = """
        {
          "organization-name": "Google Inc.",
          "report-id": "2026.09.20T00.00.00Z_example.com",
          "policies": [{
            "policy": { "policy-type": "sts", "policy-domain": "example.com" },
            "summary": {
              "total-successful-session-count": 1200,
              "total-failure-session-count": 4
            },
            "failure-details": [
              { "result-type": "certificate-expired", "receiving-mx-hostname": "mx.example.com", "failed-session-count": 4 }
            ]
          }]
        }
        """;

    private static byte[] Gzip(string text)
    {
        using MemoryStream output = new();

        using (GZipStream gzip = new(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            gzip.Write(bytes, 0, bytes.Length);
        }

        return output.ToArray();
    }

    /// <summary>A report message as Google actually sends one: a gzip attachment, base64-encoded.</summary>
    private static byte[] ReportMessage(
        string contentType = "application/tlsrpt+gzip",
        string encoding = "base64",
        byte[]? attachment = null)
    {
        string body = Convert.ToBase64String(attachment ?? Gzip(ReportJson), Base64FormattingOptions.InsertLineBreaks);

        return Encoding.ASCII.GetBytes(
            "From: noreply-smtp-tls-reporting@google.com\r\n" +
            "To: tlsrpt@example.com\r\n" +
            "Subject: Report Domain: example.com\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: multipart/mixed; boundary=\"b1\"\r\n" +
            "\r\n" +
            "--b1\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n" +
            "\r\n" +
            "This is an aggregate TLS report.\r\n" +
            "\r\n" +
            "--b1\r\n" +
            $"Content-Type: {contentType}; name=\"report.json.gz\"\r\n" +
            $"Content-Transfer-Encoding: {encoding}\r\n" +
            "Content-Disposition: attachment; filename=\"report.json.gz\"\r\n" +
            "\r\n" +
            body + "\r\n" +
            "--b1--\r\n");
    }

    private static TlsReport Extract(byte[] message)
    {
        Extractor.TryExtract(message, out TlsReport? report, out string? error).ShouldBeTrue(error);
        return report.ShouldNotBeNull();
    }

    private static string Refuse(byte[] message)
    {
        Extractor.TryExtract(message, out TlsReport? report, out string? error).ShouldBeFalse();
        report.ShouldBeNull();
        return error.ShouldNotBeNull();
    }

    [Fact]
    public void A_report_message_gives_up_its_report()
    {
        TlsReport report = Extract(ReportMessage());

        report.OrganizationName.ShouldBe("Google Inc.");
        report.SuccessfulSessionCount.ShouldBe(1200);
        report.FailedSessionCount.ShouldBe(4);
        report.FailuresByImpact().ShouldHaveSingleItem()
            .Result.ShouldBe(TlsFailureResult.CertificateExpired);
    }

    /// <summary>
    /// §3 registers application/tlsrpt+gzip and real senders use several other types. Insisting
    /// on the registered one would discard most reports, so the parse is the real test.
    /// </summary>
    [Theory]
    [InlineData("application/tlsrpt+gzip")]
    [InlineData("application/gzip")]
    [InlineData("application/x-gzip")]
    [InlineData("application/octet-stream")]
    public void The_media_type_the_sender_chose_does_not_decide_it(string contentType) =>
        Extract(ReportMessage(contentType)).OrganizationName.ShouldBe("Google Inc.");

    /// <summary>
    /// An 8BITMIME path carries the gzip without base64, so the identity encodings have to work
    /// too.
    /// </summary>
    [Fact]
    public void An_unencoded_attachment_is_read()
    {
        byte[] gz = Gzip(ReportJson);

        byte[] message = Encoding.ASCII.GetBytes(
            "From: reporter@example.net\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: application/tlsrpt+gzip\r\n" +
            "Content-Transfer-Encoding: binary\r\n" +
            "\r\n")
            .Concat(gz)
            .ToArray();

        Extract(message).OrganizationName.ShouldBe("Google Inc.");
    }

    /// <summary>
    /// RFC 2045 §6.8 requires base64 to be line-wrapped, so every real attachment carries CRLFs
    /// that a naive decode would refuse.
    /// </summary>
    [Fact]
    public void Line_wrapped_base64_is_read() =>
        Extract(ReportMessage()).ReportId.ShouldBe("2026.09.20T00.00.00Z_example.com");

    /// <summary>
    /// An operator forwarding a report to postmaster is a real way for one to arrive, and the
    /// report is then inside a message/rfc822 part.
    /// </summary>
    [Fact]
    public void A_forwarded_report_is_found_inside_the_forwarded_message()
    {
        string inner = Encoding.ASCII.GetString(ReportMessage());

        byte[] forwarded = Encoding.ASCII.GetBytes(
            "From: admin@example.com\r\n" +
            "To: postmaster@example.com\r\n" +
            "Subject: Fwd: Report Domain: example.com\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: multipart/mixed; boundary=\"outer\"\r\n" +
            "\r\n" +
            "--outer\r\n" +
            "Content-Type: text/plain\r\n" +
            "\r\n" +
            "Have a look at this.\r\n" +
            "\r\n" +
            "--outer\r\n" +
            "Content-Type: message/rfc822\r\n" +
            "\r\n" +
            inner +
            "\r\n--outer--\r\n");

        Extract(forwarded).OrganizationName.ShouldBe("Google Inc.");
    }

    // ---- The bounds ---------------------------------------------------------------------------

    /// <summary>
    /// The one that matters. Gzip's ratio is unbounded, so a small attachment can ask for
    /// arbitrary memory — a bound on the attachment alone would not catch it.
    /// </summary>
    [Fact]
    public void A_compression_bomb_is_refused_rather_than_decompressed()
    {
        // A few hundred kilobytes of zeroes compresses to almost nothing and expands past the
        // ceiling, which is the whole shape of the attack.
        byte[] bomb = Gzip(new string('\0', TlsReportExtractor.MaxDecompressedBytes + 1024));

        bomb.Length.ShouldBeLessThan(TlsReportExtractor.MaxEncodedBytes);

        Refuse(ReportMessage(attachment: bomb)).ShouldContain("decompresses to more than");
    }

    /// <summary>
    /// Refused rather than truncated: a half-read report parses into a smaller set of failures
    /// than the sender counted, which is worse than no report at all.
    /// </summary>
    [Fact]
    public void An_oversized_report_is_not_silently_truncated() =>
        Refuse(ReportMessage(attachment: Gzip(new string('x', TlsReportExtractor.MaxDecompressedBytes + 1))))
            .ShouldNotContain("truncat");

    [Fact]
    public void A_part_that_is_not_gzip_is_refused_with_a_reason() =>
        Refuse(ReportMessage(attachment: Encoding.UTF8.GetBytes("this is not gzip at all")))
            .ShouldContain("not gzip");

    [Fact]
    public void Gzip_that_is_not_a_report_is_refused_with_the_parser_s_reason() =>
        Refuse(ReportMessage(attachment: Gzip("""{ "not": "a report" }""")))
            .ShouldContain("policies");

    [Fact]
    public void Malformed_base64_is_refused_with_a_reason()
    {
        byte[] message = Encoding.ASCII.GetBytes(
            "MIME-Version: 1.0\r\n" +
            "Content-Type: application/tlsrpt+gzip\r\n" +
            "Content-Transfer-Encoding: base64\r\n" +
            "\r\n" +
            "!!!! not base64 !!!!\r\n");

        Refuse(message).ShouldContain("base64");
    }

    /// <summary>
    /// quoted-printable is deliberately not attempted: no sender uses it for a gzip attachment,
    /// and a wrong decode would produce plausible bytes that fail later with a confusing error.
    /// </summary>
    [Fact]
    public void An_encoding_this_does_not_read_says_so() =>
        Refuse(ReportMessage(encoding: "quoted-printable")).ShouldContain("transfer encoding");

    /// <summary>
    /// A message with nothing attachment-shaped is a covering note or a bounce, not a failure
    /// worth a confusing diagnosis.
    /// </summary>
    [Fact]
    public void A_message_with_no_attachment_says_that_rather_than_guessing()
    {
        byte[] plain = Encoding.ASCII.GetBytes(
            "From: someone@example.net\r\n" +
            "Content-Type: text/plain\r\n" +
            "\r\n" +
            "Just a note, no report here.\r\n");

        Refuse(plain).ShouldContain("no attachment");
    }

    /// <summary>
    /// When several parts were tried, each one's reason is kept — "no report found" on a
    /// message whose parts each failed differently is a diagnosis nobody can act on.
    /// </summary>
    [Fact]
    public void Every_candidate_s_own_reason_is_reported()
    {
        byte[] message = Encoding.ASCII.GetBytes(
            "MIME-Version: 1.0\r\n" +
            "Content-Type: multipart/mixed; boundary=\"b1\"\r\n" +
            "\r\n" +
            "--b1\r\n" +
            "Content-Type: application/gzip\r\n" +
            "Content-Transfer-Encoding: base64\r\n" +
            "\r\n" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes("not gzip")) + "\r\n" +
            "--b1\r\n" +
            "Content-Type: application/gzip\r\n" +
            "Content-Transfer-Encoding: quoted-printable\r\n" +
            "\r\n" +
            "whatever\r\n" +
            "--b1--\r\n");

        string error = Refuse(message);

        error.ShouldContain("not gzip");
        error.ShouldContain("transfer encoding");
    }
}
