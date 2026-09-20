using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// The message a delivery test sends. A real message, because the whole point is that a receiver
/// applies its ordinary rules to it — anything malformed would be judged as malformed rather
/// than as this server's configuration.
/// </summary>
public sealed class DeliveryTestMessageTests
{
    private static readonly EmailAddress Sender = EmailAddress.Parse("postmaster@example.com");
    private static readonly EmailAddress Recipient = EmailAddress.Parse("someone@example.net");

    private static string Compose(DateTimeOffset? now = null) =>
        DeliveryTestMessage.Compose(
            Sender,
            Recipient,
            "<abc123@mail.example.com>",
            now ?? new DateTimeOffset(2026, 9, 20, 11, 30, 5, TimeSpan.Zero));

    [Fact]
    public void The_message_carries_the_addresses_it_was_composed_for()
    {
        string text = Compose();

        text.ShouldContain("From: <postmaster@example.com>\r\n");
        text.ShouldContain("To: <someone@example.net>\r\n");
        text.ShouldContain("Message-ID: <abc123@mail.example.com>\r\n");
        text.ShouldContain($"Subject: {DeliveryTestMessage.Subject}\r\n");
    }

    /// <summary>
    /// RFC 5322 §3.3's <c>date-time</c> in the fixed form every mail system writes, and
    /// invariant: a host with a Turkish or French locale would otherwise produce month names no
    /// receiver parses.
    /// </summary>
    [Fact]
    public void The_date_is_an_invariant_rfc_5322_date_time()
    {
        Compose().ShouldContain("Date: Sun, 20 Sep 2026 11:30:05 +0000\r\n");
    }

    /// <summary>
    /// The offset is written even though the instant is UTC, because <c>date-time</c>'s
    /// <c>zone</c> is not optional.
    /// </summary>
    [Fact]
    public void A_non_utc_instant_is_still_written_as_utc_with_an_explicit_zone()
    {
        string text = Compose(new DateTimeOffset(2026, 9, 20, 13, 30, 5, TimeSpan.FromHours(2)));

        text.ShouldContain("Date: Sun, 20 Sep 2026 11:30:05 +0000\r\n");
    }

    /// <summary>
    /// <b>RFC 3834's field, with the value for something a machine produced that is not a
    /// reply.</b> Without it, a receiver running an out-of-office responder answers this
    /// message, and the answer arrives at whatever address the test was sent from — which may
    /// be a mailbox nobody reads, or a loop.
    /// </summary>
    [Fact]
    public void The_message_says_it_was_generated_by_a_machine()
    {
        Compose().ShouldContain("Auto-Submitted: auto-generated\r\n");
    }

    /// <summary>
    /// The headers end with one blank line and the body follows. RFC 5322 §2.1 makes that
    /// separator the whole structure of a message, and a composer that ran them together would
    /// have the receiver read the body as headers.
    /// </summary>
    [Fact]
    public void The_headers_are_separated_from_the_body_by_one_blank_line()
    {
        string text = Compose();
        int boundary = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);

        boundary.ShouldBeGreaterThan(0);
        text[..boundary].ShouldNotContain("This is an automated test message");
        text[(boundary + 4)..].ShouldStartWith("This is an automated test message");
    }

    /// <summary>
    /// <b>It explains itself.</b> Whoever receives it is a person the operator nominated, quite
    /// possibly on a mailbox they do not control, and a message with no explanation is
    /// indistinguishable from a probe by a stranger.
    /// </summary>
    [Fact]
    public void The_body_says_what_it_is_who_sent_it_and_that_no_reply_is_needed()
    {
        string text = Compose();

        text.ShouldContain("automated test message");
        text.ShouldContain("example.com");
        text.ShouldContain("No reply is needed");
        text.ShouldContain("record what it made of this message's SPF, DKIM and DMARC");
    }

    /// <summary>
    /// The body points at the receiving system's authentication header without naming it.
    /// <c>NoUntrustedAuthenticationHeaderTrustTests</c> scans production source for that field
    /// name outside comments, and the guard — against computing this server's own verdicts from
    /// a header read off the wire — is worth more than the precision of one sentence.
    /// </summary>
    [Fact]
    public void The_body_does_not_name_the_header_the_security_guard_watches_for()
    {
        Compose().ShouldNotContain("Authentication-Results", Case.Insensitive);
    }

    /// <summary>Every line ends CRLF, which RFC 5322 §2.1 requires of every one of them.</summary>
    [Fact]
    public void Every_line_ends_with_crlf()
    {
        string text = Compose();

        text.ShouldEndWith("\r\n");
        text.Replace("\r\n", string.Empty, StringComparison.Ordinal)
            .ShouldNotContain("\n");
    }

    [Fact]
    public void The_composer_refuses_incomplete_arguments()
    {
        DateTimeOffset now = DateTimeOffset.UnixEpoch;

        Should.Throw<ArgumentNullException>(
            () => DeliveryTestMessage.Compose(null!, Recipient, "<a@b>", now));

        Should.Throw<ArgumentNullException>(
            () => DeliveryTestMessage.Compose(Sender, null!, "<a@b>", now));

        Should.Throw<ArgumentException>(
            () => DeliveryTestMessage.Compose(Sender, Recipient, "  ", now));
    }
}
