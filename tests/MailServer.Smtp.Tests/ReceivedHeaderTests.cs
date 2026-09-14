using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;

namespace MailServer.Smtp.Tests;

public sealed class ReceivedHeaderTests
{
    private static readonly DateTimeOffset When = new(2026, 3, 1, 14, 30, 45, TimeSpan.Zero);

    private static readonly StoredMessageId MessageId =
        new(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"));

    private static ReceivedHeaderContext Context(
        string? greeted = "client.example.net",
        string? reverseDns = null,
        string? tls = null,
        string protocol = "ESMTP",
        string recipient = "user@example.com") =>
        new(
            IpAddressValue.Parse("198.51.100.20"),
            greeted,
            reverseDns,
            "mail.example.com",
            EmailAddress.Parse(recipient),
            protocol,
            tls,
            MessageId,
            When);

    [Fact]
    public void The_header_records_the_hop()
    {
        string header = ReceivedHeader.Build(Context());

        header.ShouldStartWith("Received: from client.example.net (");
        header.ShouldContain("[198.51.100.20]");
        header.ShouldContain("by mail.example.com with ESMTP");
        header.ShouldContain("for <user@example.com>");
        header.ShouldContain("Sun, 01 Mar 2026 14:30:45 +0000");
        header.ShouldEndWith("\r\n");
    }

    [Fact]
    public void The_claimed_name_and_the_observed_address_are_visually_distinct()
    {
        // The whole value of the header to a postmaster: the name before the parentheses is what
        // the client said, and the address inside them is what this server saw. Presenting them
        // alike would make a forged EHLO name look like evidence.
        string header = ReceivedHeader.Build(Context(greeted: "totally.legitimate.example"));

        header.ShouldContain("from totally.legitimate.example ([198.51.100.20])");
    }

    [Fact]
    public void A_resolved_reverse_dns_name_sits_with_the_address_not_with_the_claim()
    {
        string header = ReceivedHeader.Build(Context(reverseDns: "mail-out.example.net"));

        header.ShouldContain("(mail-out.example.net [198.51.100.20])");
    }

    [Fact]
    public void A_client_that_did_not_greet_is_recorded_as_unknown()
    {
        ReceivedHeader.Build(Context(greeted: null)).ShouldContain("from unknown (");
    }

    // ---------------------------------------------------------------------------------------
    // Header injection.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("evil\r\nX-Spam-Status: No")]
    [InlineData("evil\nX-Spam-Status: No")]
    [InlineData("evil\rX-Spam-Status: No")]
    [InlineData("evil\0X-Spam-Status: No")]
    public void A_line_ending_in_the_greeted_name_cannot_start_a_new_header(string hostile)
    {
        // The EHLO name is attacker-chosen text going into a header block. A CR or LF in it would
        // end this header and begin another - written into the stored message, where every
        // downstream spam filter and mail client reads it as genuine.
        string header = ReceivedHeader.Build(Context(greeted: hostile));

        header.ShouldNotContain("\r\nX-Spam-Status:");
        header.ShouldNotContain("\nX-Spam-Status:");
        header.ShouldContain("from evilX-Spam-Status: No (");
    }

    [Fact]
    public void The_header_is_one_folded_field_and_nothing_else()
    {
        // Continuation lines must begin with whitespace, or they are separate header fields. A
        // header that folded wrongly would split into fields nobody intended.
        string header = ReceivedHeader.Build(Context(greeted: "evil\r\nInjected: yes", reverseDns: "x\r\ny"));

        string[] lines = header.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        lines[0].ShouldStartWith("Received: ");

        foreach (string continuation in lines.Skip(1))
        {
            continuation.ShouldStartWith("\t", customMessage: $"'{continuation}' is not a continuation line.");
        }
    }

    [Fact]
    public void A_very_long_claimed_name_is_truncated()
    {
        // Without a cap, a peer that sends a four-kilobyte EHLO name adds four kilobytes of its
        // own choosing to every message it delivers, and this server stores it.
        string header = ReceivedHeader.Build(Context(greeted: new string('h', 4000)));

        header.Length.ShouldBeLessThan(1000);
    }

    [Fact]
    public void Sanitising_keeps_ordinary_text_intact()
    {
        ReceivedHeader.Sanitize("mail-out-1.example.net").ShouldBe("mail-out-1.example.net");
        ReceivedHeader.Sanitize(null).ShouldBeNull();
        ReceivedHeader.Sanitize(string.Empty).ShouldBe(string.Empty);
    }

    // ---------------------------------------------------------------------------------------
    // The "with" clause, which is what a postmaster reads to check whether TLS was used.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(false, false, false, "SMTP")]
    [InlineData(false, true, true, "SMTP")]
    [InlineData(true, false, false, "ESMTP")]
    [InlineData(true, true, false, "ESMTPS")]
    [InlineData(true, true, true, "ESMTPSA")]
    public void The_protocol_name_describes_what_actually_happened(
        bool extended,
        bool tls,
        bool authenticated,
        string expected)
    {
        // Reporting ESMTPS for a session that was never encrypted would make the header lie
        // about the one property it is most often consulted for.
        ReceivedHeader.DescribeProtocol(extended, tls, authenticated).ShouldBe(expected);
    }

    [Fact]
    public void A_tls_description_appears_only_when_there_was_one()
    {
        ReceivedHeader.Build(Context(protocol: "ESMTPS", tls: "TLS1.3 with TLS_AES_256_GCM_SHA384"))
            .ShouldContain("with ESMTPS (TLS1.3 with TLS_AES_256_GCM_SHA384)");

        ReceivedHeader.Build(Context(protocol: "ESMTP")).ShouldContain("with ESMTP\r\n");
    }

    [Fact]
    public void The_timestamp_always_carries_an_offset()
    {
        // A trace header timestamped without one is unusable for reconstructing a path across
        // time zones, which is the only reason anyone reads the timestamp.
        ReceivedHeader.Build(Context()).ShouldContain("+0000");
    }

    [Fact]
    public void The_message_id_appears_so_a_delivery_can_be_traced_to_its_stored_file()
    {
        ReceivedHeader.Build(Context()).ShouldContain("id 0f8fad5bd9cb469fa16570867728950e");
    }
}
