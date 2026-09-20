using MailServer.Domain.Mail;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;

namespace MailServer.Authentication.Tests;

/// <summary>
/// Reading <c>Received:</c> headers back into RFC 5321 §4.4's clauses.
/// </summary>
/// <remarks>
/// Nothing this parser produces is evidence: any host in a path can write any Received header it
/// likes. These tests are about reading faithfully what was claimed, which is what makes a forged
/// chain visible as a forged chain.
/// </remarks>
public sealed class ReceivedTraceTests
{
    // ---------------------------------------------------------------------------------------
    // The clauses.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The FROM clause is split into what the client claimed and what the server observed.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §4.4 annotates its <c>TCP-info</c> production "Information derived by server from
    /// TCP connection not client EHLO" — so the greeted name is a claim and the bracketed address
    /// is not. An analyser that flattened them into one string would lose the only distinction in
    /// the header that survives a hostile sender.
    /// </remarks>
    [Fact]
    public void The_from_clause_separates_the_claim_from_the_observation()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from claimed.example.net (real.example.org [203.0.113.10]) " +
            "by mail.example.com with ESMTPS id abc123; " +
            "Sat, 19 Sep 2026 12:00:00 +0000");

        ReceivedFrom from = hop.From.ShouldNotBeNull();

        from.GreetedName.ShouldBe("claimed.example.net");
        from.ObservedName.ShouldBe("real.example.org");
        from.ObservedAddress.ShouldBe("203.0.113.10");
    }

    /// <summary>Every clause RFC 5321 §4.4 defines is read.</summary>
    [Fact]
    public void Every_clause_is_read()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from a.example.net (a.example.net [198.51.100.7]) " +
            "by mail.example.com via TCP with ESMTPSA id 7f3a " +
            "for <recipient@example.com>; " +
            "Sat, 19 Sep 2026 12:00:00 +0000");

        hop.By.ShouldBe("mail.example.com");
        hop.Via.ShouldBe("TCP");
        hop.With.ShouldBe("ESMTPSA");
        hop.Id.ShouldBe("7f3a");
        hop.For.ShouldBe("<recipient@example.com>");
        hop.Unparsed.ShouldBeFalse();
    }

    /// <summary>
    /// A TCP-info with only an address yields no observed name.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §4.4: <c>TCP-info = address-literal / ( Domain FWS address-literal )</c> — the
    /// name is optional, and most servers do not do the reverse lookup that would supply it.
    /// </remarks>
    [Fact]
    public void A_tcp_info_with_only_an_address_yields_no_observed_name()
    {
        ReceivedFrom from = ReceivedTrace
            .Parse("from claimed.example.net ([203.0.113.10]) by mail.example.com; " +
                   "Sat, 19 Sep 2026 12:00:00 +0000")
            .From.ShouldNotBeNull();

        from.ObservedName.ShouldBeNull();
        from.ObservedAddress.ShouldBe("203.0.113.10");
    }

    /// <summary>
    /// An IPv6 literal's <c>IPv6:</c> tag is part of the syntax, not part of the address.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §4.1.3 requires the tag on an IPv6 address-literal. Leaving it on would give an
    /// operator a string that no lookup tool accepts.
    /// </remarks>
    [Fact]
    public void An_ipv6_literals_tag_is_not_part_of_the_address()
    {
        ReceivedTrace
            .Parse("from a.example.net ([IPv6:2001:db8::1]) by mail.example.com; " +
                   "Sat, 19 Sep 2026 12:00:00 +0000")
            .From.ShouldNotBeNull().ObservedAddress.ShouldBe("2001:db8::1");
    }

    /// <summary>A header with no TCP-info still yields the greeted name.</summary>
    [Fact]
    public void A_from_clause_with_no_comment_is_all_claim()
    {
        ReceivedFrom from = ReceivedTrace
            .Parse("from a.example.net by mail.example.com; Sat, 19 Sep 2026 12:00:00 +0000")
            .From.ShouldNotBeNull();

        from.GreetedName.ShouldBe("a.example.net");
        from.ObservedName.ShouldBeNull();
        from.ObservedAddress.ShouldBeNull();
    }

    /// <summary>
    /// A clause keyword inside a hostname is not a clause.
    /// </summary>
    /// <remarks>
    /// Without a token-boundary check, <c>by</c> matches inside <c>mailby.example.com</c> and
    /// <c>id</c> matches inside almost any hostname carrying those two letters — splitting one
    /// clause into several and attributing the pieces to hops that do not exist.
    /// </remarks>
    [Fact]
    public void A_clause_keyword_inside_a_hostname_is_not_a_clause()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from mailby.example.net by identity.example.com; Sat, 19 Sep 2026 12:00:00 +0000");

        hop.From.ShouldNotBeNull().GreetedName.ShouldBe("mailby.example.net");
        hop.By.ShouldBe("identity.example.com");
        hop.Id.ShouldBeNull();
    }

    /// <summary>Clause keywords are matched without regard to case.</summary>
    [Fact]
    public void Clause_keywords_are_case_insensitive()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "FROM a.example.net BY mail.example.com WITH ESMTP; Sat, 19 Sep 2026 12:00:00 +0000");

        hop.From.ShouldNotBeNull().GreetedName.ShouldBe("a.example.net");
        hop.By.ShouldBe("mail.example.com");
        hop.With.ShouldBe("ESMTP");
    }

    // ---------------------------------------------------------------------------------------
    // The timestamp.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The split is at the last top-level semicolon, so a comment may contain others.
    /// </summary>
    /// <remarks>
    /// <c>with ESMTPS (TLS1.3; AEAD-AES256-GCM-SHA384)</c> is a shape real servers emit. Taking
    /// the first semicolon would read "AEAD-AES256-GCM-SHA384)…" as the date and lose the hop's
    /// timestamp — and with it both delays either side of that hop.
    /// </remarks>
    [Fact]
    public void A_semicolon_inside_a_comment_does_not_end_the_clauses()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from a.example.net ([203.0.113.10]) by mail.example.com " +
            "with ESMTPS (TLS1.3; AEAD-AES256-GCM-SHA384) id 7f3a; " +
            "Sat, 19 Sep 2026 12:00:00 +0000");

        hop.Timestamp.ShouldBe(new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));
        hop.Id.ShouldBe("7f3a");
    }

    /// <summary>A semicolon inside an angle-addr does not end the clauses either.</summary>
    [Fact]
    public void A_semicolon_inside_an_angle_addr_does_not_end_the_clauses()
    {
        ReceivedTrace
            .Parse("from a.example.net by mail.example.com for <odd;name@example.com>; " +
                   "Sat, 19 Sep 2026 12:00:00 +0000")
            .Timestamp.ShouldBe(new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));
    }

    /// <summary>
    /// With two top-level semicolons, the date follows the last one.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §4.4: <c>Stamp = From-domain By-domain Opt-info [CFWS] ";" FWS date-time</c> —
    /// one semicolon, and a date-time contains none. So when a relay emits a stray extra one,
    /// the last is still the one before the date. Taking the first would make the date read
    /// "by z; Sat, …", which parses as nothing and costs the hop its timestamp — and a lost
    /// timestamp costs two delays, not one.
    /// </remarks>
    [Fact]
    public void With_two_top_level_semicolons_the_date_follows_the_last()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from a.example.net ([203.0.113.10]); by mail.example.com; " +
            "Sat, 19 Sep 2026 12:00:00 +0000");

        hop.Timestamp.ShouldBe(new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));
        hop.By.ShouldBe("mail.example.com");
    }

    /// <summary>A trailing parenthesised comment after the zone does not break the date.</summary>
    [Theory]
    [InlineData("Sat, 19 Sep 2026 12:00:00 +0000 (UTC)")]
    [InlineData("Sat, 19 Sep 2026 12:00:00 +0000")]
    public void A_comment_after_the_zone_does_not_break_the_date(string date)
    {
        ReceivedTrace.Parse($"by mail.example.com; {date}")
            .Timestamp.ShouldBe(new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));
    }

    /// <summary>
    /// RFC 5322 §4.3's obsolete zone names are read.
    /// </summary>
    /// <remarks>
    /// <c>obs-zone = "UT" / "GMT" / "EST" / "EDT" / "CST" / "CDT" / "MST" / "MDT" / "PST" /
    /// "PDT"</c>. The platform's own date parser reads none of them, so a header stamped by an
    /// older relay would lose its timestamp — and a lost timestamp costs two delays, not one.
    /// </remarks>
    [Theory]
    [InlineData("Sat, 19 Sep 2026 12:00:00 GMT", 0)]
    [InlineData("Sat, 19 Sep 2026 12:00:00 UT", 0)]
    [InlineData("Sat, 19 Sep 2026 12:00:00 EST", -5)]
    [InlineData("Sat, 19 Sep 2026 12:00:00 PDT", -7)]
    public void The_obsolete_zone_names_are_read(string date, int offsetHours)
    {
        DateTimeOffset stamp = ReceivedTrace.Parse($"by mail.example.com; {date}")
            .Timestamp.ShouldNotBeNull();

        stamp.Offset.ShouldBe(TimeSpan.FromHours(offsetHours));
        stamp.UtcDateTime.ShouldBe(new DateTime(2026, 9, 19, 12 - offsetHours, 0, 0, DateTimeKind.Utc));
    }

    /// <summary>An unreadable date leaves the timestamp null rather than failing the parse.</summary>
    [Fact]
    public void An_unreadable_date_leaves_the_timestamp_null()
    {
        ReceivedHop hop = ReceivedTrace.Parse("by mail.example.com; yesterday afternoon");

        hop.Timestamp.ShouldBeNull();
        hop.By.ShouldBe("mail.example.com");
    }

    // ---------------------------------------------------------------------------------------
    // Tolerance.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A header with nothing recognisable is returned, marked.
    /// </summary>
    /// <remarks>
    /// RFC 5322 §3.6.7 says outright that "the trace fields are strictly informational, and any
    /// formal interpretation of them is outside of the scope of this document", so a header that
    /// yields no clause is not an error. Dropping it would shorten a path the operator is
    /// counting — and a hop whose header cannot be read is exactly the hop worth looking at.
    /// </remarks>
    [Fact]
    public void A_header_with_nothing_recognisable_is_still_a_hop()
    {
        ReceivedHop hop = ReceivedTrace.Parse("something entirely unlike a trace header");

        hop.Unparsed.ShouldBeTrue();
        hop.By.ShouldBeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void An_empty_header_is_unparsed(string? value)
    {
        ReceivedTrace.Parse(value).Unparsed.ShouldBeTrue();
    }

    /// <summary>Folding is removed, keeping the whitespace that followed it.</summary>
    [Fact]
    public void Folding_is_removed()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from a.example.net ([203.0.113.10])\r\n\tby mail.example.com\r\n\twith ESMTPS;" +
            "\r\n\tSat, 19 Sep 2026 12:00:00 +0000");

        hop.By.ShouldBe("mail.example.com");
        hop.With.ShouldBe("ESMTPS");
        hop.Timestamp.ShouldNotBeNull();
    }

    /// <summary>Comments are collected, so nothing in the header is silently dropped.</summary>
    [Fact]
    public void Comments_are_collected()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from a.example.net (a.example.net [203.0.113.10]) by mail.example.com " +
            "with ESMTPS (TLS1.3); Sat, 19 Sep 2026 12:00:00 +0000");

        hop.Comments.ShouldContain("a.example.net [203.0.113.10]");
        hop.Comments.ShouldContain("TLS1.3");
    }

    /// <summary>
    /// Nested comments are handled, because RFC 5322 §3.2.2 allows them.
    /// </summary>
    /// <remarks>
    /// <c>ccontent = ctext / quoted-pair / comment</c> — a comment may contain a comment. A
    /// scanner that counted the first <c>)</c> as the end would treat the rest of the header as
    /// clause text and find clauses inside somebody's free-form note.
    /// </remarks>
    [Fact]
    public void Nested_comments_are_handled()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from a.example.net (outer (inner) more [203.0.113.10]) by mail.example.com; " +
            "Sat, 19 Sep 2026 12:00:00 +0000");

        hop.By.ShouldBe("mail.example.com");
        hop.From.ShouldNotBeNull().ObservedAddress.ShouldBe("203.0.113.10");
    }

    /// <summary>An unterminated comment still yields what it opened.</summary>
    [Fact]
    public void An_unterminated_comment_still_yields_its_contents()
    {
        ReceivedHop hop = ReceivedTrace.Parse("from a.example.net (unknown [203.0.113.10]");

        hop.Comments.ShouldContain(c => c.Contains("203.0.113.10", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // The chain.
    // ---------------------------------------------------------------------------------------

    private static string Header(string by, string stamp, string from = "a.example.net") =>
        $"from {from} ([203.0.113.10]) by {by}; {stamp}";

    /// <summary>
    /// Delays are computed against the hop below, which is the earlier one.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §4.4: "SMTP servers MUST prepend Received lines to messages; they MUST NOT change
    /// the order of existing lines or insert Received lines in any other location." So the
    /// topmost header is the most recent hop, and the one below it handed the message over.
    /// Reading the block in the other direction would invert every delay in the chain.
    /// </remarks>
    [Fact]
    public void A_delay_is_measured_against_the_hop_below()
    {
        ReceivedChain chain = ReceivedTrace.ParseChain(
        [
            Header("third.example.com", "Sat, 19 Sep 2026 12:00:30 +0000"),
            Header("second.example.com", "Sat, 19 Sep 2026 12:00:10 +0000"),
            Header("first.example.com", "Sat, 19 Sep 2026 12:00:00 +0000"),
        ]);

        chain.Hops.Count.ShouldBe(3);
        chain.Hops[0].Delay.ShouldBe(TimeSpan.FromSeconds(20));
        chain.Hops[1].Delay.ShouldBe(TimeSpan.FromSeconds(10));

        // The oldest hop has nothing before it.
        chain.Hops[2].Delay.ShouldBeNull();
    }

    /// <summary>The total transit spans the earliest readable stamp to the latest.</summary>
    [Fact]
    public void The_total_transit_spans_the_whole_chain()
    {
        ReceivedChain chain = ReceivedTrace.ParseChain(
        [
            Header("third.example.com", "Sat, 19 Sep 2026 12:05:00 +0000"),
            Header("second.example.com", "Sat, 19 Sep 2026 12:00:10 +0000"),
            Header("first.example.com", "Sat, 19 Sep 2026 12:00:00 +0000"),
        ]);

        chain.TotalTransit.ShouldBe(TimeSpan.FromMinutes(5));
    }

    /// <summary>
    /// A negative delay is reported, not clamped.
    /// </summary>
    /// <remarks>
    /// Two hops keep independent clocks, so a message can be stamped as arriving before it was
    /// sent. Clamping to zero would hide the one thing that tells an operator: one of those two
    /// hosts has a clock problem, which is itself a deliverability finding and which silently
    /// distorts every other delay in the chain.
    /// </remarks>
    [Fact]
    public void A_negative_delay_is_reported_rather_than_clamped()
    {
        ReceivedChain chain = ReceivedTrace.ParseChain(
        [
            Header("second.example.com", "Sat, 19 Sep 2026 12:00:00 +0000"),
            Header("first.example.com", "Sat, 19 Sep 2026 12:00:30 +0000"),
        ]);

        chain.Hops[0].Delay.ShouldBe(TimeSpan.FromSeconds(-30));
    }

    /// <summary>Offsets are honoured, so hops in different zones compare correctly.</summary>
    [Fact]
    public void Hops_in_different_zones_compare_correctly()
    {
        ReceivedChain chain = ReceivedTrace.ParseChain(
        [
            Header("second.example.com", "Sat, 19 Sep 2026 12:00:10 +0000"),
            Header("first.example.com", "Sat, 19 Sep 2026 07:00:00 -0500"),
        ]);

        chain.Hops[0].Delay.ShouldBe(TimeSpan.FromSeconds(10));
    }

    /// <summary>A hop with no timestamp breaks the delay either side of it, and no more.</summary>
    [Fact]
    public void A_hop_with_no_timestamp_breaks_only_its_own_delays()
    {
        ReceivedChain chain = ReceivedTrace.ParseChain(
        [
            Header("third.example.com", "Sat, 19 Sep 2026 12:00:30 +0000"),
            "by second.example.com",
            Header("first.example.com", "Sat, 19 Sep 2026 12:00:00 +0000"),
        ]);

        chain.Hops[0].Delay.ShouldBeNull();
        chain.Hops[1].Delay.ShouldBeNull();
        chain.Hops.Count.ShouldBe(3);
        chain.TotalTransit.ShouldBe(TimeSpan.FromSeconds(30));
    }

    /// <summary>An empty chain is an empty chain, not a failure.</summary>
    [Fact]
    public void An_empty_chain_has_no_transit()
    {
        ReceivedChain chain = ReceivedTrace.ParseChain([]);

        chain.Hops.ShouldBeEmpty();
        chain.TotalTransit.ShouldBeNull();
    }

    // ---------------------------------------------------------------------------------------
    // Round trip against this server's own generator.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// What <see cref="ReceivedHeader.Build"/> writes, this parser reads back.
    /// </summary>
    /// <remarks>
    /// The test that ties the two halves together: until there was a parser, nothing could check
    /// that the header this server emits is one anybody can read. A change to either side that
    /// broke the other would otherwise show up only in somebody else's postmaster tooling.
    /// </remarks>
    [Fact]
    public void This_servers_own_header_parses_back_to_what_went_in()
    {
        DateTimeOffset now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);
        StoredMessageId messageId = StoredMessageId.New();

        string built = ReceivedHeader.Build(new ReceivedHeaderContext(
            IpAddressValue.Parse("203.0.113.10"),
            GreetedName: "client.example.net",
            ReverseDnsName: "real.example.org",
            LocalHostname: "mail.example.com",
            Recipient: EmailAddress.Parse("recipient@example.com"),
            Protocol: "ESMTPS",
            TlsDescription: "TLS1.3 with AEAD-AES256-GCM-SHA384",
            MessageId: messageId,
            ReceivedAt: now));

        // Strip the field name the generator includes, which is what a header reader would do.
        string value = built["Received:".Length..].Trim();

        ReceivedHop hop = ReceivedTrace.Parse(value);

        ReceivedFrom from = hop.From.ShouldNotBeNull();

        from.GreetedName.ShouldBe("client.example.net");
        from.ObservedName.ShouldBe("real.example.org");
        from.ObservedAddress.ShouldBe("203.0.113.10");

        hop.By.ShouldBe("mail.example.com");
        hop.With.ShouldBe("ESMTPS");
        hop.Id.ShouldBe(messageId.Value.ToString("N"));
        hop.For.ShouldBe("<recipient@example.com>");
        hop.Timestamp.ShouldBe(now);
        hop.Unparsed.ShouldBeFalse();
    }

    /// <summary>
    /// The same round trip for the shape this server actually emits today.
    /// </summary>
    /// <remarks>
    /// <c>SmtpConnectionHandler</c> passes <c>ReverseDnsName: null</c> unconditionally and names
    /// a recipient only when there is exactly one, so the header most messages carry has neither.
    /// Testing the fully-populated shape alone would leave the common one uncovered.
    /// </remarks>
    [Fact]
    public void The_header_this_server_emits_in_practice_parses_back()
    {
        string built = ReceivedHeader.Build(new ReceivedHeaderContext(
            IpAddressValue.Parse("198.51.100.7"),
            GreetedName: "client.example.net",
            ReverseDnsName: null,
            LocalHostname: "mail.example.com",
            Recipient: null,
            Protocol: "ESMTP",
            TlsDescription: null,
            MessageId: StoredMessageId.New(),
            ReceivedAt: new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero)));

        ReceivedHop hop = ReceivedTrace.Parse(built["Received:".Length..].Trim());

        hop.From.ShouldNotBeNull().ObservedAddress.ShouldBe("198.51.100.7");
        hop.From.ShouldNotBeNull().ObservedName.ShouldBeNull();
        hop.By.ShouldBe("mail.example.com");
        hop.For.ShouldBeNull();
        hop.Timestamp.ShouldNotBeNull();
    }

    /// <summary>
    /// A hostile EHLO name makes the clause structure ambiguous, and the parse says so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The greeted name is attacker-chosen text. <c>ReceivedHeader.Sanitize</c> strips control
    /// characters so it cannot end the header, but it can still contain the word "by" — and then
    /// the attacker's keyword sits before the real one in the text.
    /// </para>
    /// <para>
    /// <b>Neither reading is authoritative, so the parse reports the ambiguity rather than
    /// picking one.</b> Silently preferring the first would hand an operator a receiving host
    /// the message never touched, presented with exactly the confidence of a real one; a forged
    /// trace header that reads cleanly is worth more to whoever forged it than one that does
    /// not parse at all. The address in brackets is the part of the header the attacker could
    /// not choose, and it is still read correctly.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_hostile_greeted_name_makes_the_clauses_ambiguous()
    {
        string built = ReceivedHeader.Build(new ReceivedHeaderContext(
            IpAddressValue.Parse("203.0.113.10"),
            GreetedName: "evil.example by trusted.example.com with ESMTPS",
            ReverseDnsName: null,
            LocalHostname: "mail.example.com",
            Recipient: null,
            Protocol: "ESMTP",
            TlsDescription: null,
            MessageId: StoredMessageId.New(),
            ReceivedAt: new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero)));

        ReceivedHop hop = ReceivedTrace.Parse(built["Received:".Length..].Trim());

        hop.AmbiguousClauses.ShouldBeTrue();

        // The greeted name is the one domain §4.4's Extended-Domain allows, not the whole run.
        hop.From.ShouldNotBeNull().GreetedName.ShouldBe("evil.example");

        // And the part the attacker could not choose is read correctly regardless.
        hop.From.ShouldNotBeNull().ObservedAddress.ShouldBe("203.0.113.10");
    }

    /// <summary>An ordinary header is not flagged as ambiguous.</summary>
    [Fact]
    public void An_ordinary_header_is_not_ambiguous()
    {
        ReceivedTrace
            .Parse("from a.example.net (a.example.net [203.0.113.10]) by mail.example.com " +
                   "with ESMTPS id 7f3a for <r@example.com>; Sat, 19 Sep 2026 12:00:00 +0000")
            .AmbiguousClauses.ShouldBeFalse();
    }

    /// <summary>
    /// Extra text that contains no clause keyword is not flagged.
    /// </summary>
    /// <remarks>
    /// Some relays write a bare "from unknown" or add a word of their own. That is untidy rather
    /// than ambiguous, and flagging it would make the signal useless by firing on ordinary mail.
    /// </remarks>
    [Fact]
    public void Extra_text_without_a_clause_keyword_is_not_ambiguous()
    {
        ReceivedHop hop = ReceivedTrace.Parse(
            "from a.example.net unverified ([203.0.113.10]) by mail.example.com; " +
            "Sat, 19 Sep 2026 12:00:00 +0000");

        hop.AmbiguousClauses.ShouldBeFalse();
        hop.From.ShouldNotBeNull().GreetedName.ShouldBe("a.example.net");
    }
}
