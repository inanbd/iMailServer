using System.Text;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// The records an operator is told to publish. Every one of these is something that has to be
/// right the first time: an operator who publishes what this produces and finds mail still
/// refused has no way to tell which line was the wrong one.
/// </summary>
public sealed class DnsRecordPlanTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");
    private static readonly DomainName MailHost = DomainName.Parse("mail.example.com");
    private static readonly IpAddressValue V4 = IpAddressValue.Parse("203.0.113.10");
    private static readonly IpAddressValue V6 = IpAddressValue.Parse("2001:db8::10");

    private static DnsPlanRequest Request(
        IReadOnlyList<IpAddressValue>? addresses = null,
        DkimKeyPublication? dkim = null,
        string? dmarcReports = "dmarc@example.com",
        string? tlsReports = null,
        string? mtaStsId = null,
        PublicSuffixList? suffixes = null) =>
        new(
            Domain,
            MailHost,
            addresses ?? [V4],
            dkim,
            dmarcReports is null ? null : EmailAddress.Parse(dmarcReports),
            tlsReports is null ? null : EmailAddress.Parse(tlsReports),
            mtaStsId,
            suffixes);

    private static DnsRecordAdvice? Named(DnsZonePlan plan, string name, DnsRecordKind kind) =>
        plan.Records.FirstOrDefault(r =>
            string.Equals(r.Name, name, StringComparison.Ordinal) && r.Kind == kind);

    private static string Joined(DnsRecordAdvice record) => string.Concat(record.Values);

    private static bool HasCaveat(DnsZonePlan plan, string fragment) =>
        plan.Caveats.Any(c => c.Text.Contains(fragment, StringComparison.Ordinal));

    // ---------------------------------------------------------------------------------------
    // Splitting a TXT value into character-strings.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 1035 §3.3.14's `character-string` is a length octet and that many octets, so 255 is
    /// the ceiling. A value that fits is one string and must not be chopped for tidiness.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(254)]
    [InlineData(255)]
    public void A_value_that_fits_is_one_string(int length)
    {
        DnsRecordPlan.SplitTxt(new string('a', length)).ShouldHaveSingleItem();
    }

    /// <summary>One octet past the limit is two strings, not a truncation and not a refusal.</summary>
    [Fact]
    public void A_value_one_octet_too_long_is_two_strings()
    {
        IReadOnlyList<string> parts = DnsRecordPlan.SplitTxt(new string('a', 256));

        parts.Count.ShouldBe(2);
        parts[0].Length.ShouldBe(255);
        parts[1].Length.ShouldBe(1);
    }

    /// <summary>
    /// The split is free of meaning, so the only thing that must survive it is the value.
    /// RFC 6376 §3.6.2.2: "Strings in a TXT RR MUST be concatenated together before use with no
    /// intervening whitespace." RFC 7208 §3.3 says the same for SPF.
    /// </summary>
    [Fact]
    public void The_parts_concatenate_back_to_the_value()
    {
        string value = string.Concat(Enumerable.Range(0, 900).Select(i => (char)('a' + (i % 26))));

        IReadOnlyList<string> parts = DnsRecordPlan.SplitTxt(value);

        parts.Count.ShouldBe(4);
        string.Concat(parts).ShouldBe(value);
        parts.ShouldAllBe(p => Encoding.UTF8.GetByteCount(p) <= 255);
    }

    /// <summary>
    /// The limit counts octets. Two hundred two-octet characters is four hundred octets and must
    /// be split, even though it is two hundred characters — and a splitter that counted
    /// characters would publish one string the wire cannot carry.
    /// </summary>
    [Fact]
    public void The_limit_is_counted_in_octets_rather_than_characters()
    {
        string value = new('\u00e9', 200);

        IReadOnlyList<string> parts = DnsRecordPlan.SplitTxt(value);

        parts.Count.ShouldBe(2);
        parts.ShouldAllBe(p => Encoding.UTF8.GetByteCount(p) <= 255);
        string.Concat(parts).ShouldBe(value);
    }

    /// <summary>
    /// And never in the middle of one. Two halves of a character concatenate back to a
    /// replacement character rather than to the character, so a key or a policy split that way
    /// is quietly corrupt.
    /// </summary>
    /// <remarks>
    /// A two-octet character is the case that catches it: 255 is odd, so the boundary falls
    /// inside the 128th character rather than neatly between two. The first string comes back
    /// one octet short of the limit, which is the correct amount of room to leave.
    /// </remarks>
    [Fact]
    public void A_character_is_never_split_across_two_strings()
    {
        string value = new('\u00e9', 128);

        IReadOnlyList<string> parts = DnsRecordPlan.SplitTxt(value);

        parts.Count.ShouldBe(2);
        parts[0].ShouldBe(new string('\u00e9', 127));
        Encoding.UTF8.GetByteCount(parts[0]).ShouldBe(254);
        parts[1].ShouldBe("\u00e9");
        string.Concat(parts).ShouldBe(value);
    }

    [Fact]
    public void Splitting_refuses_a_null_value()
    {
        Should.Throw<ArgumentNullException>(() => DnsRecordPlan.SplitTxt(null!));
    }

    // ---------------------------------------------------------------------------------------
    // The host and its exchanger.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_host_gets_an_address_record_per_family()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request([V4, V6]));

        Named(plan, "mail.example.com", DnsRecordKind.A)!.Values.ShouldBe(["203.0.113.10"]);
        Named(plan, "mail.example.com", DnsRecordKind.Aaaa)!.Values.ShouldBe(["2001:db8::10"]);
    }

    /// <summary>
    /// A family this server has no address in gets no record. An empty A record is not a record,
    /// and an operator handed one will invent a value for it.
    /// </summary>
    [Fact]
    public void A_family_with_no_address_gets_no_record()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request([V4]));

        Named(plan, "mail.example.com", DnsRecordKind.Aaaa).ShouldBeNull();
    }

    /// <summary>
    /// RFC 5321 §5.1 ranks exchangers by preference, and ten leaves room to add a backup later
    /// without editing the record that already works.
    /// </summary>
    [Fact]
    public void The_exchanger_names_the_host_with_room_to_add_another()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request());

        Named(plan, "example.com", DnsRecordKind.Mx)!.Values
            .ShouldBe(["10 mail.example.com."]);
    }

    /// <summary>
    /// RFC 2181 §10.3: "The domain name used as the value of a NS resource record, or part of
    /// the value of a MX resource record must not be an alias." It works with some senders and
    /// not others, which is the worst way for a configuration to be wrong.
    /// </summary>
    [Fact]
    public void The_plan_says_the_exchanger_must_not_be_an_alias()
    {
        DnsRecordPlan.Create(Request()).Caveats
            .ShouldContain(c => c.Subject == "Mail exchanger" && c.Text.Contains("CNAME", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // SPF.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Spf_authorises_the_exchanger_and_every_sending_address()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request([V4, V6]));

        Joined(plan.Records.Single(r =>
            r.Kind == DnsRecordKind.Txt && Joined(r).StartsWith("v=spf1", StringComparison.Ordinal)))
            .ShouldBe("v=spf1 mx ip4:203.0.113.10 ip6:2001:db8::10 -all");
    }

    /// <summary>
    /// One record, because RFC 7208 §4.5 makes two a permanent error: "If the resultant record
    /// set includes more than one record, check_host() produces the 'permerror' result."
    /// </summary>
    [Fact]
    public void Only_one_spf_record_is_proposed()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request([V4, V6]));

        plan.Records
            .Count(r => r.Kind == DnsRecordKind.Txt && Joined(r).StartsWith("v=spf1", StringComparison.Ordinal))
            .ShouldBe(1);
    }

    // ---------------------------------------------------------------------------------------
    // DKIM.
    // ---------------------------------------------------------------------------------------

    private static DkimKeyPublication Key(string material) =>
        new(DkimSelector.Parse("mail2026"), DkimKeyAlgorithm.RsaSha256, material);

    [Fact]
    public void The_key_is_published_under_its_selector_and_domainkey()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(dkim: Key("AAAB")));

        DnsRecordAdvice record = Named(
            plan, "mail2026._domainkey.example.com", DnsRecordKind.Txt)!;

        Joined(record).ShouldBe("v=DKIM1; k=rsa; p=AAAB");
    }

    /// <summary>
    /// A 2048-bit key's base64 runs past 255 octets, which is the case this whole splitting
    /// business exists for — and the case an operator's provider is most likely to truncate.
    /// </summary>
    [Fact]
    public void A_real_sized_key_is_split_and_flagged()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(dkim: Key(new string('A', 392))));

        DnsRecordAdvice record = Named(
            plan, "mail2026._domainkey.example.com", DnsRecordKind.Txt)!;

        record.Values.Count.ShouldBeGreaterThan(1);
        Joined(record).ShouldBe($"v=DKIM1; k=rsa; p={new string('A', 392)}");
        HasCaveat(plan, "truncated key parses and verifies nothing").ShouldBeTrue();
    }

    /// <summary>
    /// No key is not silence. SPF alone breaks on every forwarded message, and an operator who
    /// sees SPF and DMARC in the plan and no DKIM will assume DKIM is optional.
    /// </summary>
    [Fact]
    public void A_domain_with_no_key_is_told_to_generate_one()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request());

        plan.Records.ShouldNotContain(r => r.Name.Contains("_domainkey", StringComparison.Ordinal));
        HasCaveat(plan, "No DKIM key has been generated").ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // DMARC.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// It starts at p=none, which agrees with what the readiness report says about the same
    /// value: "That is the right setting while you are reading reports".
    /// </summary>
    [Fact]
    public void Dmarc_starts_at_none_and_asks_for_reports()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request());

        DnsRecordAdvice record = Named(plan, "_dmarc.example.com", DnsRecordKind.Txt)!;

        Joined(record).ShouldBe("v=DMARC1; p=none; rua=mailto:dmarc@example.com");
        record.Purpose.ShouldContain("p=quarantine");
    }

    [Fact]
    public void A_dmarc_record_without_reports_is_flagged_as_published_blind()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(dmarcReports: null));

        Joined(Named(plan, "_dmarc.example.com", DnsRecordKind.Txt)!).ShouldBe("v=DMARC1; p=none");
        HasCaveat(plan, "published blind").ShouldBeTrue();
    }

    /// <summary>
    /// RFC 7489 §7.1 only engages when the reporting address is outside the policy's own
    /// organizational domain, so the ordinary case must not be warned about.
    /// </summary>
    [Fact]
    public void Reports_inside_the_domain_need_no_authorisation()
    {
        DnsRecordPlan.Create(Request()).Caveats
            .ShouldNotContain(c => c.Text.Contains("_report._dmarc", StringComparison.Ordinal));
    }

    /// <summary>
    /// And the comparison is by organizational domain, not by name — §7.1 says "the
    /// Organizational Domain at which that record was discovered is not identical to the
    /// Organizational Domain of the host part". Comparing names would raise this on the most
    /// ordinary configuration there is.
    /// </summary>
    [Fact]
    public void Reports_elsewhere_in_the_same_organization_need_no_authorisation()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(
            dmarcReports: "dmarc@reports.example.com",
            suffixes: PublicSuffixList.Parse("com\nnet\n")));

        plan.Caveats.ShouldNotContain(c => c.Text.Contains("_report._dmarc", StringComparison.Ordinal));
    }

    /// <summary>
    /// A third-party analytics service is the case that silently swallows every report. §7.1:
    /// "Where the above algorithm fails to confirm that the external reporting was authorized by
    /// the Report Receiver, the URI MUST be ignored by the Mail Receiver generating the report."
    /// </summary>
    [Fact]
    public void Reports_to_another_organization_name_the_record_that_authorises_them()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(
            dmarcReports: "reports@dmarc-vendor.net",
            suffixes: PublicSuffixList.Parse("com\nnet\n")));

        HasCaveat(plan, "example.com._report._dmarc.dmarc-vendor.net").ShouldBeTrue();
    }

    /// <summary>
    /// With no suffix list to ask, any difference earns the caveat. Telling an operator to
    /// publish a record they turn out not to need costs a minute; the reverse costs them every
    /// report, with nothing anywhere to say so.
    /// </summary>
    [Fact]
    public void Without_a_suffix_list_any_other_domain_earns_the_caveat()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(dmarcReports: "dmarc@reports.example.com"));

        HasCaveat(plan, "_report._dmarc").ShouldBeTrue();
    }

    // ---------------------------------------------------------------------------------------
    // MTA-STS and TLS-RPT.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Mta_sts_is_absent_unless_an_id_is_chosen()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request());

        plan.Records.ShouldNotContain(r => r.Name.Contains("mta-sts", StringComparison.Ordinal));
        plan.Caveats.ShouldNotContain(c => c.Subject == "MTA-STS");
    }

    [Fact]
    public void Mta_sts_publishes_the_advertisement_and_the_policy_host()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(mtaStsId: "20260920T104500"));

        Joined(Named(plan, "_mta-sts.example.com", DnsRecordKind.Txt)!)
            .ShouldBe("v=STSv1; id=20260920T104500;");

        Named(plan, "mta-sts.example.com", DnsRecordKind.A)!.Values.ShouldBe(["203.0.113.10"]);
    }

    /// <summary>
    /// The TXT record alone does nothing: RFC 8461 §3.2 has senders fetch the policy over HTTPS
    /// from a fixed well-known path, and an advertisement without a fetchable policy buys
    /// nothing.
    /// </summary>
    [Fact]
    public void Mta_sts_says_the_record_alone_does_nothing()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(mtaStsId: "20260920T104500"));

        HasCaveat(plan, "https://mta-sts.example.com/.well-known/mta-sts.txt").ShouldBeTrue();
    }

    /// <summary>
    /// RFC 8461 §3.1: <c>sts-id = %s"id=" 1*32(ALPHA / DIGIT)</c>. An id with punctuation is a
    /// record every sender discards, so proposing one would be proposing silence.
    /// </summary>
    [Theory]
    [InlineData("2026-09-20T10:45:00Z")]
    [InlineData("2026_09_20")]
    [InlineData("aaaaaaaaaabbbbbbbbbbccccccccccddd")]
    public void An_id_the_grammar_refuses_is_not_proposed(string id)
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(mtaStsId: id));

        plan.Records.ShouldNotContain(r => r.Name.StartsWith("_mta-sts", StringComparison.Ordinal));
        HasCaveat(plan, "one to thirty-two letters and digits").ShouldBeTrue();
    }

    [Fact]
    public void Tls_reporting_is_published_when_an_address_is_chosen()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request(tlsReports: "tlsrpt@example.com"));

        DnsRecordAdvice record = Named(plan, "_smtp._tls.example.com", DnsRecordKind.Txt)!;

        Joined(record).ShouldBe("v=TLSRPTv1; rua=mailto:tlsrpt@example.com");
        record.IsOptional.ShouldBeTrue();
    }

    [Fact]
    public void Tls_reporting_is_absent_without_an_address()
    {
        DnsRecordPlan.Create(Request()).Records
            .ShouldNotContain(r => r.Name.StartsWith("_smtp._tls", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // Reverse DNS, which is the one record that is not the operator's.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Named by the reverse name rather than by the address, because that is the record's actual
    /// owner name and the thing a provider's support ticket needs to say.
    /// </summary>
    [Fact]
    public void Reverse_records_use_the_reverse_name_and_belong_to_the_address_owner()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request([V4]));

        DnsRecordAdvice record = plan.Records.Single(r => r.Kind == DnsRecordKind.Ptr);

        record.Name.ShouldBe("10.113.0.203.in-addr.arpa");
        record.Values.ShouldBe(["mail.example.com."]);
        record.Placement.ShouldBe(DnsRecordPlacement.IpOwner);
    }

    [Fact]
    public void Every_sending_address_gets_a_reverse_record()
    {
        DnsRecordPlan.Create(Request([V4, V6])).Records
            .Count(r => r.Kind == DnsRecordKind.Ptr).ShouldBe(2);
    }

    [Fact]
    public void The_plan_says_reverse_dns_is_not_the_operators_to_publish()
    {
        DnsRecordPlan.Create(Request()).Caveats
            .ShouldContain(c => c.Subject == "Reverse DNS" &&
                c.Text.Contains("not yours to publish", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // Degenerate inputs.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A server that does not know its own address still gets a usable plan: the MX, SPF, DKIM
    /// and DMARC records all name the host rather than an address.
    /// </summary>
    [Fact]
    public void A_server_with_no_known_address_still_gets_the_rest_of_the_plan()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request([]));

        plan.Records.ShouldNotContain(r =>
            r.Kind == DnsRecordKind.A || r.Kind == DnsRecordKind.Aaaa);
        plan.Records.ShouldNotContain(r => r.Kind == DnsRecordKind.Ptr);
        Named(plan, "example.com", DnsRecordKind.Mx).ShouldNotBeNull();
        HasCaveat(plan, "does not know a public address for itself").ShouldBeTrue();
    }

    /// <summary>
    /// A private address in public DNS resolves to nothing reachable, and in SPF it authorises
    /// nobody — a plan that pasted it in without comment would produce a configuration that
    /// looks complete and delivers nothing.
    /// </summary>
    [Fact]
    public void A_private_address_is_called_out()
    {
        DnsZonePlan plan = DnsRecordPlan.Create(Request([IpAddressValue.Parse("192.168.1.10")]));

        HasCaveat(plan, "private space").ShouldBeTrue();
    }

    [Fact]
    public void The_planner_refuses_a_null_request()
    {
        Should.Throw<ArgumentNullException>(() => DnsRecordPlan.Create(null!));
        Should.Throw<ArgumentNullException>(() => DnsRecordPlan.ToZoneText(null!));
    }

    // ---------------------------------------------------------------------------------------
    // The zone text.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Fully qualified and dot-terminated, because a relative name pasted under the wrong
    /// $ORIGIN becomes _dmarc.example.com.example.com — which resolves, answers nothing, and
    /// looks right at a glance.
    /// </summary>
    [Fact]
    public void Every_owner_name_in_the_zone_text_is_absolute()
    {
        string text = DnsRecordPlan.ToZoneText(DnsRecordPlan.Create(Request(dkim: Key("AAAB"))));

        foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            line.TrimStart(';', ' ').Split(' ')[0].ShouldEndWith(".");
        }
    }

    [Fact]
    public void Txt_values_are_quoted_and_given_as_separate_strings()
    {
        string text = DnsRecordPlan.ToZoneText(
            DnsRecordPlan.Create(Request(dkim: Key(new string('A', 300)))));

        text.ShouldContain("mail2026._domainkey.example.com. IN TXT \"v=DKIM1; k=rsa; p=AAA");
        text.ShouldContain("\" \"");
    }

    /// <summary>
    /// A quote or a backslash inside a value has to survive into the zone file as itself.
    /// Nothing this planner writes contains either today, which is exactly why the escaping
    /// order would go unnoticed: escaping quotes first lets the second pass double the
    /// backslash it just added and end the string a character early.
    /// </summary>
    [Fact]
    public void A_value_containing_a_quote_or_a_backslash_is_escaped_once()
    {
        DnsZonePlan plan = new(
            [
                new DnsRecordAdvice(
                    "odd.example.com",
                    DnsRecordKind.Txt,
                    [@"a""b\c"],
                    DnsRecordPlacement.OwnZone,
                    "A value nothing in this plan produces."),
            ],
            []);

        DnsRecordPlan.ToZoneText(plan).Trim()
            .ShouldBe(@"odd.example.com. IN TXT ""a\""b\\c""");
    }

    /// <summary>
    /// Several values of a non-TXT record are separate records with one owner name, unlike a
    /// TXT record's several character-strings, which are one record. Collapsing the two cases
    /// onto one rendering would publish "203.0.113.10 198.51.100.7" as a single A record.
    /// </summary>
    [Fact]
    public void Several_addresses_are_rendered_as_several_records()
    {
        DnsZonePlan plan = new(
            [
                new DnsRecordAdvice(
                    "mail.example.com",
                    DnsRecordKind.A,
                    ["203.0.113.10", "198.51.100.7"],
                    DnsRecordPlacement.OwnZone,
                    "Two addresses."),
            ],
            []);

        DnsRecordPlan.ToZoneText(plan).Trim().Split('\n').Select(l => l.Trim()).ShouldBe(
        [
            "mail.example.com. IN A 203.0.113.10",
            "mail.example.com. IN A 198.51.100.7",
        ]);
    }

    /// <summary>
    /// Commented rather than omitted. An operator pasting this into their zone must not publish
    /// a PTR into it, and must not be left thinking the plan forgot reverse DNS.
    /// </summary>
    [Fact]
    public void Records_the_operator_cannot_publish_are_commented_out()
    {
        string text = DnsRecordPlan.ToZoneText(DnsRecordPlan.Create(Request()));

        text.ShouldContain("; 10.113.0.203.in-addr.arpa. IN PTR mail.example.com.");
        text.ShouldNotContain("\n10.113.0.203");
    }
}
