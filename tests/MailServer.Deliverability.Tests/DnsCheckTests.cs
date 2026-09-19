using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Deliverability.Tests;

public sealed class DnsCheckTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");
    private static readonly DomainName Hostname = DomainName.Parse("mail.example.com");
    private static readonly IpAddressValue Address = IpAddressValue.Parse("203.0.113.10");
    private static readonly IpAddressValue Backup = IpAddressValue.Parse("198.51.100.7");

    private const string Issuer = "letsencrypt.org";

    private static MxTarget Mx(
        string host,
        int preference = 10,
        IReadOnlyList<IpAddressValue>? addresses = null,
        bool alias = false) =>
        new(preference, host, addresses ?? [Address], alias);

    /// <summary>
    /// A correct configuration, with one aspect replaced.
    /// </summary>
    /// <remarks>
    /// As elsewhere in this project, null means "leave this correct", so a test that needs a
    /// lookup to have <i>not answered</i> builds <see cref="DnsFacts"/> directly.
    /// </remarks>
    private static DnsFacts Facts(
        IReadOnlyList<MxTarget>? mx = null,
        TimeSpan? ttl = null,
        IReadOnlyList<string>? caa = null,
        string? issuer = Issuer) =>
        new(
            Domain,
            Hostname,
            mx ?? [Mx("mail.example.com"), Mx("mx2.example.com", 20, [Backup])],
            ttl ?? TimeSpan.FromHours(1),
            caa ?? [],
            issuer);

    private static DeliverabilityCheck Check(DnsFacts facts, string id) =>
        DnsChecks.Evaluate(facts).Single(c => c.Id == id);

    // ---------------------------------------------------------------------------------------
    // Shape.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Every_dns_check_is_in_the_dns_category()
    {
        foreach (DeliverabilityCheck check in DnsChecks.Evaluate(Facts()))
        {
            check.Category.ShouldBe(DeliverabilityCategory.Dns);
        }
    }

    /// <summary>The weights add up to the category's share, so the score cannot drift.</summary>
    [Fact]
    public void The_dns_weights_sum_to_fifteen()
    {
        DnsChecks.Evaluate(Facts()).Sum(c => c.Weight).ShouldBe(15);
    }

    [Fact]
    public void Dns_check_ids_are_unique()
    {
        IReadOnlyList<DeliverabilityCheck> checks = DnsChecks.Evaluate(Facts());

        checks.Select(c => c.Id).Distinct().Count().ShouldBe(checks.Count);
    }

    [Fact]
    public void A_correctly_configured_domain_passes_every_dns_check()
    {
        foreach (DeliverabilityCheck check in DnsChecks.Evaluate(Facts()))
        {
            check.Outcome.ShouldBe(DeliverabilityOutcome.Pass, check.Id);
        }
    }

    /// <summary>Anything that is not a pass says what to do about it.</summary>
    [Fact]
    public void Every_dns_finding_carries_a_remedy()
    {
        DnsFacts[] broken =
        [
            Facts(mx: []),
            Facts(mx: [new MxTarget(0, ".", [], false)]),
            Facts(mx: [Mx("mail.example.com", addresses: [])]),
            Facts(mx: [Mx("mail.example.com", alias: true)]),
            Facts(mx: [Mx("mail.example.com")]),
            Facts(mx: [Mx("mx.elsewhere.net")]),
            Facts(ttl: TimeSpan.FromSeconds(30)),
            Facts(ttl: TimeSpan.FromDays(7)),
            Facts(caa: ["0 issue \"digicert.com\""]),
            Facts(caa: ["0 issue \";\""]),
        ];

        foreach (DnsFacts facts in broken)
        {
            foreach (DeliverabilityCheck check in DnsChecks.Evaluate(facts))
            {
                if (check.Outcome is DeliverabilityOutcome.Warn or DeliverabilityOutcome.Fail)
                {
                    check.Remedy.ShouldNotBeNullOrWhiteSpace(check.Id);
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // MX publication.
    // ---------------------------------------------------------------------------------------

    /// <summary>An MX lookup that did not answer is not a domain without an MX.</summary>
    [Fact]
    public void An_unanswered_mx_lookup_leaves_every_mx_check_unjudged()
    {
        DnsFacts facts = new(Domain, Hostname, null, null, [], Issuer);

        foreach (string id in new[]
                 {
                     DnsChecks.MxPublishedId,
                     DnsChecks.MxResolvesId,
                     DnsChecks.MxNotAliasId,
                     DnsChecks.MxRedundancyId,
                     DnsChecks.MxPointsHereId,
                 })
        {
            Check(facts, id).Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, id);
        }
    }

    /// <summary>
    /// No MX warns rather than fails, because RFC 5321 §5.1 still delivers.
    /// </summary>
    /// <remarks>
    /// §5.1: "If an empty list of MXs is returned, the address is treated as if it was associated
    /// with an implicit MX RR, with a preference of 0, pointing to that host." Calling that a
    /// failure would be wrong about the mechanism; calling it a pass would hide that delivery
    /// now depends on whatever the domain's A record points at accepting SMTP.
    /// </remarks>
    [Fact]
    public void No_mx_record_warns_because_the_implicit_mx_still_delivers()
    {
        DeliverabilityCheck check = Check(Facts(mx: []), DnsChecks.MxPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("implicit", Case.Insensitive);
    }

    /// <summary>
    /// A null MX fails: RFC 7505 makes it an explicit refusal to accept mail.
    /// </summary>
    /// <remarks>
    /// §3: "To indicate that a domain does not accept email, it advertises a single MX RR […]
    /// consisting of preference number 0 and a zero-length label, written in master files as '.',
    /// as the exchange domain". Assessing a mail server for a domain that has published one is a
    /// contradiction, and the only useful thing to do is name it.
    /// </remarks>
    [Fact]
    public void A_null_mx_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(mx: [new MxTarget(0, ".", [], false)]),
            DnsChecks.MxPublishedId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("does not accept email");
    }

    /// <summary>
    /// A null MX is not a route, so the checks that judge routes do not judge it.
    /// </summary>
    /// <remarks>
    /// "." resolves to nothing and is nobody's host name. Counting it as a route would produce
    /// three more findings — unresolvable, not this server, no redundancy — all describing the
    /// same single fact the published check already reported.
    /// </remarks>
    [Fact]
    public void A_null_mx_is_not_counted_as_a_route()
    {
        DnsFacts facts = Facts(mx: [new MxTarget(0, ".", [], false)]);

        foreach (string id in new[]
                 {
                     DnsChecks.MxResolvesId,
                     DnsChecks.MxNotAliasId,
                     DnsChecks.MxRedundancyId,
                     DnsChecks.MxPointsHereId,
                 })
        {
            Check(facts, id).Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive, id);
        }
    }

    // ---------------------------------------------------------------------------------------
    // MX resolution.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A target that resolves to nothing is a failure when it is the only one.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §5.1: the MX's "domain name, when queried, MUST return at least one address
    /// record (e.g., A or AAAA RR) that gives the IP address of the SMTP server to which the
    /// message should be directed."
    /// </remarks>
    [Fact]
    public void A_sole_mx_target_that_resolves_to_nothing_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(mx: [Mx("mail.example.com", addresses: [])]),
            DnsChecks.MxResolvesId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("no sender can reach");
    }

    /// <summary>
    /// One dead target among several warns: mail still arrives, late.
    /// </summary>
    /// <remarks>
    /// Senders fall through to the remaining MX records, so nothing is lost — but every message
    /// that tries the dead one first waits for a connection timeout. A failure would overstate
    /// it and a pass would hide a cost the operator is paying on every message.
    /// </remarks>
    [Fact]
    public void One_dead_mx_target_among_several_warns()
    {
        DeliverabilityCheck check = Check(
            Facts(mx: [Mx("mail.example.com"), Mx("dead.example.com", 20, [])]),
            DnsChecks.MxResolvesId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("1 of 2");
    }

    /// <summary>A target whose lookup did not answer leaves the check unjudged.</summary>
    [Fact]
    public void An_mx_target_that_did_not_answer_leaves_resolution_unjudged()
    {
        Check(Facts(mx: [new MxTarget(10, "mail.example.com", null, false)]), DnsChecks.MxResolvesId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// A measured fault is reported even when another target went unanswered.
    /// </summary>
    /// <remarks>
    /// Withholding a finding that was measured because a second lookup timed out wastes the
    /// answer that did arrive.
    /// </remarks>
    [Fact]
    public void A_dead_target_is_reported_even_when_another_did_not_answer()
    {
        Check(
                Facts(mx:
                [
                    new MxTarget(10, "mail.example.com", null, false),
                    Mx("dead.example.com", 20, []),
                ]),
                DnsChecks.MxResolvesId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    // ---------------------------------------------------------------------------------------
    // MX aliasing.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An aliased MX fails.
    /// </summary>
    /// <remarks>
    /// RFC 2181 §10.3: an MX's target "must not be an alias[…] It can also have other RRs, but
    /// never a CNAME RR." The reason it is a failure rather than a warning is in RFC 5321 §5.1 —
    /// the behaviour "lies outside the scope of this Standard", so each sender decides for
    /// itself and the resulting loss is partial, intermittent and attributed to anything but DNS.
    /// </remarks>
    [Fact]
    public void An_aliased_mx_target_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(mx: [Mx("mail.example.com", alias: true)]),
            DnsChecks.MxNotAliasId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Remedy.ShouldNotBeNull().ShouldContain("mail.example.com");
    }

    /// <summary>One aliased target among several is still a failure.</summary>
    [Fact]
    public void One_aliased_target_among_several_still_fails()
    {
        Check(
                Facts(mx: [Mx("mail.example.com"), Mx("mx2.example.com", 20, [Backup], alias: true)]),
                DnsChecks.MxNotAliasId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Fail);
    }

    // ---------------------------------------------------------------------------------------
    // Redundancy and routing.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A single target with a single address warns.
    /// </summary>
    /// <remarks>
    /// RFC 5321 §5.1: "the SMTP client SHOULD try at least two addresses." A SHOULD, and a
    /// single-host mail server is a legitimate thing to run, so this warns.
    /// </remarks>
    [Fact]
    public void A_single_mx_with_a_single_address_warns()
    {
        Check(Facts(mx: [Mx("mail.example.com")]), DnsChecks.MxRedundancyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Warn);
    }

    /// <summary>One multihomed target is two routes in, which is what the SHOULD asks for.</summary>
    [Fact]
    public void One_multihomed_mx_target_counts_as_redundancy()
    {
        Check(
                Facts(mx: [Mx("mail.example.com", addresses: [Address, Backup])]),
                DnsChecks.MxRedundancyId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// An MX that names something else warns rather than failing.
    /// </summary>
    /// <remarks>
    /// A filtering service or relay in front of this server is a real and correct architecture,
    /// and the DNS looks identical to the case where an operator built a mail server and never
    /// pointed the domain at it. The check names the arrangement and lets the operator recognise
    /// their own.
    /// </remarks>
    [Fact]
    public void An_mx_pointing_elsewhere_warns_rather_than_failing()
    {
        DeliverabilityCheck check = Check(
            Facts(mx: [Mx("mx.filtering-service.net")]),
            DnsChecks.MxPointsHereId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Warn);
        check.Detail.ShouldContain("filtering service");
    }

    /// <summary>Being one of several is enough; the others may legitimately be backups.</summary>
    [Fact]
    public void Being_one_mx_among_several_passes()
    {
        Check(
                Facts(mx: [Mx("mx.backup.net"), Mx("mail.example.com", 20)]),
                DnsChecks.MxPointsHereId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// The comparison ignores case and a trailing root label.
    /// </summary>
    /// <remarks>
    /// DNS is case-insensitive and a name from a resolver may or may not carry its trailing dot.
    /// Comparing the raw strings would report a correctly configured domain as pointing
    /// somewhere else, on nothing more than how the answer was spelled.
    /// </remarks>
    [Theory]
    [InlineData("mail.example.com.")]
    [InlineData("MAIL.EXAMPLE.COM")]
    [InlineData("Mail.Example.Com.")]
    public void The_hostname_comparison_ignores_case_and_the_root_label(string host)
    {
        Check(Facts(mx: [Mx(host)]), DnsChecks.MxPointsHereId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    // ---------------------------------------------------------------------------------------
    // TTL.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Both ends of the range warn, and neither fails.
    /// </summary>
    /// <remarks>
    /// RFC 2181 §8 says only that a TTL is "an unsigned number, with a minimum value of 0, and a
    /// maximum value of 2147483647". Every value here conforms, so what is left is a trade-off
    /// between lookups and propagation delay — and an operator mid-migration wants a low TTL
    /// and should not be told they are wrong.
    /// </remarks>
    [Theory]
    [InlineData(30, DeliverabilityOutcome.Warn)]
    [InlineData(299, DeliverabilityOutcome.Warn)]
    [InlineData(300, DeliverabilityOutcome.Pass)]
    [InlineData(3600, DeliverabilityOutcome.Pass)]
    [InlineData(86400, DeliverabilityOutcome.Pass)]
    [InlineData(86401, DeliverabilityOutcome.Warn)]
    [InlineData(604800, DeliverabilityOutcome.Warn)]
    public void The_ttl_check_warns_at_both_ends_and_never_fails(int seconds, DeliverabilityOutcome expected)
    {
        Check(Facts(ttl: TimeSpan.FromSeconds(seconds)), DnsChecks.TtlSanityId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>The finding says it is advice, not conformance.</summary>
    [Fact]
    public void The_ttl_finding_says_no_rfc_sets_the_range()
    {
        Check(Facts(ttl: TimeSpan.FromSeconds(30)), DnsChecks.TtlSanityId)
            .Detail.ShouldContain("No RFC sets a range");
    }

    /// <summary>The observed TTL travels with the evidence, as the report promises.</summary>
    [Fact]
    public void The_observed_ttl_is_carried_in_the_evidence()
    {
        Check(Facts(ttl: TimeSpan.FromHours(2)), DnsChecks.TtlSanityId)
            .Evidence.ShouldNotBeNull().Ttl.ShouldBe(TimeSpan.FromHours(2));
    }

    /// <summary>No observed TTL leaves the check unjudged rather than passing it.</summary>
    [Fact]
    public void An_unobserved_ttl_leaves_the_check_unjudged()
    {
        Check(new DnsFacts(Domain, Hostname, [Mx("mail.example.com")], null, [], Issuer),
                DnsChecks.TtlSanityId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    // ---------------------------------------------------------------------------------------
    // CAA.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// No CAA record is a pass, not a gap.
    /// </summary>
    /// <remarks>
    /// RFC 8659 §4: "Before issuing a certificate, a compliant CA MUST check for publication of a
    /// Relevant RRset. If such an RRset exists, a CA MUST NOT issue a certificate unless[…]" — a
    /// restriction exists only where an RRset does. Treating absence as a finding would tell most
    /// of the internet to publish a record they do not need.
    /// </remarks>
    [Fact]
    public void No_caa_record_passes()
    {
        Check(Facts(caa: []), DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>A CAA set naming this server's issuer passes.</summary>
    [Fact]
    public void A_caa_record_naming_the_issuer_passes()
    {
        Check(Facts(caa: ["0 issue \"letsencrypt.org\""]), DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// A CAA set restricted to another CA fails, because renewal will fail.
    /// </summary>
    /// <remarks>
    /// The consequence is what makes this a mail check: a refused renewal ends in an expired
    /// certificate, and an expired certificate ends STARTTLS, MTA-STS and every receiver that
    /// requires them — sixty days after the record was published, by which time nobody connects
    /// the two events.
    /// </remarks>
    [Fact]
    public void A_caa_record_naming_another_ca_fails()
    {
        DeliverabilityCheck check = Check(
            Facts(caa: ["0 issue \"digicert.com\""]),
            DnsChecks.CaaAllowsIssuerId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Remedy.ShouldNotBeNull().ShouldContain("letsencrypt.org");
    }

    /// <summary>Any one permission naming the issuer is enough.</summary>
    [Fact]
    public void One_permission_among_several_naming_the_issuer_passes()
    {
        Check(
                Facts(caa: ["0 issue \"digicert.com\"", "0 issue \"letsencrypt.org\""]),
                DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// An empty issue value forbids every CA, and is reported as that rather than as a name.
    /// </summary>
    /// <remarks>
    /// RFC 8659 §4.2: "FQDN owners can use an issue Property Tag with no issuer-domain-name to
    /// request no issuance." Matching it as a name would silently compare "" against the issuer
    /// and report the ordinary "restricted to someone else" finding, which names no one.
    /// </remarks>
    [Fact]
    public void An_empty_caa_issue_value_forbids_everything()
    {
        DeliverabilityCheck check = Check(
            Facts(caa: ["0 issue \";\""]),
            DnsChecks.CaaAllowsIssuerId);

        check.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        check.Detail.ShouldContain("forbids all certificate issuance");
    }

    /// <summary>
    /// Parameters after a semicolon are for the CA and restrict nobody.
    /// </summary>
    /// <remarks>
    /// RFC 8659 §4.2: <c>issue-value = *WSP [issuer-domain-name *WSP] [";" *WSP [parameters *WSP]]</c>.
    /// Reading the whole value as a name would compare "letsencrypt.org;validationmethods=dns-01"
    /// against the issuer and fail a correctly configured domain.
    /// </remarks>
    [Fact]
    public void Caa_parameters_after_a_semicolon_are_not_part_of_the_issuer_name()
    {
        Check(
                Facts(caa: ["0 issue \"letsencrypt.org; validationmethods=dns-01\""]),
                DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// Tags that restrict nothing do not restrict this.
    /// </summary>
    /// <remarks>
    /// RFC 8659 §4: an RRset that "contains no Property Tags that restrict issuance (for
    /// instance, if it contains only iodef Property Tags or only Property Tags unrecognized by
    /// the CA)" does not restrict issuance. <c>issuewild</c> governs wildcard certificates,
    /// which this server does not request.
    /// </remarks>
    [Theory]
    [InlineData("0 iodef \"mailto:security@example.com\"")]
    [InlineData("0 issuewild \";\"")]
    [InlineData("0 contactemail \"ops@example.com\"")]
    public void Caa_tags_that_do_not_restrict_issuance_are_ignored(string record)
    {
        Check(Facts(caa: [record]), DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>The issuer name is compared without regard to case or a trailing dot.</summary>
    [Fact]
    public void The_caa_issuer_comparison_ignores_case()
    {
        Check(Facts(caa: ["0 issue \"LetsEncrypt.ORG\""]), DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Pass);
    }

    /// <summary>
    /// Without a known issuer there is nothing to compare CAA against.
    /// </summary>
    /// <remarks>
    /// A server whose certificate is installed by hand has no renewal to break, so guessing a CA
    /// in order to produce a verdict would invent a finding.
    /// </remarks>
    [Fact]
    public void Without_a_known_issuer_the_caa_check_is_unjudged()
    {
        Check(Facts(caa: ["0 issue \"digicert.com\""], issuer: null), DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>An unanswered CAA lookup is not an absent CAA record.</summary>
    [Fact]
    public void An_unanswered_caa_lookup_leaves_the_check_unjudged()
    {
        Check(new DnsFacts(Domain, Hostname, [Mx("mail.example.com")], TimeSpan.FromHours(1), null, Issuer),
                DnsChecks.CaaAllowsIssuerId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    // ---------------------------------------------------------------------------------------
    // The category as a whole.
    // ---------------------------------------------------------------------------------------

    /// <summary>A correct configuration scores the whole fifteen points.</summary>
    [Fact]
    public void A_correctly_configured_domain_scores_the_whole_category()
    {
        DeliverabilityReport report = DeliverabilityReport.From(
            DnsChecks.Evaluate(Facts()),
            new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));

        report.Score.ShouldBe(100d);
        report.Readiness.ShouldBe(DeliverabilityReadiness.Ready);

        report.Categories
            .Single(c => c.Category == DeliverabilityCategory.Dns)
            .Earned.ShouldBe(15d, 0.0001);
    }
}
