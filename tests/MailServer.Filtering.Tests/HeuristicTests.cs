using System.Text;
using MailServer.Domain.Enums;
using MailServer.Domain.Filtering;
using MailServer.Domain.Mail;

namespace MailServer.Filtering.Tests;

/// <summary>Builds a header block the way the wire carries one.</summary>
internal static class Headers
{
    public static readonly DateTimeOffset Received = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);

    public static RawMessageHeaders Parse(params string[] fields)
    {
        string block = string.Join("\r\n", fields) + "\r\n\r\n";

        RawMessageHeaders.TryParse(
            Encoding.ASCII.GetBytes(block), out RawMessageHeaders? headers, out string? error)
            .ShouldBeTrue(error);

        return headers!;
    }

    /// <summary>A message with nothing structurally wrong with it.</summary>
    public static RawMessageHeaders WellFormed(params string[] extra) =>
        Parse([
            "From: Alice <alice@example.com>",
            "To: Bob <bob@example.net>",
            "Subject: Lunch on Thursday",
            "Date: Tue, 22 Sep 2026 11:58:00 +0000",
            "Message-ID: <abc123@example.com>",
            .. extra,
        ]);

    public static EnvelopeFacts Envelope(int recipients = 1) => new(recipients, Received);
}

public sealed class HeaderHeuristicTests
{
    private static IReadOnlyList<string> NamesFor(RawMessageHeaders headers, EnvelopeFacts? envelope = null) =>
        [.. HeaderHeuristics.Evaluate(headers, envelope ?? Headers.Envelope()).Select(s => s.Name)];

    [Fact]
    public void Finds_nothing_wrong_with_an_ordinary_message() =>
        NamesFor(Headers.WellFormed()).ShouldBeEmpty();

    [Fact]
    public void Notices_a_missing_Date() =>
        NamesFor(Headers.Parse(
            "From: a@example.com", "To: b@example.net", "Message-ID: <x@example.com>"))
            .ShouldContain("MISSING_DATE");

    [Fact]
    public void Notices_a_missing_Message_ID() =>
        NamesFor(Headers.Parse(
            "From: a@example.com", "To: b@example.net", "Date: Tue, 22 Sep 2026 11:58:00 +0000"))
            .ShouldContain("MISSING_MESSAGE_ID");

    /// <summary>
    /// Two From headers is an attack, not sloppiness: clients differ on which they display, so
    /// a signature that authenticates one can be shown under the other.
    /// </summary>
    [Fact]
    public void Treats_two_From_headers_as_serious()
    {
        RawMessageHeaders headers = Headers.WellFormed("From: Mallory <mallory@evil.example>");

        IReadOnlyList<FilterSignal> signals = HeaderHeuristics.Evaluate(headers, Headers.Envelope());

        FilterSignal signal = signals.ShouldHaveSingleItem();
        signal.Name.ShouldBe("MULTIPLE_FROM");
        signal.Score.ShouldBeGreaterThanOrEqualTo(FilterPolicy.Default.JunkThreshold - 1.0);
    }

    [Fact]
    public void Notices_a_message_addressed_to_nobody() =>
        NamesFor(Headers.Parse(
            "From: a@example.com",
            "Subject: Hello",
            "Date: Tue, 22 Sep 2026 11:58:00 +0000",
            "Message-ID: <x@example.com>"))
            .ShouldContain("NO_DESTINATION_HEADER");

    [Fact]
    public void A_Cc_alone_is_a_destination() =>
        NamesFor(Headers.Parse(
            "From: a@example.com",
            "Cc: c@example.net",
            "Date: Tue, 22 Sep 2026 11:58:00 +0000",
            "Message-ID: <x@example.com>"))
            .ShouldNotContain("NO_DESTINATION_HEADER");

    /// <summary>A date in the future pins a message to the top of a sorted inbox forever.</summary>
    [Fact]
    public void Notices_a_Date_far_in_the_future() =>
        NamesFor(Headers.Parse(
            "From: a@example.com",
            "To: b@example.net",
            "Date: Fri, 22 Sep 2028 11:58:00 +0000",
            "Message-ID: <x@example.com>"))
            .ShouldContain("DATE_IN_FUTURE");

    [Fact]
    public void Notices_a_Date_far_in_the_past() =>
        NamesFor(Headers.Parse(
            "From: a@example.com",
            "To: b@example.net",
            "Date: Mon, 22 Sep 2014 11:58:00 +0000",
            "Message-ID: <x@example.com>"))
            .ShouldContain("DATE_IN_PAST");

    /// <summary>A clock a few hours out is ordinary, and must not be scored.</summary>
    [Theory]
    [InlineData("Tue, 22 Sep 2026 20:00:00 +0000")]
    [InlineData("Mon, 21 Sep 2026 08:00:00 +0000")]
    [InlineData("Wed, 23 Sep 2026 11:00:00 +0000")]
    public void Tolerates_an_unsynchronised_clock(string date) =>
        NamesFor(Headers.Parse(
            "From: a@example.com", "To: b@example.net", $"Date: {date}", "Message-ID: <x@example.com>"))
            .ShouldBeEmpty();

    /// <summary>
    /// A Date this server cannot parse is not scored. RFC 5322 §3.3 has obsolete forms real
    /// senders still emit, and scoring a parse failure means scoring this parser's coverage.
    /// </summary>
    [Fact]
    public void Does_not_score_a_Date_it_cannot_read() =>
        NamesFor(Headers.Parse(
            "From: a@example.com", "To: b@example.net", "Date: sometime last week", "Message-ID: <x@example.com>"))
            .ShouldBeEmpty();

    [Fact]
    public void Notices_a_very_large_envelope() =>
        NamesFor(Headers.WellFormed(), Headers.Envelope(recipients: 500))
            .ShouldContain("MANY_RECIPIENTS");

    [Fact]
    public void An_ordinary_envelope_is_not_a_signal() =>
        NamesFor(Headers.WellFormed(), Headers.Envelope(recipients: 5)).ShouldBeEmpty();
}

public sealed class ShoutingSubjectTests
{
    [Theory]
    [InlineData("URGENT ACTION REQUIRED NOW", true)]
    [InlineData("YOUR ACCOUNT HAS BEEN SUSPENDED", true)]
    [InlineData("Lunch on Thursday", false)]
    [InlineData("OK", false)]
    [InlineData("FYI", false)]
    [InlineData("RE: FW: Q3", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Judges_only_a_long_uniformly_upper_case_subject(string? subject, bool expected) =>
        HeaderHeuristics.IsShouting(subject).ShouldBe(expected);

    /// <summary>
    /// Most of the world's writing systems have no case. "No lower-case letters" as the test
    /// would fire on every message written in them — a filter that scored mail for its alphabet.
    /// </summary>
    [Theory]
    [InlineData("請儘快回覆這封重要的郵件謝謝您")]
    [InlineData("لا يوجد حروف كبيرة أو صغيرة هنا على الإطلاق")]
    [InlineData("このメールには大文字も小文字もありません")]
    [InlineData("1234567890 !@#$%^&*() ---------")]
    public void Never_fires_on_a_script_without_case(string subject) =>
        HeaderHeuristics.IsShouting(subject).ShouldBeFalse();

    /// <summary>
    /// An RFC 2047 encoded word is a base64 or quoted-printable blob. Its case says nothing
    /// about the text, and decoding it would put a decoder on the delivery path for one point.
    /// </summary>
    [Fact]
    public void Skips_an_encoded_subject() =>
        HeaderHeuristics.IsShouting("=?UTF-8?B?VVJHRU5UIEFDVElPTiBSRVFVSVJFRA==?=").ShouldBeFalse();

    [Fact]
    public void Fires_through_the_evaluator_too()
    {
        RawMessageHeaders headers = Headers.Parse(
            "From: a@example.com",
            "To: b@example.net",
            "Subject: URGENT ACTION REQUIRED NOW",
            "Date: Tue, 22 Sep 2026 11:58:00 +0000",
            "Message-ID: <x@example.com>");

        HeaderHeuristics.Evaluate(headers, Headers.Envelope())
            .ShouldHaveSingleItem().Name.ShouldBe("SHOUTING_SUBJECT");
    }
}

public sealed class AuthenticationWeightingTests
{
    private static IReadOnlyList<FilterSignal> Weigh(
        SpfResult? spf = null,
        DkimVerificationResult? dkim = null,
        DmarcResult? dmarc = null,
        DmarcPolicy? disposition = null) =>
        AuthenticationWeighting.Evaluate(new AuthenticationFacts(spf, dkim, dmarc, disposition));

    [Fact]
    public void Says_nothing_when_nothing_was_evaluated() => Weigh().ShouldBeEmpty();

    /// <summary>
    /// A well-authenticated message has to be able to absorb a heuristic misfire, which means
    /// its authentication signals must outweigh one.
    /// </summary>
    [Fact]
    public void A_full_pass_earns_enough_credit_to_survive_a_misfire()
    {
        double credit = Weigh(SpfResult.Pass, DkimVerificationResult.Pass, DmarcResult.Pass)
            .Sum(s => s.Score);

        credit.ShouldBeLessThan(-HeaderHeuristics.MissingDateScore);
    }

    [Fact]
    public void Weighs_a_DMARC_failure_more_when_the_domain_asked_for_enforcement()
    {
        double none = Weigh(dmarc: DmarcResult.Fail, disposition: DmarcPolicy.None).Sum(s => s.Score);
        double quarantine = Weigh(dmarc: DmarcResult.Fail, disposition: DmarcPolicy.Quarantine).Sum(s => s.Score);

        quarantine.ShouldBeGreaterThan(none);
    }

    [Fact]
    public void Names_the_published_policy_in_the_detail() =>
        Weigh(dmarc: DmarcResult.Fail, disposition: DmarcPolicy.Reject)
            .ShouldHaveSingleItem().Detail.ShouldContain("p=reject");

    /// <summary>
    /// A DNS timeout is a fact about this server's resolver. Scoring it would make a local
    /// outage look like a spam wave, and junk the mail of whoever sent during it.
    /// </summary>
    [Theory]
    [InlineData(SpfResult.TempError)]
    [InlineData(SpfResult.PermError)]
    [InlineData(SpfResult.None)]
    [InlineData(SpfResult.Neutral)]
    public void Never_scores_an_SPF_non_answer(SpfResult result) => Weigh(spf: result).ShouldBeEmpty();

    [Theory]
    [InlineData(DkimVerificationResult.TempError)]
    [InlineData(DkimVerificationResult.PermError)]
    [InlineData(DkimVerificationResult.None)]
    public void Never_scores_a_DKIM_non_answer(DkimVerificationResult result) =>
        Weigh(dkim: result).ShouldBeEmpty();

    /// <summary>
    /// A broken signature is worth more than no signature: it means the message was modified,
    /// or somebody attached a signature they could not produce.
    /// </summary>
    [Fact]
    public void A_broken_signature_counts_against_where_no_signature_does_not()
    {
        Weigh(dkim: DkimVerificationResult.Fail).ShouldHaveSingleItem().Score.ShouldBeGreaterThan(0);
        Weigh(dkim: DkimVerificationResult.None).ShouldBeEmpty();
    }

    /// <summary>
    /// SPF passes for anybody who controls the envelope domain, including a spammer who
    /// registered one this morning. It must be worth much less than a DMARC pass.
    /// </summary>
    [Fact]
    public void Trusts_an_SPF_pass_far_less_than_a_DMARC_pass()
    {
        double spf = Math.Abs(Weigh(spf: SpfResult.Pass).ShouldHaveSingleItem().Score);
        double dmarc = Math.Abs(Weigh(dmarc: DmarcResult.Pass).ShouldHaveSingleItem().Score);

        spf.ShouldBeLessThan(dmarc);
    }

    /// <summary>
    /// A domain publishing <c>p=quarantine</c> has asked receivers, in DNS, to treat mail that
    /// fails its alignment as suspicious (RFC 7489 §6.3). The junk folder is what that means,
    /// so this one signal is enough on its own — the publisher is the authority on their own
    /// mail, and the disposition only reaches the filter when sampling selected the message.
    /// </summary>
    [Fact]
    public void Honours_a_published_quarantine_request_on_its_own()
    {
        Weigh(dmarc: DmarcResult.Fail, disposition: DmarcPolicy.Quarantine)
            .Sum(s => s.Score)
            .ShouldBeGreaterThanOrEqualTo(FilterPolicy.Default.JunkThreshold);
    }

    /// <summary>
    /// But nothing about authentication alone puts a message where only an operator can see it.
    /// Holding mail is this server's own decision, and one signal never earns it.
    /// </summary>
    [Fact]
    public void No_single_authentication_signal_quarantines_a_message()
    {
        foreach (DmarcPolicy disposition in Enum.GetValues<DmarcPolicy>())
        {
            Weigh(dmarc: DmarcResult.Fail, disposition: disposition)
                .Sum(s => s.Score)
                .ShouldBeLessThan(FilterPolicy.Default.QuarantineThreshold);
        }
    }

    /// <summary>
    /// A message that merely fails DMARC against a domain asking for nothing is weighed, not
    /// junked: p=none is a domain saying it is still watching its own reports.
    /// </summary>
    [Fact]
    public void Does_not_junk_a_failure_the_domain_asked_nothing_about() =>
        Weigh(dmarc: DmarcResult.Fail, disposition: DmarcPolicy.None)
            .Sum(s => s.Score)
            .ShouldBeLessThan(FilterPolicy.Default.JunkThreshold);
}
