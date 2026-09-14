using MailServer.Domain.Policies;

namespace MailServer.Acme.Tests;

/// <summary>
/// The rate limiter, which exists to stop this server harming its own installation.
/// </summary>
/// <remarks>
/// Every refusal here is a refusal to do something the CA would have accepted or rejected
/// anyway. The value is entirely in the cases where the CA would have <i>rejected</i> it:
/// a failed validation costs one of five slots per hostname per hour, and five of those lock an
/// operator out for the rest of the hour with nothing to do but wait.
/// </remarks>
public sealed class RateLimitTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private readonly AcmeRateLimitPolicy _policy = new();

    [Fact]
    public void A_first_issuance_is_allowed()
    {
        _policy.Evaluate(0, 0, 0, null, Now).IsAllowed.ShouldBeTrue();
    }

    /// <summary>
    /// The limit operators actually hit: retrying the same hostname list after a
    /// misconfiguration burns it five times over before anyone notices.
    /// </summary>
    [Fact]
    public void The_duplicate_certificate_limit_is_enforced_with_headroom()
    {
        // Four issued, limit five, margin one - so the fifth is refused locally rather than
        // being the CA's to reject.
        RateLimitDecision decision = _policy.Evaluate(0, 4, 0, Now.AddDays(-2), Now);

        decision.IsAllowed.ShouldBeFalse();
        decision.Reason.ShouldNotBeNull().ShouldContain("this exact set of hostnames");
        decision.Reason!.ShouldContain("staging");
    }

    [Fact]
    public void Three_duplicates_still_leave_room()
    {
        _policy.Evaluate(0, 3, 0, Now.AddDays(-2), Now).IsAllowed.ShouldBeTrue();
    }

    [Fact]
    public void The_failed_validation_limit_is_enforced()
    {
        RateLimitDecision decision = _policy.Evaluate(0, 0, 5, Now.AddMinutes(-30), Now);

        decision.IsAllowed.ShouldBeFalse();
        decision.Reason.ShouldNotBeNull().ShouldContain("last hour");

        // The message has to say what to do, because "wait" is not actionable and retrying
        // extends the block.
        decision.Reason!.ShouldContain("Fix the underlying problem");
    }

    [Fact]
    public void The_per_registered_domain_limit_is_enforced()
    {
        RateLimitDecision decision = _policy.Evaluate(49, 0, 0, Now.AddDays(-3), Now);

        decision.IsAllowed.ShouldBeFalse();
        decision.Reason.ShouldNotBeNull().ShouldContain("registered domain");
    }

    /// <summary>
    /// Checked most-specific first: an operator who has hit both limits needs to hear about
    /// the failures, because that is the one they caused and the one they can fix.
    /// </summary>
    [Fact]
    public void Failed_validations_are_reported_before_the_duplicate_limit()
    {
        RateLimitDecision decision = _policy.Evaluate(0, 10, 5, Now.AddMinutes(-10), Now);

        decision.Reason.ShouldNotBeNull().ShouldContain("last hour");
    }

    [Fact]
    public void A_refusal_says_when_the_limit_clears()
    {
        DateTimeOffset oldest = Now.AddDays(-2);

        RateLimitDecision decision = _policy.Evaluate(0, 5, 0, oldest, Now);

        decision.RetryAfterUtc.ShouldBe(oldest.Add(_policy.WeeklyWindow));
    }

    /// <summary>
    /// The margin exists because the local count can disagree with the CA's — a certificate
    /// issued for the same domain by another tool counts against theirs and not ours.
    /// </summary>
    [Fact]
    public void The_safety_margin_stops_one_short_of_the_published_limit()
    {
        _policy.SafetyMargin.ShouldBeGreaterThan(0);

        int lastAllowed = _policy.DuplicateCertificatesPerWeek - _policy.SafetyMargin - 1;

        _policy.Evaluate(0, lastAllowed, 0, Now.AddDays(-1), Now).IsAllowed.ShouldBeTrue();
        _policy.Evaluate(0, lastAllowed + 1, 0, Now.AddDays(-1), Now).IsAllowed.ShouldBeFalse();
    }

    [Fact]
    public void The_published_limits_are_the_ones_lets_encrypt_documents()
    {
        _policy.CertificatesPerRegisteredDomainPerWeek.ShouldBe(50);
        _policy.DuplicateCertificatesPerWeek.ShouldBe(5);
        _policy.FailedValidationsPerHostnamePerHour.ShouldBe(5);
        _policy.WeeklyWindow.ShouldBe(TimeSpan.FromDays(7));
        _policy.FailureWindow.ShouldBe(TimeSpan.FromHours(1));
    }
}
