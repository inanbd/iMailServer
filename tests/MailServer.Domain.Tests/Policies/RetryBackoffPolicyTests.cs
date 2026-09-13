using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;

namespace MailServer.Domain.Tests.Policies;

public sealed class RetryBackoffPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A deterministic jitter source: 0.5 maps to the centre, i.e. no offset.</summary>
    private static double NoJitter() => 0.5;

    [Fact]
    public void The_default_schedule_backs_off_as_documented()
    {
        RetryBackoffPolicy policy = new(jitterFraction: 0);

        policy.GetInterval(1).ShouldBe(TimeSpan.FromMinutes(1));
        policy.GetInterval(2).ShouldBe(TimeSpan.FromMinutes(5));
        policy.GetInterval(3).ShouldBe(TimeSpan.FromMinutes(15));
        policy.GetInterval(4).ShouldBe(TimeSpan.FromMinutes(30));
        policy.GetInterval(5).ShouldBe(TimeSpan.FromHours(1));
        policy.GetInterval(6).ShouldBe(TimeSpan.FromHours(2));
        policy.GetInterval(7).ShouldBe(TimeSpan.FromHours(4));
        policy.GetInterval(8).ShouldBe(TimeSpan.FromHours(8));
    }

    [Fact]
    public void The_schedule_plateaus_at_its_last_interval_rather_than_growing_forever()
    {
        RetryBackoffPolicy policy = new(jitterFraction: 0);

        // Attempt 20 uses the same interval as attempt 8. Unbounded growth would push the
        // next attempt past the message's own expiry window and effectively drop it silently.
        policy.GetInterval(20).ShouldBe(policy.GetInterval(8));
    }

    [Fact]
    public void Attempt_numbers_below_one_are_rejected()
    {
        RetryBackoffPolicy policy = new();

        Should.Throw<ArgumentOutOfRangeException>(() => policy.GetInterval(0));
        Should.Throw<ArgumentOutOfRangeException>(() => policy.GetInterval(-1));
    }

    [Fact]
    public void Jitter_keeps_the_mean_interval_unchanged()
    {
        RetryBackoffPolicy policy = new(jitterFraction: 0.15);

        // A jitter sample of 0.5 maps to the centre of the range, so the interval is exact.
        DateTimeOffset next = policy.GetNextAttemptUtc(1, Now, NoJitter);

        next.ShouldBe(Now.AddMinutes(1));
    }

    [Fact]
    public void Jitter_stays_inside_the_configured_fraction()
    {
        const double Fraction = 0.2;
        RetryBackoffPolicy policy = new(jitterFraction: Fraction);

        TimeSpan baseInterval = TimeSpan.FromMinutes(1);

        // The extremes of the random range.
        DateTimeOffset earliest = policy.GetNextAttemptUtc(1, Now, () => 0.0);
        DateTimeOffset latest = policy.GetNextAttemptUtc(1, Now, () => 1.0);

        (earliest - Now).ShouldBe(baseInterval * (1 - Fraction), TimeSpan.FromMilliseconds(1));
        (latest - Now).ShouldBe(baseInterval * (1 + Fraction), TimeSpan.FromMilliseconds(1));
    }

    [Fact]
    public void A_schedule_that_decreases_is_rejected()
    {
        // A backoff that shortens over time attacks the destination instead of backing off
        // from it, which is exactly how a sending IP gets throttled and then blocklisted.
        Should.Throw<DomainRuleViolationException>(
                () => new RetryBackoffPolicy([1, 5, 2]))
            .Code.ShouldBe("retry.schedule.not_ascending");
    }

    [Fact]
    public void An_empty_schedule_is_rejected() =>
        Should.Throw<DomainRuleViolationException>(() => new RetryBackoffPolicy([]))
            .Code.ShouldBe("retry.schedule.empty");

    [Fact]
    public void A_non_positive_interval_is_rejected() =>
        Should.Throw<DomainRuleViolationException>(() => new RetryBackoffPolicy([1, 0, 5]))
            .Code.ShouldBe("retry.schedule.non_positive");

    [Theory]
    [InlineData(-0.1)]
    [InlineData(0.6)]
    public void A_jitter_fraction_outside_zero_to_half_is_rejected(double fraction) =>
        Should.Throw<DomainRuleViolationException>(
                () => new RetryBackoffPolicy(jitterFraction: fraction))
            .Code.ShouldBe("retry.jitter.out_of_range");

    [Fact]
    public void A_message_expires_after_the_configured_lifetime()
    {
        RetryBackoffPolicy policy = new(maximumLifetime: TimeSpan.FromDays(5));

        policy.HasExpired(Now, Now.AddDays(4)).ShouldBeFalse();
        policy.HasExpired(Now, Now.AddDays(5)).ShouldBeTrue();
        policy.HasExpired(Now, Now.AddDays(6)).ShouldBeTrue();
    }

    [Fact]
    public void A_delay_warning_is_due_once_past_the_threshold_and_only_once()
    {
        RetryBackoffPolicy policy = new(delayWarningThreshold: TimeSpan.FromHours(4));

        policy.ShouldSendDelayWarning(Now, Now.AddHours(3), warningAlreadySent: false).ShouldBeFalse();
        policy.ShouldSendDelayWarning(Now, Now.AddHours(4), warningAlreadySent: false).ShouldBeTrue();

        // Sending a second "still delayed" DSN for the same message is backscatter.
        policy.ShouldSendDelayWarning(Now, Now.AddHours(8), warningAlreadySent: true).ShouldBeFalse();
    }

    [Fact]
    public void A_custom_schedule_is_honoured()
    {
        RetryBackoffPolicy policy = new([2, 10, 60], jitterFraction: 0);

        policy.ScheduleLength.ShouldBe(3);
        policy.GetInterval(1).ShouldBe(TimeSpan.FromMinutes(2));
        policy.GetInterval(3).ShouldBe(TimeSpan.FromMinutes(60));
        policy.GetInterval(99).ShouldBe(TimeSpan.FromMinutes(60));
    }
}
