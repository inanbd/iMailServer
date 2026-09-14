using MailServer.Domain.Enums;
using MailServer.Domain.Policies;

namespace MailServer.Domain.Tests.Policies;

/// <summary>
/// Renewal thresholds, escalation, and the rule that must never change.
/// </summary>
public sealed class CertificateRenewalPolicyTests
{
    private readonly CertificateRenewalPolicy _policy = new();

    [Theory]
    [InlineData(90, RenewalAction.None)]
    [InlineData(31, RenewalAction.None)]
    [InlineData(30, RenewalAction.Renew)]
    [InlineData(15, RenewalAction.Renew)]
    [InlineData(8, RenewalAction.Renew)]
    [InlineData(7, RenewalAction.RenewUrgently)]
    [InlineData(1, RenewalAction.RenewUrgently)]
    [InlineData(0, RenewalAction.RenewUrgently)]
    [InlineData(-5, RenewalAction.RenewUrgently)]
    public void The_action_follows_the_days_remaining(int daysRemaining, RenewalAction expected)
    {
        _policy.GetAction(daysRemaining).ShouldBe(expected);
    }

    [Theory]
    [InlineData(90, HealthState.Healthy)]
    [InlineData(31, HealthState.Healthy)]
    [InlineData(30, HealthState.Warning)]
    [InlineData(8, HealthState.Warning)]
    [InlineData(7, HealthState.Critical)]
    [InlineData(0, HealthState.Critical)]
    [InlineData(-1, HealthState.Critical)]
    public void Health_escalates_as_expiry_approaches(int daysRemaining, HealthState expected)
    {
        _policy.GetHealthState(daysRemaining).ShouldBe(expected);
    }

    /// <summary>
    /// The lowest crossed threshold is reported, so an alert at 20 days says "21" and one at
    /// 6 says "7". Reporting the highest would make every alert from 30 days on read "30", and
    /// the escalation an operator is supposed to notice would be invisible.
    /// </summary>
    [Theory]
    [InlineData(45, null)]
    [InlineData(31, null)]
    [InlineData(30, 30)]
    [InlineData(22, 30)]
    [InlineData(21, 21)]
    [InlineData(15, 21)]
    [InlineData(14, 14)]
    [InlineData(8, 14)]
    [InlineData(7, 7)]
    [InlineData(1, 7)]
    [InlineData(-3, 7)]
    public void The_lowest_crossed_escalation_threshold_is_reported(int daysRemaining, int? expected)
    {
        _policy.GetEscalationThreshold(daysRemaining).ShouldBe(expected);
    }

    /// <summary>
    /// The one rule in this product that is asserted rather than merely documented.
    /// </summary>
    /// <remarks>
    /// Substituting a self-signed certificate when renewal fails would convert a warning
    /// affecting nobody — a certificate with weeks left and a retry pending — into a
    /// simultaneous TLS failure against every verifying remote MTA and every mail client in
    /// the organisation. The failure mode is strictly worse than the problem it would be
    /// "fixing", which is why the answer is never.
    /// </remarks>
    [Fact]
    public void A_failed_renewal_may_never_downgrade_to_self_signed()
    {
        CertificateRenewalPolicy.MayDowngradeToSelfSignedOnRenewalFailure.ShouldBeFalse();
    }

    [Fact]
    public void The_self_signed_warning_is_stated_in_full()
    {
        CertificateRenewalPolicy.SelfSignedWarning
            .ShouldContain("NOT PUBLICLY TRUSTED");

        CertificateRenewalPolicy.SelfSignedWarning
            .ShouldContain("MAY DISPLAY CERTIFICATE WARNINGS");

        CertificateRenewalPolicy.SelfSignedWarning
            .ShouldContain("USE LET'S ENCRYPT OR ANOTHER PUBLIC CA");
    }

    [Fact]
    public void The_thresholds_descend()
    {
        IReadOnlyList<int> thresholds = _policy.EscalationThresholdDays;

        thresholds.ShouldNotBeEmpty();

        for (int i = 1; i < thresholds.Count; i++)
        {
            thresholds[i].ShouldBeLessThan(thresholds[i - 1]);
        }

        // The renewal window must open no later than the first alert, or the first thing an
        // operator hears about a certificate is a warning for a renewal never attempted.
        thresholds[0].ShouldBeLessThanOrEqualTo(_policy.RenewalWindowDays);
    }
}
