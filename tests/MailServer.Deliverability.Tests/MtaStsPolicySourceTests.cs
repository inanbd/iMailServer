using MailServer.Application.Abstractions.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Deliverability;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// Turning configuration into the policy this server publishes.
/// </summary>
/// <remarks>
/// The interesting cases are all about <i>not</i> publishing. RFC 8461 §8.3 makes this the one
/// setting in the product that can stop mail arriving that was arriving perfectly well, so every
/// path that is unsure of itself has to end in silence rather than in a policy.
/// </remarks>
public sealed class MtaStsPolicySourceTests
{
    private static IMtaStsPolicySource Source(Action<MtaStsOptions> configure)
    {
        MailServerOptions options = new();

        configure(options.Deliverability.MtaSts);

        return new MtaStsPolicySource(
            Options.Create(options),
            NullLogger<MtaStsPolicySource>.Instance);
    }

    /// <summary>
    /// Publishing is opt-in. An installation that has not asked for it serves nothing, and
    /// senders use ordinary opportunistic TLS.
    /// </summary>
    [Fact]
    public void Nothing_is_published_by_default()
    {
        IMtaStsPolicySource source = Source(_ => { });

        source.IsPublishing.ShouldBeFalse();
        source.Current().ShouldBeNull();
    }

    /// <summary>
    /// §8.3 recommends starting in testing mode: senders report failures through TLS-RPT and
    /// deliver anyway, so a wrong mx list is a report rather than a bounce.
    /// </summary>
    [Fact]
    public void The_default_mode_is_testing()
    {
        MtaStsPolicy policy = Source(sts =>
        {
            sts.Enabled = true;
            sts.MxHosts = ["mail.example.com"];
        }).Current().ShouldNotBeNull();

        policy.Mode.ShouldBe(MtaStsMode.Testing);
        policy.MaxAgeSeconds.ShouldBe(604_800L);
    }

    [Fact]
    public void An_enabled_policy_is_composed_from_configuration()
    {
        MtaStsPolicy policy = Source(sts =>
        {
            sts.Enabled = true;
            sts.Mode = MtaStsMode.Enforce;
            sts.MxHosts = ["mail.example.com", "backup.example.net"];
            sts.MaxAgeSeconds = 86_400;
        }).Current().ShouldNotBeNull();

        policy.Mode.ShouldBe(MtaStsMode.Enforce);
        policy.MxPatterns.ShouldBe(["mail.example.com", "backup.example.net"]);
        policy.MaxAgeSeconds.ShouldBe(86_400L);
        policy.Covers("mail.example.com").ShouldBeTrue();
        policy.Covers("elsewhere.example.org").ShouldBeFalse();
    }

    /// <summary>
    /// Enabled with no mx is the misconfiguration that matters: in enforce mode it would tell
    /// every conforming sender that no host may receive this domain's mail. Serving nothing is
    /// the safe outcome, and it must not take the host down either.
    /// </summary>
    [Theory]
    [InlineData(MtaStsMode.Enforce)]
    [InlineData(MtaStsMode.Testing)]
    public void An_invalid_policy_disables_publishing_rather_than_failing(MtaStsMode mode)
    {
        IMtaStsPolicySource source = Source(sts =>
        {
            sts.Enabled = true;
            sts.Mode = mode;
            sts.MxHosts = [];
        });

        source.IsPublishing.ShouldBeFalse();
        source.Current().ShouldBeNull();
    }

    /// <summary>
    /// §5's withdrawal file. "Publish nothing" and "publish mode: none" are different
    /// statements, and the second is an active instruction to senders holding a cached policy.
    /// </summary>
    [Fact]
    public void Mode_none_is_publishable_without_an_mx_because_it_withdraws_a_policy()
    {
        IMtaStsPolicySource source = Source(sts =>
        {
            sts.Enabled = true;
            sts.Mode = MtaStsMode.None;
            sts.MxHosts = [];
        });

        source.IsPublishing.ShouldBeTrue();
        source.Current().ShouldNotBeNull().Mode.ShouldBe(MtaStsMode.None);
    }

    /// <summary>
    /// The served bytes and the advertised id have to be one fact rather than two that agree,
    /// so the policy is resolved once and handed back unchanged.
    /// </summary>
    [Fact]
    public void The_policy_is_stable_across_reads()
    {
        IMtaStsPolicySource source = Source(sts =>
        {
            sts.Enabled = true;
            sts.MxHosts = ["mail.example.com"];
        });

        source.Current().ShouldBeSameAs(source.Current());
    }

    [Fact]
    public void The_port_defaults_to_443()
    {
        Source(_ => { }).Port.ShouldBe(443);
        Source(sts => sts.Port = 8443).Port.ShouldBe(8443);
    }
}
