using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Mailboxes.Tests;

/// <summary>
/// Quota inheritance and enforcement.
/// </summary>
/// <remarks>
/// <para>
/// Milestone 5's stated exit criterion includes "quota enforcement tested". The rule under test
/// is "zero means inherit the domain default", which sounds trivial and is exactly the kind of
/// rule that gets reimplemented slightly differently in the delivery path and the admin UI —
/// and then they disagree about whether a mailbox is full.
/// </para>
/// <para>
/// The decision that matters most here is <b>checking before accepting</b>. Accepting a message
/// that takes a mailbox over quota and bouncing it afterwards means the sender has already been
/// told it was delivered; refusing at RCPT TO with a temporary failure keeps the message in
/// their queue, where it can still be retried after the user clears space.
/// </para>
/// </remarks>
public sealed class QuotaTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private static MailDomain Domain(long defaultQuotaBytes) =>
        MailDomain.Create(
            DomainId.New(),
            DomainName.Parse("example.com"),
            Now,
            DomainName.Parse("mail.example.com"),
            QuotaBytes.FromBytes(defaultQuotaBytes));

    private static Mailbox CreateMailbox(MailDomain domain, long quotaBytes) =>
        Mailbox.Create(
            domain.Id,
            EmailAddress.Parse("alice@example.com"),
            domain,
            "Alice",
            QuotaBytes.FromBytes(quotaBytes),
            MailboxAccess.All,
            Now);

    // ---- Inheritance ------------------------------------------------------------------------

    [Fact]
    public void A_mailbox_with_no_quota_inherits_the_domain_default()
    {
        MailDomain domain = Domain(1_000_000);
        Mailbox mailbox = CreateMailbox(domain, quotaBytes: 0);

        mailbox.EffectiveQuota(domain.DefaultMailboxQuota).Bytes.ShouldBe(1_000_000);
    }

    [Fact]
    public void A_mailbox_with_its_own_quota_overrides_the_domain_default()
    {
        MailDomain domain = Domain(1_000_000);
        Mailbox mailbox = CreateMailbox(domain, quotaBytes: 500_000);

        mailbox.EffectiveQuota(domain.DefaultMailboxQuota).Bytes.ShouldBe(500_000);
    }

    [Fact]
    public void A_mailbox_quota_may_exceed_the_domain_default()
    {
        MailDomain domain = Domain(1_000_000);
        Mailbox mailbox = CreateMailbox(domain, quotaBytes: 5_000_000);

        // Deliberately permitted. The domain value is a default for new mailboxes, not a
        // ceiling on them, and an operator granting one person more space is a normal request.
        mailbox.EffectiveQuota(domain.DefaultMailboxQuota).Bytes.ShouldBe(5_000_000);
    }

    /// <summary>
    /// The consequence of "zero means inherit": a mailbox cannot be explicitly unlimited while
    /// its domain has a quota.
    /// </summary>
    /// <remarks>
    /// Asserted rather than left implicit, because it is the one sharp edge of the encoding and
    /// an operator who sets a mailbox to "unlimited" and finds it limited deserves to have that
    /// documented somewhere other than a surprise.
    /// </remarks>
    [Fact]
    public void A_mailbox_cannot_be_unlimited_while_its_domain_has_a_quota()
    {
        MailDomain domain = Domain(1_000_000);
        Mailbox mailbox = CreateMailbox(domain, quotaBytes: 0);

        mailbox.Quota.IsUnlimited.ShouldBeTrue("the mailbox's own value is 'inherit'");
        mailbox.EffectiveQuota(domain.DefaultMailboxQuota).IsUnlimited.ShouldBeFalse();
    }

    [Fact]
    public void Both_unlimited_means_genuinely_unlimited()
    {
        MailDomain domain = Domain(0);
        Mailbox mailbox = CreateMailbox(domain, quotaBytes: 0);

        mailbox.EffectiveQuota(domain.DefaultMailboxQuota).IsUnlimited.ShouldBeTrue();
        mailbox.WouldExceedQuota(long.MaxValue / 2, domain.DefaultMailboxQuota).ShouldBeFalse();
    }

    // ---- Enforcement ------------------------------------------------------------------------

    [Fact]
    public void A_message_that_fits_is_accepted()
    {
        MailDomain domain = Domain(1_000);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.AddStorage(400, Now);

        mailbox.WouldExceedQuota(500, domain.DefaultMailboxQuota).ShouldBeFalse();
    }

    [Fact]
    public void A_message_that_would_not_fit_is_refused()
    {
        MailDomain domain = Domain(1_000);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.AddStorage(900, Now);

        // Checked BEFORE accepting. Accepting and then bouncing means the sender was already
        // told it was delivered.
        mailbox.WouldExceedQuota(200, domain.DefaultMailboxQuota).ShouldBeTrue();
    }

    /// <summary>
    /// A quota of 1000 bytes means 1000 bytes may be stored — so a message that fills it
    /// exactly is accepted, and the mailbox is full afterwards.
    /// </summary>
    /// <remarks>
    /// The two checks read as though they disagree and do not. <c>WouldBeExceededBy</c> uses
    /// <c>&gt;</c> and <c>IsExceededBy</c> uses <c>&gt;=</c>, which together mean: you may fill
    /// exactly to the limit, and once there you are full. Asserting both halves in one test is
    /// the only way that stays obviously intentional rather than looking like an off-by-one
    /// somebody should "fix".
    /// </remarks>
    [Fact]
    public void A_message_filling_the_quota_exactly_is_accepted_and_the_mailbox_is_then_full()
    {
        MailDomain domain = Domain(1_000);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.AddStorage(900, Now);

        mailbox.WouldExceedQuota(100, domain.DefaultMailboxQuota).ShouldBeFalse();

        mailbox.AddStorage(100, Now);

        // Now full: the next message of any size is refused.
        mailbox.WouldExceedQuota(1, domain.DefaultMailboxQuota).ShouldBeTrue();
        domain.DefaultMailboxQuota.IsExceededBy(mailbox.StorageUsedBytes).ShouldBeTrue();
    }

    [Fact]
    public void Usage_accumulates_and_releases()
    {
        MailDomain domain = Domain(10_000);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.AddStorage(3_000, Now);
        mailbox.AddStorage(2_000, Now);
        mailbox.StorageUsedBytes.ShouldBe(5_000);

        mailbox.ReleaseStorage(1_500, Now);
        mailbox.StorageUsedBytes.ShouldBe(3_500);
    }

    /// <summary>
    /// The counter is maintained incrementally, so a missed increment must not make it
    /// negative — a negative total reports every mailbox as empty, and a quota that silently
    /// stops applying is worse than one that is slightly high until the next recount.
    /// </summary>
    [Fact]
    public void Releasing_more_than_is_stored_clamps_at_zero()
    {
        MailDomain domain = Domain(10_000);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.AddStorage(100, Now);
        mailbox.ReleaseStorage(5_000, Now);

        mailbox.StorageUsedBytes.ShouldBe(0);
    }

    [Fact]
    public void A_recount_replaces_the_running_total()
    {
        MailDomain domain = Domain(10_000);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.AddStorage(9_999, Now);
        mailbox.ResetStorage(1_234, Now);

        mailbox.StorageUsedBytes.ShouldBe(1_234);
    }

    /// <summary>
    /// Lowering a quota below current usage is permitted, because refusing it would leave an
    /// operator unable to act on a mailbox that is already too large — exactly when they most
    /// need to.
    /// </summary>
    [Fact]
    public void A_quota_may_be_set_below_current_usage()
    {
        MailDomain domain = Domain(0);
        Mailbox mailbox = CreateMailbox(domain, 10_000);

        mailbox.AddStorage(8_000, Now);

        Should.NotThrow(() => mailbox.SetQuota(QuotaBytes.FromBytes(5_000), Now));

        mailbox.WouldExceedQuota(1, domain.DefaultMailboxQuota).ShouldBeTrue();
        mailbox.QuotaPercentageUsed(domain.DefaultMailboxQuota).ShouldBeGreaterThan(100);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(500, 50)]
    [InlineData(1_000, 100)]
    [InlineData(1_500, 150)]
    public void The_percentage_reflects_usage_against_the_effective_quota(long used, double expected)
    {
        MailDomain domain = Domain(1_000);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.AddStorage(used, Now);

        mailbox.QuotaPercentageUsed(domain.DefaultMailboxQuota).ShouldBe(expected, 0.01);
    }

    // ---- Message size -----------------------------------------------------------------------

    [Fact]
    public void The_maximum_message_size_inherits_the_same_way()
    {
        MailDomain domain = Domain(0);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.EffectiveMaxMessageSize(domain.MaxMessageSizeBytes)
            .ShouldBe(domain.MaxMessageSizeBytes);

        mailbox.SetMaxMessageSize(1_000, Now);

        mailbox.EffectiveMaxMessageSize(domain.MaxMessageSizeBytes).ShouldBe(1_000);
    }

    // ---- Status -----------------------------------------------------------------------------

    /// <summary>
    /// The distinction that matters: a suspended mailbox keeps accepting mail while refusing
    /// logins. Rejecting mail would announce the suspension to every sender, which for a
    /// compromised account is the wrong thing to broadcast.
    /// </summary>
    [Fact]
    public void A_suspended_mailbox_accepts_mail_but_refuses_logins()
    {
        MailDomain domain = Domain(0);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.SetStatus(MailboxStatus.Suspended, Now);

        mailbox.AcceptsMail.ShouldBeTrue();
        mailbox.AllowsLogin.ShouldBeFalse();
        mailbox.AllowsAccess(MailboxAccess.Imap).ShouldBeFalse();
    }

    [Fact]
    public void A_disabled_mailbox_refuses_both()
    {
        MailDomain domain = Domain(0);
        Mailbox mailbox = CreateMailbox(domain, 0);

        mailbox.SetStatus(MailboxStatus.Disabled, Now);

        mailbox.AcceptsMail.ShouldBeFalse();
        mailbox.AllowsLogin.ShouldBeFalse();
    }

    [Fact]
    public void Access_flags_gate_each_protocol_independently()
    {
        MailDomain domain = Domain(0);

        Mailbox mailbox = Mailbox.Create(
            domain.Id,
            EmailAddress.Parse("alice@example.com"),
            domain,
            null,
            QuotaBytes.Unlimited,
            MailboxAccess.Imap | MailboxAccess.Submission,
            Now);

        mailbox.AllowsAccess(MailboxAccess.Imap).ShouldBeTrue();
        mailbox.AllowsAccess(MailboxAccess.Submission).ShouldBeTrue();
        mailbox.AllowsAccess(MailboxAccess.Pop3).ShouldBeFalse();
    }

    /// <summary>
    /// A mailbox with no protocols enabled is a mailbox nobody can reach, which is what
    /// "disabled" already says clearly and reversibly.
    /// </summary>
    [Fact]
    public void A_mailbox_cannot_have_every_protocol_disabled()
    {
        MailDomain domain = Domain(0);

        Should.Throw<Domain.Exceptions.DomainRuleViolationException>(() => Mailbox.Create(
            domain.Id,
            EmailAddress.Parse("alice@example.com"),
            domain,
            null,
            QuotaBytes.Unlimited,
            MailboxAccess.None,
            Now)).Code.ShouldBe("mailbox.access.none");
    }

    [Fact]
    public void A_mailbox_address_must_be_in_its_own_domain()
    {
        MailDomain domain = Domain(0);

        Should.Throw<Domain.Exceptions.DomainRuleViolationException>(() => Mailbox.Create(
            domain.Id,
            EmailAddress.Parse("alice@elsewhere.test"),
            domain,
            null,
            QuotaBytes.Unlimited,
            MailboxAccess.All,
            Now)).Code.ShouldBe("mailbox.address.wrong_domain");
    }
}
