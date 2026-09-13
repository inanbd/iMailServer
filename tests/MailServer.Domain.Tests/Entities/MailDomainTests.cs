using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Events;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.Entities;

public sealed class MailDomainTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static MailDomain CreatePending(string name = "example.com") =>
        MailDomain.Create(DomainId.New(), DomainName.Parse(name), Now);

    private static MailDomain CreateReadyToEnable(string name = "example.com")
    {
        MailDomain domain = CreatePending(name);
        domain.SetMailHostname(DomainName.Parse($"mail.{name}"), Now);
        return domain;
    }

    [Fact]
    public void A_new_domain_starts_pending_and_not_operational()
    {
        MailDomain domain = CreatePending();

        // Deliberate: a domain that started Active would send mail before DKIM exists and
        // before DNS has propagated, which fails authentication at every major receiver and
        // damages the sending IP's reputation for weeks.
        domain.Status.ShouldBe(DomainStatus.Pending);
        domain.IsOperational.ShouldBeFalse();
    }

    [Fact]
    public void Creating_a_domain_raises_a_created_event()
    {
        MailDomain domain = CreatePending();

        domain.DomainEvents.ShouldHaveSingleItem()
            .ShouldBeOfType<MailDomainCreatedEvent>()
            .Name.Value.ShouldBe("example.com");
    }

    [Fact]
    public void Draining_events_returns_them_once_and_then_empties()
    {
        MailDomain domain = CreatePending();

        domain.DrainDomainEvents().Count.ShouldBe(1);

        // Draining rather than clearing is what stops an event being published twice when a
        // handler drains, then something re-reads the aggregate in the same scope.
        domain.DrainDomainEvents().ShouldBeEmpty();
        domain.DomainEvents.ShouldBeEmpty();
    }

    [Fact]
    public void A_domain_without_a_mail_hostname_cannot_be_enabled()
    {
        MailDomain domain = CreatePending();

        DomainRuleViolationException ex =
            Should.Throw<DomainRuleViolationException>(() => domain.Enable(Now));

        ex.Code.ShouldBe("domain.enable.no_hostname");
        domain.Status.ShouldBe(DomainStatus.Pending);
    }

    [Fact]
    public void A_domain_with_a_mail_hostname_can_be_enabled()
    {
        MailDomain domain = CreateReadyToEnable();
        domain.DrainDomainEvents();

        domain.Enable(Now);

        domain.Status.ShouldBe(DomainStatus.Active);
        domain.IsOperational.ShouldBeTrue();
        domain.DomainEvents.ShouldContain(e => e is MailDomainEnabledEvent);
    }

    [Fact]
    public void Enabling_an_already_active_domain_is_a_no_op_and_raises_nothing()
    {
        MailDomain domain = CreateReadyToEnable();
        domain.Enable(Now);
        domain.DrainDomainEvents();

        domain.Enable(Now);

        domain.Status.ShouldBe(DomainStatus.Active);
        domain.DomainEvents.ShouldBeEmpty();
    }

    [Fact]
    public void A_domain_pending_deletion_cannot_be_enabled()
    {
        MailDomain domain = CreateReadyToEnable();
        domain.MarkForDeletion(Now);

        Should.Throw<DomainRuleViolationException>(() => domain.Enable(Now))
            .Code.ShouldBe("domain.enable.pending_deletion");
    }

    [Fact]
    public void Disabling_stops_mail_flow_but_retains_everything()
    {
        MailDomain domain = CreateReadyToEnable();
        domain.Enable(Now);

        domain.Disable(Now);

        domain.Status.ShouldBe(DomainStatus.Disabled);
        domain.IsOperational.ShouldBeFalse();
        domain.MailHostname.ShouldNotBeNull();
    }

    [Fact]
    public void Changing_the_mail_hostname_raises_an_event_carrying_the_previous_value()
    {
        MailDomain domain = CreateReadyToEnable();
        domain.DrainDomainEvents();

        domain.SetMailHostname(DomainName.Parse("mx.example.com"), Now);

        // Consumers must re-check DNS, SPF and the TLS certificate, all of which reference
        // this name, which is why the previous value travels with the event.
        MailDomainHostnameChangedEvent changed = domain.DomainEvents
            .OfType<MailDomainHostnameChangedEvent>()
            .ShouldHaveSingleItem();

        changed.PreviousHostname!.Value.ShouldBe("mail.example.com");
        changed.NewHostname.Value.ShouldBe("mx.example.com");
    }

    [Fact]
    public void Setting_the_same_mail_hostname_raises_nothing()
    {
        MailDomain domain = CreateReadyToEnable();
        domain.DrainDomainEvents();

        domain.SetMailHostname(DomainName.Parse("mail.example.com"), Now);

        domain.DomainEvents.ShouldBeEmpty();
    }

    [Fact]
    public void A_catch_all_policy_requires_a_destination()
    {
        MailDomain domain = CreatePending();

        Should.Throw<DomainRuleViolationException>(
                () => domain.SetCatchAllPolicy(CatchAllPolicy.DeliverToCatchAll, null, Now))
            .Code.ShouldBe("domain.catchall.destination_required");
    }

    [Fact]
    public void A_catch_all_destination_must_belong_to_the_same_domain()
    {
        MailDomain domain = CreatePending();

        // Routing a catch-all off-domain would make this server a forwarder for every
        // dictionary attack aimed at the domain.
        Should.Throw<DomainRuleViolationException>(
                () => domain.SetCatchAllPolicy(
                    CatchAllPolicy.DeliverToCatchAll,
                    EmailAddress.Parse("elsewhere@other.com"),
                    Now))
            .Code.ShouldBe("domain.catchall.foreign_destination");
    }

    [Fact]
    public void Switching_away_from_catch_all_clears_the_destination()
    {
        MailDomain domain = CreatePending();
        domain.SetCatchAllPolicy(
            CatchAllPolicy.DeliverToCatchAll,
            EmailAddress.Parse("catchall@example.com"),
            Now);

        domain.SetCatchAllPolicy(CatchAllPolicy.Reject, null, Now);

        domain.CatchAllPolicy.ShouldBe(CatchAllPolicy.Reject);

        // A stale destination left behind would be written to the database and violate the
        // CK_Domains_CatchAllMailbox constraint on the next save.
        domain.CatchAllMailbox.ShouldBeNull();
    }

    [Fact]
    public void A_default_mailbox_quota_cannot_exceed_the_domain_quota()
    {
        MailDomain domain = CreatePending();

        Should.Throw<DomainRuleViolationException>(
                () => domain.SetQuotas(
                    QuotaBytes.FromGigabytes(50),
                    QuotaBytes.FromGigabytes(10),
                    Now))
            .Code.ShouldBe("domain.quota.mailbox_exceeds_domain");
    }

    [Fact]
    public void An_unlimited_domain_quota_permits_any_mailbox_quota()
    {
        MailDomain domain = CreatePending();

        domain.SetQuotas(QuotaBytes.FromGigabytes(50), QuotaBytes.Unlimited, Now);

        domain.DefaultMailboxQuota.Bytes.ShouldBe(50L * 1024 * 1024 * 1024);
        domain.DomainQuota.IsUnlimited.ShouldBeTrue();
    }

    [Fact]
    public void A_max_message_size_below_the_floor_is_rejected()
    {
        // A limit this low would reject ordinary mail with attachments, which looks to the
        // sender like an outage rather than a policy.
        Should.Throw<DomainRuleViolationException>(
                () => MailDomain.Create(
                    DomainId.New(),
                    DomainName.Parse("example.com"),
                    Now,
                    maxMessageSizeBytes: 1024))
            .Code.ShouldBe("domain.max_message_size.too_small");
    }

    [Fact]
    public void AcceptsMailFor_requires_both_an_operational_domain_and_a_matching_recipient()
    {
        MailDomain domain = CreateReadyToEnable();

        domain.AcceptsMailFor(EmailAddress.Parse("user@example.com")).ShouldBeFalse();

        domain.Enable(Now);

        domain.AcceptsMailFor(EmailAddress.Parse("user@example.com")).ShouldBeTrue();
        domain.AcceptsMailFor(EmailAddress.Parse("user@other.com")).ShouldBeFalse();
    }

    [Fact]
    public void Two_domains_with_the_same_id_are_the_same_entity()
    {
        DomainId id = DomainId.New();

        MailDomain a = MailDomain.Create(id, DomainName.Parse("example.com"), Now);
        MailDomain b = MailDomain.Create(id, DomainName.Parse("example.com"), Now);

        // Entity equality is identity equality: differing attributes just mean one is staler.
        a.ShouldBe(b);
        a.GetHashCode().ShouldBe(b.GetHashCode());
    }

    [Fact]
    public void Modified_timestamp_is_null_until_the_domain_changes()
    {
        MailDomain domain = CreatePending();
        domain.ModifiedUtc.ShouldBeNull();

        domain.SetMailHostname(DomainName.Parse("mail.example.com"), Now.AddMinutes(5));

        domain.ModifiedUtc.ShouldBe(Now.AddMinutes(5));
    }
}
