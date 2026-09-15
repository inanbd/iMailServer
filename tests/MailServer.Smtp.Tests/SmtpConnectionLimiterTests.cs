using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;

namespace MailServer.Smtp.Tests;

public sealed class SmtpConnectionLimiterTests
{
    private static IpAddressValue Address(string value = "198.51.100.20") => IpAddressValue.Parse(value);

    [Fact]
    public void A_slot_is_granted_while_there_is_room()
    {
        SmtpConnectionLimiter limiter = new(maxTotal: 10, maxPerAddress: 3);

        limiter.TryAdmit(Address(), out ISmtpConnectionSlot? slot).ShouldBe(SmtpAdmission.Admitted);

        slot.ShouldNotBeNull();
        limiter.CurrentTotal.ShouldBe(1);
        limiter.CurrentFor(Address()).ShouldBe(1);
    }

    [Fact]
    public void One_address_cannot_take_more_than_its_share()
    {
        // The cheap, effective denial of service against a mail server: open connections from one
        // source until nobody else can. The global cap alone does nothing about it.
        SmtpConnectionLimiter limiter = new(maxTotal: 100, maxPerAddress: 2);

        limiter.TryAdmit(Address(), out _).ShouldBe(SmtpAdmission.Admitted);
        limiter.TryAdmit(Address(), out _).ShouldBe(SmtpAdmission.Admitted);
        limiter.TryAdmit(Address(), out ISmtpConnectionSlot? refused).ShouldBe(SmtpAdmission.AddressBusy);

        refused.ShouldBeNull();
    }

    [Fact]
    public void One_busy_address_does_not_stop_another()
    {
        SmtpConnectionLimiter limiter = new(maxTotal: 100, maxPerAddress: 1);

        limiter.TryAdmit(Address("198.51.100.20"), out _).ShouldBe(SmtpAdmission.Admitted);
        limiter.TryAdmit(Address("198.51.100.20"), out _).ShouldBe(SmtpAdmission.AddressBusy);
        limiter.TryAdmit(Address("203.0.113.9"), out _).ShouldBe(SmtpAdmission.Admitted);
    }

    [Fact]
    public void The_global_cap_stops_a_flood_from_many_addresses()
    {
        SmtpConnectionLimiter limiter = new(maxTotal: 3, maxPerAddress: 10);

        for (int i = 0; i < 3; i++)
        {
            limiter.TryAdmit(Address($"198.51.100.{i}"), out _).ShouldBe(SmtpAdmission.Admitted);
        }

        limiter.TryAdmit(Address("198.51.100.99"), out _).ShouldBe(SmtpAdmission.ServerBusy);
    }

    [Fact]
    public void Releasing_a_slot_makes_room_again()
    {
        SmtpConnectionLimiter limiter = new(maxTotal: 1, maxPerAddress: 1);

        limiter.TryAdmit(Address(), out ISmtpConnectionSlot? slot).ShouldBe(SmtpAdmission.Admitted);
        limiter.TryAdmit(Address(), out _).ShouldBe(SmtpAdmission.AddressBusy);

        slot!.Dispose();

        limiter.CurrentTotal.ShouldBe(0);
        limiter.TryAdmit(Address(), out _).ShouldBe(SmtpAdmission.Admitted);
    }

    [Fact]
    public void A_refusal_never_raises_a_count()
    {
        // A refusal that left a count raised leaks slots slowly, and the server stops accepting
        // mail days later for no visible reason.
        SmtpConnectionLimiter limiter = new(maxTotal: 1, maxPerAddress: 5);

        limiter.TryAdmit(Address("198.51.100.1"), out _).ShouldBe(SmtpAdmission.Admitted);

        for (int i = 0; i < 50; i++)
        {
            limiter.TryAdmit(Address("203.0.113.9"), out _).ShouldBe(SmtpAdmission.ServerBusy);
        }

        limiter.CurrentTotal.ShouldBe(1);
        limiter.CurrentFor(Address("203.0.113.9")).ShouldBe(0);
    }

    [Fact]
    public void Releasing_a_slot_twice_does_not_under_count()
    {
        // An under-count lets the caps be exceeded silently, which is worse than the double
        // release it came from.
        SmtpConnectionLimiter limiter = new(maxTotal: 5, maxPerAddress: 5);

        limiter.TryAdmit(Address(), out ISmtpConnectionSlot? a);
        limiter.TryAdmit(Address(), out _);

        a!.Dispose();
        a.Dispose();

        limiter.CurrentTotal.ShouldBe(1);
        limiter.CurrentFor(Address()).ShouldBe(1);
    }

    [Fact]
    public void An_address_that_goes_quiet_is_forgotten()
    {
        // A long-lived server sees a great many distinct addresses. A per-address map that only
        // ever grows is a slow leak an attacker can drive by connecting once from each of many.
        SmtpConnectionLimiter limiter = new(maxTotal: 100, maxPerAddress: 5);

        for (int i = 0; i < 100; i++)
        {
            limiter.TryAdmit(Address($"198.51.100.{i % 250}"), out ISmtpConnectionSlot? slot);
            slot!.Dispose();
        }

        limiter.CurrentTotal.ShouldBe(0);
        limiter.CurrentFor(Address("198.51.100.1")).ShouldBe(0);
    }

    [Fact]
    public async Task Concurrent_admissions_never_exceed_the_cap()
    {
        // The counts are read and raised under one lock precisely so this cannot race. Without
        // it, two threads both see room and both take the last slot.
        SmtpConnectionLimiter limiter = new(maxTotal: 20, maxPerAddress: 20);

        int admitted = 0;

        await Parallel.ForAsync(0, 500, (_, _) =>
        {
            if (limiter.TryAdmit(Address(), out _) == SmtpAdmission.Admitted)
            {
                Interlocked.Increment(ref admitted);
            }

            return ValueTask.CompletedTask;
        });

        admitted.ShouldBe(20);
        limiter.CurrentTotal.ShouldBe(20);
    }

    [Theory]
    [InlineData(0, 5)]
    [InlineData(5, 0)]
    [InlineData(-1, 5)]
    public void A_cap_of_zero_or_less_is_refused_rather_than_accepted(int total, int perAddress)
    {
        // "MaxConcurrentConnectionsTotal: 0" means "accept no mail", which is never what an
        // operator meant to configure and would be obeyed silently.
        Should.Throw<ArgumentOutOfRangeException>(() => new SmtpConnectionLimiter(total, perAddress));
    }
}
