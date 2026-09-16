using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Authentication.Tests;

public class DkimKeyTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 16, 12, 0, 0, TimeSpan.Zero);

    private static DkimKey NewGeneratedKey(int keyLengthBits = 2048) =>
        DkimKey.Generate(
            DomainId.New(),
            DkimSelector.Parse("mail202609"),
            DkimKeyAlgorithm.RsaSha256,
            publicKeyBase64: "AAAAB3NzaC1yc2EAAAADAQAB",
            keyLengthBits,
            Now);

    [Fact]
    public void Generate_starts_in_the_Generated_status()
    {
        DkimKey key = NewGeneratedKey();

        key.Status.ShouldBe(DkimKeyStatus.Generated);
        key.PublishedUtc.ShouldBeNull();
        key.ActivatedUtc.ShouldBeNull();
        key.RetiredUtc.ShouldBeNull();
    }

    [Fact]
    public void Generate_rejects_a_key_shorter_than_the_minimum()
    {
        Should.Throw<DomainRuleViolationException>(() => NewGeneratedKey(keyLengthBits: 1024))
            .Code.ShouldBe("dkim_key.key_too_short");
    }

    [Fact]
    public void Generate_rejects_the_reserved_but_unimplemented_algorithm()
    {
        Should.Throw<DomainRuleViolationException>(() => DkimKey.Generate(
                DomainId.New(),
                DkimSelector.Parse("mail202609"),
                DkimKeyAlgorithm.Ed25519Sha256,
                publicKeyBase64: "AAAA",
                keyLengthBits: 256,
                Now))
            .Code.ShouldBe("dkim_key.algorithm_not_implemented");
    }

    [Fact]
    public void The_full_rotation_lifecycle_transitions_in_order()
    {
        DkimKey key = NewGeneratedKey();
        DateTimeOffset publishedAt = Now.AddDays(1);
        DateTimeOffset activatedAt = Now.AddDays(3);
        DateTimeOffset retiredAt = Now.AddDays(400);

        key.Publish(publishedAt);
        key.Status.ShouldBe(DkimKeyStatus.Published);
        key.PublishedUtc.ShouldBe(publishedAt);

        key.Activate(activatedAt);
        key.Status.ShouldBe(DkimKeyStatus.Active);
        key.ActivatedUtc.ShouldBe(activatedAt);

        key.Retire(TimeSpan.FromDays(7), retiredAt);
        key.Status.ShouldBe(DkimKeyStatus.Retired);
        key.RetiredUtc.ShouldBe(retiredAt);
        key.SafeToDeleteAfterUtc.ShouldBe(retiredAt + TimeSpan.FromDays(7));

        key.IsSafeToDelete(retiredAt).ShouldBeFalse();
        key.IsSafeToDelete(retiredAt + TimeSpan.FromDays(8)).ShouldBeTrue();
    }

    [Fact]
    public void Activate_before_Publish_is_rejected()
    {
        DkimKey key = NewGeneratedKey();

        Should.Throw<DomainRuleViolationException>(() => key.Activate(Now))
            .Code.ShouldBe("dkim_key.invalid_transition");
    }

    [Fact]
    public void Publish_twice_is_rejected()
    {
        DkimKey key = NewGeneratedKey();
        key.Publish(Now);

        Should.Throw<DomainRuleViolationException>(() => key.Publish(Now))
            .Code.ShouldBe("dkim_key.invalid_transition");
    }

    [Fact]
    public void Retire_a_never_published_key_is_rejected()
    {
        DkimKey key = NewGeneratedKey();

        Should.Throw<DomainRuleViolationException>(() => key.Retire(TimeSpan.FromDays(1), Now))
            .Code.ShouldBe("dkim_key.invalid_transition");
    }

    [Fact]
    public void Retire_directly_from_Published_without_ever_activating_is_allowed()
    {
        DkimKey key = NewGeneratedKey();
        key.Publish(Now);

        key.Retire(TimeSpan.FromDays(1), Now.AddDays(1));

        key.Status.ShouldBe(DkimKeyStatus.Retired);
    }

    [Fact]
    public void Retire_twice_is_rejected()
    {
        DkimKey key = NewGeneratedKey();
        key.Publish(Now);
        key.Activate(Now);
        key.Retire(TimeSpan.FromDays(1), Now);

        Should.Throw<DomainRuleViolationException>(() => key.Retire(TimeSpan.FromDays(1), Now))
            .Code.ShouldBe("dkim_key.invalid_transition");
    }

    [Fact]
    public void Retire_rejects_a_negative_grace_window()
    {
        DkimKey key = NewGeneratedKey();
        key.Publish(Now);

        Should.Throw<DomainRuleViolationException>(() => key.Retire(TimeSpan.FromDays(-1), Now))
            .Code.ShouldBe("dkim_key.negative_grace_window");
    }
}
