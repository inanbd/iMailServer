using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Tests.Entities;

/// <summary>
/// UID legality and the three <c>STORE</c> flag-mutation forms (<c>FLAGS</c>, <c>+FLAGS</c>,
/// <c>-FLAGS</c>), including that <c>\Recent</c> can never be persisted through any of them.
/// </summary>
public sealed class DeliveryTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static Delivery CreateDelivery(long uid = 1) =>
        Delivery.Create(
            StoredMessageId.New(),
            new MailboxId(Guid.NewGuid()),
            MailboxFolderId.New(),
            uid,
            recipientId: Guid.NewGuid(),
            Now);

    [Fact]
    public void A_new_delivery_carries_no_flags()
    {
        CreateDelivery().Flags.ShouldBe(MessageFlags.None);
    }

    [Fact]
    public void Uid_zero_is_refused()
    {
        Should.Throw<ArgumentOutOfRangeException>(() => CreateDelivery(uid: 0));
    }

    [Fact]
    public void A_negative_uid_is_refused()
    {
        Should.Throw<ArgumentOutOfRangeException>(() => CreateDelivery(uid: -1));
    }

    [Fact]
    public void SetFlags_replaces_every_flag_at_once()
    {
        Delivery delivery = CreateDelivery();
        delivery.AddFlags(MessageFlags.Flagged);

        delivery.SetFlags(MessageFlags.Seen | MessageFlags.Answered);

        delivery.Flags.ShouldBe(MessageFlags.Seen | MessageFlags.Answered);
    }

    [Fact]
    public void AddFlags_does_not_disturb_flags_already_set()
    {
        Delivery delivery = CreateDelivery();
        delivery.AddFlags(MessageFlags.Seen);

        delivery.AddFlags(MessageFlags.Flagged);

        delivery.Flags.ShouldBe(MessageFlags.Seen | MessageFlags.Flagged);
    }

    [Fact]
    public void RemoveFlags_clears_only_the_named_flags()
    {
        Delivery delivery = CreateDelivery();
        delivery.AddFlags(MessageFlags.Seen | MessageFlags.Flagged | MessageFlags.Answered);

        delivery.RemoveFlags(MessageFlags.Flagged);

        delivery.Flags.ShouldBe(MessageFlags.Seen | MessageFlags.Answered);
    }

    [Fact]
    public void Removing_a_flag_that_was_never_set_is_a_harmless_no_op()
    {
        Delivery delivery = CreateDelivery();
        delivery.AddFlags(MessageFlags.Seen);

        delivery.RemoveFlags(MessageFlags.Deleted);

        delivery.Flags.ShouldBe(MessageFlags.Seen);
    }

    [Theory]
    [InlineData(nameof(Delivery.SetFlags))]
    [InlineData(nameof(Delivery.AddFlags))]
    public void Recent_can_never_be_set_through_flags_or_plus_flags(string method)
    {
        // RFC 3501 §2.3.2: a client is not even permitted to set \Recent via STORE. Silently
        // accepting one here would not just be unimplemented - it would be wrong.
        Delivery delivery = CreateDelivery();

        if (method == nameof(Delivery.SetFlags))
        {
            delivery.SetFlags(MessageFlags.Seen | MessageFlags.Recent);
        }
        else
        {
            delivery.AddFlags(MessageFlags.Recent);
        }

        delivery.Flags.HasFlag(MessageFlags.Recent).ShouldBeFalse();
    }

    [Fact]
    public void Recipient_id_is_optional()
    {
        Delivery delivery = Delivery.Create(
            StoredMessageId.New(),
            new MailboxId(Guid.NewGuid()),
            MailboxFolderId.New(),
            uid: 1,
            recipientId: null,
            Now);

        delivery.RecipientId.ShouldBeNull();
    }
}
