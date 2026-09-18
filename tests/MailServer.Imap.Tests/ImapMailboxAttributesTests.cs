using MailServer.Domain.Enums;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapMailboxAttributesTests
{
    // ---------------------------------------------------------------------------------------
    // Wire names.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapMailboxAttribute.NoInferiors, @"\Noinferiors")]
    [InlineData(ImapMailboxAttribute.NoSelect, @"\Noselect")]
    [InlineData(ImapMailboxAttribute.Marked, @"\Marked")]
    [InlineData(ImapMailboxAttribute.Unmarked, @"\Unmarked")]
    [InlineData(ImapMailboxAttribute.HasChildren, @"\HasChildren")]
    [InlineData(ImapMailboxAttribute.HasNoChildren, @"\HasNoChildren")]
    [InlineData(ImapMailboxAttribute.Sent, @"\Sent")]
    [InlineData(ImapMailboxAttribute.Drafts, @"\Drafts")]
    [InlineData(ImapMailboxAttribute.Trash, @"\Trash")]
    [InlineData(ImapMailboxAttribute.Junk, @"\Junk")]
    [InlineData(ImapMailboxAttribute.Archive, @"\Archive")]
    public void Every_attribute_has_the_name_its_RFC_gives_it(
        ImapMailboxAttribute attribute,
        string expected) =>
        ImapMailboxAttributes.NameOf(attribute).ShouldBe(expected);

    /// <summary>
    /// The names are the wire form, so a stray space or a forward slash would be a protocol
    /// error rather than a typo.
    /// </summary>
    [Fact]
    public void Every_name_is_a_backslash_followed_by_an_atom()
    {
        foreach (ImapMailboxAttribute attribute in Enum.GetValues<ImapMailboxAttribute>())
        {
            if (attribute == ImapMailboxAttribute.None)
            {
                continue;
            }

            string name = ImapMailboxAttributes.NameOf(attribute);

            name.ShouldStartWith(@"\");
            name.Length.ShouldBeGreaterThan(1);
            name[1..].ShouldAllBe(c => char.IsAsciiLetter(c));
        }
    }

    [Fact]
    public void None_is_not_a_single_attribute_and_has_no_name() =>
        Should.Throw<ArgumentOutOfRangeException>(
            () => ImapMailboxAttributes.NameOf(ImapMailboxAttribute.None));

    // ---------------------------------------------------------------------------------------
    // What this server is willing to claim.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A promise about the future that nothing in this product enforces. See the enum member's
    /// own remarks: a client believing it would hide a "new subfolder" action that would work.
    /// </summary>
    [Fact]
    public void Noinferiors_is_never_emitted() =>
        ImapMailboxAttributes.Emittable.ShouldNotContain(ImapMailboxAttribute.NoInferiors);

    /// <summary>
    /// RFC 3501 §7.2.2 permits the omission — "the server SHOULD NOT send either \Marked or
    /// \Unmarked" when it cannot tell — and §6.3.8 asks a server not to go to the trouble.
    /// </summary>
    [Theory]
    [InlineData(ImapMailboxAttribute.Marked)]
    [InlineData(ImapMailboxAttribute.Unmarked)]
    public void The_interesting_attributes_are_never_emitted(ImapMailboxAttribute attribute) =>
        ImapMailboxAttributes.Emittable.ShouldNotContain(attribute);

    [Fact]
    public void Emittable_lists_each_attribute_at_most_once() =>
        ImapMailboxAttributes.Emittable.Distinct().Count()
            .ShouldBe(ImapMailboxAttributes.Emittable.Count);

    /// <summary>
    /// An attribute that is emittable but unnameable, or a flag combination in the list, would
    /// be a formatting crash on a live LIST.
    /// </summary>
    [Fact]
    public void Every_emittable_attribute_is_a_single_named_flag()
    {
        foreach (ImapMailboxAttribute attribute in ImapMailboxAttributes.Emittable)
        {
            Enum.IsDefined(attribute).ShouldBeTrue($"{attribute} is not a defined member");
            ImapMailboxAttributes.NameOf(attribute).ShouldNotBeNullOrWhiteSpace();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Special use.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(FolderSpecialUse.Sent, ImapMailboxAttribute.Sent)]
    [InlineData(FolderSpecialUse.Drafts, ImapMailboxAttribute.Drafts)]
    [InlineData(FolderSpecialUse.Trash, ImapMailboxAttribute.Trash)]
    [InlineData(FolderSpecialUse.Junk, ImapMailboxAttribute.Junk)]
    [InlineData(FolderSpecialUse.Archive, ImapMailboxAttribute.Archive)]
    public void A_role_maps_to_its_RFC_6154_attribute(
        FolderSpecialUse specialUse,
        ImapMailboxAttribute expected) =>
        ImapMailboxAttributes.ForSpecialUse(specialUse).ShouldBe(expected);

    /// <summary>
    /// RFC 6154 §2 defines no \Inbox, because RFC 3501 §5.1 already reserves the name — so a
    /// client needs no attribute to recognise the primary mailbox.
    /// </summary>
    [Theory]
    [InlineData(FolderSpecialUse.Inbox)]
    [InlineData(FolderSpecialUse.None)]
    public void A_role_with_no_attribute_maps_to_none(FolderSpecialUse specialUse) =>
        ImapMailboxAttributes.ForSpecialUse(specialUse).ShouldBe(ImapMailboxAttribute.None);

    /// <summary>
    /// Total over the enum, so adding a folder role cannot silently leave LIST reporting nothing
    /// about it: whoever adds one has to come here and decide.
    /// </summary>
    [Fact]
    public void Every_folder_role_has_an_answer()
    {
        foreach (FolderSpecialUse specialUse in Enum.GetValues<FolderSpecialUse>())
        {
            ImapMailboxAttribute attribute = ImapMailboxAttributes.ForSpecialUse(specialUse);

            if (attribute != ImapMailboxAttribute.None)
            {
                ImapMailboxAttributes.Emittable.ShouldContain(attribute);
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Formatting.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void No_attributes_formats_as_nothing_at_all() =>
        ImapMailboxAttributes.Format(ImapMailboxAttribute.None).ShouldBe(string.Empty);

    [Fact]
    public void One_attribute_formats_as_its_name() =>
        ImapMailboxAttributes.Format(ImapMailboxAttribute.HasNoChildren)
            .ShouldBe(@"\HasNoChildren");

    [Fact]
    public void Several_attributes_are_separated_by_one_space() =>
        ImapMailboxAttributes
            .Format(ImapMailboxAttribute.HasChildren | ImapMailboxAttribute.Sent)
            .ShouldBe(@"\HasChildren \Sent");

    /// <summary>
    /// Structural before special-use, whatever order the flags were combined in — see
    /// <see cref="ImapMailboxAttributes.Emittable"/> on why the output is ordered at all.
    /// </summary>
    [Fact]
    public void The_order_is_the_emittable_order_and_not_the_callers()
    {
        ImapMailboxAttribute combined =
            ImapMailboxAttribute.Archive | ImapMailboxAttribute.NoSelect;

        ImapMailboxAttributes.Format(combined).ShouldBe(@"\Noselect \Archive");
    }

    /// <summary>
    /// The filtering is what makes <see cref="ImapMailboxAttributes.Emittable"/> a guarantee
    /// rather than a convention: a caller that asks for \Marked gets silence, not \Marked.
    /// </summary>
    [Theory]
    [InlineData(ImapMailboxAttribute.Marked)]
    [InlineData(ImapMailboxAttribute.Unmarked)]
    [InlineData(ImapMailboxAttribute.NoInferiors)]
    public void An_attribute_this_server_withholds_is_dropped_rather_than_formatted(
        ImapMailboxAttribute attribute) =>
        ImapMailboxAttributes.Format(attribute).ShouldBe(string.Empty);

    [Fact]
    public void A_withheld_attribute_does_not_disturb_the_ones_beside_it() =>
        ImapMailboxAttributes
            .Format(
                ImapMailboxAttribute.Marked |
                ImapMailboxAttribute.HasChildren |
                ImapMailboxAttribute.NoInferiors)
            .ShouldBe(@"\HasChildren");

    /// <summary>
    /// RFC 3501 §9's mbx-list-flags is a space-separated run of flags, so a double space or a
    /// leading one would put an empty flag on the wire.
    /// </summary>
    [Fact]
    public void Formatting_never_produces_an_empty_flag()
    {
        ImapMailboxAttribute everything = ImapMailboxAttribute.None;

        foreach (ImapMailboxAttribute attribute in Enum.GetValues<ImapMailboxAttribute>())
        {
            everything |= attribute;
        }

        string formatted = ImapMailboxAttributes.Format(everything);

        formatted.ShouldNotContain("  ");
        formatted.ShouldNotStartWith(" ");
        formatted.ShouldNotEndWith(" ");
        formatted.Split(' ').Length.ShouldBe(ImapMailboxAttributes.Emittable.Count);
    }
    /// <summary>
    /// RFC 3501 §9: mbx-list-sflag = "\Noselect" / "\Marked" / "\Unmarked", annotated
    /// "; Selectability flags; only one per LIST response". Two of the three are never emitted,
    /// so no combination a caller can build puts two on the wire — asserted over every
    /// combination rather than argued for.
    /// </summary>
    [Fact]
    public void No_combination_can_put_two_selectability_flags_on_the_wire()
    {
        string[] selectability = [@"\Noselect", @"\Marked", @"\Unmarked"];

        int all = 0;

        foreach (ImapMailboxAttribute attribute in Enum.GetValues<ImapMailboxAttribute>())
        {
            all |= (int)attribute;
        }

        for (int combination = 0; combination <= all; combination++)
        {
            string formatted = ImapMailboxAttributes.Format((ImapMailboxAttribute)combination);

            string[] names = formatted.Length == 0 ? [] : formatted.Split(' ');

            names.Count(selectability.Contains).ShouldBeLessThanOrEqualTo(
                1,
                $"combination {combination} formatted as [{formatted}]");
        }
    }

    /// <summary>
    /// RFC 3348 §3: "It is an error for the server to return both a \HasChildren and a
    /// \HasNoChildren attribute in a LIST response." A folder listing chooses between them, so
    /// the error is not reachable from the one place attributes are derived.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_listing_never_claims_both_child_attributes(bool hasChildren)
    {
        ImapFolderListing listing = new(
            "Projects",
            FolderSpecialUse.None,
            IsSubscribed: true,
            hasChildren);

        string formatted = ImapMailboxAttributes.Format(listing.Attributes);

        formatted.ShouldContain(hasChildren ? @"\HasChildren" : @"\HasNoChildren");
        formatted.ShouldNotContain(hasChildren ? @"\HasNoChildren" : @"\HasChildren");
    }

    /// <summary>
    /// RFC 3348 §3: "It is an error for the server to return both a \HasChildren and a
    /// \NoInferiors attribute in a LIST response." \Noinferiors is never emitted, so this one is
    /// unreachable too — but for the other reason, and both are worth pinning.
    /// </summary>
    [Fact]
    public void A_folder_with_children_never_also_claims_noinferiors() =>
        ImapMailboxAttributes
            .Format(ImapMailboxAttribute.HasChildren | ImapMailboxAttribute.NoInferiors)
            .ShouldBe(@"\HasChildren");
}
