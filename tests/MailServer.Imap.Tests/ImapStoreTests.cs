using MailServer.Domain.Enums;
using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapStoreTests
{
    private static ImapStoreRequest Parse(string text)
    {
        ImapStore.TryParse(text, out ImapStoreRequest? request)
            .ShouldBeTrue($"could not parse [{text}]");

        return request!;
    }

    // ---------------------------------------------------------------------------------------
    // The data item name.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3501 §9: store-att-flags = (["+" / "-"] "FLAGS" [".SILENT"]) SP … — the sign is the
    /// whole of the distinction, and its absence is a third case rather than a default.
    /// </summary>
    [Theory]
    [InlineData(@"FLAGS (\Seen)", ImapStoreMode.Replace)]
    [InlineData(@"+FLAGS (\Seen)", ImapStoreMode.Add)]
    [InlineData(@"-FLAGS (\Seen)", ImapStoreMode.Remove)]
    public void The_sign_decides_the_operation(string text, ImapStoreMode expected) =>
        Parse(text).Mode.ShouldBe(expected);

    [Theory]
    [InlineData(@"FLAGS (\Seen)", false)]
    [InlineData(@"FLAGS.SILENT (\Seen)", true)]
    [InlineData(@"+FLAGS.SILENT (\Seen)", true)]
    [InlineData(@"-FLAGS.SILENT (\Seen)", true)]
    public void The_silent_suffix_is_recognised(string text, bool expected) =>
        Parse(text).Silent.ShouldBe(expected);

    /// <summary>RFC 3501 §9 note (1): every token is matched case-insensitively.</summary>
    [Theory]
    [InlineData(@"flags (\Seen)")]
    [InlineData(@"FlAgS (\Seen)")]
    [InlineData(@"+flags.silent (\Seen)")]
    public void The_item_name_is_recognised_in_any_case(string text) =>
        Parse(text).Flags.ShouldBe(MessageFlags.Seen);

    /// <summary>FLAGS is the only data item §6.4.6 defines for STORE.</summary>
    [Theory]
    [InlineData(@"NONSENSE (\Seen)")]
    [InlineData(@"FLAG (\Seen)")]
    [InlineData(@"FLAGSS (\Seen)")]
    [InlineData(@"FLAGS.LOUD (\Seen)")]
    [InlineData(@"++FLAGS (\Seen)")]
    [InlineData(@"FLAGS")]
    [InlineData("")]
    public void A_data_item_the_grammar_does_not_have_is_refused(string text) =>
        ImapStore.TryParse(text, out _).ShouldBeFalse();

    // ---------------------------------------------------------------------------------------
    // The flag list.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// §9: … SP (flag-list / (flag *(SP flag))). Two alternatives, so a client that omits the
    /// brackets is in the right and a parser that required them would reject it.
    /// </summary>
    [Theory]
    [InlineData(@"+FLAGS (\Deleted)")]
    [InlineData(@"+FLAGS \Deleted")]
    public void The_flag_list_may_arrive_with_or_without_brackets(string text) =>
        Parse(text).Flags.ShouldBe(MessageFlags.Deleted);

    [Theory]
    [InlineData(@"+FLAGS (\Seen \Deleted)")]
    [InlineData(@"+FLAGS \Seen \Deleted")]
    public void Several_flags_combine(string text) =>
        Parse(text).Flags.ShouldBe(MessageFlags.Seen | MessageFlags.Deleted);

    /// <summary>
    /// §9: flag-list = "(" [flag *(SP flag)] ")" — the contents are optional, so STORE 1 FLAGS ()
    /// clears every flag. That is how a client marks a message unread, undeleted and unflagged
    /// in one command.
    /// </summary>
    [Fact]
    public void An_empty_bracketed_list_is_legal_and_means_no_flags()
    {
        ImapStoreRequest request = Parse("FLAGS ()");

        request.Mode.ShouldBe(ImapStoreMode.Replace);
        request.Flags.ShouldBe(MessageFlags.None);
        request.Apply(MessageFlags.Seen | MessageFlags.Deleted).ShouldBe(MessageFlags.None);
    }

    /// <summary>The bare alternative is 'flag *(SP flag)', which has no empty form.</summary>
    [Theory]
    [InlineData("FLAGS ")]
    [InlineData("FLAGS  ")]
    public void A_bare_list_with_no_flags_is_a_syntax_error(string text) =>
        ImapStore.TryParse(text, out _).ShouldBeFalse();

    [Theory]
    [InlineData(@"FLAGS (\Seen")]
    [InlineData(@"FLAGS \Seen)")]
    [InlineData(@"FLAGS ((\Seen))")]
    [InlineData(@"FLAGS (\Seen (\Deleted))")]
    [InlineData(@"FLAGS (\)")]
    [InlineData(@"FLAGS \")]
    public void A_malformed_flag_list_is_refused(string text) =>
        ImapStore.TryParse(text, out _).ShouldBeFalse();

    [Theory]
    [InlineData(@"\seen")]
    [InlineData(@"\SEEN")]
    [InlineData(@"\Seen")]
    public void A_flag_name_is_recognised_in_any_case(string name) =>
        Parse($"+FLAGS ({name})").Flags.ShouldBe(MessageFlags.Seen);

    [Fact]
    public void A_list_longer_than_the_cap_is_refused()
    {
        string tooMany = "+FLAGS (" +
            string.Join(' ', Enumerable.Repeat(@"\Seen", ImapStore.MaxFlagCount + 1)) +
            ")";

        ImapStore.TryParse(tooMany, out _).ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // Flags this server cannot store.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3501 §7.1: "If the client attempts to STORE a flag that is not in the PERMANENTFLAGS
    /// list, the server will either ignore the change or store the state change for the remainder
    /// of the current session only." Ignoring is the sanctioned choice, and refusing would break
    /// clients that send $Junk and $MDNSent without asking.
    /// </summary>
    [Theory]
    [InlineData("$Junk")]
    [InlineData("$MDNSent")]
    [InlineData("$Forwarded")]
    [InlineData(@"\Extension")]
    public void A_flag_this_server_cannot_store_is_dropped_rather_than_refused(string name)
    {
        ImapStoreRequest request = Parse($"+FLAGS ({name})");

        request.Flags.ShouldBe(MessageFlags.None);
        request.HadUnstorableFlags.ShouldBeTrue();
    }

    [Fact]
    public void A_dropped_flag_does_not_disturb_the_storable_ones_beside_it()
    {
        ImapStoreRequest request = Parse(@"+FLAGS (\Seen $Junk \Deleted)");

        request.Flags.ShouldBe(MessageFlags.Seen | MessageFlags.Deleted);
        request.HadUnstorableFlags.ShouldBeTrue();
    }

    [Fact]
    public void A_list_of_storable_flags_reports_nothing_dropped() =>
        Parse(@"+FLAGS (\Seen \Deleted)").HadUnstorableFlags.ShouldBeFalse();

    /// <summary>
    /// A name that is not a flag at all is malformed rather than merely unsupported — §9's
    /// flag-keyword is an atom and flag-extension is a backslash and an atom, and the difference
    /// decides BAD against a silent drop.
    /// </summary>
    [Theory]
    [InlineData(@"FLAGS (Junk*)")]
    [InlineData(@"FLAGS (a""b)")]
    [InlineData(@"FLAGS (a]b)")]
    public void A_name_that_is_not_a_flag_at_all_is_a_syntax_error(string text) =>
        ImapStore.TryParse(text, out _).ShouldBeFalse();

    // ---------------------------------------------------------------------------------------
    // Applying it.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Replace_takes_the_argument_wholesale() =>
        Parse(@"FLAGS (\Seen)")
            .Apply(MessageFlags.Deleted | MessageFlags.Draft)
            .ShouldBe(MessageFlags.Seen);

    [Fact]
    public void Add_leaves_what_was_already_there() =>
        Parse(@"+FLAGS (\Seen)")
            .Apply(MessageFlags.Deleted)
            .ShouldBe(MessageFlags.Seen | MessageFlags.Deleted);

    [Fact]
    public void Remove_takes_away_only_what_it_names() =>
        Parse(@"-FLAGS (\Seen)")
            .Apply(MessageFlags.Seen | MessageFlags.Deleted)
            .ShouldBe(MessageFlags.Deleted);

    [Fact]
    public void Adding_a_flag_already_set_changes_nothing() =>
        Parse(@"+FLAGS (\Seen)").Apply(MessageFlags.Seen).ShouldBe(MessageFlags.Seen);

    [Fact]
    public void Removing_a_flag_that_is_not_set_changes_nothing() =>
        Parse(@"-FLAGS (\Seen)").Apply(MessageFlags.Deleted).ShouldBe(MessageFlags.Deleted);

    /// <summary>
    /// §6.4.6 puts the exception in the sentence: "Replace the flags for the message (other than
    /// \Recent) with the argument." A replace that cleared it would alter a flag §2.3.2 says
    /// "can not be altered by the client", through a command that never mentions it.
    /// </summary>
    [Fact]
    public void Replace_preserves_recent()
    {
        MessageFlags before = MessageFlags.Recent | MessageFlags.Deleted;

        Parse(@"FLAGS (\Seen)")
            .Apply(before)
            .ShouldBe(MessageFlags.Recent | MessageFlags.Seen);
    }

    [Fact]
    public void Clearing_every_flag_still_preserves_recent() =>
        Parse("FLAGS ()")
            .Apply(MessageFlags.Recent | MessageFlags.Seen)
            .ShouldBe(MessageFlags.Recent);

    /// <summary>
    /// §9 annotates its flag production "; Does not include \Recent", so a client cannot even
    /// name it — and naming it anyway reaches the same place, because no mode can set or clear it.
    /// </summary>
    [Theory]
    [InlineData(@"+FLAGS (\Recent)")]
    [InlineData(@"-FLAGS (\Recent)")]
    [InlineData(@"FLAGS (\Recent)")]
    public void No_mode_lets_a_client_touch_recent(string text)
    {
        ImapStoreRequest request = Parse(text);

        request.Flags.HasFlag(MessageFlags.Recent).ShouldBeFalse();
        request.Apply(MessageFlags.Recent).HasFlag(MessageFlags.Recent).ShouldBeTrue();
        request.Apply(MessageFlags.None).HasFlag(MessageFlags.Recent).ShouldBeFalse();
    }

    /// <summary>
    /// Whatever a client names, the result never contains a bit outside what this server stores
    /// plus the one flag it maintains itself.
    /// </summary>
    [Theory]
    [InlineData(@"FLAGS (\Seen \Answered \Flagged \Deleted \Draft)")]
    [InlineData(@"+FLAGS (\Seen $Junk \Recent)")]
    [InlineData("FLAGS ()")]
    public void The_result_never_carries_a_bit_this_server_does_not_keep(string text)
    {
        MessageFlags result = Parse(text).Apply(MessageFlags.Recent | MessageFlags.Answered);

        (result & ~(ImapFlagNames.Settable | MessageFlags.Recent)).ShouldBe(MessageFlags.None);
    }
}
