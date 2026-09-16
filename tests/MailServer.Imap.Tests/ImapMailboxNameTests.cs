using MailServer.Domain.Imap;

namespace MailServer.Imap.Tests;

public sealed class ImapMailboxNameTests
{
    // ---------------------------------------------------------------------------------------
    // Plain ASCII needs no encoding at all.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("INBOX")]
    [InlineData("Sent Items")]
    [InlineData("Invoices 2026.Q1")]
    [InlineData("")]
    public void Ascii_names_are_unchanged_by_encoding(string name)
    {
        ImapMailboxName.Encode(name).ShouldBe(name);
    }

    [Theory]
    [InlineData("INBOX")]
    [InlineData("Sent Items")]
    [InlineData("")]
    public void Ascii_wire_text_decodes_unchanged(string name)
    {
        ImapMailboxName.TryDecode(name, out string? decoded).ShouldBeTrue();
        decoded.ShouldBe(name);
    }

    // ---------------------------------------------------------------------------------------
    // The ampersand escape.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_literal_ampersand_encodes_as_ampersand_hyphen()
    {
        ImapMailboxName.Encode("Q&A").ShouldBe("Q&-A");
    }

    [Fact]
    public void Ampersand_hyphen_decodes_to_a_literal_ampersand()
    {
        ImapMailboxName.TryDecode("Q&-A", out string? decoded).ShouldBeTrue();
        decoded.ShouldBe("Q&A");
    }

    // ---------------------------------------------------------------------------------------
    // A hand-verified vector: U+263A (☺, WHITE SMILING FACE) is the canonical modified-UTF-7
    // worked example (its UTF-16BE bytes 0x26 0x3A base64-encode, in the modified alphabet, to
    // exactly "Jjo").
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Encodes_the_canonical_smiling_face_example()
    {
        ImapMailboxName.Encode("☺").ShouldBe("&Jjo-");
    }

    [Fact]
    public void Decodes_the_canonical_smiling_face_example()
    {
        ImapMailboxName.TryDecode("&Jjo-", out string? decoded).ShouldBeTrue();
        decoded.ShouldBe("☺");
    }

    [Fact]
    public void The_smiling_face_round_trips_inside_surrounding_ascii()
    {
        string mailbox = "Fun ☺ Folder";

        string encoded = ImapMailboxName.Encode(mailbox);
        encoded.ShouldBe("Fun &Jjo- Folder");

        ImapMailboxName.TryDecode(encoded, out string? decoded).ShouldBeTrue();
        decoded.ShouldBe(mailbox);
    }

    // ---------------------------------------------------------------------------------------
    // Round-tripping, including surrogate pairs and runs of several non-ASCII characters.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("日本語")]
    [InlineData("台北")]
    [InlineData("Héllo Wörld")]
    [InlineData("😀")] // outside the BMP: a UTF-16 surrogate pair.
    [InlineData("a😀b日c")]
    [InlineData("&")]
    [InlineData("&&&")]
    [InlineData("a&b&c")]
    public void Encoding_then_decoding_returns_the_original_name(string mailbox)
    {
        string encoded = ImapMailboxName.Encode(mailbox);

        ImapMailboxName.TryDecode(encoded, out string? decoded).ShouldBeTrue();
        decoded.ShouldBe(mailbox);
    }

    [Fact]
    public void An_encoded_non_ascii_run_uses_only_wire_safe_characters()
    {
        string encoded = ImapMailboxName.Encode("日本語");

        foreach (char c in encoded)
        {
            (c is >= (char)0x20 and <= (char)0x7E).ShouldBeTrue($"'{c}' is outside printable ASCII");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Malformed wire text is refused, not guessed at.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void An_invalid_character_in_a_shift_sequence_is_refused()
    {
        // '_' is not in the modified base64 alphabet.
        ImapMailboxName.TryDecode("&Jj_-", out string? decoded).ShouldBeFalse();
        decoded.ShouldBeNull();
    }

    [Fact]
    public void Non_zero_leftover_padding_bits_are_refused()
    {
        // "Jjo" (see above) decodes cleanly to one code unit with zero leftover bits. Appending
        // one more base64 character forces two leftover bits that a correct encoder would never
        // have set to anything but zero.
        ImapMailboxName.TryDecode("&JjoB-", out string? decoded).ShouldBeFalse();
        decoded.ShouldBeNull();
    }

    [Fact]
    public void A_raw_control_character_outside_any_shift_sequence_is_refused()
    {
        ImapMailboxName.TryDecode("a\tb", out string? decoded).ShouldBeFalse();
        decoded.ShouldBeNull();
    }

    [Fact]
    public void An_unterminated_shift_at_end_of_string_is_still_accepted()
    {
        // Some encoders omit the closing '-' when nothing ambiguous follows; RFC 3501 itself
        // does not require this product to reject that, only to decode it correctly.
        ImapMailboxName.TryDecode("&Jjo", out string? decoded).ShouldBeTrue();
        decoded.ShouldBe("☺");
    }
}
