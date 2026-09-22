using System.Text;
using MailServer.Domain.Filtering;
using MailServer.Domain.Imap;
using MailServer.Infrastructure.Filtering;

namespace MailServer.Filtering.Tests;

/// <summary>
/// The decoder is what stands between the attachment policy and a one-line bypass: a sender
/// who writes the name in any encoding a client honours must not get an executable past a
/// check that only understood the plain form.
/// </summary>
public sealed class MimeFileNameTests
{
    private static string? Read(string parameterLine)
    {
        // "FILENAME" "x" "FILENAME*0*" "y" -> the flat list ImapBodyPart carries.
        string[] parts = parameterLine.Split('\u0001');

        return MimeFileName.Read(parts, "FILENAME");
    }

    private static string Params(params string[] nameThenValue) => string.Join('\u0001', nameThenValue);

    [Fact]
    public void Reads_a_plain_parameter() =>
        Read(Params("FILENAME", "report.pdf")).ShouldBe("report.pdf");

    [Fact]
    public void Returns_null_when_the_parameter_is_absent() =>
        Read(Params("CHARSET", "utf-8")).ShouldBeNull();

    /// <summary>
    /// RFC 2231 §4. The form a client saves as <c>payload.exe</c> and a naive check reads as
    /// an unrecognised parameter.
    /// </summary>
    [Fact]
    public void Decodes_an_RFC_2231_extended_parameter() =>
        Read(Params("FILENAME*", "utf-8''payload%2Eexe")).ShouldBe("payload.exe");

    [Fact]
    public void Decodes_an_extended_parameter_with_no_language() =>
        Read(Params("FILENAME*", "UTF-8''%73%65%74%75%70%2E%65%78%65")).ShouldBe("setup.exe");

    /// <summary>A charset this runtime cannot resolve must not discard the name.</summary>
    [Fact]
    public void Falls_back_to_utf8_for_an_unknown_charset() =>
        Read(Params("FILENAME*", "x-nonsense''payload%2Eexe")).ShouldBe("payload.exe");

    /// <summary>A malformed extended parameter is read as written, which is what clients do.</summary>
    [Fact]
    public void Keeps_an_extended_parameter_with_no_charset_prefix() =>
        Read(Params("FILENAME*", "payload.exe")).ShouldBe("payload.exe");

    /// <summary>RFC 2231 §3's continuations, which is how a long name is split.</summary>
    [Fact]
    public void Joins_continuation_sections() =>
        Read(Params("FILENAME*0*", "utf-8''pay", "FILENAME*1*", "load%2Eexe")).ShouldBe("payload.exe");

    /// <summary>
    /// The section number decides the order, not the order the parameters were written in.
    /// A sender who reverses them is not thereby exempt.
    /// </summary>
    [Fact]
    public void Orders_continuations_by_section_number() =>
        Read(Params("FILENAME*1*", "load%2Eexe", "FILENAME*0*", "utf-8''pay")).ShouldBe("payload.exe");

    /// <summary>Each section says for itself whether it is percent-encoded.</summary>
    [Fact]
    public void Handles_a_mix_of_encoded_and_plain_sections() =>
        Read(Params("FILENAME*0*", "utf-8''pay", "FILENAME*1", "load.exe")).ShouldBe("payload.exe");

    /// <summary>
    /// RFC 2047 §5 forbids an encoded-word in a parameter, and senders write them anyway, so
    /// clients honour them. This is the most common way an executable name is disguised.
    /// </summary>
    [Fact]
    public void Decodes_a_base64_encoded_word() =>
        Read(Params("FILENAME", "=?utf-8?B?cGF5bG9hZC5leGU=?=")).ShouldBe("payload.exe");

    [Fact]
    public void Decodes_a_quoted_printable_encoded_word() =>
        Read(Params("FILENAME", "=?utf-8?Q?payload=2Eexe?=")).ShouldBe("payload.exe");

    /// <summary>RFC 2047 §4.2's underscore-for-space.</summary>
    [Fact]
    public void Reads_an_underscore_as_a_space_in_a_Q_word() =>
        Read(Params("FILENAME", "=?utf-8?Q?my_file.exe?=")).ShouldBe("my file.exe");

    [Fact]
    public void Leaves_a_malformed_encoded_word_alone() =>
        Read(Params("FILENAME", "=?utf-8?B?not!valid!base64?=")).ShouldBe("=?utf-8?B?not!valid!base64?=");

    /// <summary>A value that merely contains "=?" in ordinary text survives intact.</summary>
    [Fact]
    public void Does_not_mangle_an_ordinary_name_containing_a_question_mark() =>
        Read(Params("FILENAME", "what=?really.pdf")).ShouldBe("what=?really.pdf");

    /// <summary>
    /// RFC 2231 §4 is preferred over the plain parameter, because that is the order a client
    /// prefers them in. A sender who writes a harmless plain name and a hostile extended one
    /// must be judged on the one the recipient will see.
    /// </summary>
    [Fact]
    public void Prefers_the_extended_form_over_the_plain_one() =>
        Read(Params("FILENAME", "invoice.pdf", "FILENAME*", "utf-8''payload%2Eexe"))
            .ShouldBe("payload.exe");

    [Fact]
    public void Prefers_continuations_over_both() =>
        Read(Params(
            "FILENAME", "invoice.pdf",
            "FILENAME*", "utf-8''decoy%2Etxt",
            "FILENAME*0*", "utf-8''pay",
            "FILENAME*1*", "load%2Eexe"))
            .ShouldBe("payload.exe");

    /// <summary>A name a stranger made enormous is clamped before it reaches a finding or a row.</summary>
    [Fact]
    public void Clamps_an_enormous_name() =>
        Read(Params("FILENAME", new string('a', 100_000)))!.Length.ShouldBe(MimeFileName.MaxLength);

    /// <summary>Parameter names are case-insensitive per RFC 2045 §5.1.</summary>
    [Fact]
    public void Matches_a_parameter_name_case_insensitively() =>
        MimeFileName.Read(["filename", "report.pdf"], "FILENAME").ShouldBe("report.pdf");

    /// <summary>An odd-length list is malformed and must not throw on the delivery path.</summary>
    [Fact]
    public void Survives_a_truncated_parameter_list() =>
        MimeFileName.Read(["FILENAME"], "FILENAME").ShouldBeNull();
}

public sealed class MimePartDescriptionTests
{
    private static ImapBodyPart Parse(string message) =>
        ImapMimeTree.Parse(Encoding.ASCII.GetBytes(message.ReplaceLineEndings("\r\n")));

    private const string Executable = """
        From: a@example.com
        Content-Type: multipart/mixed; boundary="b"

        --b
        Content-Type: text/plain

        Hello.
        --b
        Content-Type: application/octet-stream; name="setup.exe"
        Content-Disposition: attachment; filename="setup.exe"
        Content-Transfer-Encoding: base64

        AAAA
        --b--

        """;

    [Fact]
    public void Describes_an_attached_part()
    {
        ImapBodyPart root = Parse(Executable);
        ImapBodyPart attachment = root.Children[1];

        MimeFileName.IsAttachment(attachment).ShouldBeTrue();

        AttachmentDescriptor descriptor = MimeFileName.Describe(attachment);
        descriptor.FileName.ShouldBe("setup.exe");
        descriptor.MediaType.ShouldBe("application/octet-stream");
    }

    [Fact]
    public void Does_not_treat_the_readable_body_as_an_attachment() =>
        MimeFileName.IsAttachment(Parse(Executable).Children[0]).ShouldBeFalse();

    [Fact]
    public void Does_not_treat_a_multipart_container_as_an_attachment() =>
        MimeFileName.IsAttachment(Parse(Executable)).ShouldBeFalse();

    /// <summary>
    /// A sender who marks an executable inline has not made it safe, and several clients save
    /// an inline named part exactly as they would an attached one.
    /// </summary>
    [Fact]
    public void Treats_a_named_inline_part_as_an_attachment()
    {
        ImapBodyPart root = Parse("""
            From: a@example.com
            Content-Type: multipart/mixed; boundary="b"

            --b
            Content-Type: application/octet-stream; name="setup.exe"
            Content-Disposition: inline

            AAAA
            --b--

            """);

        MimeFileName.IsAttachment(root.Children[0]).ShouldBeTrue();
        MimeFileName.Describe(root.Children[0]).FileName.ShouldBe("setup.exe");
    }

    /// <summary>A part declaring attachment without a name is still an attachment.</summary>
    [Fact]
    public void Treats_an_unnamed_attachment_as_one()
    {
        ImapBodyPart root = Parse("""
            From: a@example.com
            Content-Type: multipart/mixed; boundary="b"

            --b
            Content-Type: application/octet-stream
            Content-Disposition: attachment

            AAAA
            --b--

            """);

        MimeFileName.IsAttachment(root.Children[0]).ShouldBeTrue();
        MimeFileName.Describe(root.Children[0]).FileName.ShouldBeNull();
    }
}
