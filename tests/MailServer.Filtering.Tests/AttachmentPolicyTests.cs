using MailServer.Domain.Filtering;

namespace MailServer.Filtering.Tests;

public sealed class AttachmentExtensionTests
{
    [Theory]
    [InlineData("report.pdf", "pdf")]
    [InlineData("REPORT.PDF", "pdf")]
    [InlineData("archive.tar.gz", "gz")]
    [InlineData("invoice.pdf.exe", "exe")]
    [InlineData("noextension", null)]
    [InlineData("trailingdot.", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Reads_the_last_extension(string? name, string? expected) =>
        AttachmentPolicy.ExtensionOf(name).ShouldBe(expected);

    /// <summary>
    /// Win32 discards trailing dots and spaces when opening a file, so these all name the same
    /// file to the recipient's desktop. A check that read them literally would let the whole
    /// blocked list through by appending one character.
    /// </summary>
    [Theory]
    [InlineData("payload.exe.")]
    [InlineData("payload.exe ")]
    [InlineData("payload.exe...   ")]
    [InlineData("payload.exe\t")]
    public void Strips_what_Windows_strips(string name) =>
        AttachmentPolicy.ExtensionOf(name).ShouldBe("exe");

    /// <summary>A name is only ever a name here — nothing opens it — but it must not confuse the check.</summary>
    [Theory]
    [InlineData("..\\..\\windows\\system32\\evil.exe", "exe")]
    [InlineData("/etc/passwd.txt", "txt")]
    [InlineData("C:evil.exe", "exe")]
    public void Ignores_any_path_syntax_in_the_name(string name, string expected) =>
        AttachmentPolicy.ExtensionOf(name).ShouldBe(expected);

    /// <summary>
    /// A very long tail after a dot is part of a name, not an extension. Treating it as one
    /// would put an unbounded stranger-chosen string into a set lookup on the delivery path.
    /// </summary>
    [Fact]
    public void Does_not_treat_a_long_tail_as_an_extension() =>
        AttachmentPolicy.ExtensionOf("file." + new string('a', 40)).ShouldBeNull();
}

public sealed class AttachmentPolicyTests
{
    private static AttachmentDescriptor File(string? name, string type = "application/octet-stream") =>
        new(name, type, 1024);

    [Fact]
    public void Passes_ordinary_attachments()
    {
        IReadOnlyList<AttachmentFinding> findings = AttachmentPolicy.Default.Inspect(
            [File("report.pdf", "application/pdf"), File("photo.jpg", "image/jpeg")]);

        findings.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("setup.exe")]
    [InlineData("script.vbs")]
    [InlineData("shortcut.lnk")]
    [InlineData("macro.docm")]
    [InlineData("applet.jar")]
    public void Blocks_what_a_desktop_would_run(string name)
    {
        IReadOnlyList<AttachmentFinding> findings = AttachmentPolicy.Default.Inspect([File(name)]);

        findings.ShouldHaveSingleItem().FileName.ShouldBe(name);
    }

    /// <summary>
    /// The sender chooses both the name and the declared type, so a reassuring type on an
    /// executable name is a claim by the party that chose the payload.
    /// </summary>
    [Fact]
    public void Does_not_believe_a_reassuring_media_type()
    {
        IReadOnlyList<AttachmentFinding> findings = AttachmentPolicy.Default.Inspect(
            [File("invoice.exe", "text/plain")]);

        findings.ShouldHaveSingleItem();
    }

    /// <summary>
    /// The double-extension trick works on a recipient whose desktop hides known extensions.
    /// The last extension is the one that runs, and the one this reads.
    /// </summary>
    [Fact]
    public void Blocks_a_double_extension()
    {
        AttachmentPolicy.Default.Inspect([File("statement.pdf.scr")]).ShouldHaveSingleItem();
    }

    /// <summary>
    /// A right-to-left override makes a name display as a different type in every client that
    /// honours bidirectional text. There is no legitimate use of it in a filename.
    /// </summary>
    [Fact]
    public void Blocks_a_name_that_displays_backwards()
    {
        string deceptive = "CV" + AttachmentPolicy.RightToLeftOverride + "fdp.exe";

        AttachmentFinding finding = AttachmentPolicy.Default
            .Inspect([File(deceptive)])
            .ShouldHaveSingleItem();

        finding.Reason.ShouldContain("right-to-left override");
    }

    /// <summary>
    /// And the reported name must not carry the character through into whatever renders the
    /// finding — an operator reading the quarantine list would see the same deception.
    /// </summary>
    [Fact]
    public void Does_not_pass_the_override_character_on_to_the_reader()
    {
        string deceptive = "CV" + AttachmentPolicy.RightToLeftOverride + "fdp.exe";

        AttachmentFinding finding = AttachmentPolicy.Default
            .Inspect([File(deceptive)])
            .ShouldHaveSingleItem();

        finding.FileName.ShouldNotContain(AttachmentPolicy.RightToLeftOverride.ToString());
    }

    [Fact]
    public void Leaves_an_unnamed_part_alone()
    {
        AttachmentPolicy.Default.Inspect([File(null, "text/plain")]).ShouldBeEmpty();
    }

    /// <summary>
    /// Archives are not blocked by name: doing so breaks ordinary business mail, and looking
    /// inside one is a scanner's job.
    /// </summary>
    [Theory]
    [InlineData("files.zip")]
    [InlineData("backup.7z")]
    [InlineData("source.tar.gz")]
    public void Does_not_block_archives(string name) =>
        AttachmentPolicy.Default.Inspect([File(name)]).ShouldBeEmpty();

    /// <summary>
    /// The bound on how many parts are examined is a resource limit, and reaching it is itself
    /// reported — a message must not be able to hide a blocked part by burying it under
    /// thousands of harmless ones without anybody being told.
    /// </summary>
    [Fact]
    public void Reports_that_it_stopped_examining()
    {
        AttachmentPolicy policy = new() { MaxAttachmentsExamined = 3 };

        IReadOnlyList<AttachmentFinding> findings = policy.Inspect(
            [.. Enumerable.Range(0, 50).Select(i => File($"part{i}.txt"))]);

        findings.ShouldHaveSingleItem().Reason.ShouldContain("only the first 3");
    }

    [Fact]
    public void Still_reports_what_it_found_before_the_bound()
    {
        AttachmentPolicy policy = new() { MaxAttachmentsExamined = 2 };

        IReadOnlyList<AttachmentFinding> findings = policy.Inspect(
            [File("a.exe"), File("b.txt"), File("c.txt")]);

        findings.Count.ShouldBe(2);
        findings[0].FileName.ShouldBe("a.exe");
        findings[1].FileName.ShouldBe("(the rest)");
    }

    [Fact]
    public void An_operator_can_replace_the_blocked_set()
    {
        AttachmentPolicy policy = new() { BlockedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "pdf" } };

        policy.Inspect([File("report.pdf")]).ShouldHaveSingleItem();
        policy.Inspect([File("setup.exe")]).ShouldBeEmpty();
    }
}
