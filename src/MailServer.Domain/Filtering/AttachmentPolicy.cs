namespace MailServer.Domain.Filtering;

/// <summary>One attachment, as the message described it.</summary>
/// <param name="FileName">
/// The name the message gave, already decoded from whatever RFC 2047 or RFC 2231 encoding it
/// arrived in. Null when the part named itself nothing.
/// </param>
/// <param name="MediaType">The declared type, lower-cased, as <c>type/subtype</c>.</param>
/// <param name="SizeBytes">The encoded size of the part, for reporting rather than for policy.</param>
public sealed record AttachmentDescriptor(string? FileName, string MediaType, long SizeBytes);

/// <summary>Why one attachment was refused.</summary>
/// <param name="FileName">The name as given, or <c>(unnamed)</c>.</param>
/// <param name="Reason">What the policy objected to.</param>
public sealed record AttachmentFinding(string FileName, string Reason);

/// <summary>
/// Decides whether a message's attachments are allowed through.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the cheapest real protection in the product, and it is not a malware scanner.</b>
/// It knows nothing about what is inside a file. What it knows is that a Windows desktop will
/// execute some of these on a double-click, and that no correspondent has a legitimate reason
/// to send one — which catches the entire category regardless of what the payload is or whether
/// any scanner has seen it before.
/// </para>
/// <para>
/// <b>The filename decides, never the declared type.</b> A sender picks both, so
/// <c>Content-Type: text/plain</c> on <c>invoice.exe</c> is a claim by the same party that
/// chose the payload. The type is consulted only when there is no name at all.
/// </para>
/// <para>
/// <b>Blocking is a floor, not a score.</b> A blocked attachment quarantines the message
/// outright rather than adding weight, because "this could run on the recipient's machine" is
/// not the kind of conclusion that should be tunable against a threshold.
/// </para>
/// </remarks>
public sealed class AttachmentPolicy
{
    /// <summary>
    /// Extensions a Windows desktop may execute, and which no ordinary correspondence carries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately not exhaustive — an exhaustive list is impossible, and pretending otherwise
    /// is how an operator ends up believing a name check is a malware defence. This is the set
    /// with the worst ratio of "runs on a double-click" to "somebody might legitimately send
    /// it".
    /// </para>
    /// <para>
    /// <c>.zip</c> is <b>not</b> here. Blocking archives outright breaks ordinary business mail,
    /// and looking inside one is a scanner's job — a name check that unpacked archives would be
    /// a decompression-bomb target for no gain.
    /// </para>
    /// </remarks>
    public static IReadOnlySet<string> DefaultBlockedExtensions { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // Native executables and installers.
        "exe", "com", "scr", "pif", "msi", "msp", "cpl", "dll", "drv", "sys", "ocx",
        // Shell and batch.
        "bat", "cmd", "ps1", "ps1xml", "psc1", "psm1", "sh",
        // Script hosts.
        "vb", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ws", "hta", "jar",
        // Things that run something else.
        "lnk", "scf", "url", "inf", "reg", "chm", "application", "gadget", "msc",
        // Office macro formats. The non-macro forms of the same documents are not here.
        "docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam",
    };

    /// <summary>The character that makes a filename read backwards.</summary>
    /// <remarks>
    /// U+202E RIGHT-TO-LEFT OVERRIDE. A name of <c>CV</c>, that character, then <c>fdp.exe</c>
    /// renders as <c>CVexe.pdf</c> in every mail client that honours bidirectional text,
    /// which is all of them. There is no legitimate use of it in an attachment name, so its
    /// presence is the finding — the name does not even need to end in anything blocked.
    /// </remarks>
    public const char RightToLeftOverride = '\u202E';

    /// <summary>The default policy.</summary>
    public static AttachmentPolicy Default { get; } = new();

    /// <summary>The extensions refused, without leading dots.</summary>
    public IReadOnlySet<string> BlockedExtensions { get; init; } = DefaultBlockedExtensions;

    /// <summary>
    /// The most attachments this will examine on one message.
    /// </summary>
    /// <remarks>
    /// A message with ten thousand one-byte parts is a stranger's choice about how much work
    /// this server does per message. Reaching the bound is itself a finding, so a message
    /// cannot smuggle a blocked part past the check by burying it under the limit.
    /// </remarks>
    public int MaxAttachmentsExamined { get; init; } = 200;

    /// <summary>Whether any attachment breaks the policy.</summary>
    public IReadOnlyList<AttachmentFinding> Inspect(IReadOnlyList<AttachmentDescriptor> attachments)
    {
        ArgumentNullException.ThrowIfNull(attachments);

        List<AttachmentFinding> findings = [];

        int examined = Math.Min(attachments.Count, MaxAttachmentsExamined);

        for (int i = 0; i < examined; i++)
        {
            AttachmentDescriptor attachment = attachments[i];
            string display = attachment.FileName is { Length: > 0 } n ? n : "(unnamed)";

            if (attachment.FileName is not null &&
                attachment.FileName.Contains(RightToLeftOverride, StringComparison.Ordinal))
            {
                findings.Add(new AttachmentFinding(
                    display.Replace(RightToLeftOverride, '�'),
                    "the name contains a right-to-left override, which makes it display as a different type"));

                continue;
            }

            string? extension = ExtensionOf(attachment.FileName);

            if (extension is not null && BlockedExtensions.Contains(extension))
            {
                findings.Add(new AttachmentFinding(display, $".{extension} can be executed by the recipient"));
            }
        }

        if (attachments.Count > MaxAttachmentsExamined)
        {
            // Said out loud rather than silently ignored: the parts beyond the bound were not
            // looked at, and a message that arranged to have that many is the reason to say so.
            findings.Add(new AttachmentFinding(
                "(the rest)",
                $"the message has {attachments.Count} attachments; only the first {MaxAttachmentsExamined} were examined"));
        }

        return findings;
    }

    /// <summary>
    /// The effective extension of a name a stranger chose.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Trailing dots and spaces are stripped first.</b> Win32 removes them when opening a
    /// file, so <c>payload.exe. </c> and <c>payload.exe</c> are the same file to the recipient's
    /// desktop and must be the same file to this check.
    /// </para>
    /// <para>
    /// <b>Any path syntax is discarded.</b> A name is a name; <c>..\\..\\evil.exe</c> has an
    /// extension of <c>exe</c> and is not a route anywhere, because nothing here ever opens it.
    /// </para>
    /// </remarks>
    public static string? ExtensionOf(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return null;
        }

        ReadOnlySpan<char> name = fileName.AsSpan();

        int lastSeparator = name.LastIndexOfAny('/', '\\', ':');

        if (lastSeparator >= 0)
        {
            name = name[(lastSeparator + 1)..];
        }

        name = name.TrimEnd([' ', '.', '\t', ' ']);

        int dot = name.LastIndexOf('.');

        if (dot < 0 || dot == name.Length - 1)
        {
            return null;
        }

        ReadOnlySpan<char> extension = name[(dot + 1)..];

        // A "extension" longer than any real one is not one: it is the tail of a name with a dot
        // in it. Treating it as an extension would not match anything blocked anyway, but it
        // would put an arbitrary-length stranger-chosen string into a comparison per message.
        return extension.Length is > 0 and <= 16 ? extension.ToString().ToLowerInvariant() : null;
    }
}

