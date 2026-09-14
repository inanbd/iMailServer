using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// An IMAP folder within a mailbox.
/// </summary>
/// <remarks>
/// <para>
/// Milestone 5 creates and names folders; the message storage, UID allocation and flag
/// machinery they exist to hold arrive with IMAP in Milestone 10. The folder rows are created
/// now because a mailbox needs its standard set from the moment it exists — a client that
/// connects and finds no Sent folder will make one, and will make it with whatever name its
/// locale suggests.
/// </para>
/// <para>
/// <b>UidValidity is assigned once and never changes.</b> It is the promise to a client that
/// the UIDs it cached are still the same messages. Changing it forces every client to discard
/// its local state and resynchronise the whole folder; changing it <i>accidentally</i> — by
/// regenerating it on a restart, say — does that silently and repeatedly, which reads to a user
/// as a mail client that keeps re-downloading everything.
/// </para>
/// </remarks>
public sealed class MailboxFolder : Entity<MailboxFolderId>
{
    /// <summary>The IMAP path separator this server uses.</summary>
    /// <remarks>
    /// A forward slash rather than a dot. A dot is common in older servers and collides badly
    /// with folder names containing one, which users create constantly ("Invoices 2026.Q1").
    /// </remarks>
    public const char PathSeparator = '/';

    /// <summary>Maximum depth of nesting.</summary>
    /// <remarks>
    /// A bound rather than a design target. Clients handle deep hierarchies poorly and a path
    /// has to fit in protocol responses; twenty is far past any sane structure.
    /// </remarks>
    public const int MaxDepth = 20;

    /// <summary>Maximum length of a full folder path, in characters.</summary>
    public const int MaxPathLength = 512;

    /// <summary>Rehydration constructor for the persistence layer.</summary>
    public MailboxFolder(
        MailboxFolderId id,
        MailboxId mailboxId,
        string path,
        FolderSpecialUse specialUse,
        long uidValidity,
        long nextUid,
        bool isSubscribed,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(path);

        MailboxId = mailboxId;
        Path = path;
        SpecialUse = specialUse;
        UidValidity = uidValidity;
        NextUid = nextUid;
        IsSubscribed = isSubscribed;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
    }

    public MailboxId MailboxId { get; }

    /// <summary>Full path, separated by <see cref="PathSeparator"/>.</summary>
    public string Path { get; private set; }

    /// <summary>The leaf name, which is what a user sees.</summary>
    public string Name => Path[(Path.LastIndexOf(PathSeparator) + 1)..];

    /// <summary>The RFC 6154 attribute advertised for this folder.</summary>
    public FolderSpecialUse SpecialUse { get; private set; }

    /// <summary>
    /// The UIDVALIDITY value. Assigned at creation and never changed.
    /// </summary>
    /// <remarks>
    /// No setter of any kind, deliberately. See the class remarks: a changed UIDVALIDITY is a
    /// client-visible event, and one that changes by accident is a client that resynchronises
    /// forever.
    /// </remarks>
    public long UidValidity { get; }

    /// <summary>The next UID to assign. Strictly increasing within a folder.</summary>
    public long NextUid { get; private set; }

    /// <summary>Whether the folder appears in LSUB.</summary>
    public bool IsSubscribed { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    /// <summary>True for a folder the server created and depends on.</summary>
    /// <remarks>
    /// The inbox cannot be renamed or deleted; the others can be, because an operator or a user
    /// may genuinely want a different arrangement, and the SPECIAL-USE attribute moves with
    /// whichever folder is nominated.
    /// </remarks>
    public bool IsInbox => SpecialUse == FolderSpecialUse.Inbox;

    /// <summary>Creates a folder.</summary>
    /// <exception cref="DomainRuleViolationException">The path is unusable.</exception>
    public static MailboxFolder Create(
        MailboxId mailboxId,
        string path,
        FolderSpecialUse specialUse,
        long uidValidity,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        string normalized = NormalizePath(path);

        return new MailboxFolder(
            MailboxFolderId.New(),
            mailboxId,
            normalized,
            specialUse,

            // Supplied rather than generated here: it must be strictly increasing across
            // recreations of the same folder name, which needs a clock the domain does not have.
            uidValidity,

            // UIDs start at 1. Zero is not a valid IMAP UID.
            nextUid: 1,

            // Subscribed by default, so the standard folders are visible in clients that only
            // show subscribed ones - which is most of them, by default.
            isSubscribed: true,
            createdUtc: now,
            modifiedUtc: null);
    }

    /// <summary>The standard folder set every new mailbox receives.</summary>
    /// <remarks>
    /// <para>
    /// Created up front rather than on demand. A client that connects and finds no Sent folder
    /// creates one itself, named in its own locale — which is how an account ends up with
    /// "Sent", "Sent Items" and "Gesendet", each holding part of the history.
    /// </para>
    /// <para>
    /// English names with SPECIAL-USE attributes, rather than localised names. The attribute is
    /// what a well-behaved client reads; the name is a fallback, and an English fallback is
    /// predictable for an administrator reading the filesystem.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<(string Path, FolderSpecialUse SpecialUse)> StandardFolders { get; } =
    [
        ("INBOX", FolderSpecialUse.Inbox),
        ("Sent", FolderSpecialUse.Sent),
        ("Drafts", FolderSpecialUse.Drafts),
        ("Trash", FolderSpecialUse.Trash),
        ("Junk", FolderSpecialUse.Junk),
        ("Archive", FolderSpecialUse.Archive),
    ];

    /// <summary>Allocates the next UID.</summary>
    public long AllocateUid(DateTimeOffset now)
    {
        long uid = NextUid;

        NextUid++;
        ModifiedUtc = now;

        return uid;
    }

    public void SetSubscribed(bool subscribed, DateTimeOffset now)
    {
        IsSubscribed = subscribed;
        ModifiedUtc = now;
    }

    /// <summary>Renames or moves the folder.</summary>
    /// <exception cref="DomainRuleViolationException">This is the inbox, or the path is unusable.</exception>
    public void Rename(string path, DateTimeOffset now)
    {
        if (IsInbox)
        {
            throw new DomainRuleViolationException(
                "folder.inbox.immutable",
                "INBOX cannot be renamed. RFC 3501 makes it a reserved name that every client " +
                "expects to exist.");
        }

        Path = NormalizePath(path);
        ModifiedUtc = now;
    }

    public void SetSpecialUse(FolderSpecialUse specialUse, DateTimeOffset now)
    {
        if (IsInbox && specialUse != FolderSpecialUse.Inbox)
        {
            throw new DomainRuleViolationException(
                "folder.inbox.immutable",
                "INBOX cannot be reassigned to another purpose.");
        }

        SpecialUse = specialUse;
        ModifiedUtc = now;
    }

    /// <summary>
    /// Checks and tidies a folder path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Control characters are refused rather than stripped. A folder name is echoed back in
    /// IMAP responses, and a name containing CR or LF could inject a line into the protocol
    /// stream — the same class of problem as header injection, and worth refusing at the one
    /// place folder names are created.
    /// </para>
    /// <para>
    /// Empty path segments are refused too: <c>a//b</c> is ambiguous and different clients
    /// disagree about whether it names two levels or three.
    /// </para>
    /// </remarks>
    private static string NormalizePath(string path)
    {
        string trimmed = path.Trim().Trim(PathSeparator);

        if (trimmed.Length == 0)
        {
            throw new DomainRuleViolationException(
                "folder.path.empty",
                "A folder path cannot be empty.");
        }

        if (trimmed.Length > MaxPathLength)
        {
            throw new DomainRuleViolationException(
                "folder.path.too_long",
                $"A folder path may be at most {MaxPathLength} characters.");
        }

        foreach (char c in trimmed)
        {
            if (char.IsControl(c))
            {
                throw new DomainRuleViolationException(
                    "folder.path.control_character",
                    "A folder name cannot contain control characters. Folder names are echoed " +
                    "in IMAP responses, where a carriage return or line feed would inject a " +
                    "line into the protocol stream.");
            }
        }

        string[] segments = trimmed.Split(PathSeparator);

        if (segments.Length > MaxDepth)
        {
            throw new DomainRuleViolationException(
                "folder.path.too_deep",
                $"A folder may be nested at most {MaxDepth} levels deep.");
        }

        foreach (string segment in segments)
        {
            if (segment.Trim().Length == 0)
            {
                throw new DomainRuleViolationException(
                    "folder.path.empty_segment",
                    $"'{path}' contains an empty path segment. Clients disagree about what " +
                    "that means, so it is refused rather than guessed at.");
            }
        }

        return string.Join(PathSeparator, segments);
    }
}
