using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Imap.Tests;

public sealed class ImapMailboxPathTests
{
    [Theory]
    [InlineData("INBOX")]
    [InlineData("inbox")]
    [InlineData("Inbox")]
    [InlineData("InBoX")]
    [InlineData("iNBOx")]
    public void The_inbox_is_recognised_in_any_case(string path)
    {
        // RFC 3501 section 5.1: "The case-insensitive mailbox name INBOX is a special name
        // reserved to mean the primary mailbox for this user on this server."
        ImapMailboxPath.IsInbox(path).ShouldBeTrue();
        ImapMailboxPath.Canonical(path).ShouldBe("INBOX");
    }

    [Theory]
    [InlineData("Archive")]
    [InlineData("Inbox/Sub")]
    [InlineData("MyINBOX")]
    [InlineData("INBOX2")]
    [InlineData("")]
    public void Nothing_else_is_the_inbox(string path)
    {
        // The name has to be exactly INBOX, not merely contain it: "MyINBOX" and "INBOX/Sub" are
        // ordinary folders a user made, and folding either into the primary mailbox would serve
        // the wrong mail.
        ImapMailboxPath.IsInbox(path).ShouldBeFalse();
    }

    [Theory]
    [InlineData("Receipts")]
    [InlineData("receipts")]
    [InlineData("Projects/2026")]
    [InlineData("  spaced  ")]
    [InlineData("Entwürfe")]
    public void Every_other_name_is_returned_exactly_as_it_arrived(string path)
    {
        // Section 5.1 settles only INBOX; for everything else "The interpretation of all other
        // names is implementation-dependent". This server matches exactly. A folder name
        // is the user's own text, and this server has no business deciding two spellings of it
        // are the same folder.
        ImapMailboxPath.Canonical(path).ShouldBe(path);
    }

    [Fact]
    public void A_null_name_is_not_the_inbox_and_cannot_be_canonicalised()
    {
        // IsInbox tolerates null because it answers a question about a value that may be absent;
        // Canonical returns one, and has nothing to return.
        ImapMailboxPath.IsInbox(null).ShouldBeFalse();
        Should.Throw<ArgumentNullException>(() => ImapMailboxPath.Canonical(null!));
    }
}

public sealed class ImapFolderSnapshotTests
{
    private static MailboxFolder Folder(long uidValidity = 42, long nextUid = 7) =>
        new(
            new MailboxFolderId(Guid.NewGuid()),
            new MailboxId(Guid.NewGuid()),
            "INBOX",
            FolderSpecialUse.Inbox,
            uidValidity,
            nextUid,
            isSubscribed: true,
            DateTimeOffset.UnixEpoch,
            null);

    [Fact]
    public void The_snapshot_reads_uidvalidity_and_uidnext_from_the_folder()
    {
        // Never recomputed and never derived from a timestamp: UIDVALIDITY is assigned once at
        // creation, and a UIDNEXT derived from the highest UID present would go backwards the
        // moment the last message was expunged.
        ImapFolderSnapshot snapshot = new(Folder(uidValidity: 3_857_529_045, nextUid: 4392), 0, null);

        snapshot.UidValidity.ShouldBe(3_857_529_045);
        snapshot.UidNext.ShouldBe(4392);
    }

    [Fact]
    public void The_snapshot_carries_the_folders_identity()
    {
        MailboxFolder folder = Folder();

        new ImapFolderSnapshot(folder, 0, null).FolderId.ShouldBe(folder.Id);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData(1L, true)]
    [InlineData(12L, true)]
    public void Whether_to_send_the_unseen_line_is_asked_once(long? firstUnseen, bool expected)
    {
        // RFC 3501 section 9 types the UNSEEN code's argument as an nz-number, so a folder with
        // nothing unseen omits the whole line rather than sending [UNSEEN 0]. Asking through a
        // named property keeps that from being rediscovered at every call site.
        new ImapFolderSnapshot(Folder(), 4, firstUnseen).HasUnseen.ShouldBe(expected);
    }

    [Fact]
    public void A_zero_first_unseen_is_not_treated_as_unseen()
    {
        // Sequence numbers are one-based, so zero names no message. A reader that returned 0
        // instead of null for "nothing unseen" must not produce an ungrammatical [UNSEEN 0].
        new ImapFolderSnapshot(Folder(), 4, 0).HasUnseen.ShouldBeFalse();
    }

    [Fact]
    public void An_empty_folder_is_a_legitimate_snapshot()
    {
        ImapFolderSnapshot snapshot = new(Folder(nextUid: 1), 0, null);

        snapshot.ExistsCount.ShouldBe(0);
        snapshot.HasUnseen.ShouldBeFalse();
        snapshot.UidNext.ShouldBe(1);
    }
}
