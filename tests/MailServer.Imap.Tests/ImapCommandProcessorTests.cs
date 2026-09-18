using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Imap;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Imap.Tests;

/// <summary>An authenticator that answers from a script, and remembers what it was shown.</summary>
internal sealed class ScriptedImapAuthenticator : IMailboxAuthenticator
{
    public string KnownMailbox { get; set; } = "alice@example.com";

    public string KnownPassword { get; set; } = "hunter2";

    public MailboxId KnownMailboxId { get; } = new(Guid.NewGuid());

    /// <summary>Every identity this authenticator was shown, to prove what reached it.</summary>
    public List<string> SeenIdentities { get; } = [];

    /// <summary>Every password it was shown, to prove the right one was extracted.</summary>
    public List<string> SeenPasswords { get; } = [];

    public int Calls { get; private set; }

    public Task<MailboxAuthenticationResult> AuthenticateAsync(
        SaslCredential credential,
        IpAddressValue remoteAddress,
        CancellationToken cancellationToken)
    {
        Calls++;
        SeenIdentities.Add(credential.AuthenticationIdentity);
        SeenPasswords.Add(credential.Password.ToString());

        bool ok = credential.AuthenticationIdentity == KnownMailbox &&
                  credential.Password.ToString() == KnownPassword;

        return Task.FromResult(ok
            ? new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Succeeded,
                EmailAddress.Parse(KnownMailbox),
                "Authenticated.",
                KnownMailboxId)
            : new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Failed,
                null,
                "Wrong password."));
    }
}

/// <summary>A mailbox reader answering from an in-memory set of folders.</summary>
/// <remarks>
/// The real reader is covered against a real SQLite database in
/// <c>MailServer.Persistence.Tests</c>. This one exists so the command surface can be driven
/// over every folder shape that matters — empty, all read, some unseen, belonging to somebody
/// else — without a database standing between the test and what it is asserting.
/// </remarks>
internal sealed class ScriptedImapMailboxReader : IImapMailboxReader, IImapMailboxWriter
{
    /// <summary>One folder, with the numbers every command that reads it would see.</summary>
    private sealed record Entry(
        MailboxFolder Folder,
        long ExistsCount,
        long? FirstUnseen,
        long UnseenCount);

    private readonly Dictionary<(Guid Mailbox, string Path), Entry> _folders = [];

    /// <summary>Every (mailbox, path) pair this reader was asked for.</summary>
    public List<(Guid Mailbox, string Path)> Asked { get; } = [];

    /// <summary>Every mailbox whose folders were enumerated.</summary>
    public List<Guid> Listed { get; } = [];

    public ScriptedImapMailboxReader Add(
        MailboxId mailboxId,
        string path,
        long existsCount = 0,
        long? firstUnseen = null,
        long uidValidity = 3_857_529_045,
        long nextUid = 1,
        FolderSpecialUse specialUse = FolderSpecialUse.None,
        bool subscribed = true,
        long? unseenCount = null)
    {
        MailboxFolder folder = new(
            new MailboxFolderId(Guid.NewGuid()),
            mailboxId,
            path,
            specialUse,
            uidValidity,
            nextUid,
            subscribed,
            DateTimeOffset.UnixEpoch,
            null);

        _folders[(mailboxId.Value, path)] = new Entry(
            folder,
            existsCount,
            firstUnseen,

            // Defaults to "one unread if anything is unread", which is enough for the tests that
            // only care that the count is a count. A test about the count itself passes its own.
            unseenCount ?? (firstUnseen is null ? 0 : 1));

        return this;
    }

    public Task<ImapFolderSnapshot?> OpenFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken)
    {
        // The real reader applies the INBOX rule in its WHERE clause; this applies it here, so
        // both agree about what a client's name refers to.
        string canonical = ImapMailboxPath.Canonical(path);

        Asked.Add((mailboxId.Value, canonical));

        return Task.FromResult(
            _folders.TryGetValue((mailboxId.Value, canonical), out Entry? entry)
                ? new ImapFolderSnapshot(entry.Folder, entry.ExistsCount, entry.FirstUnseen)
                : null);
    }

    public Task<ImapFolderStatus?> ReadStatusAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken)
    {
        string canonical = ImapMailboxPath.Canonical(path);

        Asked.Add((mailboxId.Value, canonical));

        return Task.FromResult(
            _folders.TryGetValue((mailboxId.Value, canonical), out Entry? entry)
                ? new ImapFolderStatus(entry.Folder, entry.ExistsCount, entry.UnseenCount)
                : null);
    }

    /// <summary>
    /// The folders of one mailbox, with <c>HasChildren</c> derived the way the real reader
    /// derives it.
    /// </summary>
    /// <remarks>
    /// Through <see cref="ImapMailboxPattern.ParentsAmong"/>, which is the same call the real
    /// reader makes. Reimplementing the derivation here would let the fake and the product
    /// disagree about the one thing this fake exists to feed the product.
    /// </remarks>
    public Task<IReadOnlyList<ImapFolderListing>> ListFoldersAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken)
    {
        Listed.Add(mailboxId.Value);

        List<MailboxFolder> mine =
        [
            .. _folders
                .Where(pair => pair.Key.Mailbox == mailboxId.Value)
                .Select(pair => pair.Value.Folder),
        ];

        IReadOnlySet<string> parents = ImapMailboxPattern.ParentsAmong(mine.Select(f => f.Path));

        List<ImapFolderListing> listings =
        [
            .. mine
                .OrderBy(folder => folder.Path, StringComparer.Ordinal)
                .Select(folder => new ImapFolderListing(
                    folder.Path,
                    folder.SpecialUse,
                    folder.IsSubscribed,
                    parents.Contains(folder.Path))),
        ];

        return Task.FromResult<IReadOnlyList<ImapFolderListing>>(listings);
    }

    /// <summary>Messages, keyed by the folder they were put in.</summary>
    private readonly Dictionary<(Guid Mailbox, string Path), List<ImapMessageSummary>> _messages = [];

    /// <summary>
    /// Puts messages in a folder, numbered from 1 in UID order.
    /// </summary>
    /// <remarks>
    /// The sequence numbers are assigned here rather than passed in, because RFC 3501 §2.3.1.2
    /// makes them positions: a test that chose them independently of the UID order could assert
    /// a pairing the real reader can never produce.
    /// </remarks>
    public ScriptedImapMailboxReader Deliver(
        MailboxId mailboxId,
        string path,
        params long[] uids)
    {
        List<ImapMessageSummary> summaries = [];

        long sequenceNumber = 1;

        foreach (long uid in uids.OrderBy(u => u))
        {
            summaries.Add(new ImapMessageSummary(
                sequenceNumber++,
                uid,
                MessageFlags.Seen,
                new DateTimeOffset(2026, 3, 1, 9, 30, 15, TimeSpan.Zero),
                SizeBytes: 100 * uid));
        }

        _messages[(mailboxId.Value, path)] = summaries;

        return this;
    }

    /// <summary>The mailbox and folder every summary read was scoped to.</summary>
    public List<(Guid Mailbox, Guid Folder)> Read { get; } = [];

    public Task<IReadOnlyList<ImapMessageSummary>> ReadSummariesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        CancellationToken cancellationToken)
    {
        Read.Add((mailboxId.Value, folderId.Value));

        // Found by folder id, the way the real reader's WHERE clause finds it - so a test that
        // selected one folder and fetched from another would fail here too.
        KeyValuePair<(Guid Mailbox, string Path), Entry> owner = _folders
            .FirstOrDefault(pair =>
                pair.Value.Folder.Id.Value == folderId.Value &&
                pair.Key.Mailbox == mailboxId.Value);

        if (owner.Value is null ||
            !_messages.TryGetValue(owner.Key, out List<ImapMessageSummary>? all))
        {
            return Task.FromResult<IReadOnlyList<ImapMessageSummary>>([]);
        }

        if (all.Count == 0)
        {
            return Task.FromResult<IReadOnlyList<ImapMessageSummary>>([]);
        }

        long maxValue = byUid ? all[^1].Uid : all[^1].SequenceNumber;

        List<ImapMessageSummary> matched =
        [
            .. all.Where(s => set.Contains(byUid ? s.Uid : s.SequenceNumber, maxValue)),
        ];

        return Task.FromResult<IReadOnlyList<ImapMessageSummary>>(matched);
    }

    /// <summary>Every store this fake was asked to perform.</summary>
    public List<(Guid Mailbox, Guid Folder, ImapStoreRequest Request)> Stored { get; } = [];

    /// <summary>
    /// Applies a store to the in-memory messages, so a later FETCH sees what a STORE did.
    /// </summary>
    /// <remarks>
    /// The same object serves both interfaces on purpose. A fake whose writes were invisible to
    /// its own reads could not catch a handler that reported the value it asked for rather than
    /// the value that was written, which is the defect
    /// <see cref="IImapMailboxWriter.StoreFlagsAsync"/> exists to prevent.
    /// </remarks>
    public async Task<IReadOnlyList<ImapMessageSummary>> StoreFlagsAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        ImapStoreRequest request,
        CancellationToken cancellationToken)
    {
        Stored.Add((mailboxId.Value, folderId.Value, request));

        IReadOnlyList<ImapMessageSummary> before = await ReadSummariesAsync(
            mailboxId,
            folderId,
            set,
            byUid,
            cancellationToken);

        KeyValuePair<(Guid Mailbox, string Path), Entry> owner = _folders
            .FirstOrDefault(pair =>
                pair.Value.Folder.Id.Value == folderId.Value &&
                pair.Key.Mailbox == mailboxId.Value);

        if (owner.Value is null ||
            !_messages.TryGetValue(owner.Key, out List<ImapMessageSummary>? all))
        {
            return [];
        }

        List<ImapMessageSummary> after = [];

        foreach (ImapMessageSummary summary in before)
        {
            ImapMessageSummary updated = summary with { Flags = request.Apply(summary.Flags) };

            all[all.FindIndex(m => m.Uid == summary.Uid)] = updated;

            after.Add(updated);
        }

        return after;
    }
}

public sealed class ImapCommandProcessorTests
{
    private static readonly DateTimeOffset Start = new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private static ImapSessionContext Session(bool tls = true) =>
        new(IpAddressValue.Parse("198.51.100.20"), Start, tls);

    private static ImapCommandProcessor Processor(
        ImapSessionContext? session = null,
        ImapListenerRole role = ImapListenerRole.ImplicitTls,
        bool authAvailable = true,
        IMailboxAuthenticator? authenticator = null,
        int maxAttempts = 3,
        ScriptedImapMailboxReader? mailboxes = null) =>
        new(
            session ?? Session(),
            new ImapProcessorOptions("AetherMail", role, authAvailable, maxAttempts),
            NullLogger.Instance,
            authenticator,
            mailboxes,

            // The same object reads and writes, so a STORE's effect is visible to a later FETCH.
            mailboxes);

    private static ImapCommand Parse(string line)
    {
        ImapCommand.TryParse(line, out ImapCommand? command, out _).ShouldBeTrue($"could not parse [{line}]");
        return command!;
    }

    private static async Task<ImapCommandResult> ExecuteAsync(ImapCommandProcessor processor, string line) =>
        await processor.ExecuteAsync(Parse(line), CancellationToken.None);

    private static string Wire(ImapCommandResult result) =>
        string.Concat(result.Responses.Select(r => r.Format()));

    // ---------------------------------------------------------------------------------------
    // The greeting.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_greeting_is_untagged_and_carries_the_capabilities()
    {
        // RFC 3501 section 7.1.1, with the listing inline per section 7.2.1 - which saves the
        // client the round trip it would otherwise spend discovering whether it may log in.
        string greeting = Processor().Greeting().Format();

        greeting.ShouldStartWith("* OK [CAPABILITY IMAP4rev1 ");
        greeting.ShouldContain("AetherMail");
        greeting.ShouldEndWith("\r\n");
    }

    [Fact]
    public void A_cleartext_greeting_says_login_is_disabled()
    {
        Processor(Session(tls: false), ImapListenerRole.Cleartext)
            .Greeting()
            .Format()
            .ShouldContain("LOGINDISABLED");
    }

    // ---------------------------------------------------------------------------------------
    // The any-state commands. RFC 3501 section 6.1.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Capability_answers_untagged_data_then_a_tagged_completion()
    {
        // RFC 3501 section 6.1.1: "The server MUST send a single untagged CAPABILITY response
        // ... before the (tagged) OK response."
        ImapCommandResult result = await ExecuteAsync(Processor(), "a1 CAPABILITY");

        result.Responses.Count.ShouldBe(2);
        result.Responses[0].Format().ShouldStartWith("* CAPABILITY IMAP4rev1");
        result.Responses[1].Format().ShouldBe("a1 OK CAPABILITY completed\r\n");
        result.Action.ShouldBe(ImapSessionAction.Continue);
    }

    [Fact]
    public async Task Noop_answers_a_tagged_ok()
    {
        ImapCommandResult result = await ExecuteAsync(Processor(), "a1 NOOP");

        Wire(result).ShouldBe("a1 OK NOOP completed\r\n");
    }

    [Fact]
    public async Task Logout_sends_bye_before_the_completion_and_closes()
    {
        // RFC 3501 section 6.1.3 is explicit that the untagged BYE comes first. A client that
        // saw only the OK could not tell an orderly close from the connection dropping.
        ImapCommandProcessor processor = Processor();

        ImapCommandResult result = await ExecuteAsync(processor, "a1 LOGOUT");

        result.Responses.Count.ShouldBe(2);
        result.Responses[0].Format().ShouldStartWith("* BYE ");
        result.Responses[1].Format().ShouldBe("a1 OK LOGOUT completed\r\n");
        result.Action.ShouldBe(ImapSessionAction.CloseAfterResponse);
        processor.Session.State.ShouldBe(ImapSessionState.Logout);
    }

    [Theory]
    [InlineData("a1 CAPABILITY")]
    [InlineData("a1 NOOP")]
    [InlineData("a1 LOGOUT")]
    public async Task The_any_state_commands_work_before_authentication(string line)
    {
        ImapCommandResult result = await ExecuteAsync(
            Processor(Session(tls: false), ImapListenerRole.Cleartext),
            line);

        Wire(result).ShouldNotContain(" BAD ");
        Wire(result).ShouldNotContain(" NO ");
    }

    // ---------------------------------------------------------------------------------------
    // Unrecognised and out-of-sequence commands.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task An_unrecognised_command_earns_a_tagged_bad()
    {
        ImapCommandResult result = await ExecuteAsync(Processor(), "a1 FROBNICATE");

        Wire(result).ShouldBe("a1 BAD Unrecognised command\r\n");
    }

    [Fact]
    public async Task An_unrecognised_command_is_never_echoed_back()
    {
        // The unrecognised word is the client's own text, and a refusal must not quote it back.
        ImapCommandResult result = await ExecuteAsync(Processor(), "a1 FROBNICATE secret-data");

        Wire(result).ShouldNotContain("FROBNICATE");
        Wire(result).ShouldNotContain("secret-data");
    }

    [Theory]
    [InlineData("a1 SELECT INBOX")]
    [InlineData("a1 FETCH 1 FLAGS")]
    [InlineData("a1 LIST \"\" \"*\"")]
    [InlineData("a1 APPEND INBOX {10}")]
    public async Task A_command_needing_an_identity_is_out_of_sequence_before_login(string line)
    {
        // BAD rather than NO: NO says the request was well-formed and invites a retry, and a
        // client told NO for a command it sent in the wrong state retries in the wrong state.
        ImapCommandResult result = await ExecuteAsync(Processor(), line);

        Wire(result).ShouldContain(" BAD ");
        Wire(result).ShouldContain("not valid in this state");
    }

    [Fact]
    public async Task Re_authentication_is_refused_as_out_of_sequence()
    {
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        (await ExecuteAsync(processor, "a1 LOGIN alice@example.com hunter2")).Responses[0]
            .Format().ShouldContain(" OK ");

        Wire(await ExecuteAsync(processor, "a2 LOGIN mallory@example.com hunter2"))
            .ShouldContain("not valid in this state");
    }

    // ---------------------------------------------------------------------------------------
    // Commands that exist, are in sequence, and are not built yet.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("a1 SELECT INBOX", "SELECT")]
    [InlineData("a1 CREATE Archive", "CREATE")]
    [InlineData("a1 SUBSCRIBE Archive", "SUBSCRIBE")]
    [InlineData("a1 IDLE", "IDLE")]
    public async Task An_unimplemented_command_says_so_rather_than_pretending(string line, string verb)
    {
        // A tagged NO naming the command, not a BAD: the request was well-formed and in
        // sequence, and telling a client otherwise sends someone debugging a mail client looking
        // for a syntax error that is not there.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        string wire = Wire(await ExecuteAsync(processor, line));

        wire.ShouldContain(" NO ");
        wire.ShouldContain(verb);
        wire.ShouldContain("not implemented yet");
    }

    [Fact]
    public async Task Nothing_unimplemented_is_advertised_as_available()
    {
        // The pairing that keeps the refusals honest: a complying client never sends a command
        // this processor would refuse, because the capability listing never offered it.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        IReadOnlyList<string> capabilities = processor.Capabilities();

        capabilities.ShouldNotContain("IDLE");
        capabilities.ShouldNotContain("NAMESPACE");
        capabilities.ShouldNotContain("UNSELECT");
        capabilities.ShouldNotContain("MOVE");
    }

    // ---------------------------------------------------------------------------------------
    // SELECT and EXAMINE. RFC 3501 sections 6.3.1 and 6.3.2.
    // ---------------------------------------------------------------------------------------

    /// <summary>An authenticated processor with one folder in the authenticated mailbox.</summary>
    private static async Task<(ImapCommandProcessor Processor, ScriptedImapMailboxReader Mailboxes)>
        SelectableAsync(
            string path = "INBOX",
            long existsCount = 0,
            long? firstUnseen = null,
            long uidValidity = 3_857_529_045,
            long nextUid = 1)
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, path, existsCount, firstUnseen, uidValidity, nextUid);

        ImapCommandProcessor processor = Processor(authenticator: authenticator, mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        return (processor, mailboxes);
    }

    [Fact]
    public async Task Select_emits_the_responses_rfc_3501_asks_for_in_order()
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync(
            existsCount: 172,
            firstUnseen: 12,
            uidValidity: 3_857_529_045,
            nextUid: 4392);

        ImapCommandResult result = await ExecuteAsync(processor, "a1 SELECT INBOX");

        string[] lines = [.. result.Responses.Select(r => r.Format().TrimEnd('\r', '\n'))];

        lines.ShouldBe(
        [
            "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)",
            "* 172 EXISTS",
            "* 0 RECENT",
            "* OK [UNSEEN 12] First unseen message",
            "* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted",
            "* OK [UIDVALIDITY 3857529045] UIDs valid",
            "* OK [UIDNEXT 4392] Predicted next UID",
            "a1 OK [READ-WRITE] SELECT completed",
        ]);
    }

    [Fact]
    public async Task Select_moves_the_session_into_the_selected_state()
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync(uidValidity: 999);

        await ExecuteAsync(processor, "a1 SELECT INBOX");

        processor.Session.State.ShouldBe(ImapSessionState.Selected);
        processor.Session.SelectedFolderId.ShouldNotBeNull();
        processor.Session.SelectedFolderUidValidity.ShouldBe(999);
        processor.Session.IsSelectedReadOnly.ShouldBeFalse();
    }

    [Fact]
    public async Task Examine_opens_the_same_mailbox_read_only()
    {
        // RFC 3501 section 6.3.2: "identical to SELECT and returns the same output; however, the
        // selected mailbox is identified as read-only".
        (ImapCommandProcessor processor, _) = await SelectableAsync(existsCount: 2);

        ImapCommandResult result = await ExecuteAsync(processor, "a1 EXAMINE INBOX");

        string wire = Wire(result);

        wire.ShouldContain("* 2 EXISTS");
        wire.ShouldContain("[PERMANENTFLAGS ()]");
        wire.ShouldContain("a1 OK [READ-ONLY] EXAMINE completed");
        processor.Session.IsSelectedReadOnly.ShouldBeTrue();
    }

    [Fact]
    public async Task An_empty_permanentflags_list_is_what_read_only_means()
    {
        // Empty and meaningful: nothing may be changed, so nothing persists.
        (ImapCommandProcessor processor, _) = await SelectableAsync();

        Wire(await ExecuteAsync(processor, "a1 EXAMINE INBOX"))
            .ShouldContain("* OK [PERMANENTFLAGS ()] Flags permitted");
    }

    [Fact]
    public async Task The_unseen_line_is_omitted_when_nothing_is_unseen()
    {
        // RFC 3501 section 9 types the code's argument as an nz-number, so there is no way to
        // say "none": the whole line goes rather than being sent as an ungrammatical [UNSEEN 0].
        (ImapCommandProcessor processor, _) = await SelectableAsync(existsCount: 4, firstUnseen: null);

        string wire = Wire(await ExecuteAsync(processor, "a1 SELECT INBOX"));

        wire.ShouldNotContain("UNSEEN");
        wire.ShouldContain("* 4 EXISTS");
    }

    [Fact]
    public async Task An_empty_mailbox_selects_and_reports_zero()
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync(existsCount: 0);

        string wire = Wire(await ExecuteAsync(processor, "a1 SELECT INBOX"));

        wire.ShouldContain("* 0 EXISTS");
        wire.ShouldContain("* 0 RECENT");
        wire.ShouldNotContain("UNSEEN");
        processor.Session.State.ShouldBe(ImapSessionState.Selected);
    }

    [Fact]
    public async Task Recent_is_always_zero()
    {
        // \Recent is reserved and never set, so zero is what this server's own state says - a
        // deliberate deviation from RFC 3501 section 2.3.2's SHOULD, not conformance to it.
        (ImapCommandProcessor processor, _) = await SelectableAsync(existsCount: 9, firstUnseen: 1);

        Wire(await ExecuteAsync(processor, "a1 SELECT INBOX")).ShouldContain("* 0 RECENT");
    }

    [Fact]
    public async Task Selecting_a_mailbox_that_is_not_there_is_refused_and_selects_nothing()
    {
        // RFC 3501 section 6.3.1: "if a SELECT command that fails is attempted, no mailbox is
        // selected." A session left with its old folder open would have a following FETCH
        // silently read the wrong one.
        (ImapCommandProcessor processor, _) = await SelectableAsync();

        await ExecuteAsync(processor, "a1 SELECT INBOX");
        processor.Session.State.ShouldBe(ImapSessionState.Selected);

        ImapCommandResult result = await ExecuteAsync(processor, "a2 SELECT Nonexistent");

        Wire(result).ShouldBe("a2 NO No such mailbox\r\n");
        processor.Session.State.ShouldBe(ImapSessionState.Authenticated);
        processor.Session.SelectedFolderId.ShouldBeNull();
    }

    [Fact]
    public async Task A_failed_select_does_not_offer_trycreate()
    {
        // RFC 3501 sections 6.3.11 and 6.4.7 attach that code to APPEND and COPY, where creating
        // the mailbox and retrying is the recovery. A client cannot recover from selecting a
        // folder that is not there by creating one - it wanted the mail that was in it.
        (ImapCommandProcessor processor, _) = await SelectableAsync();

        Wire(await ExecuteAsync(processor, "a1 SELECT Nonexistent")).ShouldNotContain("TRYCREATE");
    }

    [Fact]
    public async Task Switching_mailboxes_deselects_the_old_one_first()
    {
        // RFC 3501 section 6.3.1: "the SELECT command automatically deselects any currently
        // selected mailbox before attempting the new selection". Unlike CLOSE, this never
        // expunges.
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", uidValidity: 111)
            .Add(authenticator.KnownMailboxId, "Archive", uidValidity: 222);

        ImapCommandProcessor processor = Processor(authenticator: authenticator, mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        await ExecuteAsync(processor, "a1 SELECT INBOX");
        processor.Session.SelectedFolderUidValidity.ShouldBe(111);

        await ExecuteAsync(processor, "a2 SELECT Archive");
        processor.Session.SelectedFolderUidValidity.ShouldBe(222);
        processor.Session.State.ShouldBe(ImapSessionState.Selected);
    }

    [Theory]
    [InlineData("inbox")]
    [InlineData("InBoX")]
    [InlineData("INBOX")]
    public async Task The_inbox_is_reachable_in_any_case(string asked)
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync();

        Wire(await ExecuteAsync(processor, $"a1 SELECT {asked}")).ShouldContain("a1 OK [READ-WRITE]");
    }

    [Fact]
    public async Task A_quoted_mailbox_name_is_read_correctly()
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync("My Folder");

        Wire(await ExecuteAsync(processor, "a1 SELECT \"My Folder\""))
            .ShouldContain("a1 OK [READ-WRITE]");
    }

    [Fact]
    public async Task A_modified_utf7_mailbox_name_is_decoded_before_the_lookup()
    {
        // The wire form is modified UTF-7 (RFC 3501 section 5.1.3); the stored path is the
        // decoded name. A lookup on the undecoded form would never find a non-ASCII folder.
        (ImapCommandProcessor processor, ScriptedImapMailboxReader mailboxes) =
            await SelectableAsync("Entw\u00fcrfe");

        Wire(await ExecuteAsync(processor, "a1 SELECT Entw&APw-rfe"))
            .ShouldContain("a1 OK [READ-WRITE]");

        mailboxes.Asked.ShouldContain(a => a.Path == "Entw\u00fcrfe");
    }

    [Fact]
    public async Task A_mailbox_name_that_is_not_modified_utf7_is_refused_without_being_echoed()
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a1 SELECT &AAA-secret&"));

        wire.ShouldContain(" NO ");
        wire.ShouldNotContain("secret");
    }

    [Theory]
    [InlineData("a1 SELECT")]
    [InlineData("a1 SELECT INBOX Archive")]
    [InlineData("a1 SELECT \"unterminated")]
    public async Task A_malformed_select_earns_a_bad(string line)
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync();

        string wire = Wire(await ExecuteAsync(processor, line));

        wire.ShouldContain(" BAD ");
        wire.ShouldContain("one mailbox name");
    }

    [Fact]
    public async Task Select_only_ever_asks_for_the_authenticated_mailbox()
    {
        // The authorisation boundary as the processor sees it: the mailbox id comes from the
        // session, never from the command, so there is nothing a client can send that would make
        // this ask about somebody else's mail.
        (ImapCommandProcessor processor, ScriptedImapMailboxReader mailboxes) = await SelectableAsync();

        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, "a2 SELECT Archive");

        Guid authenticated = processor.Session.AuthenticatedMailboxId!.Value.Value;

        mailboxes.Asked.ShouldAllBe(a => a.Mailbox == authenticated);
    }

    [Fact]
    public async Task Select_without_a_reader_configured_says_it_is_not_implemented()
    {
        // Null is a legitimate configuration rather than a missing dependency, and this is what
        // makes the refusal honest rather than a stub that looks like success.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 SELECT INBOX")).ShouldContain("not implemented yet");
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS. RFC 3501 section 6.2.1.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Starttls_is_accepted_on_a_cleartext_connection_and_asks_for_the_handshake()
    {
        ImapCommandResult result = await ExecuteAsync(
            Processor(Session(tls: false), ImapListenerRole.Cleartext),
            "a1 STARTTLS");

        Wire(result).ShouldBe("a1 OK Begin TLS negotiation now\r\n");
        result.Action.ShouldBe(ImapSessionAction.StartTlsHandshake);
    }

    [Fact]
    public async Task Starttls_is_refused_inside_the_tunnel_it_would_create()
    {
        // Not caught by the state machine: a successful STARTTLS leaves the session in the
        // not-authenticated state, so sequencing alone would let a client ask twice.
        ImapCommandResult result = await ExecuteAsync(
            Processor(Session(tls: true), ImapListenerRole.Cleartext),
            "a1 STARTTLS");

        Wire(result).ShouldBe("a1 BAD TLS is already active\r\n");
        result.Action.ShouldBe(ImapSessionAction.Continue);
    }

    [Fact]
    public async Task Starttls_is_refused_on_the_implicit_tls_listener()
    {
        // There is no honest moment on port 993 when STARTTLS is legal.
        Wire(await ExecuteAsync(Processor(Session(tls: false), ImapListenerRole.ImplicitTls), "a1 STARTTLS"))
            .ShouldContain("not available on this listener");
    }

    // ---------------------------------------------------------------------------------------
    // LOGIN. RFC 3501 section 6.2.3. The argument is a cleartext password.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Login_authenticates_and_moves_the_session_on()
    {
        ScriptedImapAuthenticator authenticator = new();
        ImapCommandProcessor processor = Processor(authenticator: authenticator);

        ImapCommandResult result = await ExecuteAsync(processor, "a1 LOGIN alice@example.com hunter2");

        Wire(result).ShouldContain("a1 OK ");
        processor.Session.State.ShouldBe(ImapSessionState.Authenticated);
        processor.Session.AuthenticatedMailbox!.Value.ShouldBe("alice@example.com");
        processor.Session.AuthenticatedMailboxId.ShouldBe(authenticator.KnownMailboxId);
    }

    [Fact]
    public async Task A_successful_login_carries_the_new_capability_listing()
    {
        // RFC 3501 section 7.2.1: the list changes on authentication - STARTTLS, LOGINDISABLED
        // and the AUTH= atoms all drop out - so it rides on the completion.
        string wire = Wire(await ExecuteAsync(
            Processor(authenticator: new ScriptedImapAuthenticator()),
            "a1 LOGIN alice@example.com hunter2"));

        wire.ShouldContain("[CAPABILITY IMAP4rev1");
        wire.ShouldNotContain("LOGINDISABLED");
        wire.ShouldNotContain("AUTH=");
    }

    [Fact]
    public async Task Login_reads_a_quoted_password()
    {
        ScriptedImapAuthenticator authenticator = new() { KnownPassword = "pass word" };

        Wire(await ExecuteAsync(
                Processor(authenticator: authenticator),
                "a1 LOGIN \"alice@example.com\" \"pass word\""))
            .ShouldContain(" OK ");

        authenticator.SeenPasswords.ShouldContain("pass word");
    }

    [Fact]
    public async Task Login_reads_a_password_containing_an_escaped_quote()
    {
        ScriptedImapAuthenticator authenticator = new() { KnownPassword = "pa\"ss" };

        Wire(await ExecuteAsync(
                Processor(authenticator: authenticator),
                "a1 LOGIN alice@example.com \"pa\\\"ss\""))
            .ShouldContain(" OK ");
    }

    [Fact]
    public async Task Login_is_refused_without_tls()
    {
        // Not redundant with LOGINDISABLED. That capability tells a complying client not to try;
        // this is what happens when one tries anyway, and RFC 3501 section 6.2.3 requires the
        // refusal to exist as well as the advertisement.
        ScriptedImapAuthenticator authenticator = new();

        ImapCommandResult result = await ExecuteAsync(
            Processor(Session(tls: false), ImapListenerRole.Cleartext, authenticator: authenticator),
            "a1 LOGIN alice@example.com hunter2");

        Wire(result).ShouldContain("LOGIN is disabled without TLS");
        authenticator.Calls.ShouldBe(0, "the credential must not even be checked in the clear.");
    }

    [Fact]
    public async Task Login_is_refused_while_authentication_is_unimplemented()
    {
        ImapCommandResult result = await ExecuteAsync(
            Processor(authAvailable: false, authenticator: new ScriptedImapAuthenticator()),
            "a1 LOGIN alice@example.com hunter2");

        Wire(result).ShouldContain("LOGIN is not available");
    }

    [Fact]
    public async Task Login_with_no_authenticator_configured_is_refused_rather_than_crashing()
    {
        Wire(await ExecuteAsync(Processor(), "a1 LOGIN alice@example.com hunter2"))
            .ShouldContain(" NO ");
    }

    [Theory]
    [InlineData("a1 LOGIN")]
    [InlineData("a1 LOGIN alice@example.com")]
    [InlineData("a1 LOGIN alice@example.com hunter2 extra")]
    [InlineData("a1 LOGIN \"unterminated hunter2")]
    public async Task A_malformed_login_earns_a_bad(string line)
    {
        ImapCommandResult result = await ExecuteAsync(
            Processor(authenticator: new ScriptedImapAuthenticator()),
            line);

        Wire(result).ShouldContain(" BAD ");
        Wire(result).ShouldContain("userid and a password");
    }

    [Fact]
    public async Task A_wrong_password_is_refused_without_saying_which_part_was_wrong()
    {
        // "The username was fine" is a fact about which mailboxes exist, and address enumeration
        // is the first step of every credential-stuffing run against a mail server.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        string wrongPassword = Wire(await ExecuteAsync(processor, "a1 LOGIN alice@example.com wrong"));
        string unknownUser = Wire(await ExecuteAsync(processor, "a2 LOGIN nobody@example.com hunter2"));

        wrongPassword.ShouldBe("a1 NO Authentication failed\r\n");
        unknownUser.ShouldBe("a2 NO Authentication failed\r\n");
    }

    [Theory]
    [InlineData("a1 LOGIN alice@example.com hunter2")]
    [InlineData("a1 LOGIN alice@example.com wrong")]
    [InlineData("a1 LOGIN \"alice@example.com\" \"s3cr3t p@ss\"")]
    [InlineData("a1 AUTHENTICATE PLAIN AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI=")]
    public async Task No_response_to_an_authentication_command_ever_contains_the_credential(string line)
    {
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        string wire = Wire(await ExecuteAsync(processor, line));

        wire.ShouldNotContain("hunter2");
        wire.ShouldNotContain("wrong");
        wire.ShouldNotContain("s3cr3t");
        wire.ShouldNotContain("AGFsaWNl");
    }

    // ---------------------------------------------------------------------------------------
    // AUTHENTICATE. RFC 3501 section 6.2.2.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Authenticate_plain_with_an_initial_response_succeeds_in_one_round_trip()
    {
        // RFC 4959's initial response rides on the AUTHENTICATE line. "alice@example.com" and
        // "hunter2" as SASL PLAIN's NUL-separated triple.
        ScriptedImapAuthenticator authenticator = new();
        ImapCommandProcessor processor = Processor(authenticator: authenticator);

        ImapCommandResult result = await ExecuteAsync(
            processor,
            "a1 AUTHENTICATE PLAIN AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI=");

        Wire(result).ShouldContain("a1 OK ");
        processor.Session.State.ShouldBe(ImapSessionState.Authenticated);
        authenticator.SeenIdentities.ShouldContain("alice@example.com");
    }

    [Fact]
    public async Task Authenticate_without_an_initial_response_asks_for_a_continuation()
    {
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        ImapCommandResult result = await ExecuteAsync(processor, "a1 AUTHENTICATE PLAIN");

        result.Responses[0].Format().ShouldStartWith("+ ");
        result.Action.ShouldBe(ImapSessionAction.ReadAuthenticationResponse);
        processor.IsAuthenticationInFlight.ShouldBeTrue();
    }

    [Fact]
    public async Task The_continuation_line_completes_the_exchange_with_the_original_tag()
    {
        // The continuation carries no tag of its own: the exchange is one command spread over
        // several lines, and the completion belongs to the command that started it.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a7 AUTHENTICATE PLAIN");

        ImapCommandResult result = await processor.ContinueAuthenticationAsync(
            "AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI=",
            CancellationToken.None);

        Wire(result).ShouldContain("a7 OK ");
        processor.IsAuthenticationInFlight.ShouldBeFalse();
    }

    [Fact]
    public async Task A_cancelled_exchange_ends_it()
    {
        // RFC 3501 section 6.2.2: "If the client wishes to cancel an authentication exchange, it
        // issues a line consisting of a single '*'."
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        await ExecuteAsync(processor, "a1 AUTHENTICATE PLAIN");

        ImapCommandResult result = await processor.ContinueAuthenticationAsync(
            "*",
            CancellationToken.None);

        Wire(result).ShouldContain("a1 BAD ");
        processor.IsAuthenticationInFlight.ShouldBeFalse();
    }

    [Fact]
    public async Task Authenticate_is_refused_without_tls()
    {
        ScriptedImapAuthenticator authenticator = new();

        Wire(await ExecuteAsync(
                Processor(Session(tls: false), ImapListenerRole.Cleartext, authenticator: authenticator),
                "a1 AUTHENTICATE PLAIN AGFsaWNlQGV4YW1wbGUuY29tAGh1bnRlcjI="))
            .ShouldContain("disabled without TLS");

        authenticator.Calls.ShouldBe(0);
    }

    [Fact]
    public async Task An_unsupported_mechanism_is_refused_without_being_echoed()
    {
        // A client that sends "AUTHENTICATE <base64>" with no mechanism puts its credential in
        // the mechanism position, and no shape test separates that from a mistyped name.
        string wire = Wire(await ExecuteAsync(
            Processor(authenticator: new ScriptedImapAuthenticator()),
            "a1 AUTHENTICATE AGFsaWNlAGh1bnRlcjI="));

        wire.ShouldBe("a1 NO Unsupported authentication mechanism\r\n");
        wire.ShouldNotContain("AGFsaWNl");
    }

    [Fact]
    public async Task A_continuation_with_no_exchange_in_flight_is_answered_untagged()
    {
        // A caller bug rather than a client one - there is no tag to answer with.
        Wire(await Processor().ContinueAuthenticationAsync("x", CancellationToken.None))
            .ShouldBe("* BAD No authentication in progress\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // The attempt budget.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task The_connection_closes_once_the_attempt_budget_is_spent()
    {
        ImapCommandProcessor processor = Processor(
            authenticator: new ScriptedImapAuthenticator(),
            maxAttempts: 2);

        (await ExecuteAsync(processor, "a1 LOGIN alice@example.com wrong")).Action
            .ShouldBe(ImapSessionAction.Continue);

        ImapCommandResult last = await ExecuteAsync(processor, "a2 LOGIN alice@example.com wrong");

        last.Action.ShouldBe(ImapSessionAction.CloseAfterResponse);
        last.Responses[0].Format().ShouldStartWith("* BYE ");
        last.Responses[1].Format().ShouldContain("a2 NO ");
    }

    [Fact]
    public async Task A_closing_refusal_still_says_bye_first()
    {
        // Closing without one is indistinguishable from a network failure, which invites the
        // reconnect-and-retry loop that makes an attempt limit pointless.
        ImapCommandProcessor processor = Processor(
            authenticator: new ScriptedImapAuthenticator(),
            maxAttempts: 1);

        ImapCommandResult result = await ExecuteAsync(processor, "a1 LOGIN alice@example.com wrong");

        result.Responses.Count.ShouldBe(2);
        result.Responses[0].Format().ShouldStartWith("* BYE ");
    }

    [Fact]
    public async Task A_spent_budget_refuses_further_attempts_without_checking_them()
    {
        ScriptedImapAuthenticator authenticator = new();
        ImapCommandProcessor processor = Processor(authenticator: authenticator, maxAttempts: 1);

        await ExecuteAsync(processor, "a1 LOGIN alice@example.com wrong");
        authenticator.Calls.ShouldBe(1);

        // Even the correct password: the budget is this server's own accounting of the
        // connection, and nothing the client sends buys back another guess.
        ImapCommandResult result = await ExecuteAsync(processor, "a2 LOGIN alice@example.com hunter2");

        result.Action.ShouldBe(ImapSessionAction.CloseAfterResponse);
        authenticator.Calls.ShouldBe(1, "the credential must not be checked after the budget is spent.");
    }

    // ---------------------------------------------------------------------------------------
    // Malformed lines, which never reach ExecuteAsync.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(ImapTagFailure.Missing)]
    [InlineData(ImapTagFailure.TooLong)]
    [InlineData(ImapTagFailure.IllegalCharacter)]
    public void A_line_with_an_unusable_tag_is_answered_untagged(ImapTagFailure failure)
    {
        // RFC 3501 section 7.1.3's untagged BAD: "a protocol-level error for which the
        // associated command can not be determined". There is nothing to tag the answer with.
        ImapCommandResult result = Processor().MalformedLine(failure);

        result.Responses.Count.ShouldBe(1);
        result.Responses[0].Format().ShouldStartWith("* BAD ");
    }

    [Fact]
    public void The_offending_tag_is_never_echoed_in_any_form()
    {
        foreach (ImapTagFailure failure in Enum.GetValues<ImapTagFailure>())
        {
            string wire = Wire(Processor().MalformedLine(failure));

            wire.ShouldStartWith("* BAD ");
            wire.ShouldEndWith("\r\n");
            wire.Count(c => c == '\n').ShouldBe(1);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Every response the processor can produce is a single well-formed line.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("a1 CAPABILITY")]
    [InlineData("a1 NOOP")]
    [InlineData("a1 LOGOUT")]
    [InlineData("a1 STARTTLS")]
    [InlineData("a1 FROBNICATE")]
    [InlineData("a1 SELECT INBOX")]
    [InlineData("a1 LOGIN a b")]
    [InlineData("a1 AUTHENTICATE PLAIN")]
    [InlineData("a1 AUTHENTICATE NOSUCH")]
    [InlineData("a1 UID FETCH 1:* FLAGS")]
    public async Task Every_response_is_one_line_ending_in_crlf(string line)
    {
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        foreach (ImapResponse response in (await ExecuteAsync(processor, line)).Responses)
        {
            string formatted = response.Format();

            formatted.ShouldEndWith("\r\n");
            formatted.Count(c => c == '\n').ShouldBe(1, formatted);
            formatted.Count(c => c == '\r').ShouldBe(1, formatted);
        }
    }

    [Fact]
    public async Task A_hostile_argument_cannot_reach_the_response_stream()
    {
        // The argument is the one place a client's bytes could reach the wire, and the refusals
        // are the responses that would carry them.
        ImapCommandProcessor processor = Processor(authenticator: new ScriptedImapAuthenticator());

        string[] hostile =
        [
            "a1 SELECT \"x\" \r\n* 1 EXPUNGE",
            "a1 LOGIN \"x\r\n* 1 EXPUNGE\" y",
            "a1 FROBNICATE \r\n* 0 EXISTS",
        ];

        foreach (string line in hostile)
        {
            if (!ImapCommand.TryParse(line, out ImapCommand? command, out _))
            {
                continue;
            }

            string wire = Wire(await processor.ExecuteAsync(command, CancellationToken.None));

            wire.ShouldNotContain("EXPUNGE");
            wire.ShouldNotContain("EXISTS");
            wire.Count(c => c == '\n').ShouldBeLessThanOrEqualTo(2, wire);
        }
    }

    [Fact]
    public void The_processor_rejects_null_dependencies()
    {
        ImapProcessorOptions options = new("AetherMail", ImapListenerRole.ImplicitTls);

        Should.Throw<ArgumentNullException>(() => new ImapCommandProcessor(null!, options, NullLogger.Instance));
        Should.Throw<ArgumentNullException>(() => new ImapCommandProcessor(Session(), null!, NullLogger.Instance));
        Should.Throw<ArgumentNullException>(() => new ImapCommandProcessor(Session(), options, null!));
    }

    [Fact]
    public async Task Executing_a_null_command_is_refused()
    {
        await Should.ThrowAsync<ArgumentNullException>(
            async () => await Processor().ExecuteAsync(null!, CancellationToken.None));
    }
    // ---------------------------------------------------------------------------------------
    // LIST and LSUB.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A mailbox with a little of everything: nested folders, an unsubscribed one, a
    /// special-use one, and a level that exists only as a parent.
    /// </summary>
    private static async Task<ImapCommandProcessor> ListableAsync()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Add(authenticator.KnownMailboxId, "Sent", specialUse: FolderSpecialUse.Sent)
            .Add(authenticator.KnownMailboxId, "Projects/2026")
            .Add(authenticator.KnownMailboxId, "Projects/2026/Q1")
            .Add(authenticator.KnownMailboxId, "Archive", subscribed: false);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        return processor;
    }

    /// <summary>
    /// RFC 3501 §6.3.8's own worked exchange: C: A101 LIST "" "" answered with
    /// S: * LIST (\Noselect) "/" "". The first thing most clients send.
    /// </summary>
    [Fact]
    public async Task The_empty_pattern_is_answered_with_the_hierarchy_delimiter()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"\" \"\""));

        wire.ShouldBe("* LIST (\\Noselect) \"/\" \"\"\r\na1 OK LIST completed\r\n");
    }

    [Fact]
    public async Task The_empty_pattern_is_answered_for_lsub_too()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LSUB \"\" \"\""));

        wire.ShouldBe("* LSUB (\\Noselect) \"/\" \"\"\r\na1 OK LSUB completed\r\n");
    }

    /// <summary>
    /// '*' matches across the delimiter, so everything the mailbox holds is reported — including
    /// the unsubscribed folder, which LIST does not filter on.
    /// </summary>
    [Fact]
    public async Task A_star_pattern_lists_every_folder()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"\" \"*\""));

        wire.ShouldBe(
            "* LIST (\\HasNoChildren) \"/\" Archive\r\n" +
            "* LIST (\\HasNoChildren) \"/\" INBOX\r\n" +
            "* LIST (\\HasChildren) \"/\" Projects/2026\r\n" +
            "* LIST (\\HasNoChildren) \"/\" Projects/2026/Q1\r\n" +
            "* LIST (\\HasNoChildren \\Sent) \"/\" Sent\r\n" +
            "a1 OK LIST completed\r\n");
    }

    /// <summary>
    /// The rule from §6.3.8 that a naive implementation misses: "If the "%" wildcard is the last
    /// character of a mailbox name argument, matching levels of hierarchy are also returned. If
    /// these levels of hierarchy are not also selectable mailboxes, they are returned with the
    /// \Noselect mailbox name attribute." No folder here is called Projects, and a client that
    /// was not told about it would show a tree with Projects/2026 unreachable.
    /// </summary>
    [Fact]
    public async Task A_trailing_percent_reports_a_hierarchy_level_that_is_not_a_mailbox()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"\" \"%\""));

        wire.ShouldBe(
            "* LIST (\\HasNoChildren) \"/\" Archive\r\n" +
            "* LIST (\\HasNoChildren) \"/\" INBOX\r\n" +
            "* LIST (\\Noselect \\HasChildren) \"/\" Projects\r\n" +
            "* LIST (\\HasNoChildren \\Sent) \"/\" Sent\r\n" +
            "a1 OK LIST completed\r\n");
    }

    /// <summary>
    /// '%' does not cross the delimiter, so the grandchild is not reported at this level.
    /// </summary>
    [Fact]
    public async Task A_percent_does_not_descend_past_one_level()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"\" \"Projects/%\""));

        wire.ShouldBe(
            "* LIST (\\HasChildren) \"/\" Projects/2026\r\n" +
            "a1 OK LIST completed\r\n");
    }

    /// <summary>
    /// A real folder that is also a hierarchy level keeps its own attributes: it must not be
    /// overwritten with \Noselect, because it genuinely can be selected.
    /// </summary>
    [Fact]
    public async Task A_level_that_is_a_real_mailbox_is_not_marked_unselectable()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "Projects")
            .Add(authenticator.KnownMailboxId, "Projects/2026");

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 LIST \"\" \"%\"")).ShouldBe(
            "* LIST (\\HasChildren) \"/\" Projects\r\n" +
            "a1 OK LIST completed\r\n");
    }

    /// <summary>
    /// RFC 3501 §9: list-mailbox = 1*list-char / string, and list-char admits the wildcards. A
    /// client sending the pattern unquoted is conformant, and this is the case a reader built
    /// only for astring would reject.
    /// </summary>
    [Fact]
    public async Task An_unquoted_wildcard_pattern_is_accepted()
    {
        string quoted = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"\" \"*\""));
        string bare = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"\" *"));

        bare.ShouldBe(quoted);
    }

    /// <summary>
    /// §6.3.8: the reference is prepended, and the names that come back are full names — "Any
    /// part of the reference argument that is included in the interpreted form SHOULD prefix the
    /// interpreted form".
    /// </summary>
    [Fact]
    public async Task A_reference_is_prepended_and_the_names_come_back_in_full()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"Projects/\" \"*\""));

        wire.ShouldBe(
            "* LIST (\\HasChildren) \"/\" Projects/2026\r\n" +
            "* LIST (\\HasNoChildren) \"/\" Projects/2026/Q1\r\n" +
            "a1 OK LIST completed\r\n");
    }

    [Fact]
    public async Task A_pattern_matching_nothing_is_an_ok_with_no_data()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"\" \"Nowhere*\""));

        wire.ShouldBe("a1 OK LIST completed\r\n");
    }

    /// <summary>
    /// LSUB reports the subscription list, so the unsubscribed folder is absent from it while
    /// LIST reports it.
    /// </summary>
    [Fact]
    public async Task Lsub_omits_a_folder_that_is_not_subscribed()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LSUB \"\" \"*\""));

        wire.ShouldNotContain("Archive");
        wire.ShouldContain("INBOX");
        wire.ShouldEndWith("a1 OK LSUB completed\r\n");
    }

    /// <summary>
    /// RFC 3501 §6.3.9's MUST, and the one genuinely surprising rule in either command:
    /// "Consider what happens if "foo/bar" […] is subscribed but "foo" is not. A "%" wildcard to
    /// LSUB must return foo, not foo/bar, in the LSUB response, and it MUST be flagged with the
    /// \Noselect attribute." Note that foo is a real, selectable mailbox here — in LSUB the
    /// attribute reports absence from the subscription list, not unselectability.
    /// </summary>
    [Fact]
    public async Task Lsub_flags_an_unsubscribed_ancestor_of_a_subscribed_folder_noselect()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "foo", subscribed: false)
            .Add(authenticator.KnownMailboxId, "foo/bar", subscribed: true);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 LSUB \"\" \"%\"")).ShouldBe(
            "* LSUB (\\Noselect \\HasChildren) \"/\" foo\r\n" +
            "a1 OK LSUB completed\r\n");
    }

    /// <summary>
    /// The same mailbox through LIST, where foo is selectable and says so. §6.3.9: "the flags in
    /// the untagged LIST are considered more authoritative."
    /// </summary>
    [Fact]
    public async Task List_reports_the_same_ancestor_as_selectable()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "foo", subscribed: false)
            .Add(authenticator.KnownMailboxId, "foo/bar", subscribed: true);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 LIST \"\" \"%\"")).ShouldBe(
            "* LIST (\\HasChildren) \"/\" foo\r\n" +
            "a1 OK LIST completed\r\n");
    }

    /// <summary>
    /// LSUB derives its hierarchy levels from the subscribed subset. Taking them from every
    /// folder would tell a client about folders the user has not subscribed to, through the one
    /// command that is supposed to be about the subscription list.
    /// </summary>
    [Fact]
    public async Task Lsub_does_not_reveal_a_level_that_only_unsubscribed_folders_create()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "Secret/Plans", subscribed: false);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 LSUB \"\" \"%\""))
            .ShouldBe("a1 OK LSUB completed\r\n");
    }

    /// <summary>
    /// The authorisation boundary: the enumeration is scoped to the authenticated mailbox, so
    /// another mailbox's folders cannot appear however the pattern is written.
    /// </summary>
    [Fact]
    public async Task Another_mailboxs_folders_are_never_listed()
    {
        ScriptedImapAuthenticator authenticator = new();
        MailboxId somebodyElse = new(Guid.NewGuid());

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX")
            .Add(somebodyElse, "Payroll");

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        string wire = Wire(await ExecuteAsync(processor, "a1 LIST \"\" \"*\""));

        wire.ShouldNotContain("Payroll");
        mailboxes.Listed.ShouldBe([authenticator.KnownMailboxId.Value]);
    }

    [Theory]
    [InlineData("a1 LIST")]
    [InlineData("a1 LIST \"\"")]
    [InlineData("a1 LIST \"\" \"*\" extra")]
    public async Task A_malformed_list_earns_a_tagged_bad(string line)
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), line));

        wire.ShouldContain("a1 BAD ");
        wire.ShouldContain("reference name and a mailbox pattern");
    }

    /// <summary>
    /// A name that does not decode names no folder, and is refused without being quoted back:
    /// a malformed name is the client's own text.
    /// </summary>
    [Fact]
    public async Task A_pattern_that_is_not_modified_utf7_is_refused_without_being_echoed()
    {
        string wire = Wire(await ExecuteAsync(await ListableAsync(), "a1 LIST \"\" \"&Jj_-\""));

        wire.ShouldContain("a1 NO ");
        wire.ShouldContain("modified UTF-7");
        wire.ShouldNotContain("&Jj_-");
    }

    // ---------------------------------------------------------------------------------------
    // STATUS.
    // ---------------------------------------------------------------------------------------

    /// <summary>RFC 3501 §6.3.10's own example, with this server's own numbers.</summary>
    [Fact]
    public async Task Status_reports_the_items_asked_for()
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync(
            existsCount: 231,
            uidValidity: 3_857_529_045,
            nextUid: 44_292);

        Wire(await ExecuteAsync(processor, "a1 STATUS INBOX (UIDNEXT MESSAGES)")).ShouldBe(
            "* STATUS INBOX (UIDNEXT 44292 MESSAGES 231)\r\n" +
            "a1 OK STATUS completed\r\n");
    }

    /// <summary>
    /// §6.3.10: STATUS "does not change the currently selected mailbox". A session that had a
    /// mailbox open must still have it open afterwards, which is what a following command proves.
    /// </summary>
    [Fact]
    public async Task Status_leaves_the_selected_mailbox_alone()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 3)
            .Add(authenticator.KnownMailboxId, "Archive", existsCount: 9);

        ImapSessionContext session = Session();

        ImapCommandProcessor processor = Processor(
            session: session,
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        MailboxFolderId? before = session.SelectedFolderId;

        await ExecuteAsync(processor, "a2 STATUS Archive (MESSAGES)");

        session.SelectedFolderId.ShouldBe(before);
        session.State.ShouldBe(ImapSessionState.Selected);
    }

    /// <summary>
    /// STATUS's UNSEEN is a count and SELECT's [UNSEEN n] is a sequence number — RFC 3501
    /// §6.3.10 against §6.3.1. The same folder answering both differently is the assertion.
    /// </summary>
    [Fact]
    public async Task Status_unseen_is_a_count_where_select_unseen_is_a_position()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(
                authenticator.KnownMailboxId,
                "INBOX",
                existsCount: 12,
                firstUnseen: 12,
                unseenCount: 1);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 SELECT INBOX")).ShouldContain("[UNSEEN 12]");
        Wire(await ExecuteAsync(processor, "a2 STATUS INBOX (UNSEEN)"))
            .ShouldContain("(UNSEEN 1)");
    }

    [Fact]
    public async Task Status_for_a_folder_that_is_not_there_is_a_tagged_no()
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a1 STATUS Nowhere (MESSAGES)"));

        wire.ShouldContain("a1 NO ");
        wire.ShouldContain("No such mailbox");
    }

    /// <summary>
    /// §9 requires at least one status-att, so an empty list is a syntax error rather than a
    /// request for nothing.
    /// </summary>
    [Theory]
    [InlineData("a1 STATUS INBOX ()")]
    [InlineData("a1 STATUS INBOX")]
    [InlineData("a1 STATUS INBOX (NONSENSE)")]
    [InlineData("a1 STATUS INBOX MESSAGES")]
    [InlineData("a1 STATUS")]
    public async Task A_malformed_status_earns_a_tagged_bad(string line)
    {
        (ImapCommandProcessor processor, _) = await SelectableAsync();

        Wire(await ExecuteAsync(processor, line)).ShouldContain("a1 BAD ");
    }

    /// <summary>
    /// The mailbox is scoped to the authenticated identity, so another mailbox's folder is "no
    /// such mailbox" rather than a set of counts.
    /// </summary>
    [Fact]
    public async Task Status_cannot_read_another_mailboxs_folder()
    {
        ScriptedImapAuthenticator authenticator = new();
        MailboxId somebodyElse = new(Guid.NewGuid());

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX")
            .Add(somebodyElse, "Payroll", existsCount: 500);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 STATUS Payroll (MESSAGES)"))
            .ShouldContain("No such mailbox");
    }
    // ---------------------------------------------------------------------------------------
    // FETCH.
    // ---------------------------------------------------------------------------------------

    /// <summary>A session with INBOX selected and four messages in it, at non-contiguous UIDs.</summary>
    /// <remarks>
    /// The gaps are deliberate. UIDs are never reused, so a folder that has ever been expunged
    /// has them — and a sequence number is a position in what remains rather than a UID, which is
    /// the distinction every FETCH assertion below depends on.
    /// </remarks>
    private static async Task<ImapCommandProcessor> FetchableAsync()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 4)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 3, 7, 11, 19);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        return processor;
    }

    [Fact]
    public async Task Fetch_reports_one_line_per_message_in_sequence_order()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 FETCH 1:* UID"));

        wire.ShouldBe(
            "* 1 FETCH (UID 3)\r\n" +
            "* 2 FETCH (UID 7)\r\n" +
            "* 3 FETCH (UID 11)\r\n" +
            "* 4 FETCH (UID 19)\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// A sequence number is a position, so FETCH 2 is the second message however far its UID is
    /// from 2.
    /// </summary>
    [Fact]
    public async Task A_sequence_number_names_a_position_and_not_a_uid()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 FETCH 2 UID"));

        wire.ShouldBe("* 2 FETCH (UID 7)\r\na2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// RFC 3501 §6.4.8: "the numbers in the sequence set argument are unique identifiers instead
    /// of message sequence numbers". The same number means a different message under UID FETCH.
    /// </summary>
    [Fact]
    public async Task Uid_fetch_reads_the_numbers_as_uids()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 UID FETCH 7 FLAGS"));

        wire.ShouldBe("* 2 FETCH (FLAGS (\\Seen) UID 7)\r\na2 OK UID FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.8's MUST: "server implementations MUST implicitly include the UID message data item
    /// as part of any FETCH response caused by a UID command, regardless of whether a UID was
    /// specified as a message data item to the FETCH." Without it a client using UIDs has no way
    /// to tell which message a line is about.
    /// </summary>
    [Fact]
    public async Task Uid_fetch_includes_the_uid_even_when_it_was_not_asked_for()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 UID FETCH 1:* FLAGS"));

        wire.ShouldContain("* 1 FETCH (FLAGS (\\Seen) UID 3)");
        wire.ShouldContain("* 4 FETCH (FLAGS (\\Seen) UID 19)");
    }

    /// <summary>The plain form adds nothing the client did not ask for.</summary>
    [Fact]
    public async Task Plain_fetch_does_not_add_a_uid()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 FETCH 1 FLAGS"));

        wire.ShouldBe("* 1 FETCH (FLAGS (\\Seen))\r\na2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.8: "A non-existent unique identifier is ignored without any error message generated.
    /// Thus, it is possible for a UID FETCH command to return an OK without any data." A tagged
    /// NO would have a client report a failure for a message it had already deleted.
    /// </summary>
    [Theory]
    [InlineData("a2 UID FETCH 5 FLAGS")]
    [InlineData("a2 UID FETCH 100:200 FLAGS")]
    [InlineData("a2 FETCH 99 FLAGS")]
    public async Task A_message_that_is_not_there_is_passed_over_in_silence(string line)
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), line));

        wire.ShouldNotContain(" FETCH (");
        wire.ShouldContain(" OK ");
    }

    /// <summary>
    /// §6.4.5: "FAST — Macro equivalent to: (FLAGS INTERNALDATE RFC822.SIZE)", and every item in
    /// it is a stored column, so it is answerable today.
    /// </summary>
    [Fact]
    public async Task The_fast_macro_is_answered_in_full()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 FETCH 1 FAST"));

        wire.ShouldBe(
            "* 1 FETCH (FLAGS (\\Seen) INTERNALDATE \" 1-Mar-2026 09:30:15 +0000\" " +
            "RFC822.SIZE 300)\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.5 distinguishes "BAD - command unknown or arguments invalid" from "NO - fetch error:
    /// can't fetch that data". ENVELOPE is the second, and saying so by name beats a partial
    /// response a client cannot tell from a message with no envelope.
    /// </summary>
    [Theory]
    [InlineData("a2 FETCH 1 ENVELOPE", "ENVELOPE")]
    [InlineData("a2 FETCH 1 BODYSTRUCTURE", "BODYSTRUCTURE")]
    [InlineData("a2 FETCH 1 RFC822", "RFC822")]
    [InlineData("a2 FETCH 1 (FLAGS ENVELOPE)", "ENVELOPE")]
    [InlineData("a2 FETCH 1 ALL", "ENVELOPE")]
    [InlineData("a2 FETCH 1 FULL", "ENVELOPE")]
    public async Task An_item_needing_a_mime_reader_is_refused_by_name(string line, string item)
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), line));

        wire.ShouldContain("a2 NO ");
        wire.ShouldContain(item);
        wire.ShouldContain("not implemented yet");
        wire.ShouldNotContain(" FETCH (");
    }

    [Fact]
    public async Task A_body_section_is_refused_by_name()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 FETCH 1 BODY[HEADER]"));

        wire.ShouldContain("a2 NO ");
        wire.ShouldContain("not implemented yet");
    }

    [Theory]
    [InlineData("a2 FETCH")]
    [InlineData("a2 FETCH 1")]
    [InlineData("a2 FETCH 1 ()")]
    [InlineData("a2 FETCH 1 (FAST)")]
    [InlineData("a2 FETCH 1 NONSENSE")]
    [InlineData("a2 FETCH nonsense FLAGS")]
    [InlineData("a2 FETCH 0 FLAGS")]
    public async Task A_malformed_fetch_earns_a_tagged_bad(string line) =>
        Wire(await ExecuteAsync(await FetchableAsync(), line)).ShouldContain("a2 BAD ");

    /// <summary>
    /// FETCH is a selected-state command, and the state machine refuses it earlier — so this is
    /// about the handler's own second line of defence rather than the ordinary path.
    /// </summary>
    [Fact]
    public async Task Fetch_without_a_selected_mailbox_is_refused()
    {
        ScriptedImapAuthenticator authenticator = new();

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: new ScriptedImapMailboxReader().Add(authenticator.KnownMailboxId, "INBOX"));

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 FETCH 1 FLAGS")).ShouldContain(" BAD ");
    }

    /// <summary>
    /// The read is scoped to the authenticated mailbox as well as the selected folder — a folder
    /// id alone is a value a session hands back, and must not be enough to reach mail.
    /// </summary>
    [Fact]
    public async Task A_fetch_is_scoped_to_the_authenticated_mailbox()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 3);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, "a2 FETCH 1 UID");

        mailboxes.Read.ShouldAllBe(r => r.Mailbox == authenticator.KnownMailboxId.Value);
        mailboxes.Read.ShouldNotBeEmpty();
    }
    // ---------------------------------------------------------------------------------------
    // STORE.
    // ---------------------------------------------------------------------------------------

    /// <summary>A selected, writable INBOX holding four messages with mixed flags.</summary>
    private static async Task<(
        ImapCommandProcessor Processor,
        ScriptedImapMailboxReader Store,
        ScriptedImapAuthenticator Authenticator)>
        StorableAsync(bool readOnly = false)
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 4)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 3, 7, 11, 19);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, readOnly ? "a1 EXAMINE INBOX" : "a1 SELECT INBOX");

        return (processor, mailboxes, authenticator);
    }

    /// <summary>
    /// RFC 3501 §6.4.6: "Normally, STORE will return the updated value of the data with an
    /// untagged FETCH response." Every message the set names gets a line, whether or not its
    /// flags changed — the response is "the new value", not "what changed".
    /// </summary>
    [Fact]
    public async Task Store_reports_the_new_value_of_every_message_it_names()
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        string wire = Wire(await ExecuteAsync(processor, @"a2 STORE 1:2 +FLAGS (\Deleted)"));

        wire.ShouldBe(
            "* 1 FETCH (FLAGS (\\Seen \\Deleted))\r\n" +
            "* 2 FETCH (FLAGS (\\Seen \\Deleted))\r\n" +
            "a2 OK STORE completed\r\n");
    }

    /// <summary>
    /// The value reported is what was written, not what was asked for — proved by storing a flag
    /// that was already set and seeing the whole resulting set rather than just the argument.
    /// </summary>
    [Fact]
    public async Task The_reported_value_is_the_result_and_not_the_argument()
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        Wire(await ExecuteAsync(processor, @"a2 STORE 1 +FLAGS (\Seen)"))
            .ShouldBe("* 1 FETCH (FLAGS (\\Seen))\r\na2 OK STORE completed\r\n");
    }

    [Fact]
    public async Task Replace_takes_the_argument_wholesale_over_the_wire()
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        Wire(await ExecuteAsync(processor, @"a2 STORE 1 FLAGS (\Draft)"))
            .ShouldBe("* 1 FETCH (FLAGS (\\Draft))\r\na2 OK STORE completed\r\n");
    }

    [Fact]
    public async Task Remove_takes_away_only_what_it_names()
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        Wire(await ExecuteAsync(processor, @"a2 STORE 1 -FLAGS (\Seen)"))
            .ShouldBe("* 1 FETCH (FLAGS ())\r\na2 OK STORE completed\r\n");
    }

    /// <summary>
    /// §6.4.6: ".SILENT" "prevents the untagged FETCH". It suppresses the report and nothing
    /// else — the write still happens, which the following FETCH proves.
    /// </summary>
    [Fact]
    public async Task Silent_suppresses_the_report_but_not_the_write()
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        Wire(await ExecuteAsync(processor, @"a2 STORE 1 +FLAGS.SILENT (\Deleted)"))
            .ShouldBe("a2 OK STORE completed\r\n");

        Wire(await ExecuteAsync(processor, "a3 FETCH 1 FLAGS"))
            .ShouldContain("(FLAGS (\\Seen \\Deleted))");
    }

    /// <summary>
    /// §6.4.8's MUST covers "any FETCH response caused by a UID command", and its own note names
    /// UID STORE among them.
    /// </summary>
    [Fact]
    public async Task Uid_store_includes_the_uid_on_every_line()
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        Wire(await ExecuteAsync(processor, @"a2 UID STORE 7 +FLAGS (\Flagged)"))
            .ShouldBe(
                "* 2 FETCH (FLAGS (\\Seen \\Flagged) UID 7)\r\n" +
                "a2 OK UID STORE completed\r\n");
    }

    /// <summary>
    /// §6.3.2: an EXAMINE'd mailbox is read-only and "No changes to the permanent state of the
    /// mailbox, including per-user state, are permitted". The client was told twice already —
    /// [PERMANENTFLAGS ()] and a [READ-ONLY] completion — so this is a tagged NO rather than a
    /// silently discarded write.
    /// </summary>
    [Fact]
    public async Task Store_on_a_read_only_mailbox_is_refused()
    {
        (ImapCommandProcessor processor, ScriptedImapMailboxReader store, _) =
            await StorableAsync(readOnly: true);

        string wire = Wire(await ExecuteAsync(processor, @"a2 STORE 1 +FLAGS (\Deleted)"));

        wire.ShouldContain("a2 NO ");
        wire.ShouldContain("read-only");
        wire.ShouldNotContain(" FETCH (");

        // Refused before it reached the writer, not attempted and rolled back.
        store.Stored.ShouldBeEmpty();
    }

    /// <summary>
    /// §7.1: "the server will either ignore the change or store the state change for the
    /// remainder of the current session only". Ignoring is sanctioned, and the untagged FETCH
    /// shows the client exactly what it got.
    /// </summary>
    [Fact]
    public async Task A_keyword_this_server_cannot_store_is_ignored_rather_than_refused()
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 STORE 1 +FLAGS ($Junk)"));

        wire.ShouldContain("a2 OK ");
        wire.ShouldContain("* 1 FETCH (FLAGS (\\Seen))");
        wire.ShouldNotContain("$Junk");
    }

    /// <summary>§6.4.8: a number naming no message is ignored without an error.</summary>
    [Theory]
    [InlineData(@"a2 STORE 99 +FLAGS (\Seen)")]
    [InlineData(@"a2 UID STORE 5 +FLAGS (\Seen)")]
    public async Task Storing_to_a_message_that_is_not_there_is_an_ok_with_no_data(string line)
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        string wire = Wire(await ExecuteAsync(processor, line));

        wire.ShouldNotContain(" FETCH (");
        wire.ShouldContain(" OK ");
    }

    [Theory]
    [InlineData("a2 STORE")]
    [InlineData("a2 STORE 1")]
    [InlineData(@"a2 STORE 1 FLAGS")]
    [InlineData(@"a2 STORE 1 NONSENSE (\Seen)")]
    [InlineData(@"a2 STORE nonsense +FLAGS (\Seen)")]
    [InlineData(@"a2 STORE 0 +FLAGS (\Seen)")]
    [InlineData(@"a2 STORE 1 +FLAGS (\Seen")]
    public async Task A_malformed_store_earns_a_tagged_bad(string line)
    {
        (ImapCommandProcessor processor, _, _) = await StorableAsync();

        Wire(await ExecuteAsync(processor, line)).ShouldContain("a2 BAD ");
    }

    [Fact]
    public async Task Store_without_a_selected_mailbox_is_refused()
    {
        ScriptedImapAuthenticator authenticator = new();

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: new ScriptedImapMailboxReader().Add(authenticator.KnownMailboxId, "INBOX"));

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, @"a1 STORE 1 +FLAGS (\Seen)")).ShouldContain(" BAD ");
    }

    /// <summary>The write is scoped to the authenticated mailbox as well as the selected folder.</summary>
    [Fact]
    public async Task A_store_is_scoped_to_the_authenticated_mailbox()
    {
        (ImapCommandProcessor processor,
         ScriptedImapMailboxReader store,
         ScriptedImapAuthenticator authenticator) = await StorableAsync();

        await ExecuteAsync(processor, @"a2 STORE 1 +FLAGS (\Deleted)");

        store.Stored.ShouldNotBeEmpty();
        store.Stored.ShouldAllBe(s => s.Mailbox == authenticator.KnownMailboxId.Value);
    }
}
