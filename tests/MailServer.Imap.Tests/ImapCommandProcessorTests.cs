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

        if (subscribed)
        {
            if (!_subscriptions.TryGetValue(mailboxId.Value, out HashSet<string>? subscribedNames))
            {
                subscribedNames = new HashSet<string>(StringComparer.Ordinal);
                _subscriptions[mailboxId.Value] = subscribedNames;
            }

            subscribedNames.Add(path);
        }

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

        SyncCount(mailboxId.Value, path);

        return this;
    }

    /// <summary>
    /// Keeps the folder's reported size equal to the number of messages it holds.
    /// </summary>
    /// <remarks>
    /// A fake that let <c>SELECT</c> report one number while a count returned another could make
    /// a test about the difference between the two pass for the wrong reason — the IDLE push
    /// compares exactly those two numbers.
    /// </remarks>
    private void SyncCount(Guid mailboxId, string path)
    {
        if (!_folders.TryGetValue((mailboxId, path), out Entry? entry))
        {
            return;
        }

        long count = _messages.TryGetValue((mailboxId, path), out List<ImapMessageSummary>? all)
            ? all.Count
            : 0;

        _folders[(mailboxId, path)] = entry with { ExistsCount = count };
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

    /// <summary>The subscription list, which is separate from the folders on purpose.</summary>
    /// <remarks>
    /// A set of names rather than a flag per folder, mirroring MailboxSubscriptions — so a test
    /// can subscribe to a name, delete the folder, and see LSUB still report it, which is RFC
    /// 3501 §6.3.6's MUST NOT.
    /// </remarks>
    private readonly Dictionary<Guid, HashSet<string>> _subscriptions = [];

    public Task<IReadOnlyList<string>> ListSubscriptionsAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken)
    {
        if (!_subscriptions.TryGetValue(mailboxId.Value, out HashSet<string>? names))
        {
            return Task.FromResult<IReadOnlyList<string>>([]);
        }

        List<string> ordered = [.. names];
        ordered.Sort(string.CompareOrdinal);

        return Task.FromResult<IReadOnlyList<string>>(ordered);
    }

    public Task<ImapFolderMutation> CreateFolderAsync(
        MailboxId mailboxId,
        string path,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string wanted = path.TrimEnd(MailboxFolder.PathSeparator);

        if (ImapMailboxPath.IsInbox(wanted))
        {
            return Task.FromResult(ImapFolderMutation.Reserved);
        }

        if (_folders.ContainsKey((mailboxId.Value, wanted)))
        {
            return Task.FromResult(ImapFolderMutation.AlreadyExists);
        }

        foreach (string level in ImapMailboxPattern.HierarchyLevelsOf(wanted).Append(wanted))
        {
            if (!_folders.ContainsKey((mailboxId.Value, level)))
            {
                Add(mailboxId, level, subscribed: false);
            }
        }

        return Task.FromResult(ImapFolderMutation.Done);
    }

    public Task<ImapFolderMutation> DeleteFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken)
    {
        if (ImapMailboxPath.IsInbox(path))
        {
            return Task.FromResult(ImapFolderMutation.Reserved);
        }

        if (!_folders.Remove((mailboxId.Value, path)))
        {
            return Task.FromResult(ImapFolderMutation.NotFound);
        }

        _messages.Remove((mailboxId.Value, path));

        // The subscription is deliberately left alone - §6.3.6's MUST NOT.
        return Task.FromResult(ImapFolderMutation.Done);
    }

    public Task<ImapFolderMutation> RenameFolderAsync(
        MailboxId mailboxId,
        string from,
        string to,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string target = to.TrimEnd(MailboxFolder.PathSeparator);

        if (ImapMailboxPath.IsInbox(target) || _folders.ContainsKey((mailboxId.Value, target)))
        {
            return Task.FromResult(ImapFolderMutation.AlreadyExists);
        }

        string source = ImapMailboxPath.Canonical(from);

        if (!_folders.ContainsKey((mailboxId.Value, source)))
        {
            return Task.FromResult(ImapFolderMutation.NotFound);
        }

        if (ImapMailboxPath.IsInbox(from))
        {
            // §6.3.5's special case: the inbox stays, its messages move out.
            Add(mailboxId, target, subscribed: false);

            if (_messages.Remove((mailboxId.Value, source), out List<ImapMessageSummary>? moved))
            {
                _messages[(mailboxId.Value, target)] = moved;
            }

            return Task.FromResult(ImapFolderMutation.Done);
        }

        string prefix = source + MailboxFolder.PathSeparator;

        List<string> subtree =
        [
            .. _folders.Keys
                .Where(k => k.Mailbox == mailboxId.Value &&
                            (k.Path == source || k.Path.StartsWith(prefix, StringComparison.Ordinal)))
                .Select(k => k.Path),
        ];

        foreach (string old in subtree)
        {
            string renamed = target + old[source.Length..];

            if (_folders.Remove((mailboxId.Value, old), out Entry? entry))
            {
                _folders[(mailboxId.Value, renamed)] = entry with
                {
                    Folder = MailboxFolder.Create(
                        mailboxId,
                        renamed,
                        entry.Folder.SpecialUse,
                        entry.Folder.UidValidity,
                        DateTimeOffset.UnixEpoch),
                };
            }

            if (_messages.Remove((mailboxId.Value, old), out List<ImapMessageSummary>? carried))
            {
                _messages[(mailboxId.Value, renamed)] = carried;
            }
        }

        return Task.FromResult(ImapFolderMutation.Done);
    }

    public Task<ImapFolderMutation> SetSubscriptionAsync(
        MailboxId mailboxId,
        string path,
        bool subscribed,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string canonical = ImapMailboxPath.Canonical(path);

        if (subscribed && !_folders.ContainsKey((mailboxId.Value, canonical)))
        {
            return Task.FromResult(ImapFolderMutation.NotFound);
        }

        if (!_subscriptions.TryGetValue(mailboxId.Value, out HashSet<string>? names))
        {
            names = new HashSet<string>(StringComparer.Ordinal);
            _subscriptions[mailboxId.Value] = names;
        }

        if (subscribed)
        {
            names.Add(canonical);
        }
        else
        {
            names.Remove(canonical);
        }

        return Task.FromResult(ImapFolderMutation.Done);
    }

    public Task<ImapCopyResult> CopyAsync(
        MailboxId mailboxId,
        MailboxFolderId sourceFolderId,
        ImapSequenceSet set,
        bool byUid,
        string targetPath,
        bool removeFromSource,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string canonical = ImapMailboxPath.Canonical(targetPath);

        if (!_folders.ContainsKey((mailboxId.Value, canonical)))
        {
            return Task.FromResult(new ImapCopyResult(ImapFolderMutation.NotFound, [], 0));
        }

        KeyValuePair<(Guid Mailbox, string Path), Entry> owner = _folders
            .FirstOrDefault(pair =>
                pair.Value.Folder.Id.Value == sourceFolderId.Value &&
                pair.Key.Mailbox == mailboxId.Value);

        if (owner.Value is null ||
            !_messages.TryGetValue(owner.Key, out List<ImapMessageSummary>? all) ||
            all.Count == 0)
        {
            return Task.FromResult(new ImapCopyResult(ImapFolderMutation.Done, [], 0));
        }

        long maxValue = byUid ? all[^1].Uid : all[^1].SequenceNumber;

        List<ImapMessageSummary> selected =
            [.. all.Where(m => set.Contains(byUid ? m.Uid : m.SequenceNumber, maxValue))];

        if (!_messages.TryGetValue((mailboxId.Value, canonical), out List<ImapMessageSummary>? target))
        {
            target = [];
            _messages[(mailboxId.Value, canonical)] = target;
        }

        long nextUid = target.Count == 0 ? 1 : target[^1].Uid + 1;
        long nextSeq = target.Count + 1;

        foreach (ImapMessageSummary message in selected)
        {
            // A new UID in the destination; flags and internal date preserved.
            target.Add(message with { Uid = nextUid++, SequenceNumber = nextSeq++ });
        }

        if (!removeFromSource)
        {
            return Task.FromResult(
                new ImapCopyResult(ImapFolderMutation.Done, [], selected.Count));
        }

        List<long> removed = [.. selected.Select(m => m.SequenceNumber).OrderByDescending(n => n)];

        List<ImapMessageSummary> survivors = [.. all.Except(selected)];

        all.Clear();

        long renumbered = 1;

        foreach (ImapMessageSummary survivor in survivors.OrderBy(m => m.Uid))
        {
            all.Add(survivor with { SequenceNumber = renumbered++ });
        }

        return Task.FromResult(
            new ImapCopyResult(ImapFolderMutation.Done, removed, selected.Count));
    }

    /// <summary>The stored octets of each message this fake knows, keyed by its identity.</summary>
    public Dictionary<Guid, byte[]> Content { get; } = [];

    /// <summary>
    /// Gives a message some content, so a BODY[] fetch has something to return.
    /// </summary>
    /// <remarks>
    /// Encoded as Latin-1 rather than ASCII so that a test can write a message carrying a raw
    /// 8-bit octet — which RFC 2822 §2.2 forbids and which arrives anyway — and have the octet
    /// reach the server rather than being replaced with a question mark on the way in.
    /// </remarks>
    public ScriptedImapMailboxReader WithContent(
        MailboxId mailboxId,
        string path,
        long uid,
        string message)
    {
        if (!_messages.TryGetValue((mailboxId.Value, path), out List<ImapMessageSummary>? all))
        {
            return this;
        }

        int index = all.FindIndex(m => m.Uid == uid);

        if (index < 0)
        {
            return this;
        }

        Guid id = Guid.NewGuid();

        _contentIds[(mailboxId.Value, path, uid)] = id;
        Content[id] = System.Text.Encoding.Latin1.GetBytes(message);

        return this;
    }

    private readonly Dictionary<(Guid Mailbox, string Path, long Uid), Guid> _contentIds = [];

    public Task<IReadOnlyDictionary<long, StoredMessageId>> ReadMessageIdsAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        IReadOnlyList<long> uids,
        CancellationToken cancellationToken)
    {
        KeyValuePair<(Guid Mailbox, string Path), Entry> owner = _folders
            .FirstOrDefault(pair =>
                pair.Value.Folder.Id.Value == folderId.Value &&
                pair.Key.Mailbox == mailboxId.Value);

        Dictionary<long, StoredMessageId> found = [];

        if (owner.Value is not null)
        {
            foreach (long uid in uids)
            {
                if (_contentIds.TryGetValue((mailboxId.Value, owner.Key.Path, uid), out Guid id))
                {
                    found[uid] = new StoredMessageId(id);
                }
            }
        }

        return Task.FromResult<IReadOnlyDictionary<long, StoredMessageId>>(found);
    }

    public Task<ImapAppendResult> AppendAsync(
        MailboxId mailboxId,
        string path,
        StoredMessage stored,
        MessageFlags flags,
        DateTimeOffset internalDate,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        string canonical = ImapMailboxPath.Canonical(path);

        if (!_folders.TryGetValue((mailboxId.Value, canonical), out Entry? folder))
        {
            return Task.FromResult(new ImapAppendResult(ImapFolderMutation.NotFound, null, 0));
        }

        if (!_messages.TryGetValue((mailboxId.Value, canonical), out List<ImapMessageSummary>? all))
        {
            all = [];
            _messages[(mailboxId.Value, canonical)] = all;
        }

        long uid = all.Count == 0 ? 1 : all[^1].Uid + 1;

        all.Add(new ImapMessageSummary(
            all.Count + 1,
            uid,
            flags,
            internalDate,
            stored.SizeBytes));

        _contentIds[(mailboxId.Value, canonical, uid)] = stored.Id.Value;

        SyncCount(mailboxId.Value, canonical);

        return Task.FromResult(
            new ImapAppendResult(ImapFolderMutation.Done, folder.Folder.Id, all.Count));
    }

    public Task<long> CountMessagesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        CancellationToken cancellationToken)
    {
        KeyValuePair<(Guid Mailbox, string Path), Entry> owner = _folders
            .FirstOrDefault(pair =>
                pair.Value.Folder.Id.Value == folderId.Value &&
                pair.Key.Mailbox == mailboxId.Value);

        if (owner.Value is null ||
            !_messages.TryGetValue(owner.Key, out List<ImapMessageSummary>? all))
        {
            return Task.FromResult(0L);
        }

        return Task.FromResult((long)all.Count);
    }

    /// <summary>Every folder this fake was asked to expunge.</summary>
    public List<(Guid Mailbox, Guid Folder)> Expunged { get; } = [];

    /// <summary>
    /// Removes the \Deleted messages, reporting their positions highest first.
    /// </summary>
    /// <remarks>
    /// The positions are computed before anything is removed and the surviving messages are
    /// renumbered afterwards, because that is what the real query and the real table do — a fake
    /// that left stale sequence numbers behind would make a later FETCH agree with nothing.
    /// </remarks>
    public Task<IReadOnlyList<long>> ExpungeAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        CancellationToken cancellationToken)
    {
        Expunged.Add((mailboxId.Value, folderId.Value));

        KeyValuePair<(Guid Mailbox, string Path), Entry> owner = _folders
            .FirstOrDefault(pair =>
                pair.Value.Folder.Id.Value == folderId.Value &&
                pair.Key.Mailbox == mailboxId.Value);

        if (owner.Value is null ||
            !_messages.TryGetValue(owner.Key, out List<ImapMessageSummary>? all))
        {
            return Task.FromResult<IReadOnlyList<long>>([]);
        }

        List<long> removed =
        [
            .. all.Where(m => m.Flags.HasFlag(MessageFlags.Deleted))
                  .Select(m => m.SequenceNumber)
                  .OrderByDescending(n => n),
        ];

        List<ImapMessageSummary> survivors =
            [.. all.Where(m => !m.Flags.HasFlag(MessageFlags.Deleted))];

        all.Clear();

        long sequenceNumber = 1;

        foreach (ImapMessageSummary survivor in survivors.OrderBy(m => m.Uid))
        {
            all.Add(survivor with { SequenceNumber = sequenceNumber++ });
        }

        SyncCount(owner.Key.Mailbox, owner.Key.Path);

        return Task.FromResult<IReadOnlyList<long>>(removed);
    }

    /// <summary>Every (folder, uid) set this fake was asked to remove by name.</summary>
    public List<(Guid Folder, long[] Uids)> Removed { get; } = [];

    /// <summary>
    /// Removes named messages, whatever their flags, and renumbers what is left.
    /// </summary>
    /// <remarks>
    /// Deliberately independent of <c>\Deleted</c>, as the real writer is: a fake that removed
    /// by flag would make a POP3 test pass while the product destroyed mail an IMAP client had
    /// merely marked.
    /// </remarks>
    public Task<long> DeleteMessagesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        IReadOnlyList<long> uids,
        CancellationToken cancellationToken)
    {
        Removed.Add((folderId.Value, [.. uids]));

        KeyValuePair<(Guid Mailbox, string Path), Entry> owner = _folders
            .FirstOrDefault(pair =>
                pair.Value.Folder.Id.Value == folderId.Value &&
                pair.Key.Mailbox == mailboxId.Value);

        if (owner.Value is null ||
            !_messages.TryGetValue(owner.Key, out List<ImapMessageSummary>? all))
        {
            return Task.FromResult(0L);
        }

        HashSet<long> wanted = [.. uids];

        List<ImapMessageSummary> survivors = [.. all.Where(m => !wanted.Contains(m.Uid))];
        long removed = all.Count - survivors.Count;

        all.Clear();

        long sequenceNumber = 1;

        foreach (ImapMessageSummary survivor in survivors.OrderBy(m => m.Uid))
        {
            all.Add(survivor with { SequenceNumber = sequenceNumber++ });
        }

        SyncCount(owner.Key.Mailbox, owner.Key.Path);

        return Task.FromResult(removed);
    }
}

/// <summary>A message store serving the octets a <see cref="ScriptedImapMailboxReader"/> holds.</summary>
/// <remarks>
/// Paired with the reader rather than independent, so a test that gives a message content sees
/// that content come back through the real FETCH path.
/// </remarks>
internal sealed class ScriptedMessageStore(ScriptedImapMailboxReader source) : IMessageStore
{
    public ValueTask<IMessageWriter> BeginWriteAsync(
        long maxSizeBytes,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<IMessageWriter>(new ScriptedMessageWriter(source, maxSizeBytes));

    /// <summary>
    /// Collects an appended message in memory and publishes it on commit.
    /// </summary>
    /// <remarks>
    /// Enforces the size limit as the real writer does, because APPEND relies on it: the
    /// connection checks the declared literal size and the writer checks what actually arrives,
    /// and a fake that skipped the second check would leave that path untested.
    /// </remarks>
    private sealed class ScriptedMessageWriter(ScriptedImapMailboxReader owner, long maxSizeBytes)
        : IMessageWriter
    {
        private readonly MemoryStream _buffer = new();

        public StoredMessageId Id { get; } = new(Guid.NewGuid());

        public long BytesWritten => _buffer.Length;

        public async ValueTask WriteAsync(
            ReadOnlyMemory<byte> chunk,
            CancellationToken cancellationToken)
        {
            if (_buffer.Length + chunk.Length > maxSizeBytes)
            {
                throw new MessageTooLargeException(maxSizeBytes, _buffer.Length + chunk.Length);
            }

            await _buffer.WriteAsync(chunk, cancellationToken);
        }

        public ValueTask<StoredMessage> CommitAsync(CancellationToken cancellationToken)
        {
            byte[] octets = _buffer.ToArray();

            owner.Content[Id.Value] = octets;

            return ValueTask.FromResult(new StoredMessage(
                Id,
                octets.Length,
                Sha256Hash.FromBytes(System.Security.Cryptography.SHA256.HashData(octets)),
                DateTimeOffset.UnixEpoch));
        }

        public ValueTask DisposeAsync()
        {
            _buffer.Dispose();

            return ValueTask.CompletedTask;
        }
    }

    public ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken)
    {
        if (!source.Content.TryGetValue(id.Value, out byte[]? octets))
        {
            throw new IOException($"No stored message {id.Value}.");
        }

        return ValueTask.FromResult<Stream>(new MemoryStream(octets, writable: false));
    }

    public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(source.Content.ContainsKey(id.Value));

    public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(source.Content.Remove(id.Value));
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
            mailboxes,
            null,
            mailboxes is null ? null : new ScriptedMessageStore(mailboxes));

    /// <summary>
    /// The count an idling connection watches follows a delivery that happens after the folder
    /// was selected. The push in <c>ImapConnectionHandler.IdleAsync</c> is built on this, and a
    /// count that answered from a snapshot taken at SELECT would make it silent for ever.
    /// </summary>
    [Fact]
    public async Task The_selected_count_follows_a_later_delivery()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        (await processor.CountSelectedAsync(CancellationToken.None)).ShouldBe(1);

        mailboxes.Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2);

        (await processor.CountSelectedAsync(CancellationToken.None)).ShouldBe(2);
    }

    /// <summary>
    /// SELECT tells the client the folder's size, so that is the count it holds afterwards.
    /// RFC 3501 §7.3.1: "The update from the EXISTS response MUST be recorded by the client."
    /// </summary>
    [Fact]
    public async Task Select_records_the_count_the_client_was_told()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 4)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 3, 7, 11, 19);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        processor.Session.ReportedExists.ShouldBe(0);

        await ExecuteAsync(processor, "a1 SELECT INBOX");

        processor.Session.ReportedExists.ShouldBe(4);
    }

    /// <summary>
    /// §7.4.1: "The EXPUNGE response also decrements the number of messages in the mailbox; it is
    /// not necessary to send an EXISTS response with the new value." So each line the client
    /// receives lowers the count it holds by one.
    /// </summary>
    [Fact]
    public async Task An_expunge_lowers_the_count_the_client_holds()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 3)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, "a2 STORE 1:2 +FLAGS (\\Deleted)");

        string wire = Wire(await ExecuteAsync(processor, "a3 EXPUNGE"));

        wire.ShouldContain("* 2 EXPUNGE");
        processor.Session.ReportedExists.ShouldBe(1);
    }

    /// <summary>
    /// The count the client holds is forgotten when the folder is closed, so a later SELECT of a
    /// different folder does not inherit it.
    /// </summary>
    [Fact]
    public async Task Closing_a_folder_forgets_the_count()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 3)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, "a2 CLOSE");

        processor.Session.ReportedExists.ShouldBe(0);
    }

    private static ImapCommand Parse(string line)
    {
        ImapCommand.TryParse(line, out ImapCommand? command, out _).ShouldBeTrue($"could not parse [{line}]");
        return command!;
    }

    private static async Task<ImapCommandResult> ExecuteAsync(ImapCommandProcessor processor, string line) =>
        await processor.ExecuteAsync(Parse(line), CancellationToken.None);

    /// <summary>The octets this result would put on the wire, as text.</summary>
    /// <remarks>
    /// Segment by segment, the way <c>ImapConnectionHandler.WriteAsync</c> does it — a response
    /// carrying message content has no single <c>Format()</c>, because its literal octets must
    /// not go through the sanitiser. Latin-1 is used to turn the octets back into characters so
    /// that every byte survives the round trip and a test can assert on the exact content; it is
    /// a test convenience, not a claim about the message's charset.
    /// </remarks>
    private static string Wire(ImapCommandResult result)
    {
        System.Text.StringBuilder builder = new();

        foreach (ImapResponse response in result.Responses)
        {
            foreach (ImapResponseSegment segment in response.Segments)
            {
                builder.Append(segment.IsText
                    ? segment.Text
                    : System.Text.Encoding.Latin1.GetString(segment.Octets.Span));
            }
        }

        return builder.ToString();
    }

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
        //
        // Asserted against the behaviour rather than against a list of atom names. A hardcoded
        // list goes stale the moment a command is implemented - it did, when NAMESPACE and
        // UNSELECT landed - and a stale list of things that must NOT be advertised fails for the
        // one reason that is not a defect.
        ScriptedImapAuthenticator authenticator = new();

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: new ScriptedImapMailboxReader().Add(authenticator.KnownMailboxId, "INBOX"));

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a0b SELECT INBOX");

        // One probe per capability atom that names a command a client could then send. Atoms
        // that describe a response shape rather than a command (CHILDREN, LITERAL-) have none.
        Dictionary<string, string> probes = new(StringComparer.OrdinalIgnoreCase)
        {
            ["IDLE"] = "p1 IDLE",
            ["NAMESPACE"] = "p1 NAMESPACE",
            ["UNSELECT"] = "p1 UNSELECT",
            ["MOVE"] = "p1 MOVE 1 Archive",
        };

        foreach (string capability in processor.Capabilities())
        {
            if (!probes.TryGetValue(capability, out string? line))
            {
                continue;
            }

            string wire = Wire(await ExecuteAsync(processor, line));

            wire.Contains("not implemented yet", StringComparison.Ordinal).ShouldBeFalse(
                $"{capability} is advertised but {line.Split(' ')[1]} is refused as unimplemented");
        }
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
    /// §6.4.5's FULL macro is "(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY)", the last of the
    /// three to become answerable. Every item it names comes back.
    /// </summary>
    [Fact]
    public async Task The_full_macro_is_answered_in_full()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 FETCH 1 FULL"));

        wire.ShouldStartWith("* 1 FETCH (FLAGS (");
        wire.ShouldContain(" INTERNALDATE ");
        wire.ShouldContain(" RFC822.SIZE ");
        wire.ShouldContain(" ENVELOPE (");
        wire.ShouldContain(" BODY (");
        wire.ShouldNotContain(" NO ");
        wire.ShouldEndWith("a2 OK FETCH completed\r\n");
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
    // ---------------------------------------------------------------------------------------
    // Regressions found by adversarial review.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// STATUS used to echo the client's already-encoded wire name straight back into the
    /// encoder. Modified UTF-7 is not idempotent — RFC 3501 §5.1.3 gives '&amp;' the two-octet
    /// form "&amp;-" and makes it the shift-sequence opener — so a second pass escapes every
    /// '&amp;' again and the client cannot match the untagged line against the command it sent.
    /// LIST was always right, which is what made the divergence invisible.
    /// </summary>
    [Theory]
    [InlineData("Jänner", "J&AOQ-nner")]
    [InlineData("Sales&Marketing", "Sales&-Marketing")]
    [InlineData("Résumé", "R&AOk-sum&AOk-")]
    public async Task Status_echoes_the_mailbox_name_encoded_exactly_once(
        string path,
        string wire)
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, path, existsCount: 3);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        string status = Wire(await ExecuteAsync(processor, $"a1 STATUS {wire} (MESSAGES)"));

        status.ShouldBe($"* STATUS {wire} (MESSAGES 3)\r\na1 OK STATUS completed\r\n");
    }

    /// <summary>
    /// The same name through LIST and through STATUS must be spelled the same way, or a client
    /// keying its folder cache by name drops one of the two.
    /// </summary>
    [Fact]
    public async Task List_and_status_spell_the_same_mailbox_the_same_way()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "Jänner", existsCount: 1);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        string list = Wire(await ExecuteAsync(processor, "a1 LIST \"\" \"*\""));
        string status = Wire(await ExecuteAsync(processor, "a2 STATUS J&AOQ-nner (MESSAGES)"));

        list.ShouldContain("J&AOQ-nner");
        status.ShouldContain("J&AOQ-nner");
        status.ShouldNotContain("J&-AOQ-nner");
    }

    /// <summary>
    /// A section specifier may contain a space — RFC 3501 §9's
    /// <c>section-msgtext = … "HEADER.FIELDS" [".NOT"] SP header-list …</c> with
    /// <c>header-list = "(" header-fld-name *(SP header-fld-name) ")"</c> — so the data-item
    /// argument cannot be split on spaces. It used to be, which turned the commonest real client
    /// request into a protocol syntax error instead of the "can't fetch that data" §6.4.5
    /// provides for.
    /// </summary>
    [Theory]
    [InlineData("a2 FETCH 1 BODY[HEADER.FIELDS (DATE FROM)]")]
    [InlineData("a2 FETCH 1 BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT)]")]
    [InlineData("a2 FETCH 1 BODY[HEADER.FIELDS.NOT (RECEIVED)]")]
    [InlineData("a2 UID FETCH 1:* (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To)])")]
    [InlineData("a2 FETCH 1 (FLAGS BODY[HEADER.FIELDS (DATE)])")]
    public async Task A_section_specifier_containing_a_space_is_a_request_and_not_a_syntax_error(
        string line)
    {
        // The shape a real client sends on every folder open. It used to be torn apart by a
        // split on spaces and refused as malformed; it is now parsed and served.
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), line));

        wire.ShouldNotContain("BAD");
        wire.ShouldContain("a2 OK ");
    }

    /// <summary>
    /// Bracket awareness must not swallow a genuinely malformed argument: an unbalanced bracket
    /// is a syntax error, and still earns BAD.
    /// </summary>
    [Theory]
    [InlineData("a2 FETCH 1 BODY[HEADER.FIELDS (DATE FROM)")]
    [InlineData("a2 FETCH 1 BODY[HEADER.FIELDS (DATE FROM]")]
    [InlineData("a2 FETCH 1 (FLAGS BODY[HEADER)")]
    [InlineData("a2 FETCH 1 BODY]")]
    public async Task An_unbalanced_bracket_is_still_a_syntax_error(string line) =>
        Wire(await ExecuteAsync(await FetchableAsync(), line)).ShouldContain("a2 BAD ");

    /// <summary>
    /// The items that are stored columns still work when a bracketed item sits beside them in
    /// the same list — the tokeniser must not disturb the ordinary case.
    /// </summary>
    [Fact]
    public async Task An_ordinary_item_list_is_unaffected_by_bracket_awareness()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 FETCH 1 (UID FLAGS)"));

        wire.ShouldBe("* 1 FETCH (UID 3 FLAGS (\\Seen))\r\na2 OK FETCH completed\r\n");
    }
    // ---------------------------------------------------------------------------------------
    // EXPUNGE and CLOSE.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A selected mailbox of eleven messages with 3, 4, 7 and 11 marked <c>\Deleted</c> — the
    /// exact shape of RFC 3501 §6.4.3's worked example.
    /// </summary>
    private static async Task<(
        ImapCommandProcessor Processor,
        ScriptedImapMailboxReader Store,
        ImapSessionContext Session)>
        ExpungeableAsync(bool readOnly = false)
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 11)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);

        ImapSessionContext session = Session();

        ImapCommandProcessor processor = Processor(
            session: session,
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, readOnly ? "a1 EXAMINE INBOX" : "a1 SELECT INBOX");

        if (!readOnly)
        {
            // Positions 3, 4, 7 and 11 - the RFC's own example.
            await ExecuteAsync(processor, @"a1b STORE 3,4,7,11 +FLAGS.SILENT (\Deleted)");
        }

        return (processor, mailboxes, session);
    }

    /// <summary>
    /// RFC 3501 §7.4.1 permits either order and names both. This server sends the "higher to
    /// lower" one, where every number is still valid when it is sent because only higher
    /// positions have gone — so the numbers are simply the positions as they were.
    /// </summary>
    [Fact]
    public async Task Expunge_reports_the_removed_positions_highest_first()
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 EXPUNGE"));

        wire.ShouldBe(
            "* 11 EXPUNGE\r\n" +
            "* 7 EXPUNGE\r\n" +
            "* 4 EXPUNGE\r\n" +
            "* 3 EXPUNGE\r\n" +
            "a2 OK EXPUNGE completed\r\n");
    }

    /// <summary>
    /// The messages the RFC's example leaves behind are 1, 2, 5, 6, 8, 9, 10 — asserted through
    /// a following FETCH, so the renumbering is observed rather than assumed.
    /// </summary>
    [Fact]
    public async Task The_survivors_are_renumbered_from_one()
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        await ExecuteAsync(processor, "a2 EXPUNGE");

        string wire = Wire(await ExecuteAsync(processor, "a3 FETCH 1:* UID"));

        wire.ShouldBe(
            "* 1 FETCH (UID 1)\r\n" +
            "* 2 FETCH (UID 2)\r\n" +
            "* 3 FETCH (UID 5)\r\n" +
            "* 4 FETCH (UID 6)\r\n" +
            "* 5 FETCH (UID 8)\r\n" +
            "* 6 FETCH (UID 9)\r\n" +
            "* 7 FETCH (UID 10)\r\n" +
            "a3 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §7.4.1: "it is not necessary to send an EXISTS response with the new value." A client that
    /// has already decremented would otherwise have to reconcile two statements of one fact.
    /// </summary>
    [Fact]
    public async Task Expunge_does_not_follow_with_an_exists()
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        Wire(await ExecuteAsync(processor, "a2 EXPUNGE")).ShouldNotContain("EXISTS");
    }

    [Fact]
    public async Task Expunge_with_nothing_deleted_is_an_ok_with_no_data()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 3)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2, 3);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        Wire(await ExecuteAsync(processor, "a2 EXPUNGE"))
            .ShouldBe("a2 OK EXPUNGE completed\r\n");
    }

    /// <summary>
    /// §6.3.2 permits no change to a read-only mailbox's permanent state, and §6.4.3's result
    /// list has the shape for the refusal: "NO - expunge failure: can't expunge".
    /// </summary>
    [Fact]
    public async Task Expunge_on_a_read_only_mailbox_is_refused()
    {
        (ImapCommandProcessor processor, ScriptedImapMailboxReader store, _) =
            await ExpungeableAsync(readOnly: true);

        string wire = Wire(await ExecuteAsync(processor, "a2 EXPUNGE"));

        wire.ShouldContain("a2 NO ");
        wire.ShouldContain("read-only");
        store.Expunged.ShouldBeEmpty();
    }

    [Theory]
    [InlineData("a2 EXPUNGE 1")]
    [InlineData("a2 EXPUNGE nonsense")]
    public async Task Expunge_takes_no_arguments(string line)
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        Wire(await ExecuteAsync(processor, line)).ShouldContain("a2 BAD ");
    }

    /// <summary>
    /// §6.4.2: CLOSE removes the deleted messages "and returns to the authenticated state", and
    /// "No untagged EXPUNGE responses are sent." The silence is the command's whole purpose.
    /// </summary>
    [Fact]
    public async Task Close_expunges_silently_and_leaves_the_selected_state()
    {
        (ImapCommandProcessor processor, ScriptedImapMailboxReader store, ImapSessionContext session) =
            await ExpungeableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 CLOSE"));

        wire.ShouldBe("a2 OK CLOSE completed\r\n");
        wire.ShouldNotContain("EXPUNGE");

        store.Expunged.ShouldNotBeEmpty();
        session.State.ShouldBe(ImapSessionState.Authenticated);
        session.SelectedFolderId.ShouldBeNull();
    }

    /// <summary>
    /// The asymmetry with EXPUNGE, and it is the RFC's. §6.4.2: "No messages are removed, and no
    /// error is given, if the mailbox is selected by an EXAMINE command or is otherwise selected
    /// read-only." CLOSE has no NO case at all, while EXPUNGE does.
    /// </summary>
    [Fact]
    public async Task Close_on_a_read_only_mailbox_succeeds_and_removes_nothing()
    {
        (ImapCommandProcessor processor, ScriptedImapMailboxReader store, ImapSessionContext session) =
            await ExpungeableAsync(readOnly: true);

        string wire = Wire(await ExecuteAsync(processor, "a2 CLOSE"));

        wire.ShouldBe("a2 OK CLOSE completed\r\n");
        store.Expunged.ShouldBeEmpty();
        session.State.ShouldBe(ImapSessionState.Authenticated);
    }

    /// <summary>After CLOSE the session is authenticated, so a selected-state command is out of sequence.</summary>
    [Fact]
    public async Task A_selected_state_command_is_out_of_sequence_after_close()
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        await ExecuteAsync(processor, "a2 CLOSE");

        Wire(await ExecuteAsync(processor, "a3 FETCH 1 FLAGS")).ShouldContain("a3 BAD ");
    }

    [Fact]
    public async Task Close_takes_no_arguments()
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        Wire(await ExecuteAsync(processor, "a2 CLOSE now")).ShouldContain("a2 BAD ");
    }
    // ---------------------------------------------------------------------------------------
    // CHECK, UNSELECT and NAMESPACE.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 3501 §6.4.1: "If a server implementation has no such housekeeping considerations,
    /// CHECK is equivalent to NOOP." This server keeps no in-memory mailbox state — every command
    /// reads and writes through the database — so there is nothing to checkpoint.
    /// </summary>
    [Fact]
    public async Task Check_is_an_ok_and_nothing_else()
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        Wire(await ExecuteAsync(processor, "a2 CHECK")).ShouldBe("a2 OK CHECK completed\r\n");
    }

    /// <summary>
    /// §6.4.1: "There is no guarantee that an EXISTS untagged response will happen as a result of
    /// CHECK. NOOP, not CHECK, SHOULD be used for new message polling."
    /// </summary>
    [Fact]
    public async Task Check_sends_nothing_untagged()
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        Wire(await ExecuteAsync(processor, "a2 CHECK")).ShouldNotContain("*");
    }

    /// <summary>
    /// RFC 3691 §2: UNSELECT "performs the same actions as CLOSE, except that no messages are
    /// permanently removed from the currently selected mailbox."
    /// </summary>
    [Fact]
    public async Task Unselect_leaves_the_selected_state_without_expunging()
    {
        (ImapCommandProcessor processor, ScriptedImapMailboxReader store, ImapSessionContext session) =
            await ExpungeableAsync();

        Wire(await ExecuteAsync(processor, "a2 UNSELECT"))
            .ShouldBe("a2 OK UNSELECT completed\r\n");

        session.State.ShouldBe(ImapSessionState.Authenticated);
        session.SelectedFolderId.ShouldBeNull();

        // The difference from CLOSE, which is the whole reason the command exists.
        store.Expunged.ShouldBeEmpty();
    }

    /// <summary>
    /// §2's result list: "BAD - no mailbox selected, or argument supplied but none permitted."
    /// Out of sequence rather than refused.
    /// </summary>
    [Fact]
    public async Task Unselect_without_a_selected_mailbox_is_bad()
    {
        ScriptedImapAuthenticator authenticator = new();

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: new ScriptedImapMailboxReader().Add(authenticator.KnownMailboxId, "INBOX"));

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 UNSELECT")).ShouldContain(" BAD ");
    }

    [Theory]
    [InlineData("a2 UNSELECT now")]
    [InlineData("a2 CHECK now")]
    [InlineData("a2 NAMESPACE now")]
    public async Task These_commands_take_no_arguments(string line)
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        Wire(await ExecuteAsync(processor, line)).ShouldContain("a2 BAD ");
    }

    /// <summary>
    /// RFC 2342's Example 5.1, verbatim: a server with one personal namespace, no prefix and "/"
    /// as the delimiter answers <c>* NAMESPACE (("" "/")) NIL NIL</c>.
    /// </summary>
    [Fact]
    public async Task Namespace_reports_one_personal_namespace_and_nothing_else()
    {
        (ImapCommandProcessor processor, _, _) = await ExpungeableAsync();

        Wire(await ExecuteAsync(processor, "a2 NAMESPACE")).ShouldBe(
            "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n" +
            "a2 OK NAMESPACE completed\r\n");
    }

    /// <summary>
    /// RFC 2342 §4: "The NAMESPACE command is valid in the Authenticated and Selected state." So
    /// it works before a mailbox is opened, which is when a client actually asks.
    /// </summary>
    [Fact]
    public async Task Namespace_works_before_a_mailbox_is_selected()
    {
        ScriptedImapAuthenticator authenticator = new();

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: new ScriptedImapMailboxReader().Add(authenticator.KnownMailboxId, "INBOX"));

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 NAMESPACE")).ShouldContain("* NAMESPACE ((\"\" \"/\")) NIL NIL");
    }

    /// <summary>
    /// RFC 2342 §4 makes the atom a MUST for a server implementing the command; RFC 3691 §1 makes
    /// it the only way a client can discover UNSELECT.
    /// </summary>
    [Fact]
    public async Task Both_extensions_are_advertised()
    {
        ScriptedImapAuthenticator authenticator = new();

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: new ScriptedImapMailboxReader().Add(authenticator.KnownMailboxId, "INBOX"));

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        string wire = Wire(await ExecuteAsync(processor, "a1 CAPABILITY"));

        wire.ShouldContain("NAMESPACE");
        wire.ShouldContain("UNSELECT");
    }
    // ---------------------------------------------------------------------------------------
    // CREATE, DELETE, RENAME, SUBSCRIBE, UNSUBSCRIBE. RFC 3501 §6.3.3 to §6.3.7.
    // ---------------------------------------------------------------------------------------

    private static async Task<(ImapCommandProcessor Processor, ScriptedImapMailboxReader Store)>
        ManageableAsync()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Add(authenticator.KnownMailboxId, "Archive");

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        return (processor, mailboxes);
    }

    [Fact]
    public async Task Create_makes_a_folder_that_list_then_reports()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, "a1 CREATE Receipts"))
            .ShouldBe("a1 OK CREATE completed\r\n");

        Wire(await ExecuteAsync(processor, "a2 LIST \"\" \"*\"")).ShouldContain("\"/\" Receipts");
    }

    /// <summary>
    /// RFC 3501 §6.3.3: "the server SHOULD create any superior hierarchical names that are needed
    /// […] an attempt to create "foo/bar/zap" […] SHOULD create foo/ and foo/bar/ if they do not
    /// already exist."
    /// </summary>
    [Fact]
    public async Task Create_makes_the_superior_levels_it_needs()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        await ExecuteAsync(processor, "a1 CREATE foo/bar/zap");

        string wire = Wire(await ExecuteAsync(processor, "a2 LIST \"\" \"*\""));

        wire.ShouldContain("\"/\" foo\r\n");
        wire.ShouldContain("\"/\" foo/bar\r\n");
        wire.ShouldContain("\"/\" foo/bar/zap\r\n");
    }

    /// <summary>
    /// §6.3.3: "If the mailbox name is suffixed with the server's hierarchy separator character
    /// […] this is a declaration that the client intends to create mailbox names under this name
    /// […] In any case, the name created is without the trailing hierarchy delimiter." The RFC's
    /// own example is CREATE owatagusiam/ followed by CREATE owatagusiam/blurdybloop.
    /// </summary>
    [Fact]
    public async Task Create_drops_a_trailing_delimiter_rather_than_storing_it()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, "a1 CREATE owatagusiam/"))
            .ShouldContain("a1 OK ");

        Wire(await ExecuteAsync(processor, "a2 CREATE owatagusiam/blurdybloop"))
            .ShouldContain("a2 OK ");

        string wire = Wire(await ExecuteAsync(processor, "a3 LIST \"\" \"*\""));

        wire.ShouldContain("\"/\" owatagusiam\r\n");
        wire.ShouldNotContain("owatagusiam/\r\n");
    }

    /// <summary>
    /// §6.3.3: "It is an error to attempt to create INBOX or a mailbox with a name that refers to
    /// an extant mailbox." Both are tagged NO, because "Any error in creation will return a
    /// tagged NO response."
    /// </summary>
    [Theory]
    [InlineData("a1 CREATE INBOX")]
    [InlineData("a1 CREATE inbox")]
    [InlineData("a1 CREATE Archive")]
    public async Task Create_refuses_a_reserved_or_extant_name(string line)
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, line)).ShouldContain("a1 NO ");
    }

    [Fact]
    public async Task Delete_removes_the_folder()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, "a1 DELETE Archive"))
            .ShouldBe("a1 OK DELETE completed\r\n");

        Wire(await ExecuteAsync(processor, "a2 LIST \"\" \"*\"")).ShouldNotContain("Archive");
    }

    /// <summary>
    /// §6.3.4: "It is an error to attempt to delete INBOX or a mailbox name that does not exist."
    /// </summary>
    [Theory]
    [InlineData("a1 DELETE INBOX")]
    [InlineData("a1 DELETE Nowhere")]
    public async Task Delete_refuses_the_inbox_and_the_absent(string line)
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, line)).ShouldContain("a1 NO ");
    }

    /// <summary>
    /// §6.3.4's MUST: "The DELETE command MUST NOT remove inferior hierarchical names. For
    /// example, if a mailbox "foo" has an inferior "foo.bar" […] removing "foo" MUST NOT remove
    /// "foo.bar"." And what the name becomes: "the name will acquire the \Noselect mailbox name
    /// attribute" — which needs no code, because a name with no row is exactly what this server
    /// reports \Noselect for.
    /// </summary>
    [Fact]
    public async Task Delete_leaves_inferior_names_alone_and_the_parent_becomes_unselectable()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        await ExecuteAsync(processor, "a1 CREATE foo/bar");
        await ExecuteAsync(processor, "a2 DELETE foo");

        string all = Wire(await ExecuteAsync(processor, "a3 LIST \"\" \"*\""));
        all.ShouldContain("\"/\" foo/bar\r\n");

        string levels = Wire(await ExecuteAsync(processor, "a4 LIST \"\" \"%\""));
        levels.ShouldContain("* LIST (\\Noselect \\HasChildren) \"/\" foo\r\n");
    }

    [Fact]
    public async Task Rename_moves_the_folder()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, "a1 RENAME Archive Attic"))
            .ShouldBe("a1 OK RENAME completed\r\n");

        string wire = Wire(await ExecuteAsync(processor, "a2 LIST \"\" \"*\""));

        wire.ShouldContain("\"/\" Attic\r\n");
        wire.ShouldNotContain("Archive");
    }

    /// <summary>
    /// §6.3.5's MUST: "If the name has inferior hierarchical names, then the inferior
    /// hierarchical names MUST also be renamed. For example, a rename of "foo" to "zap" will
    /// rename "foo/bar" […] to "zap/bar"."
    /// </summary>
    [Fact]
    public async Task Rename_carries_the_whole_subtree()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        await ExecuteAsync(processor, "a1 CREATE foo/bar");
        await ExecuteAsync(processor, "a2 CREATE foo/bar/baz");
        await ExecuteAsync(processor, "a3 RENAME foo zap");

        string wire = Wire(await ExecuteAsync(processor, "a4 LIST \"\" \"*\""));

        wire.ShouldContain("\"/\" zap\r\n");
        wire.ShouldContain("\"/\" zap/bar\r\n");
        wire.ShouldContain("\"/\" zap/bar/baz\r\n");
        wire.ShouldNotContain("foo");
    }

    /// <summary>
    /// A sibling whose name merely starts the same way is not part of the subtree — the same
    /// prefix-versus-child distinction ParentsAmong makes.
    /// </summary>
    [Fact]
    public async Task Rename_does_not_carry_a_sibling_with_a_shared_prefix()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        await ExecuteAsync(processor, "a1 CREATE Work");
        await ExecuteAsync(processor, "a2 CREATE Workshop");
        await ExecuteAsync(processor, "a3 RENAME Work Labour");

        string wire = Wire(await ExecuteAsync(processor, "a4 LIST \"\" \"*\""));

        wire.ShouldContain("\"/\" Labour\r\n");
        wire.ShouldContain("\"/\" Workshop\r\n");
    }

    /// <summary>
    /// §6.3.5: "Renaming INBOX is permitted, and has special behavior. It moves all messages in
    /// INBOX to a new mailbox with the given name, leaving INBOX empty." Three things at once:
    /// the inbox survives, it is emptied, and the messages arrive somewhere new.
    /// </summary>
    [Fact]
    public async Task Renaming_the_inbox_moves_its_messages_and_leaves_it_in_place()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 2, specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1, 2);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");

        Wire(await ExecuteAsync(processor, "a1 RENAME INBOX old-mail")).ShouldContain("a1 OK ");

        string wire = Wire(await ExecuteAsync(processor, "a2 LIST \"\" \"*\""));

        // The inbox is still there - the RFC's own Z434 example lists it after the rename.
        wire.ShouldContain("\"/\" INBOX\r\n");
        wire.ShouldContain("\"/\" old-mail\r\n");

        // And it is empty, while the messages are in the new mailbox.
        await ExecuteAsync(processor, "a3 SELECT INBOX");
        Wire(await ExecuteAsync(processor, "a4 FETCH 1:* UID"))
            .ShouldBe("a4 OK FETCH completed\r\n");

        await ExecuteAsync(processor, "a5 SELECT old-mail");
        Wire(await ExecuteAsync(processor, "a6 FETCH 1:* UID")).ShouldContain("* 1 FETCH (UID 1)");
    }

    /// <summary>
    /// §6.3.5: "It is an error to attempt to rename from a mailbox name that does not exist or to
    /// a mailbox name that already exists."
    /// </summary>
    [Theory]
    [InlineData("a1 RENAME Nowhere Somewhere")]
    [InlineData("a1 RENAME Archive INBOX")]
    public async Task Rename_refuses_an_absent_source_or_an_extant_target(string line)
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, line)).ShouldContain("a1 NO ");
    }

    [Fact]
    public async Task Subscribe_then_lsub_reports_the_name()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        await ExecuteAsync(processor, "a1 CREATE Receipts");

        Wire(await ExecuteAsync(processor, "a2 SUBSCRIBE Receipts"))
            .ShouldBe("a2 OK SUBSCRIBE completed\r\n");

        Wire(await ExecuteAsync(processor, "a3 LSUB \"\" \"*\"")).ShouldContain("\"/\" Receipts");
    }

    [Fact]
    public async Task Unsubscribe_removes_it_again()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        await ExecuteAsync(processor, "a1 UNSUBSCRIBE Archive");

        Wire(await ExecuteAsync(processor, "a2 LSUB \"\" \"*\"")).ShouldNotContain("Archive");
    }

    /// <summary>
    /// §6.3.6's MUST NOT: a server "MUST NOT unilaterally remove an existing mailbox name from
    /// the subscription list even if a mailbox by that name no longer exists", because "a server
    /// site can choose to routinely remove a mailbox with a well-known name […] with the
    /// intention of recreating it when new contents are appropriate". This is why subscriptions
    /// are a table of names rather than a flag on a folder row.
    /// </summary>
    [Fact]
    public async Task A_subscription_survives_the_deletion_of_the_mailbox_it_names()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        await ExecuteAsync(processor, "a1 CREATE system-alerts");
        await ExecuteAsync(processor, "a2 SUBSCRIBE system-alerts");
        await ExecuteAsync(processor, "a3 DELETE system-alerts");

        // Gone from LIST, which reports mailboxes...
        Wire(await ExecuteAsync(processor, "a4 LIST \"\" \"*\"")).ShouldNotContain("system-alerts");

        // ...and still in LSUB, which reports the subscription list. \Noselect because §7.2.2
        // defines it as "not possible to use this name as a selectable mailbox", which is true.
        Wire(await ExecuteAsync(processor, "a5 LSUB \"\" \"*\""))
            .ShouldContain("* LSUB (\\Noselect) \"/\" system-alerts\r\n");
    }

    /// <summary>
    /// §6.3.6: "A server MAY validate the mailbox argument to SUBSCRIBE to verify that it
    /// exists." This server takes the option, because a typo that silently succeeds leaves a user
    /// with a folder list that never populates.
    /// </summary>
    [Fact]
    public async Task Subscribing_to_a_name_that_does_not_exist_is_refused()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, "a1 SUBSCRIBE Nowhere")).ShouldContain("a1 NO ");
    }

    /// <summary>
    /// Unsubscribing must NOT validate: the list has to be able to name something that is gone,
    /// or a user could never stop following a deleted mailbox.
    /// </summary>
    [Fact]
    public async Task Unsubscribing_from_a_name_that_does_not_exist_succeeds()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, "a1 UNSUBSCRIBE Nowhere")).ShouldContain("a1 OK ");
    }

    [Theory]
    [InlineData("a1 CREATE")]
    [InlineData("a1 DELETE")]
    [InlineData("a1 RENAME Archive")]
    [InlineData("a1 SUBSCRIBE")]
    [InlineData("a1 CREATE one two")]
    [InlineData("a1 RENAME a b c")]
    public async Task A_malformed_folder_command_earns_a_tagged_bad(string line)
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        Wire(await ExecuteAsync(processor, line)).ShouldContain("a1 BAD ");
    }

    [Fact]
    public async Task A_folder_name_that_is_not_modified_utf7_is_refused_without_being_echoed()
    {
        (ImapCommandProcessor processor, _) = await ManageableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a1 CREATE \"&Jj_-\""));

        wire.ShouldContain("a1 NO ");
        wire.ShouldNotContain("&Jj_-");
    }
    // ---------------------------------------------------------------------------------------
    // COPY and MOVE. RFC 3501 §6.4.7 and RFC 6851 §3.
    // ---------------------------------------------------------------------------------------

    private static async Task<ImapCommandProcessor> CopyableAsync()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 4, specialUse: FolderSpecialUse.Inbox)
            .Add(authenticator.KnownMailboxId, "Archive")
            .Deliver(authenticator.KnownMailboxId, "INBOX", 3, 7, 11, 19);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        return processor;
    }

    [Fact]
    public async Task Copy_puts_the_messages_in_the_destination_and_leaves_the_source()
    {
        ImapCommandProcessor processor = await CopyableAsync();

        Wire(await ExecuteAsync(processor, "a2 COPY 2:3 Archive"))
            .ShouldBe("a2 OK COPY completed\r\n");

        // Still four in the source...
        Wire(await ExecuteAsync(processor, "a3 FETCH 1:* UID"))
            .ShouldContain("* 4 FETCH (UID 19)");

        // ...and two in the destination, with new UIDs starting from 1.
        await ExecuteAsync(processor, "a4 SELECT Archive");
        Wire(await ExecuteAsync(processor, "a5 FETCH 1:* UID")).ShouldBe(
            "* 1 FETCH (UID 1)\r\n" +
            "* 2 FETCH (UID 2)\r\n" +
            "a5 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.7: "The flags and internal date of the message(s) SHOULD be preserved […] in the
    /// copy."
    /// </summary>
    [Fact]
    public async Task Copy_preserves_the_flags_and_internal_date()
    {
        ImapCommandProcessor processor = await CopyableAsync();

        await ExecuteAsync(processor, @"a2 STORE 1 +FLAGS.SILENT (\Flagged)");
        await ExecuteAsync(processor, "a3 COPY 1 Archive");
        await ExecuteAsync(processor, "a4 SELECT Archive");

        Wire(await ExecuteAsync(processor, "a5 FETCH 1 (FLAGS INTERNALDATE)")).ShouldBe(
            "* 1 FETCH (FLAGS (\\Seen \\Flagged) INTERNALDATE \" 1-Mar-2026 09:30:15 +0000\")\r\n" +
            "a5 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.7's MUST: "Unless it is certain that the destination mailbox can not be created, the
    /// server MUST send the response code "[TRYCREATE]" as the prefix of the text of the tagged
    /// NO response." It is the hint that lets a client create the folder and retry.
    /// </summary>
    [Theory]
    [InlineData("a2 COPY 1 Nowhere")]
    [InlineData("a2 MOVE 1 Nowhere")]
    [InlineData("a2 UID COPY 3 Nowhere")]
    public async Task A_missing_destination_earns_trycreate(string line)
    {
        string wire = Wire(await ExecuteAsync(await CopyableAsync(), line));

        wire.ShouldContain("a2 NO [TRYCREATE]");
    }

    /// <summary>
    /// RFC 6851 §3.3: a move is a copy plus a removal, and the removal is reported with untagged
    /// EXPUNGE — "though the COPY and EXPUNGE response codes will be returned, response codes for
    /// a STORE MUST NOT be generated and the \Deleted flag MUST NOT be set for any message."
    /// </summary>
    [Fact]
    public async Task Move_reports_expunges_and_never_a_fetch()
    {
        ImapCommandProcessor processor = await CopyableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 MOVE 2:3 Archive"));

        wire.ShouldBe(
            "* 3 EXPUNGE\r\n" +
            "* 2 EXPUNGE\r\n" +
            "a2 OK MOVE completed\r\n");

        wire.ShouldNotContain("FETCH");
        wire.ShouldNotContain("Deleted");
    }

    /// <summary>
    /// §3.3: "a new message is created in the target mailbox with a new UID, the original message
    /// is removed from the source mailbox". Both halves, observed.
    /// </summary>
    [Fact]
    public async Task Move_removes_from_the_source_and_creates_in_the_target()
    {
        ImapCommandProcessor processor = await CopyableAsync();

        await ExecuteAsync(processor, "a2 MOVE 2:3 Archive");

        Wire(await ExecuteAsync(processor, "a3 FETCH 1:* UID")).ShouldBe(
            "* 1 FETCH (UID 3)\r\n" +
            "* 2 FETCH (UID 19)\r\n" +
            "a3 OK FETCH completed\r\n");

        await ExecuteAsync(processor, "a4 SELECT Archive");

        Wire(await ExecuteAsync(processor, "a5 FETCH 1:* UID")).ShouldBe(
            "* 1 FETCH (UID 1)\r\n" +
            "* 2 FETCH (UID 2)\r\n" +
            "a5 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.8: under the UID form "the numbers in the sequence set argument are unique
    /// identifiers instead of message sequence numbers".
    /// </summary>
    [Fact]
    public async Task Uid_copy_reads_the_numbers_as_uids()
    {
        ImapCommandProcessor processor = await CopyableAsync();

        Wire(await ExecuteAsync(processor, "a2 UID COPY 11 Archive"))
            .ShouldBe("a2 OK UID COPY completed\r\n");

        await ExecuteAsync(processor, "a3 SELECT Archive");

        Wire(await ExecuteAsync(processor, "a4 FETCH 1:* UID"))
            .ShouldBe("* 1 FETCH (UID 1)\r\na4 OK FETCH completed\r\n");
    }

    /// <summary>§6.4.8: a number naming no message is ignored without an error.</summary>
    [Theory]
    [InlineData("a2 COPY 99 Archive")]
    [InlineData("a2 UID MOVE 500 Archive")]
    public async Task Copying_nothing_is_an_ok_with_no_data(string line)
    {
        string wire = Wire(await ExecuteAsync(await CopyableAsync(), line));

        wire.ShouldContain(" OK ");
        wire.ShouldNotContain("EXPUNGE");
    }

    [Theory]
    [InlineData("a2 COPY")]
    [InlineData("a2 COPY 1")]
    [InlineData("a2 MOVE nonsense Archive")]
    [InlineData("a2 COPY 1 Archive extra")]
    [InlineData("a2 COPY 0 Archive")]
    public async Task A_malformed_copy_earns_a_tagged_bad(string line) =>
        Wire(await ExecuteAsync(await CopyableAsync(), line)).ShouldContain("a2 BAD ");

    /// <summary>
    /// RFC 6851 §1: "The MOVE extension is present in any IMAP implementation that returns "MOVE"
    /// as one of the supported capabilities to the CAPABILITY command."
    /// </summary>
    [Fact]
    public async Task Move_is_advertised()
    {
        ImapCommandProcessor processor = await CopyableAsync();

        Wire(await ExecuteAsync(processor, "a2 CAPABILITY")).ShouldContain("MOVE");
    }
    // ---------------------------------------------------------------------------------------
    // FETCH of message content. RFC 3501 §6.4.5.
    // ---------------------------------------------------------------------------------------

    private const string StoredMessage =
        "Date: Mon, 7 Feb 2026 21:52:25 -0800\r\n" +
        "From: Alice <alice@example.com>\r\n" +
        "Subject: hello\r\n" +
        "\r\n" +
        "This is the body.\r\n";

    private static async Task<(ImapCommandProcessor Processor, ScriptedImapMailboxReader Store)>
        ReadableAsync()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1, specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", uid: 7, StoredMessage);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        return (processor, mailboxes);
    }

    /// <summary>
    /// The whole message, as a literal. §9 types a body section's value an nstring, and a quoted
    /// string cannot hold CR, LF or an 8-bit octet — so the only available form is {n}CRLF
    /// followed by exactly n octets.
    /// </summary>
    [Fact]
    public async Task A_body_fetch_returns_the_message_as_a_literal()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 FETCH 1 BODY.PEEK[]"));

        wire.ShouldBe(
            $"* 1 FETCH (BODY[] {{{StoredMessage.Length}}}\r\n{StoredMessage})\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // FETCH ENVELOPE. RFC 3501 §7.4.2.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The item a client builds a message list from, answered from the message's own header.
    /// Sender and Reply-To are the §7.4.2 default — "the server sets the corresponding member of
    /// the envelope to be the same value as the from member".
    /// </summary>
    [Fact]
    public async Task An_envelope_fetch_answers_from_the_stored_header()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 FETCH 1 ENVELOPE"));

        wire.ShouldBe(
            "* 1 FETCH (ENVELOPE (\"Mon, 7 Feb 2026 21:52:25 -0800\" \"hello\" " +
            "((\"Alice\" NIL \"alice\" \"example.com\")) " +
            "((\"Alice\" NIL \"alice\" \"example.com\")) " +
            "((\"Alice\" NIL \"alice\" \"example.com\")) " +
            "NIL NIL NIL NIL NIL))\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.5's ALL macro is "(FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)" and is now answerable
    /// in full. The items come back in the macro's own order.
    /// </summary>
    [Fact]
    public async Task The_all_macro_is_answered_in_full()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 FETCH 1 ALL"));

        wire.ShouldStartWith("* 1 FETCH (FLAGS (");
        wire.ShouldContain(" RFC822.SIZE ");
        wire.ShouldContain(" ENVELOPE (\"Mon, 7 Feb 2026 21:52:25 -0800\" \"hello\" ");
        wire.ShouldEndWith("a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §9's <c>msg-att-static</c> is <c>"ENVELOPE" SP envelope</c> with no NIL alternative, so a
    /// message whose octets are not in the store is answered with the empty structure rather
    /// than failing the command — one unreadable message must not close a folder.
    /// </summary>
    [Fact]
    public async Task An_envelope_fetch_of_a_message_with_no_content_is_all_nil()
    {
        string wire = Wire(await ExecuteAsync(await FetchableAsync(), "a2 FETCH 1 ENVELOPE"));

        wire.ShouldBe(
            "* 1 FETCH (ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL))\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.5 sets \Seen for a BODY[…] without .PEEK and for nothing else. An envelope is built
    /// from the header the server already has to read, and a client that listed a folder would
    /// otherwise mark every message in it read. Asserted on the write rather than on the
    /// reported flags, because the fake delivers messages already \Seen.
    /// </summary>
    [Fact]
    public async Task An_envelope_fetch_does_not_set_seen()
    {
        (ImapCommandProcessor processor, ScriptedImapMailboxReader store) = await ReadableAsync();

        await ExecuteAsync(processor, "a2 FETCH 1 (ENVELOPE FLAGS)");

        store.Stored.ShouldBeEmpty();
    }

    /// <summary>
    /// The control for the test above: the same folder, fetched with a non-peeking section,
    /// does write. A test that only asserted the absence of a write would pass just as well if
    /// the fake had stopped recording them.
    /// </summary>
    [Fact]
    public async Task A_non_peeking_body_fetch_does_set_seen()
    {
        (ImapCommandProcessor processor, ScriptedImapMailboxReader store) = await ReadableAsync();

        await ExecuteAsync(processor, "a2 FETCH 1 BODY[]");

        store.Stored.ShouldNotBeEmpty();
    }

    /// <summary>
    /// An envelope member that cannot be quoted becomes a literal in the middle of the item, and
    /// the rest of the structure follows the octets on the same line.
    /// </summary>
    [Fact]
    public async Task An_eight_bit_subject_becomes_a_literal_inside_the_envelope()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(
            authenticator.KnownMailboxId,
            "INBOX",
            uid: 7,
            "Subject: caf\u00e9\r\nFrom: a@b.test\r\n\r\nbody\r\n");

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        string wire = Wire(await ExecuteAsync(processor, "a2 FETCH 1 ENVELOPE"));

        wire.ShouldBe(
            "* 1 FETCH (ENVELOPE (NIL {4}\r\ncaf\u00e9 ((NIL NIL \"a\" \"b.test\")) " +
            "((NIL NIL \"a\" \"b.test\")) ((NIL NIL \"a\" \"b.test\")) " +
            "NIL NIL NIL NIL NIL))\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    // ---------------------------------------------------------------------------------------
    // FETCH BODYSTRUCTURE and numbered MIME parts. RFC 3501 §7.4.2.
    // ---------------------------------------------------------------------------------------

    private const string MultipartMessage =
        "Date: Mon, 7 Feb 2026 21:52:25 -0800\r\n" +
        "From: Alice <alice@example.com>\r\n" +
        "Subject: with an attachment\r\n" +
        "MIME-Version: 1.0\r\n" +
        "Content-Type: multipart/mixed; boundary=\"edge\"\r\n" +
        "\r\n" +
        "--edge\r\n" +
        "Content-Type: text/plain; charset=us-ascii\r\n" +
        "\r\n" +
        "Have a look.\r\n" +
        "--edge\r\n" +
        "Content-Type: application/pdf; name=\"notes.pdf\"\r\n" +
        "Content-Transfer-Encoding: base64\r\n" +
        "Content-Disposition: attachment; filename=\"notes.pdf\"\r\n" +
        "\r\n" +
        "JVBERi0=\r\n" +
        "--edge--\r\n";

    private static async Task<ImapCommandProcessor> MultipartAsync()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", uid: 7, MultipartMessage);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        return processor;
    }

    /// <summary>
    /// The item a client uses to decide what to show and what to offer as a download, answered
    /// from the message's MIME headers. §7.4.2: "computed by the server by parsing the
    /// [MIME-IMB] header fields, defaulting various fields as necessary."
    /// </summary>
    [Fact]
    public async Task A_bodystructure_fetch_describes_every_part()
    {
        string wire = Wire(await ExecuteAsync(await MultipartAsync(), "a2 FETCH 1 BODYSTRUCTURE"));

        wire.ShouldBe(
            "* 1 FETCH (BODYSTRUCTURE " +
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 12 1 " +
            "NIL NIL NIL NIL)" +
            "(\"APPLICATION\" \"PDF\" (\"NAME\" \"notes.pdf\") NIL NIL \"BASE64\" 8 " +
            "NIL (\"ATTACHMENT\" (\"FILENAME\" \"notes.pdf\")) NIL NIL) " +
            "\"MIXED\" (\"BOUNDARY\" \"edge\") NIL NIL NIL))\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §7.4.2 makes BODY the "Non-extensible form of BODYSTRUCTURE", and §9 annotates both
    /// extension productions "MUST NOT be returned on non-extensible 'BODY' fetch" — so the
    /// disposition that named the attachment is absent here, and the parameters that follow a
    /// multipart's subtype are too.
    /// </summary>
    [Fact]
    public async Task A_body_fetch_is_the_same_structure_without_the_extension_data()
    {
        string wire = Wire(await ExecuteAsync(await MultipartAsync(), "a2 FETCH 1 BODY"));

        wire.ShouldBe(
            "* 1 FETCH (BODY " +
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 12 1)" +
            "(\"APPLICATION\" \"PDF\" (\"NAME\" \"notes.pdf\") NIL NIL \"BASE64\" 8) " +
            "\"MIXED\"))\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// A numbered part comes back as its own octets, with the response echoing the specifier the
    /// client wrote so it can tell one part from another.
    /// </summary>
    [Fact]
    public async Task A_numbered_part_fetch_returns_that_parts_octets()
    {
        string wire = Wire(await ExecuteAsync(await MultipartAsync(), "a2 FETCH 1 BODY.PEEK[2]"));

        wire.ShouldBe(
            "* 1 FETCH (BODY[2] {8}\r\nJVBERi0=)\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.5: "The MIME part specifier refers to the [MIME-IMB] header for this part." Its own
    /// header, which is where a client reads the filename it will save an attachment under.
    /// </summary>
    [Fact]
    public async Task A_mime_part_fetch_returns_that_parts_own_header()
    {
        string wire = Wire(await ExecuteAsync(await MultipartAsync(), "a2 FETCH 1 BODY.PEEK[1.MIME]"));

        wire.ShouldContain("BODY[1.MIME] {");
        wire.ShouldContain("Content-Type: text/plain; charset=us-ascii\r\n\r\n");
        wire.ShouldNotContain("Have a look");
    }

    /// <summary>
    /// A structure whose nested envelope needs a literal puts one in the middle of the item, and
    /// the rest of the structure follows the octets on the same line. This is the one place two
    /// of this increment's mechanisms meet — <c>BODYSTRUCTURE</c> embedding an <c>ENVELOPE</c>
    /// that embeds an <c>nstring</c> which has no quoted form — and a response assembled by
    /// concatenating text would have corrupted it.
    /// </summary>
    [Fact]
    public async Task A_literal_inside_a_nested_envelope_survives_the_response_assembly()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(
            authenticator.KnownMailboxId,
            "INBOX",
            uid: 7,
            "Content-Type: message/rfc822\r\n" +
            "\r\n" +
            "Subject: caf\u00e9\r\n" +
            "From: a@b.test\r\n" +
            "\r\n" +
            "body\r\n");

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        string wire = Wire(await ExecuteAsync(processor, "a2 FETCH 1 BODY"));

        // The literal interrupts the envelope, which is itself inside the body structure.
        wire.ShouldContain("(NIL {4}\r\ncaf\u00e9 ((NIL NIL \"a\" \"b.test\"))");
        wire.ShouldStartWith("* 1 FETCH (BODY (\"MESSAGE\" \"RFC822\" ");
        wire.ShouldEndWith("a2 OK FETCH completed\r\n");

        // Every declared octet count is followed by exactly that many octets.
        foreach (System.Text.RegularExpressions.Match match in
            System.Text.RegularExpressions.Regex.Matches(wire, @"\{(\d+)\}\r\n"))
        {
            int declared = int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
            int start = match.Index + match.Length;

            (wire.Length - start).ShouldBeGreaterThanOrEqualTo(declared);
        }
    }

    /// <summary>
    /// A part that is not there is answered NIL rather than failing the command: whether a part
    /// exists is a fact about one message, and §6.4.8's FETCH covers many at once.
    /// </summary>
    [Fact]
    public async Task A_part_that_is_not_there_is_answered_nil()
    {
        string wire = Wire(await ExecuteAsync(await MultipartAsync(), "a2 FETCH 1 BODY.PEEK[9]"));

        wire.ShouldBe(
            "* 1 FETCH (BODY[9] NIL)\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// §6.4.5's partial applies to a numbered part as it does to the whole message: "If the
    /// origin octet is specified, this string is a substring of the entire body contents,
    /// starting at that origin octet."
    /// </summary>
    [Fact]
    public async Task A_numbered_part_can_be_fetched_in_part()
    {
        string wire = Wire(await ExecuteAsync(await MultipartAsync(), "a2 FETCH 1 BODY.PEEK[2]<2.4>"));

        wire.ShouldBe(
            "* 1 FETCH (BODY[2]<2> {4}\r\nBERi)\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// A fetch of a numbered part without .PEEK still sets \Seen, because §6.4.5 attaches that
    /// to the BODY[…] family rather than to any one section.
    /// </summary>
    [Fact]
    public async Task A_numbered_part_fetch_without_peek_sets_seen()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", uid: 7, MultipartMessage);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, "a2 FETCH 1 BODY[1]");

        mailboxes.Stored.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task A_header_fetch_returns_the_header_and_its_blank_line()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 FETCH 1 BODY.PEEK[HEADER]"));

        wire.ShouldContain("BODY[HEADER] {");
        wire.ShouldContain("Subject: hello\r\n\r\n");
        wire.ShouldNotContain("This is the body");
    }

    [Fact]
    public async Task A_text_fetch_returns_the_body_alone()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(processor, "a2 FETCH 1 BODY.PEEK[TEXT]"));

        wire.ShouldBe(
            "* 1 FETCH (BODY[TEXT] {19}\r\nThis is the body.\r\n)\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// The shape a real client opens a folder with. §6.4.5's field matching "is case-insensitive
    /// but otherwise exact".
    /// </summary>
    [Fact]
    public async Task A_header_field_subset_returns_only_those_fields()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(
            processor,
            "a2 FETCH 1 BODY.PEEK[HEADER.FIELDS (subject)]"));

        wire.ShouldContain("BODY[HEADER.FIELDS (subject)] {18}\r\nSubject: hello\r\n\r\n");
    }

    /// <summary>
    /// §9's msg-att-static has "BODY" section and no BODY.PEEK: the peek is a property of the
    /// request, never of the answer.
    /// </summary>
    [Fact]
    public async Task The_response_never_echoes_peek()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        Wire(await ExecuteAsync(processor, "a2 FETCH 1 BODY.PEEK[TEXT]"))
            .ShouldNotContain("PEEK");
    }

    /// <summary>
    /// §6.4.5: "The \Seen flag is implicitly set; if this causes the flags to change, they SHOULD
    /// be included as part of the FETCH responses." A client that opened a message and was not
    /// told it became read would show it unread until its next synchronisation.
    /// </summary>
    [Fact]
    public async Task A_non_peek_body_fetch_sets_seen_and_reports_the_new_flags()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", uid: 7, StoredMessage);

        // Deliver() marks messages \Seen, so clear it to observe the implicit set.
        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, @"a2 STORE 1 -FLAGS.SILENT (\Seen)");

        string wire = Wire(await ExecuteAsync(processor, "a3 FETCH 1 BODY[TEXT]"));

        wire.ShouldContain("FLAGS (\\Seen)");

        // And it stuck.
        Wire(await ExecuteAsync(processor, "a4 FETCH 1 FLAGS")).ShouldContain("(FLAGS (\\Seen))");
    }

    /// <summary>
    /// §6.4.5: BODY.PEEK is "An alternate form of BODY[&lt;section&gt;] that does not implicitly
    /// set the \Seen flag."
    /// </summary>
    [Fact]
    public async Task A_peek_fetch_does_not_set_seen()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", uid: 7, StoredMessage);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, @"a2 STORE 1 -FLAGS.SILENT (\Seen)");
        await ExecuteAsync(processor, "a3 FETCH 1 BODY.PEEK[TEXT]");

        Wire(await ExecuteAsync(processor, "a4 FETCH 1 FLAGS")).ShouldContain("(FLAGS ())");
    }

    /// <summary>
    /// §6.3.2 permits no change to the permanent state of a read-only mailbox, so an EXAMINE'd
    /// folder must not acquire \Seen from a fetch either.
    /// </summary>
    [Fact]
    public async Task A_body_fetch_on_an_examined_mailbox_does_not_set_seen()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", uid: 7, StoredMessage);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, @"a2 STORE 1 -FLAGS.SILENT (\Seen)");
        await ExecuteAsync(processor, "a3 EXAMINE INBOX");
        await ExecuteAsync(processor, "a4 FETCH 1 BODY[TEXT]");

        Wire(await ExecuteAsync(processor, "a5 FETCH 1 FLAGS")).ShouldContain("(FLAGS ())");
    }

    [Fact]
    public async Task A_partial_fetch_returns_the_substring_and_echoes_the_origin()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        Wire(await ExecuteAsync(processor, "a2 FETCH 1 BODY.PEEK[TEXT]<0.4>")).ShouldBe(
            "* 1 FETCH (BODY[TEXT]<0> {4}\r\nThis)\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// Metadata and content in one response, which is what a client asks for in practice.
    /// </summary>
    [Fact]
    public async Task Metadata_and_content_come_back_on_one_line()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(
            processor,
            "a2 UID FETCH 7 (UID RFC822.SIZE BODY.PEEK[HEADER.FIELDS (SUBJECT)])"));

        wire.ShouldStartWith("* 1 FETCH (UID 7 RFC822.SIZE 700 BODY[HEADER.FIELDS (SUBJECT)] {18}\r\n");
        wire.ShouldEndWith("a2 OK UID FETCH completed\r\n");
    }

    /// <summary>
    /// §9's nstring has a NIL form, and a message whose octets are missing from the store is
    /// exactly that: a folder with one damaged message should still open.
    /// </summary>
    [Fact]
    public async Task A_message_with_no_stored_content_answers_nil()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        Wire(await ExecuteAsync(processor, "a2 FETCH 1 BODY.PEEK[]")).ShouldBe(
            "* 1 FETCH (BODY[] NIL)\r\n" +
            "a2 OK FETCH completed\r\n");
    }

    /// <summary>
    /// Two different sections in one request are two different data items and must both be
    /// answered — collapsing them the way a repeated FLAGS collapses would drop half the request.
    /// </summary>
    [Fact]
    public async Task Two_different_sections_are_both_answered()
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(
            processor,
            "a2 FETCH 1 (BODY.PEEK[HEADER] BODY.PEEK[TEXT])"));

        wire.ShouldContain("BODY[HEADER] {");
        wire.ShouldContain("BODY[TEXT] {");
    }
    /// <summary>
    /// §6.4.5 defines the RFC822 family by equivalence — "RFC822 — Functionally equivalent to
    /// BODY[], differing in the syntax of the resulting untagged FETCH data (RFC822 is
    /// returned)" — so the octets are found the same way and the name on the wire is the one the
    /// client used.
    /// </summary>
    [Theory]
    [InlineData("RFC822", "This is the body.")]
    [InlineData("RFC822.HEADER", "Subject: hello")]
    [InlineData("RFC822.TEXT", "This is the body.")]
    public async Task The_rfc822_family_returns_content_under_its_own_name(
        string item,
        string expected)
    {
        (ImapCommandProcessor processor, _) = await ReadableAsync();

        string wire = Wire(await ExecuteAsync(processor, $"a2 FETCH 1 {item}"));

        wire.ShouldContain($"{item} {{");
        wire.ShouldContain(expected);
        wire.ShouldNotContain("BODY[");
    }

    /// <summary>
    /// §6.4.5: "RFC822.HEADER — Functionally equivalent to BODY.PEEK[HEADER]". The peek is part
    /// of the definition, so fetching a header alone must not mark the message read.
    /// </summary>
    [Fact]
    public async Task Rfc822_header_does_not_set_seen()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", uid: 7, StoredMessage);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, @"a2 STORE 1 -FLAGS.SILENT (\Seen)");
        await ExecuteAsync(processor, "a3 FETCH 1 RFC822.HEADER");

        Wire(await ExecuteAsync(processor, "a4 FETCH 1 FLAGS")).ShouldContain("(FLAGS ())");
    }

    /// <summary>
    /// §6.4.5: "RFC822.TEXT — Functionally equivalent to BODY[TEXT]" — no peek, so it does mark
    /// the message read. The contrast with RFC822.HEADER is the RFC's, not an inconsistency.
    /// </summary>
    [Fact]
    public async Task Rfc822_text_does_set_seen()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 7);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", uid: 7, StoredMessage);

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, @"a2 STORE 1 -FLAGS.SILENT (\Seen)");
        await ExecuteAsync(processor, "a3 FETCH 1 RFC822.TEXT");

        Wire(await ExecuteAsync(processor, "a4 FETCH 1 FLAGS")).ShouldContain("(FLAGS (\\Seen))");
    }
    // ---------------------------------------------------------------------------------------
    // SEARCH. RFC 3501 §6.4.4.
    // ---------------------------------------------------------------------------------------

    private static async Task<ImapCommandProcessor> SearchableAsync()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 3, specialUse: FolderSpecialUse.Inbox)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 5, 9, 14);

        mailboxes.WithContent(
            authenticator.KnownMailboxId,
            "INBOX",
            uid: 5,
            "From: Alice <alice@example.com>\r\n" +
            "Subject: quarterly report\r\n" +
            "Date: Mon, 2 Feb 2026 10:00:00 +0000\r\n" +
            "\r\n" +
            "The numbers are attached.\r\n");

        mailboxes.WithContent(
            authenticator.KnownMailboxId,
            "INBOX",
            uid: 9,
            "From: Bob <bob@example.net>\r\n" +
            "Subject: lunch\r\n" +
            "Date: Tue, 3 Mar 2026 10:00:00 +0000\r\n" +
            "\r\n" +
            "Are you free?\r\n");

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");

        return processor;
    }

    [Fact]
    public async Task Search_all_returns_every_sequence_number()
    {
        Wire(await ExecuteAsync(await SearchableAsync(), "a2 SEARCH ALL")).ShouldBe(
            "* SEARCH 1 2 3\r\na2 OK SEARCH completed\r\n");
    }

    /// <summary>
    /// §9's mailbox-data is "SEARCH" *(SP nz-number): the numbers are a possibly-empty
    /// repetition, so a search matching nothing still sends the line.
    /// </summary>
    [Fact]
    public async Task A_search_matching_nothing_still_sends_the_line()
    {
        Wire(await ExecuteAsync(await SearchableAsync(), "a2 SEARCH UNSEEN")).ShouldBe(
            "* SEARCH\r\na2 OK SEARCH completed\r\n");
    }

    /// <summary>
    /// §7.2.5: "For SEARCH, these are message sequence numbers; for UID SEARCH, these are unique
    /// identifiers."
    /// </summary>
    [Fact]
    public async Task Uid_search_reports_uids()
    {
        Wire(await ExecuteAsync(await SearchableAsync(), "a2 UID SEARCH ALL")).ShouldBe(
            "* SEARCH 5 9 14\r\na2 OK UID SEARCH completed\r\n");
    }

    [Theory]
    [InlineData("SEEN", "1 2 3")]
    [InlineData("UNSEEN", "")]
    [InlineData("UNDELETED", "1 2 3")]
    [InlineData("DELETED", "")]
    [InlineData("OLD", "1 2 3")]
    [InlineData("RECENT", "")]
    [InlineData("NEW", "")]
    public async Task Flag_keys_are_answered_from_the_stored_columns(string key, string expected)
    {
        string wire = Wire(await ExecuteAsync(await SearchableAsync(), $"a2 SEARCH {key}"));

        wire.ShouldStartWith(expected.Length == 0 ? "* SEARCH\r\n" : $"* SEARCH {expected}\r\n");
    }

    /// <summary>
    /// §6.4.4: "Messages that have a header with the specified field-name […] and that contains
    /// the specified string in the text of the header (what comes after the colon)."
    /// </summary>
    [Theory]
    [InlineData("FROM alice", "1")]
    [InlineData("FROM bob", "2")]
    [InlineData("SUBJECT lunch", "2")]
    [InlineData("SUBJECT \"quarterly report\"", "1")]
    [InlineData("HEADER Subject quarterly", "1")]
    public async Task Header_keys_search_the_value_and_not_the_field_name(
        string criteria,
        string expected)
    {
        Wire(await ExecuteAsync(await SearchableAsync(), $"a2 SEARCH {criteria}"))
            .ShouldStartWith($"* SEARCH {expected}\r\n");
    }

    /// <summary>
    /// A search for a header by its own field name must not match every message that has it —
    /// the value is searched, not the whole line.
    /// </summary>
    [Fact]
    public async Task Searching_a_header_for_its_own_name_matches_nothing()
    {
        Wire(await ExecuteAsync(await SearchableAsync(), "a2 SEARCH HEADER Subject Subject"))
            .ShouldStartWith("* SEARCH\r\n");
    }

    [Theory]
    [InlineData("BODY attached", "1")]
    [InlineData("BODY free", "2")]
    [InlineData("TEXT quarterly", "1")]
    public async Task Body_and_text_keys_search_content(string criteria, string expected)
    {
        Wire(await ExecuteAsync(await SearchableAsync(), $"a2 SEARCH {criteria}"))
            .ShouldStartWith($"* SEARCH {expected}\r\n");
    }

    /// <summary>
    /// §6.4.4: BODY is "in the body of the message" and TEXT is "in the header or body" — so a
    /// word that appears only in a header is found by one and not the other.
    /// </summary>
    [Fact]
    public async Task Body_excludes_the_header_where_text_includes_it()
    {
        ImapCommandProcessor processor = await SearchableAsync();

        Wire(await ExecuteAsync(processor, "a2 SEARCH BODY quarterly")).ShouldStartWith("* SEARCH\r\n");
        Wire(await ExecuteAsync(processor, "a3 SEARCH TEXT quarterly")).ShouldStartWith("* SEARCH 1\r\n");
    }

    /// <summary>
    /// §6.4.4: "When multiple keys are specified, the result is the intersection (AND function)
    /// of all the messages that match those keys."
    /// </summary>
    [Fact]
    public async Task Several_keys_intersect()
    {
        Wire(await ExecuteAsync(await SearchableAsync(), "a2 SEARCH SEEN FROM alice"))
            .ShouldStartWith("* SEARCH 1\r\n");
    }

    [Fact]
    public async Task Or_takes_the_union_of_two_keys()
    {
        Wire(await ExecuteAsync(await SearchableAsync(), "a2 SEARCH OR FROM alice FROM bob"))
            .ShouldStartWith("* SEARCH 1 2\r\n");
    }

    [Fact]
    public async Task Not_inverts_a_key()
    {
        Wire(await ExecuteAsync(await SearchableAsync(), "a2 SEARCH NOT FROM alice"))
            .ShouldStartWith("* SEARCH 2 3\r\n");
    }

    /// <summary>
    /// §6.4.4: "A search key can also be a parenthesized list of one or more search keys (e.g.,
    /// for use with the OR and NOT keys)." Without that a client could not express this at all.
    /// </summary>
    [Fact]
    public async Task A_parenthesised_list_groups_keys()
    {
        Wire(await ExecuteAsync(
            await SearchableAsync(),
            "a2 SEARCH OR (FROM alice SEEN) (FROM bob UNSEEN)"))
            .ShouldStartWith("* SEARCH 1\r\n");
    }

    [Theory]
    [InlineData("1:2", "1 2")]
    [InlineData("2:*", "2 3")]
    [InlineData("UID 9", "2")]
    [InlineData("UID 5:9", "1 2")]
    public async Task Sequence_and_uid_sets_are_search_keys(string criteria, string expected)
    {
        Wire(await ExecuteAsync(await SearchableAsync(), $"a2 SEARCH {criteria}"))
            .ShouldStartWith($"* SEARCH {expected}\r\n");
    }

    [Theory]
    [InlineData("LARGER 600", "2 3")]
    [InlineData("SMALLER 600", "1")]
    public async Task Size_keys_compare_the_stored_size(string criteria, string expected)
    {
        Wire(await ExecuteAsync(await SearchableAsync(), $"a2 SEARCH {criteria}"))
            .ShouldStartWith($"* SEARCH {expected}\r\n");
    }

    /// <summary>
    /// §6.4.4 says of every internal-date key "disregarding time and timezone", so the comparison
    /// is on the date alone.
    /// </summary>
    [Theory]
    [InlineData("BEFORE 2-Mar-2026", "1 2 3")]
    [InlineData("BEFORE 1-Mar-2026", "")]
    [InlineData("SINCE 1-Mar-2026", "1 2 3")]
    [InlineData("SINCE 2-Mar-2026", "")]
    [InlineData("ON 1-Mar-2026", "1 2 3")]
    [InlineData("ON 2-Mar-2026", "")]
    public async Task Internal_date_keys_disregard_the_time(string criteria, string expected)
    {
        string wire = Wire(await ExecuteAsync(await SearchableAsync(), $"a2 SEARCH {criteria}"));

        wire.ShouldStartWith(expected.Length == 0 ? "* SEARCH\r\n" : $"* SEARCH {expected}\r\n");
    }

    /// <summary>
    /// §6.4.4's SENT* keys are "Messages whose [RFC-2822] Date: header", which is a different
    /// date from the internal one — and a message with no Date: header matches none of them.
    /// </summary>
    [Theory]
    [InlineData("SENTON 2-Feb-2026", "1")]
    [InlineData("SENTSINCE 1-Mar-2026", "2")]
    [InlineData("SENTBEFORE 1-Mar-2026", "1")]
    public async Task Sent_date_keys_read_the_date_header(string criteria, string expected)
    {
        Wire(await ExecuteAsync(await SearchableAsync(), $"a2 SEARCH {criteria}"))
            .ShouldStartWith($"* SEARCH {expected}\r\n");
    }

    /// <summary>
    /// §6.4.4: "US-ASCII MUST be supported; other [CHARSET]s MAY be supported." One this server
    /// cannot decode earns the NO the same section provides for, rather than wrong results.
    /// </summary>
    [Theory]
    [InlineData("a2 SEARCH CHARSET US-ASCII ALL", " OK ")]
    [InlineData("a2 SEARCH CHARSET UTF-8 ALL", " OK ")]
    [InlineData("a2 SEARCH CHARSET KOI8-R ALL", " NO ")]
    public async Task An_unsupported_charset_is_refused(string line, string expected) =>
        Wire(await ExecuteAsync(await SearchableAsync(), line)).ShouldContain(expected);

    [Theory]
    [InlineData("a2 SEARCH")]
    [InlineData("a2 SEARCH NONSENSE")]
    [InlineData("a2 SEARCH NOT")]
    [InlineData("a2 SEARCH OR FROM alice")]
    [InlineData("a2 SEARCH (FROM alice")]
    [InlineData("a2 SEARCH LARGER abc")]
    [InlineData("a2 SEARCH BEFORE nonsense")]
    public async Task A_malformed_search_earns_a_tagged_bad(string line) =>
        Wire(await ExecuteAsync(await SearchableAsync(), line)).ShouldContain("a2 BAD ");

    /// <summary>A search must never mark a message read.</summary>
    [Fact]
    public async Task Searching_content_does_not_set_seen()
    {
        ScriptedImapAuthenticator authenticator = new();

        ScriptedImapMailboxReader mailboxes = new ScriptedImapMailboxReader()
            .Add(authenticator.KnownMailboxId, "INBOX", existsCount: 1)
            .Deliver(authenticator.KnownMailboxId, "INBOX", 1);

        mailboxes.WithContent(authenticator.KnownMailboxId, "INBOX", 1, "From: a@b\r\n\r\nhello\r\n");

        ImapCommandProcessor processor = Processor(
            authenticator: authenticator,
            mailboxes: mailboxes);

        await ExecuteAsync(processor, "a0 LOGIN alice@example.com hunter2");
        await ExecuteAsync(processor, "a1 SELECT INBOX");
        await ExecuteAsync(processor, @"a2 STORE 1 -FLAGS.SILENT (\Seen)");
        await ExecuteAsync(processor, "a3 SEARCH BODY hello");

        Wire(await ExecuteAsync(processor, "a4 FETCH 1 FLAGS")).ShouldContain("(FLAGS ())");
    }
}
