using System.Text;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Imap;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;

namespace MailServer.Pop3.Tests;

/// <summary>An authenticator that knows one mailbox and one password.</summary>
/// <remarks>
/// Deliberately not a mock framework: the tests assert on what the processor did with the
/// result, and a hand-written fake makes the credential that reached it inspectable.
/// </remarks>
internal sealed class ScriptedPop3Authenticator : IMailboxAuthenticator
{
    public MailboxId KnownMailboxId { get; } = new(Guid.NewGuid());

    public string KnownAddress { get; init; } = "alice@example.com";

    public string KnownPassword { get; init; } = "hunter2";

    /// <summary>Every (identity, password) pair this fake was asked about.</summary>
    public List<(string Identity, string Password)> Attempts { get; } = [];

    public Task<MailboxAuthenticationResult> AuthenticateAsync(
        SaslCredential credential,
        IpAddressValue remoteAddress,
        CancellationToken cancellationToken)
    {
        string password = new(credential.Password);

        Attempts.Add((credential.AuthenticationIdentity, password));

        bool ok =
            credential.AuthenticationIdentity.Equals(KnownAddress, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(password, KnownPassword, StringComparison.Ordinal);

        return Task.FromResult(ok
            ? new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Succeeded,
                EmailAddress.Parse(KnownAddress),
                "ok",
                KnownMailboxId)
            : new MailboxAuthenticationResult(
                MailboxAuthenticationOutcome.Failed,
                null,
                "refused"));
    }
}

/// <summary>
/// A mailbox with one folder and some messages in it.
/// </summary>
/// <remarks>
/// Implements both halves of the repository because a POP3 session reads and then, at
/// <c>QUIT</c>, writes — and a test that used two objects could not see the write land where the
/// read came from.
/// </remarks>
internal sealed class ScriptedPop3Mailboxes : IImapMailboxReader, IImapMailboxWriter
{
    private readonly List<ImapMessageSummary> _messages = [];

    public ScriptedPop3Mailboxes(MailboxId mailboxId, long uidValidity = 3_857_529_045)
    {
        MailboxId = mailboxId;
        Folder = new MailboxFolder(
            new MailboxFolderId(Guid.NewGuid()),
            mailboxId,
            "INBOX",
            FolderSpecialUse.Inbox,
            uidValidity,
            nextUid: 1,
            isSubscribed: true,
            DateTimeOffset.UnixEpoch,
            null);
    }

    public MailboxId MailboxId { get; }

    public MailboxFolder Folder { get; }

    /// <summary>The stored octets of each message, keyed by its UID.</summary>
    public Dictionary<long, byte[]> Content { get; } = [];

    /// <summary>Every UID set this fake was asked to remove.</summary>
    public List<long[]> Removed { get; } = [];

    /// <summary>Whether the folder can be opened at all. False makes OpenFolderAsync answer null.</summary>
    public bool FolderExists { get; set; } = true;

    /// <summary>Set to throw from the removal, for the failure path RFC 1939 §6 has a reply for.</summary>
    public bool FailRemoval { get; set; }

    public ScriptedPop3Mailboxes Deliver(long uid, string message)
    {
        byte[] octets = Encoding.Latin1.GetBytes(message);

        _messages.Add(new ImapMessageSummary(
            _messages.Count + 1,
            uid,
            MessageFlags.None,
            new DateTimeOffset(2026, 3, 1, 9, 30, 15, TimeSpan.Zero),
            octets.Length));

        Content[uid] = octets;

        return this;
    }

    public Task<ImapFolderSnapshot?> OpenFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken) =>
        Task.FromResult(FolderExists && mailboxId.Value == MailboxId.Value
            ? new ImapFolderSnapshot(Folder, _messages.Count, null)
            : null);

    public Task<IReadOnlyList<ImapMessageSummary>> ReadSummariesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ImapMessageSummary>>([.. _messages]);

    public Task<IReadOnlyDictionary<long, StoredMessageId>> ReadMessageIdsAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        IReadOnlyList<long> uids,
        CancellationToken cancellationToken)
    {
        Dictionary<long, StoredMessageId> located = [];

        foreach (long uid in uids)
        {
            if (Content.ContainsKey(uid))
            {
                located[uid] = new StoredMessageId(UidToGuid(uid));
            }
        }

        return Task.FromResult<IReadOnlyDictionary<long, StoredMessageId>>(located);
    }

    public Task<long> DeleteMessagesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        IReadOnlyList<long> uids,
        CancellationToken cancellationToken)
    {
        if (FailRemoval)
        {
            throw new InvalidOperationException("the removal was told to fail");
        }

        Removed.Add([.. uids]);

        HashSet<long> wanted = [.. uids];
        int before = _messages.Count;

        _messages.RemoveAll(m => wanted.Contains(m.Uid));

        foreach (long uid in wanted)
        {
            Content.Remove(uid);
        }

        return Task.FromResult((long)(before - _messages.Count));
    }

    /// <summary>A stable identity for a UID, so the store and the reader agree.</summary>
    internal static Guid UidToGuid(long uid)
    {
        byte[] bytes = new byte[16];

        BitConverter.TryWriteBytes(bytes, uid);

        return new Guid(bytes);
    }

    // ---- Everything else the interfaces require and POP3 never calls -------------------------

    public Task<IReadOnlyList<ImapFolderListing>> ListFoldersAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ImapFolderListing>>([]);

    public Task<ImapFolderStatus?> ReadStatusAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken) =>
        Task.FromResult<ImapFolderStatus?>(null);

    public Task<IReadOnlyList<string>> ListSubscriptionsAsync(
        MailboxId mailboxId,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<string>>([]);

    public Task<long> CountMessagesAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        CancellationToken cancellationToken) =>
        Task.FromResult((long)_messages.Count);

    public Task<IReadOnlyList<ImapMessageSummary>> StoreFlagsAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        ImapStoreRequest request,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ImapMessageSummary>>([]);

    public Task<IReadOnlyList<long>> ExpungeAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<long>>([]);

    public Task<ImapFolderMutation> CreateFolderAsync(
        MailboxId mailboxId,
        string path,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        Task.FromResult(ImapFolderMutation.NotFound);

    public Task<ImapFolderMutation> DeleteFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken) =>
        Task.FromResult(ImapFolderMutation.NotFound);

    public Task<ImapFolderMutation> RenameFolderAsync(
        MailboxId mailboxId,
        string from,
        string to,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        Task.FromResult(ImapFolderMutation.NotFound);

    public Task<ImapCopyResult> CopyAsync(
        MailboxId mailboxId,
        MailboxFolderId folderId,
        ImapSequenceSet set,
        bool byUid,
        string path,
        bool removeFromSource,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        Task.FromResult(new ImapCopyResult(ImapFolderMutation.NotFound, [], 0));

    public Task<ImapAppendResult> AppendAsync(
        MailboxId mailboxId,
        string path,
        StoredMessage stored,
        MessageFlags flags,
        DateTimeOffset internalDate,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        Task.FromResult(new ImapAppendResult(ImapFolderMutation.NotFound, null, 0));

    public Task<ImapFolderMutation> SetSubscriptionAsync(
        MailboxId mailboxId,
        string path,
        bool subscribed,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        Task.FromResult(ImapFolderMutation.NotFound);
}

/// <summary>A message store serving the octets a <see cref="ScriptedPop3Mailboxes"/> holds.</summary>
internal sealed class ScriptedPop3MessageStore(ScriptedPop3Mailboxes source) : IMessageStore
{
    /// <summary>Set to throw from a read, for the unreadable-message path.</summary>
    public bool FailReads { get; set; }

    public ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken)
    {
        if (FailReads)
        {
            throw new IOException("the read was told to fail");
        }

        foreach ((long uid, byte[] octets) in source.Content)
        {
            if (ScriptedPop3Mailboxes.UidToGuid(uid) == id.Value)
            {
                return ValueTask.FromResult<Stream>(new MemoryStream(octets, writable: false));
            }
        }

        throw new IOException("no such message");
    }

    public ValueTask<IMessageWriter> BeginWriteAsync(
        long maxSizeBytes,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("POP3 never writes a message.");

    public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(true);

    public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(true);
}
