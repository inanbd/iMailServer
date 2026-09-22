using System.Text;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Filtering;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.Filtering;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Filtering.Tests;

/// <summary>A message store backed by a dictionary.</summary>
internal sealed class FakeMessageStore : IMessageStore
{
    private readonly Dictionary<Guid, byte[]> _messages = [];

    /// <summary>How many times a message's bytes have been opened.</summary>
    public int Reads { get; private set; }

    /// <summary>Set to fail every read, to test that the filter does not take a failure as a verdict.</summary>
    public bool FailReads { get; set; }

    public StoredMessage Add(string content) => Add(Encoding.ASCII.GetBytes(content.ReplaceLineEndings("\r\n")));

    public StoredMessage Add(byte[] content)
    {
        Guid id = Guid.NewGuid();
        _messages[id] = content;

        return new StoredMessage(
            new StoredMessageId(id),
            content.Length,
            Sha256Hash.FromBytes(System.Security.Cryptography.SHA256.HashData(content)),
            DateTimeOffset.UtcNow);
    }

    /// <summary>Declares a message far bigger than its bytes, so the size bound can be tested cheaply.</summary>
    public StoredMessage AddClaimingSize(string content, long sizeBytes)
    {
        StoredMessage stored = Add(content);

        return stored with { SizeBytes = sizeBytes };
    }

    public ValueTask<IMessageWriter> BeginWriteAsync(long maxSizeBytes, CancellationToken cancellationToken) =>
        throw new NotSupportedException("The filter never writes.");

    public ValueTask<Stream> OpenReadAsync(StoredMessageId id, CancellationToken cancellationToken)
    {
        Reads++;

        if (FailReads)
        {
            throw new IOException("The store is broken.");
        }

        return ValueTask.FromResult<Stream>(new MemoryStream(_messages[id.Value], writable: false));
    }

    public ValueTask<bool> ExistsAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_messages.ContainsKey(id.Value));

    public ValueTask<bool> DeleteAsync(StoredMessageId id, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_messages.Remove(id.Value));
}

/// <summary>A scanner that answers however a test tells it to.</summary>
internal sealed class FakeMalwareScanner(MalwareScanResult result, bool enabled = true) : IMalwareScanner
{
    /// <summary>How many times it was asked.</summary>
    public int Scans { get; private set; }

    /// <summary>Set to throw, to test that a broken engine does not stop mail.</summary>
    public bool Throw { get; set; }

    public string Name => "fake-scanner";

    public bool IsEnabled => enabled;

    public Task<MalwareScanResult> ScanAsync(Stream content, CancellationToken cancellationToken)
    {
        Scans++;

        if (Throw)
        {
            throw new InvalidOperationException("The engine fell over.");
        }

        return Task.FromResult(result);
    }
}

/// <summary>A reputation provider that answers from a fixed table.</summary>
internal sealed class FakeReputationProvider(params ReputationListing[] listings) : IReputationProvider
{
    public IReadOnlyList<string> Lists { get; } =
        listings.Length == 0 ? [] : [.. listings.Select(l => l.Provider).Distinct()];

    public Task<IReadOnlyList<ReputationListing>> CheckAddressAsync(
        IpAddressValue address, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ReputationListing>>(listings);

    public Task<IReadOnlyList<ReputationListing>> CheckDomainAsync(
        DomainName domain, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ReputationListing>>(listings);
}

/// <summary>A check that does whatever a test needs, including misbehaving.</summary>
internal sealed class StubSpamCheck(
    string name,
    SpamCheckResult result,
    bool needsContent = false) : ISpamCheck
{
    public int Inspections { get; private set; }

    public bool Throw { get; set; }

    public string Name => name;

    public bool NeedsContent => needsContent;

    public Task<SpamCheckResult> InspectAsync(
        MessageFilterContext context, CancellationToken cancellationToken)
    {
        Inspections++;

        if (Throw)
        {
            throw new InvalidOperationException($"{name} is broken.");
        }

        return Task.FromResult(result);
    }
}

/// <summary>Shared fixture values.</summary>
internal static class Fixture
{
    public static readonly DateTimeOffset Now = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);

    public static NullLogger<T> Log<T>() => NullLogger<T>.Instance;

    public static IpAddressValue Peer { get; } = IpAddressValue.Parse("198.51.100.7");

    public static MessageAuthenticationFacts NoAuthentication { get; } = new(null, null, null, null);

    public static MessageAuthenticationFacts FullPass { get; } =
        new(SpfResult.Pass, DkimVerificationResult.Pass, DmarcResult.Pass, DmarcPolicy.None);

    public static MessageFilterRequest Request(
        StoredMessage message,
        MessageAuthenticationFacts? authentication = null,
        int recipients = 1) =>
        new(message, null, Peer, recipients, authentication ?? NoAuthentication, Now);

    /// <summary>A well-formed message with one attachment of the caller's choosing.</summary>
    public static string WithAttachment(string fileNameParameter) => $"""
        From: Alice <alice@example.com>
        To: Bob <bob@example.net>
        Subject: Documents
        Date: Tue, 22 Sep 2026 11:58:00 +0000
        Message-ID: <abc@example.com>
        Content-Type: multipart/mixed; boundary="b"

        --b
        Content-Type: text/plain

        See attached.
        --b
        Content-Type: application/octet-stream
        Content-Disposition: attachment; {fileNameParameter}

        AAAA
        --b--

        """;

    /// <summary>A message with nothing structurally wrong with it and no attachment.</summary>
    public const string Ordinary = """
        From: Alice <alice@example.com>
        To: Bob <bob@example.net>
        Subject: Lunch on Thursday
        Date: Tue, 22 Sep 2026 11:58:00 +0000
        Message-ID: <abc@example.com>
        Content-Type: text/plain

        Shall we say one o'clock?

        """;
}
