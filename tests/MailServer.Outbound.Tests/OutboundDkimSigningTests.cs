using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Certificates;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Dkim;
using MailServer.Infrastructure.Smtp.Outbound;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Outbound.Tests;

/// <summary>
/// <see cref="OutboundSmtpClient"/>'s DKIM signing wiring: it looks up the From: header's
/// domain, finds an active key (or doesn't), and prepends a real DKIM-Signature line to the wire
/// bytes only when one exists — proved here by having a fake <see cref="DkimMessageVerifier"/>
/// (the real production class, fed a fake DNS resolver) verify what the fake remote MTA actually
/// received.
/// </summary>
public sealed class OutboundDkimSigningTests
{
    private readonly FakeServerIdentity _identity = new();
    private readonly FakeMessageStore _store = new();

    private static (MailDomain Domain, DkimKey Key, byte[] PrivateKey, string PublicKeyBase64) SetUpActiveKey(
        string domainName)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        MailDomain domain = MailDomain.Create(DomainId.New(), DomainName.Parse(domainName), now);

        using RSA rsa = RSA.Create(2048);
        byte[] privateKey = rsa.ExportPkcs8PrivateKey();
        string publicKeyBase64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());

        DkimKey key = DkimKey.Generate(
            domain.Id, DkimSelector.Parse("mail202609"), DkimKeyAlgorithm.RsaSha256, publicKeyBase64, 2048, now);
        key.Publish(now);
        key.Activate(now);

        return (domain, key, privateKey, publicKeyBase64);
    }

    private OutboundSmtpClient CreateClient(IDomainRepository domains, IDkimKeyRepository keys) =>
        new(
            _identity,
            _store,
            new CertificateChainValidator(NullLogger<CertificateChainValidator>.Instance),
            domains,
            keys,
            new DkimMessageSigner(),
            new FakeClock(DateTimeOffset.UtcNow),
            Options.Create(new MailServerOptions
            {
                Outbound = new OutboundOptions
                {
                    ConnectTimeoutSeconds = 5,
                    CommandTimeoutSeconds = 5,
                    DataTimeoutSeconds = 5,
                },
            }),
            NullLogger<OutboundSmtpClient>.Instance);

    private async Task<StoredMessageId> StoreMessageAsync(string message)
    {
        await using IMessageWriter writer = await _store.BeginWriteAsync(1024 * 1024, CancellationToken.None);
        await writer.WriteAsync(Encoding.ASCII.GetBytes(message), CancellationToken.None);
        StoredMessage stored = await writer.CommitAsync(CancellationToken.None);
        return stored.Id;
    }

    [Fact]
    public async Task A_message_from_a_domain_with_an_active_key_is_signed_with_a_verifiable_signature()
    {
        (MailDomain domain, DkimKey key, byte[] privateKey, string publicKeyBase64) = SetUpActiveKey("example.com");

        var domains = new SingleDomainRepository(domain);
        var keys = new SingleKeyRepository(key, privateKey);

        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync(
            "From: Alice <alice@example.com>\r\n" +
            "To: bob@destination.example\r\n" +
            "Subject: Hi\r\n" +
            "Date: Wed, 16 Sep 2026 12:00:00 +0000\r\n" +
            "Message-ID: <abc@example.com>\r\n" +
            "\r\n" +
            "Hello, Bob!\r\n");

        OutboundDeliveryResult result = await CreateClient(domains, keys).DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("alice@example.com"),
                EmailAddress.Parse("bob@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        result.Outcome.ShouldBe(DeliveryOutcome.Delivered);

        string received = mta.ReceivedBody.ShouldNotBeNull();
        received.ShouldStartWith("DKIM-Signature: ");

        byte[] buffer = Encoding.ASCII.GetBytes(received + "\r\n\r\n");
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? parseError)
            .ShouldBeTrue(parseError);

        var resolver = new FixedPublicKeyResolver(publicKeyBase64);
        var verifier = new DkimMessageVerifier(
            resolver, new FakeClock(DateTimeOffset.UtcNow), NullLogger<DkimMessageVerifier>.Instance);

        using var bodyStream = new MemoryStream(buffer[headers!.HeaderBlockLength..]);
        IReadOnlyList<DkimVerifiedSignature> verified = await verifier.VerifyAsync(
            headers, bodyStream, CancellationToken.None);

        verified.Count.ShouldBe(1);
        verified[0].Result.ShouldBe(DkimVerificationResult.Pass);
        verified[0].SigningDomain.ShouldBe(domain.Name);
    }

    [Fact]
    public async Task A_message_from_a_domain_with_no_active_key_is_sent_unsigned()
    {
        (MailDomain domain, DkimKey key, byte[] privateKey, _) = SetUpActiveKey("example.com");
        key.Retire(TimeSpan.FromDays(1), DateTimeOffset.UtcNow); // no longer Active

        var domains = new SingleDomainRepository(domain);
        var keys = new SingleKeyRepository(key, privateKey);

        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync(
            "From: alice@example.com\r\nTo: bob@destination.example\r\n\r\nHello.\r\n");

        await CreateClient(domains, keys).DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("alice@example.com"),
                EmailAddress.Parse("bob@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        mta.ReceivedBody.ShouldNotBeNull().ShouldNotContain("DKIM-Signature:");
    }

    [Fact]
    public async Task A_message_from_a_domain_this_server_does_not_host_is_sent_unsigned()
    {
        var domains = new FakeDomainRepository();
        var keys = new FakeDkimKeyRepository();

        await using FakeRemoteMta mta = new();
        StoredMessageId messageId = await StoreMessageAsync(
            "From: someone@unrelated.example\r\nTo: bob@destination.example\r\n\r\nHello.\r\n");

        await CreateClient(domains, keys).DeliverAsync(
            new OutboundDeliveryRequest(
                "127.0.0.1", mta.Port, EmailAddress.Parse("someone@unrelated.example"),
                EmailAddress.Parse("bob@destination.example"), messageId, RequireTls: false),
            CancellationToken.None);

        mta.ReceivedBody.ShouldNotBeNull().ShouldNotContain("DKIM-Signature:");
    }

    // ---- Fakes ----------------------------------------------------------------------------

    private sealed class SingleDomainRepository(MailDomain domain) : IDomainRepository
    {
        public Task<MailDomain?> GetByIdAsync(DomainId id, CancellationToken cancellationToken) =>
            Task.FromResult(id == domain.Id ? domain : null);

        public Task<MailDomain?> GetByNameAsync(DomainName name, CancellationToken cancellationToken) =>
            Task.FromResult(name == domain.Name ? domain : null);

        public Task<bool> ExistsAsync(DomainName name, CancellationToken cancellationToken) =>
            Task.FromResult(name == domain.Name);

        public Task<IReadOnlyList<MailDomain>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MailDomain>>([domain]);

        public Task<IReadOnlyList<MailDomain>> GetOperationalAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MailDomain>>([domain]);

        public Task AddAsync(MailDomain d, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task UpdateAsync(MailDomain d, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RemoveAsync(DomainId id, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<int> CountMailboxesAsync(DomainId id, CancellationToken cancellationToken) => Task.FromResult(0);
    }

    private sealed class SingleKeyRepository(DkimKey key, byte[] privateKey) : IDkimKeyRepository
    {
        public Task<DkimKey?> GetAsync(DkimKeyId id, CancellationToken cancellationToken) =>
            Task.FromResult(id == key.Id ? key : null);

        public Task<IReadOnlyList<DkimKey>> GetForDomainAsync(DomainId domainId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DkimKey>>(domainId == key.DomainId ? [key] : []);

        public Task<DkimKey?> GetActiveForDomainAsync(DomainId domainId, CancellationToken cancellationToken) =>
            Task.FromResult(domainId == key.DomainId && key.Status == DkimKeyStatus.Active ? key : null);

        public Task<IReadOnlyList<DkimKey>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DkimKey>>([key]);

        public Task AddAsync(DkimKey k, byte[] pkcs8PrivateKey, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task UpdateAsync(DkimKey k, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RemoveAsync(DkimKeyId id, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<byte[]?> GetPrivateKeyAsync(DkimKeyId id, CancellationToken cancellationToken) =>
            Task.FromResult(id == key.Id ? privateKey : null);
    }

    private sealed class FixedPublicKeyResolver(string publicKeyBase64) : IDkimPublicKeyResolver
    {
        public Task<DkimPublicKeyLookupResult> ResolveAsync(
            DkimSelector selector, DomainName signingDomain, CancellationToken cancellationToken)
        {
            DkimPublicKeyRecord.TryParse($"v=DKIM1; k=rsa; p={publicKeyBase64}", out DkimPublicKeyRecord? record, out _);
            return Task.FromResult(DkimPublicKeyLookupResult.Success(record!));
        }
    }
}
