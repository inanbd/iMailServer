using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dkim;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Authentication.Tests;

/// <summary>
/// <see cref="DkimMessageSigner"/> and <see cref="DkimMessageVerifier"/> against each other: the
/// only way to prove the canonicalization, header-selection and blank-signature-value logic
/// actually agree with themselves, since there is no held-out RFC 6376 test vector using a key
/// this test can sign with.
/// </summary>
public sealed class DkimMessageSignerVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 16, 12, 0, 0, TimeSpan.Zero);
    private static readonly DomainName SigningDomain = DomainName.Parse("example.com");
    private static readonly DkimSelector Selector = DkimSelector.Parse("mail202609");

    private const string SampleMessage =
        "From: Alice <alice@example.com>\r\n" +
        "To: Bob <bob@example.org>\r\n" +
        "Subject: Hello\r\n" +
        "Date: Wed, 16 Sep 2026 12:00:00 +0000\r\n" +
        "Message-ID: <abc123@example.com>\r\n" +
        "MIME-Version: 1.0\r\n" +
        "Content-Type: text/plain\r\n" +
        "\r\n" +
        "Hello, Bob!\r\n" +
        "\r\n" +
        "- Alice\r\n";

    private static (RawMessageHeaders Headers, byte[] Body) ParseSample(string message)
    {
        byte[] buffer = Encoding.ASCII.GetBytes(message);
        RawMessageHeaders.TryParse(buffer, out RawMessageHeaders? headers, out string? error).ShouldBeTrue(error);
        return (headers!, buffer[headers!.HeaderBlockLength..]);
    }

    private static (byte[] Pkcs8PrivateKey, string PublicKeyBase64) GenerateKeyPair()
    {
        using RSA rsa = RSA.Create(2048);
        return (rsa.ExportPkcs8PrivateKey(), Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()));
    }

    private static byte[] BuildSignedMessage(string dkimSignatureValue, string originalMessage) =>
        Encoding.ASCII.GetBytes($"DKIM-Signature: {dkimSignatureValue}\r\n" + originalMessage);

    private sealed class FakeDkimPublicKeyResolver(
        Func<DkimSelector, DomainName, DkimPublicKeyLookupResult> respond) : IDkimPublicKeyResolver
    {
        public Task<DkimPublicKeyLookupResult> ResolveAsync(
            DkimSelector selector, DomainName signingDomain, CancellationToken cancellationToken) =>
            Task.FromResult(respond(selector, signingDomain));
    }

    private static IDkimPublicKeyResolver ResolverReturning(string publicKeyBase64) =>
        new FakeDkimPublicKeyResolver((_, _) =>
            DkimPublicKeyLookupResult.Success(new DkimPublicKeyRecordTestBuilder(publicKeyBase64).Build()));

    /// <summary>Builds a <see cref="DkimPublicKeyRecord"/> via its own TryParse, for test setup only.</summary>
    private sealed class DkimPublicKeyRecordTestBuilder(string publicKeyBase64)
    {
        public DkimPublicKeyRecord Build()
        {
            DkimPublicKeyRecord.TryParse($"v=DKIM1; k=rsa; p={publicKeyBase64}", out DkimPublicKeyRecord? record, out _);
            return record!;
        }
    }

    private static async Task<byte[]> SignAsync(
        RawMessageHeaders headers, byte[] body, byte[] pkcs8PrivateKey, DateTimeOffset? now = null)
    {
        var signer = new DkimMessageSigner();
        using var bodyStream = new MemoryStream(body);

        DkimSignatureTags tags = await signer.SignAsync(
            headers, bodyStream, SigningDomain, Selector, pkcs8PrivateKey, now ?? Now,
            cancellationToken: CancellationToken.None);

        return Encoding.ASCII.GetBytes(tags.Compose());
    }

    private static async Task<IReadOnlyList<DkimVerifiedSignature>> VerifyAsync(
        byte[] signedMessage, IDkimPublicKeyResolver resolver)
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(Encoding.ASCII.GetString(signedMessage));
        var verifier = new DkimMessageVerifier(resolver, NullLogger<DkimMessageVerifier>.Instance);
        using var bodyStream = new MemoryStream(body);

        return await verifier.VerifyAsync(headers, bodyStream, CancellationToken.None);
    }

    [Fact]
    public async Task A_freshly_signed_untampered_message_verifies()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] privateKey, string publicKeyBase64) = GenerateKeyPair();

        byte[] signatureValue = await SignAsync(headers, body, privateKey);
        byte[] signedMessage = BuildSignedMessage(Encoding.ASCII.GetString(signatureValue), SampleMessage);

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(
            signedMessage, ResolverReturning(publicKeyBase64));

        results.Count.ShouldBe(1);
        results[0].Result.ShouldBe(DkimVerificationResult.Pass);
        results[0].SigningDomain.ShouldBe(SigningDomain);
    }

    [Fact]
    public async Task A_message_with_no_signature_reports_None()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        var verifier = new DkimMessageVerifier(
            ResolverReturning("unused"), NullLogger<DkimMessageVerifier>.Instance);

        using var bodyStream = new MemoryStream(body);
        IReadOnlyList<DkimVerifiedSignature> results = await verifier.VerifyAsync(headers, bodyStream, CancellationToken.None);

        results.Count.ShouldBe(1);
        results[0].Result.ShouldBe(DkimVerificationResult.None);
    }

    [Fact]
    public async Task Tampering_with_a_signed_header_after_signing_fails_verification()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] privateKey, string publicKeyBase64) = GenerateKeyPair();

        byte[] signatureValue = await SignAsync(headers, body, privateKey);

        string tamperedMessage = SampleMessage.Replace("Subject: Hello", "Subject: Hello (edited)", StringComparison.Ordinal);
        byte[] signedMessage = BuildSignedMessage(Encoding.ASCII.GetString(signatureValue), tamperedMessage);

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(
            signedMessage, ResolverReturning(publicKeyBase64));

        results[0].Result.ShouldBe(DkimVerificationResult.Fail);
    }

    [Fact]
    public async Task Tampering_with_the_body_after_signing_fails_verification()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] privateKey, string publicKeyBase64) = GenerateKeyPair();

        byte[] signatureValue = await SignAsync(headers, body, privateKey);

        string tamperedMessage = SampleMessage.Replace("Hello, Bob!", "Hello, Bob! Please wire $10,000.", StringComparison.Ordinal);
        byte[] signedMessage = BuildSignedMessage(Encoding.ASCII.GetString(signatureValue), tamperedMessage);

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(
            signedMessage, ResolverReturning(publicKeyBase64));

        results[0].Result.ShouldBe(DkimVerificationResult.Fail);
    }

    [Fact]
    public async Task Adding_a_second_From_header_after_signing_fails_verification_via_oversigning()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] privateKey, string publicKeyBase64) = GenerateKeyPair();

        byte[] signatureValue = await SignAsync(headers, body, privateKey);

        // Prepend a second, attacker-chosen From header - the header-injection scenario
        // oversigning exists to defeat.
        string tamperedMessage = "From: attacker@evil.example\r\n" + SampleMessage;
        byte[] signedMessage = BuildSignedMessage(Encoding.ASCII.GetString(signatureValue), tamperedMessage);

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(
            signedMessage, ResolverReturning(publicKeyBase64));

        results[0].Result.ShouldBe(DkimVerificationResult.Fail);
    }

    [Fact]
    public async Task A_wrong_public_key_fails_verification()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] privateKey, _) = GenerateKeyPair();
        (_, string wrongPublicKeyBase64) = GenerateKeyPair();

        byte[] signatureValue = await SignAsync(headers, body, privateKey);
        byte[] signedMessage = BuildSignedMessage(Encoding.ASCII.GetString(signatureValue), SampleMessage);

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(
            signedMessage, ResolverReturning(wrongPublicKeyBase64));

        results[0].Result.ShouldBe(DkimVerificationResult.Fail);
    }

    [Fact]
    public async Task A_temporary_dns_failure_reports_TempError()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] privateKey, _) = GenerateKeyPair();

        byte[] signatureValue = await SignAsync(headers, body, privateKey);
        byte[] signedMessage = BuildSignedMessage(Encoding.ASCII.GetString(signatureValue), SampleMessage);

        var resolver = new FakeDkimPublicKeyResolver(
            (_, _) => DkimPublicKeyLookupResult.Temporary("resolver timed out"));

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(signedMessage, resolver);

        results[0].Result.ShouldBe(DkimVerificationResult.TempError);
    }

    [Fact]
    public async Task A_missing_selector_reports_PermError()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] privateKey, _) = GenerateKeyPair();

        byte[] signatureValue = await SignAsync(headers, body, privateKey);
        byte[] signedMessage = BuildSignedMessage(Encoding.ASCII.GetString(signatureValue), SampleMessage);

        var resolver = new FakeDkimPublicKeyResolver(
            (_, _) => DkimPublicKeyLookupResult.Permanent("no TXT record"));

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(signedMessage, resolver);

        results[0].Result.ShouldBe(DkimVerificationResult.PermError);
    }

    [Fact]
    public async Task A_revoked_key_reports_PermError()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] privateKey, _) = GenerateKeyPair();

        byte[] signatureValue = await SignAsync(headers, body, privateKey);
        byte[] signedMessage = BuildSignedMessage(Encoding.ASCII.GetString(signatureValue), SampleMessage);

        DkimPublicKeyRecord.TryParse("v=DKIM1; p=", out DkimPublicKeyRecord? revoked, out _);
        var resolver = new FakeDkimPublicKeyResolver((_, _) => DkimPublicKeyLookupResult.Success(revoked!));

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(signedMessage, resolver);

        results[0].Result.ShouldBe(DkimVerificationResult.PermError);
    }

    [Fact]
    public async Task An_unsupported_canonicalization_reports_PermError_without_touching_dns()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);

        string unsupportedSignature =
            "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=mail202609; " +
            "h=from; bh=YWJj; b=c2ln";

        byte[] signedMessage = BuildSignedMessage(unsupportedSignature, SampleMessage);

        var resolver = new FakeDkimPublicKeyResolver(
            (_, _) => throw new InvalidOperationException("DNS must not be queried for an unsupported signature."));

        IReadOnlyList<DkimVerifiedSignature> results = await VerifyAsync(signedMessage, resolver);

        results[0].Result.ShouldBe(DkimVerificationResult.PermError);
    }

    [Fact]
    public async Task Two_signatures_on_one_message_are_each_verified_independently()
    {
        (RawMessageHeaders headers, byte[] body) = ParseSample(SampleMessage);
        (byte[] goodKey, string goodPublicKeyBase64) = GenerateKeyPair();
        (byte[] otherKey, _) = GenerateKeyPair();

        byte[] goodSignature = await SignAsync(headers, body, goodKey);
        byte[] badSignature = await SignAsync(headers, body, otherKey); // signed with a key DNS won't return

        string message =
            $"DKIM-Signature: {Encoding.ASCII.GetString(goodSignature)}\r\n" +
            $"DKIM-Signature: {Encoding.ASCII.GetString(badSignature)}\r\n" +
            SampleMessage;

        (RawMessageHeaders combinedHeaders, byte[] combinedBody) = ParseSample(message);
        var verifier = new DkimMessageVerifier(
            ResolverReturning(goodPublicKeyBase64), NullLogger<DkimMessageVerifier>.Instance);

        using var bodyStream = new MemoryStream(combinedBody);
        IReadOnlyList<DkimVerifiedSignature> results = await verifier.VerifyAsync(
            combinedHeaders, bodyStream, CancellationToken.None);

        results.Count.ShouldBe(2);
        results[0].Result.ShouldBe(DkimVerificationResult.Pass);
        results[1].Result.ShouldBe(DkimVerificationResult.Fail);
    }
}
