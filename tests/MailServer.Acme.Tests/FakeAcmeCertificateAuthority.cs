using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Acme;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Acme.Tests;

/// <summary>
/// A stand-in certificate authority that records what it was asked and answers as told.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a fake at this seam rather than a stub HTTP server.</b> <see cref="IAcmeClient"/> is
/// the boundary between this product's issuance logic and Certes' protocol handling. Everything
/// this suite is responsible for — pre-flight, rate limiting, challenge publication and
/// cleanup, storage, binding, and what happens on each failure — sits on <i>this</i> side of
/// it. A stub HTTP server would additionally exercise Certes' JWS signing and nonce handling,
/// which is third-party code with its own tests.
/// </para>
/// <para>
/// The part that genuinely cannot be tested here is Certes talking to Let's Encrypt, because
/// that needs a publicly resolvable domain and inbound port 80. That limitation is stated
/// plainly in docs/LetsEncrypt.md rather than papered over with a test that proves less than it
/// appears to.
/// </para>
/// </remarks>
internal sealed class FakeAcmeCertificateAuthority : IAcmeClient, IAcmeClientFactory
{
    private readonly List<DomainName> _lastIdentifiers = [];

    public FakeAcmeCertificateAuthority() => OrderUrl = null;

    /// <summary>Set to make <see cref="CreateOrderAsync"/> fail as the CA would.</summary>
    public AcmeProtocolException? CreateOrderFailure { get; set; }

    /// <summary>Set to make validation fail, as a misconfigured domain would.</summary>
    public AcmeProtocolException? ValidationFailure { get; set; }

    /// <summary>Set to make finalisation fail.</summary>
    public AcmeProtocolException? FinalizeFailure { get; set; }

    /// <summary>Set to make account registration fail.</summary>
    public AcmeProtocolException? RegistrationFailure { get; set; }

    /// <summary>Which challenge type the CA should offer.</summary>
    public AcmeChallengeType OfferedChallengeType { get; set; } = AcmeChallengeType.Http01;

    public int CreateOrderCalls { get; private set; }

    public int ValidateCalls { get; private set; }

    public int FinalizeCalls { get; private set; }

    public int RegistrationCalls { get; private set; }

    /// <summary>The challenges handed out by the most recent order.</summary>
    public IReadOnlyList<AcmeChallenge> IssuedChallenges { get; private set; } = [];

    public string? OrderUrl { get; private set; }

    public Task<IAcmeClient> CreateAsync(
        string directoryUrl,
        string accountKeyPem,
        CancellationToken cancellationToken) => Task.FromResult<IAcmeClient>(this);

    public Task<AcmeAccountRegistration> EnsureAccountAsync(
        string directoryUrl,
        string accountKeyPem,
        string contactEmail,
        bool acceptTermsOfService,
        CancellationToken cancellationToken)
    {
        RegistrationCalls++;

        if (RegistrationFailure is not null)
        {
            throw RegistrationFailure;
        }

        return Task.FromResult(new AcmeAccountRegistration(
            "https://ca.test.invalid/acct/1",
            "https://ca.test.invalid/terms"));
    }

    public Task<IReadOnlyList<AcmeChallenge>> CreateOrderAsync(
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        CancellationToken cancellationToken)
    {
        CreateOrderCalls++;

        if (CreateOrderFailure is not null)
        {
            throw CreateOrderFailure;
        }

        _lastIdentifiers.Clear();
        _lastIdentifiers.AddRange(identifiers);

        OrderUrl = $"https://ca.test.invalid/order/{CreateOrderCalls}";

        List<AcmeChallenge> challenges = [];

        foreach (DomainName identifier in identifiers)
        {
            string token = $"token-{identifier.Value}-{CreateOrderCalls}";

            challenges.Add(OfferedChallengeType == AcmeChallengeType.Dns01
                ? new AcmeChallenge(
                    identifier,
                    AcmeChallengeType.Dns01,
                    token,
                    $"digest-of-{token}",
                    $"_acme-challenge.{identifier.Value}")
                : new AcmeChallenge(
                    identifier,
                    AcmeChallengeType.Http01,
                    token,
                    $"{token}.key-authorization"));
        }

        IssuedChallenges = challenges;

        return Task.FromResult<IReadOnlyList<AcmeChallenge>>(challenges);
    }

    public Task ValidateChallengesAsync(CancellationToken cancellationToken)
    {
        ValidateCalls++;

        return ValidationFailure is not null
            ? throw ValidationFailure
            : Task.CompletedTask;
    }

    public Task<AcmeIssuedCertificate> FinalizeOrderAsync(
        IReadOnlyList<DomainName> identifiers,
        int keySizeBits,
        CancellationToken cancellationToken)
    {
        FinalizeCalls++;

        if (FinalizeFailure is not null)
        {
            throw FinalizeFailure;
        }

        // A real certificate covering the requested names, so everything downstream - storage,
        // SAN parsing, binding, selection - operates on the genuine article rather than a
        // placeholder that would hide a mismatch.
        return Task.FromResult(new AcmeIssuedCertificate(
            IssueCertificate(identifiers)));
    }

    /// <summary>Issues a real, briefly-valid certificate for the identifiers.</summary>
    /// <remarks>
    /// 90 days, matching Let's Encrypt, so a renewal-window test does not need a different
    /// lifetime from the one production will see.
    /// </remarks>
    private static X509Certificate2 IssueCertificate(IReadOnlyList<DomainName> identifiers)
    {
        using RSA key = RSA.Create(2048);

        CertificateRequest request = new(
            new X500DistinguishedName($"CN={identifiers[0].Value}"),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            true));

        SubjectAlternativeNameBuilder san = new();

        foreach (DomainName identifier in identifiers)
        {
            san.AddDnsName(identifier.Value);
        }

        request.CertificateExtensions.Add(san.Build());

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(90));
    }
}

/// <summary>A DNS provider that records what it was asked to publish and remove.</summary>
internal sealed class RecordingDnsChallengeProvider : IDnsChallengeProvider
{
    public List<string> Published { get; } = [];

    public List<string> Removed { get; } = [];

    /// <summary>When false, behaves like the manual provider and returns instructions.</summary>
    public bool SupportsAutomaticPublication { get; set; } = true;

    public string Name => "Recording";

    public Task<DnsChallengePublication> PublishAsync(
        DomainName identifier,
        string recordName,
        string recordValue,
        CancellationToken cancellationToken)
    {
        Published.Add(recordName);

        return Task.FromResult(SupportsAutomaticPublication
            ? new DnsChallengePublication(true)
            : new DnsChallengePublication(false, $"Create TXT {recordName} = {recordValue}"));
    }

    public Task<bool> IsPublishedAsync(
        string recordName,
        string expectedValue,
        CancellationToken cancellationToken) => Task.FromResult(true);

    public Task RemoveAsync(string recordName, CancellationToken cancellationToken)
    {
        Removed.Add(recordName);
        return Task.CompletedTask;
    }
}

/// <summary>A pre-flight check that answers as the test tells it to.</summary>
internal sealed class ScriptedPreflightCheck : IAcmePreflightCheck
{
    public bool ShouldBlock { get; set; }

    public string BlockReason { get; set; } = "Pre-flight refused this order.";

    public int Calls { get; private set; }

    public Task<PreflightReport> CheckAsync(
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        CancellationToken cancellationToken)
    {
        Calls++;

        return Task.FromResult(new PreflightReport(
        [
            new PreflightFinding(
                identifiers[0],
                !ShouldBlock,
                ShouldBlock ? BlockReason : "Looks fine.",
                ShouldBlock),
        ]));
    }
}
