using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using System.Security.Cryptography.X509Certificates;

namespace MailServer.Deliverability.Tests;

/// <summary>
/// Repository fakes for the report orchestrator.
/// </summary>
/// <remarks>
/// Every method the orchestrator does not call throws. A fake that returned an empty list from
/// everything would let a change that started calling a different method pass silently, and the
/// whole point of these tests is which questions the orchestrator asks.
/// </remarks>
internal sealed class FakeDomains(MailDomain? domain = null) : IDomainRepository
{
    public Task<MailDomain?> GetByNameAsync(DomainName name, CancellationToken cancellationToken) =>
        Task.FromResult(domain);

    public Task<MailDomain?> GetByIdAsync(DomainId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<bool> ExistsAsync(DomainName name, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<IReadOnlyList<MailDomain>> GetAllAsync(CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<IReadOnlyList<MailDomain>> GetOperationalAsync(CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task AddAsync(MailDomain domain, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task UpdateAsync(MailDomain domain, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task RemoveAsync(DomainId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<int> CountMailboxesAsync(DomainId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

internal sealed class FakeDkimKeys(IReadOnlyList<DkimKey>? keys = null) : IDkimKeyRepository
{
    public Task<IReadOnlyList<DkimKey>> GetForDomainAsync(
        DomainId domainId,
        CancellationToken cancellationToken) =>
        Task.FromResult(keys ?? []);

    public Task<DkimKey?> GetAsync(DkimKeyId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    /// <summary>
    /// Answered from the same seed rather than from a second one, so a test cannot set up a
    /// folder of keys whose "active" one is not among them — which no real repository can
    /// produce and which would let a consumer that picked the wrong key pass.
    /// </summary>
    public Task<DkimKey?> GetActiveForDomainAsync(DomainId domainId, CancellationToken cancellationToken) =>
        Task.FromResult(keys?.FirstOrDefault(k => k.Status == DkimKeyStatus.Active));

    public Task<IReadOnlyList<DkimKey>> GetAllAsync(CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task AddAsync(DkimKey key, byte[] pkcs8PrivateKey, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task UpdateAsync(DkimKey key, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task RemoveAsync(DkimKeyId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<byte[]?> GetPrivateKeyAsync(DkimKeyId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

internal sealed class FakeCertificates(
    Certificate? certificate = null,
    CertificateBinding? binding = null) : ICertificateRepository
{
    public Task<CertificateBinding?> GetBindingByHostnameAsync(
        DomainName hostname,
        CancellationToken cancellationToken) =>
        Task.FromResult(binding);

    public Task<Certificate?> GetAsync(CertificateId id, CancellationToken cancellationToken) =>
        Task.FromResult(certificate);

    public Task<Certificate?> GetByThumbprintAsync(
        CertificateThumbprint thumbprint,
        CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<IReadOnlyList<Certificate>> GetAllAsync(CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task AddAsync(Certificate certificate, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task UpdateAsync(Certificate certificate, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task RemoveAsync(CertificateId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<IReadOnlyList<CertificateBinding>> GetBindingsAsync(CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<IReadOnlyList<CertificateBinding>> GetBindingsForCertificateAsync(
        CertificateId certificateId,
        CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<CertificateBinding?> GetBindingAsync(
        CertificateBindingId id,
        CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task AddBindingAsync(CertificateBinding binding, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task UpdateBindingAsync(CertificateBinding binding, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task RemoveBindingAsync(CertificateBindingId id, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task ClearOtherDefaultsAsync(CertificateBindingId keep, CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

/// <summary>A provider with no certificate, so no chain is built in a test.</summary>
internal sealed class NoTlsCertificate : ITlsCertificateProvider
{
    public X509Certificate2? Select(string? hostname, CertificatePurpose purpose) => null;

    public Task ReloadAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public IReadOnlyCollection<DomainName> ConfiguredHostnames => [];

    public bool IsReady => false;
}

/// <summary>
/// A resolver that cancels the run and then throws, the way a real one does mid-lookup.
/// </summary>
/// <remarks>
/// The scripted resolver ignores its token, so a test that merely handed a pre-cancelled one to
/// the orchestrator would assert nothing: nothing would throw, the run would complete, and the
/// test would fail for the right reason by accident. This makes the cancellation arrive where it
/// actually arrives — inside a probe, as an <see cref="OperationCanceledException"/> the
/// boundary must not treat as a probe failure.
/// </remarks>
internal sealed class CancellingDiagnosticsService(CancellationTokenSource source)
    : MailServer.Application.Abstractions.Dns.IDnsDiagnosticsService
{
    public Task<MailServer.Application.Abstractions.Dns.DnsDiagnosticAnswer> LookupAsync(
        string name,
        MailServer.Application.Abstractions.Dns.DnsDiagnosticRecordType type,
        CancellationToken cancellationToken)
    {
        source.Cancel();

        throw new OperationCanceledException(source.Token);
    }

    public Task<MailServer.Application.Abstractions.Dns.DnsDiagnosticAnswer> LookupPointerAsync(
        IpAddressValue address,
        CancellationToken cancellationToken) =>
        LookupAsync(address.ToReverseDnsName(), default, cancellationToken);
}

/// <summary>A probe that always throws, for the boundary the orchestrator puts around them.</summary>
internal sealed class ThrowingDiagnosticsService : MailServer.Application.Abstractions.Dns.IDnsDiagnosticsService
{
    public Task<MailServer.Application.Abstractions.Dns.DnsDiagnosticAnswer> LookupAsync(
        string name,
        MailServer.Application.Abstractions.Dns.DnsDiagnosticRecordType type,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException("the resolver is unavailable");

    public Task<MailServer.Application.Abstractions.Dns.DnsDiagnosticAnswer> LookupPointerAsync(
        IpAddressValue address,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException("the resolver is unavailable");
}
