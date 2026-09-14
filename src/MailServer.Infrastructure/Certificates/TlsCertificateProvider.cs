using System.Collections.Frozen;
using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Certificates;

/// <summary>
/// The hot-swappable certificate source consulted on every TLS handshake.
/// </summary>
/// <remarks>
/// <para>
/// A singleton holding one immutable <see cref="Snapshot"/> in a field replaced by
/// <see cref="Interlocked.Exchange{T}(ref T, T)"/>. Readers take no lock at all: they read the
/// reference once and use whatever they got. Writers build a complete new snapshot off the
/// handshake path and publish it in a single instruction.
/// </para>
/// <para>
/// <b>Why an immutable snapshot rather than a concurrent dictionary.</b> A reload changes
/// several entries at once — a renewed certificate, its binding, possibly the default. A
/// mutable map would expose intermediate states in which a handshake could see the new
/// certificate for one hostname and the old one for another, or briefly find no default at
/// all. Swapping a whole snapshot means no handshake ever observes a half-applied reload.
/// </para>
/// <para>
/// <b>The rollback window.</b> The previous snapshot's certificates are not disposed
/// immediately: a handshake that read the old reference microseconds before the swap is still
/// using them, and disposing an <see cref="X509Certificate2"/> out from under an in-flight
/// handshake produces an <c>ObjectDisposedException</c> inside the TLS stack. They are held
/// for <see cref="RollbackWindow"/> and disposed on the next reload after that.
/// </para>
/// </remarks>
internal sealed class TlsCertificateProvider : ITlsCertificateProvider, IDisposable
{
    /// <summary>
    /// How long a superseded snapshot's certificates are kept alive after being replaced.
    /// </summary>
    /// <remarks>
    /// Generous on purpose. The cost of holding a few certificates for an extra minute is a
    /// few kilobytes; the cost of disposing one a millisecond too early is a failed handshake
    /// that looks like an intermittent TLS fault.
    /// </remarks>
    private static readonly TimeSpan RollbackWindow = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<TlsCertificateProvider> _logger;
    private readonly Lock _reloadGate = new();

    private Snapshot _current = Snapshot.Empty;
    private Snapshot? _superseded;
    private DateTimeOffset _supersededAtUtc;

    public TlsCertificateProvider(
        IServiceScopeFactory scopeFactory,
        ILogger<TlsCertificateProvider> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    public bool IsReady => _current.HasAny;

    public IReadOnlyCollection<DomainName> ConfiguredHostnames => _current.Hostnames;

    /// <summary>
    /// Chooses a certificate. Runs on the handshake path: no locks, no allocation, no I/O.
    /// </summary>
    public X509Certificate2? Select(string? hostname, CertificatePurpose purpose)
    {
        // Read once. Everything after this point works against a consistent snapshot even if
        // a reload publishes a new one mid-method.
        Snapshot snapshot = _current;

        if (!snapshot.HasAny)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(hostname) &&
            snapshot.ByHostname.TryGetValue(hostname, out Entry? exact) &&
            exact.AppliesTo(purpose))
        {
            return exact.Certificate;
        }

        // No SNI, an unknown name, or a binding that does not cover this service. Falling back
        // to the default is what keeps a non-SNI MTA — still a meaningful share of inbound
        // mail — able to deliver, instead of failing the handshake with an opaque error.
        return snapshot.Default?.AppliesTo(purpose) == true
            ? snapshot.Default.Certificate
            : null;
    }

    public async Task ReloadAsync(CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = _scopeFactory.CreateAsyncScope();

        ICertificateRepository repository =
            scope.ServiceProvider.GetRequiredService<ICertificateRepository>();

        ICertificateManager manager =
            scope.ServiceProvider.GetRequiredService<ICertificateManager>();

        IReadOnlyList<CertificateBinding> bindings = await repository
            .GetBindingsAsync(cancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, Entry> byHostname = new(StringComparer.OrdinalIgnoreCase);
        Entry? defaultEntry = null;

        foreach (CertificateBinding binding in bindings)
        {
            Certificate? metadata = await repository
                .GetAsync(binding.CertificateId, cancellationToken)
                .ConfigureAwait(false);

            if (metadata is null)
            {
                _logger.LogError(
                    "The binding for {Hostname} names certificate {CertificateId}, which does " +
                    "not exist. The hostname will fall back to the default certificate.",
                    binding.Hostname,
                    binding.CertificateId);

                continue;
            }

            X509Certificate2? certificate = await manager
                .LoadAsync(metadata.KeyLocation, cancellationToken)
                .ConfigureAwait(false);

            if (certificate is null)
            {
                // Already logged in detail by the loader. Not fatal: other hostnames still
                // work, and failing the whole reload would take down TLS for all of them
                // because one certificate file went missing.
                continue;
            }

            Entry entry = new(certificate, binding.Purpose);

            byHostname[binding.Hostname.Value] = entry;

            if (binding.IsDefault)
            {
                defaultEntry = entry;
            }
        }

        // Without a default, a handshake carrying no SNI has nothing to present. Picking an
        // arbitrary certificate is better than refusing the connection: a name mismatch is a
        // warning the remote can choose to accept, whereas no certificate is a hard failure.
        if (defaultEntry is null && byHostname.Count > 0)
        {
            defaultEntry = byHostname.Values.First();

            _logger.LogWarning(
                "No certificate binding is marked as the default. A handshake that offers no " +
                "SNI hostname will be served an arbitrary certificate, which may not match " +
                "the name the client expects. Mark one binding as the default.");
        }

        Snapshot replacement = new(
            byHostname.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase),
            defaultEntry);

        Snapshot previous;

        lock (_reloadGate)
        {
            previous = Interlocked.Exchange(ref _current, replacement);

            // Dispose the snapshot superseded by the PREVIOUS reload, if its window has
            // elapsed. Never the one just replaced - a handshake may be using it right now.
            if (_superseded is not null &&
                DateTimeOffset.UtcNow - _supersededAtUtc > RollbackWindow)
            {
                _superseded.Dispose();
                _superseded = null;
            }

            if (_superseded is null && !ReferenceEquals(previous, Snapshot.Empty))
            {
                _superseded = previous;
                _supersededAtUtc = DateTimeOffset.UtcNow;
            }
        }

        _logger.LogInformation(
            "TLS certificates reloaded: {HostnameCount} hostname binding(s) active. In-flight " +
            "connections continue on the certificate they started with.",
            replacement.ByHostname.Count);
    }

    public void Dispose()
    {
        _current.Dispose();
        _superseded?.Dispose();
    }

    /// <summary>One hostname's certificate and the services it serves.</summary>
    private sealed class Entry(X509Certificate2 certificate, CertificatePurpose purpose)
    {
        public X509Certificate2 Certificate { get; } = certificate;

        public bool AppliesTo(CertificatePurpose required) =>
            required == CertificatePurpose.None || (purpose & required) == required;

        public void Dispose() => Certificate.Dispose();
    }

    /// <summary>
    /// An immutable view of the whole certificate configuration.
    /// </summary>
    /// <remarks>
    /// <see cref="FrozenDictionary{TKey,TValue}"/> because this is built rarely and read on
    /// every handshake, which is exactly the access pattern it optimises for.
    /// </remarks>
    private sealed class Snapshot(
        FrozenDictionary<string, Entry> byHostname,
        Entry? defaultEntry)
    {
        public static Snapshot Empty { get; } =
            new(FrozenDictionary<string, Entry>.Empty, null);

        public FrozenDictionary<string, Entry> ByHostname { get; } = byHostname;

        public Entry? Default { get; } = defaultEntry;

        public bool HasAny => Default is not null || ByHostname.Count > 0;

        public IReadOnlyCollection<DomainName> Hostnames =>
            [.. ByHostname.Keys
                .Select(static k => DomainName.TryParse(k, out DomainName? d) ? d : null)
                .Where(static d => d is not null)
                .Select(static d => d!)];

        public void Dispose()
        {
            // Distinct instances only: one certificate may be bound to several hostnames, and
            // the default is usually also present in the map.
            HashSet<Entry> seen = [];

            foreach (Entry entry in ByHostname.Values)
            {
                if (seen.Add(entry))
                {
                    entry.Dispose();
                }
            }

            if (Default is not null && seen.Add(Default))
            {
                Default.Dispose();
            }
        }
    }
}
