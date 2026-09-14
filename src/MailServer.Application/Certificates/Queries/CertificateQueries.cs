using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Certificates.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Certificates.Queries;

/// <summary>Builds certificate DTOs, joining a certificate to its bindings.</summary>
/// <remarks>
/// Shared by the commands and the queries so that one certificate is described identically
/// wherever it appears. Two mappers is how a list view and a detail view come to disagree
/// about a certificate's status.
/// </remarks>
internal static class CertificateMapper
{
    private static readonly CertificateRenewalPolicy Policy = new();

    public static async Task<CertificateDto> ToDtoAsync(
        Certificate certificate,
        ICertificateRepository repository,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<CertificateBinding> bindings = await repository
            .GetBindingsForCertificateAsync(certificate.Id, cancellationToken)
            .ConfigureAwait(false);

        return ToDto(certificate, bindings, now);
    }

    public static CertificateDto ToDto(
        Certificate certificate,
        IReadOnlyList<CertificateBinding> bindings,
        DateTimeOffset now)
    {
        List<DomainName> boundHostnames = [.. bindings.Select(static b => b.Hostname)];

        return new CertificateDto
        {
            Id = certificate.Id.Value,
            Thumbprint = certificate.Thumbprint.Value,
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            SerialNumber = certificate.SerialNumber,
            SubjectAlternativeNames =
                [.. certificate.SubjectAlternativeNames.Select(static n => n.Value)],
            Source = certificate.Source,

            // A self-signed certificate's chain never builds to a trusted root, and saying so
            // is more useful than reporting Healthy for something clients will warn about.
            Status = certificate.GetStatus(
                now,
                Policy,
                boundHostnames,
                chainIsTrusted: !certificate.IsSelfSigned),

            NotBeforeUtc = certificate.NotBeforeUtc,
            NotAfterUtc = certificate.NotAfterUtc,
            DaysRemaining = certificate.DaysRemaining(now),
            AutoRenew = certificate.AutoRenew,
            LastRenewalUtc = certificate.LastRenewalUtc,
            LastRenewalError = certificate.LastRenewalError,
            IsSelfSigned = certificate.IsSelfSigned,
            Bindings = [.. bindings.Select(ToBindingDto)],
        };
    }

    public static CertificateBindingDto ToBindingDto(CertificateBinding binding) => new()
    {
        Id = binding.Id.Value,
        Hostname = binding.Hostname.Value,
        CertificateId = binding.CertificateId.Value,
        Purpose = binding.Purpose,
        IsDefault = binding.IsDefault,
        CreatedUtc = binding.CreatedUtc,
    };
}

// =========================================================================================

/// <summary>Every certificate known to this server, soonest expiry first.</summary>
public sealed record GetCertificatesQuery : IQuery<IReadOnlyList<CertificateDto>>,
                                            IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetCertificatesQueryHandler(
    ICertificateRepository repository,
    IClock clock)
    : IRequestHandler<GetCertificatesQuery, IReadOnlyList<CertificateDto>>
{
    public async Task<IReadOnlyList<CertificateDto>> Handle(
        GetCertificatesQuery request,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<Certificate> certificates = await repository
            .GetAllAsync(cancellationToken)
            .ConfigureAwait(false);

        // One read of all bindings, grouped in memory, rather than one query per certificate.
        // The certificate count is small and bounded; the round trips would not be.
        IReadOnlyList<CertificateBinding> bindings = await repository
            .GetBindingsAsync(cancellationToken)
            .ConfigureAwait(false);

        ILookup<CertificateId, CertificateBinding> byCertificate =
            bindings.ToLookup(static b => b.CertificateId);

        DateTimeOffset now = clock.UtcNow;

        return [.. certificates.Select(c =>
            CertificateMapper.ToDto(c, [.. byCertificate[c.Id]], now))];
    }
}

/// <summary>One certificate in full.</summary>
public sealed record GetCertificateQuery : IQuery<CertificateDto>, IAuthorizedRequest
{
    public required Guid CertificateId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetCertificateQueryHandler(
    ICertificateRepository repository,
    IClock clock)
    : IRequestHandler<GetCertificateQuery, CertificateDto>
{
    public async Task<CertificateDto> Handle(
        GetCertificateQuery request,
        CancellationToken cancellationToken)
    {
        CertificateId id = new(request.CertificateId);

        Certificate certificate =
            await repository.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(
                nameof(Certificate),
                request.CertificateId.ToString());

        return await CertificateMapper
            .ToDtoAsync(certificate, repository, clock.UtcNow, cancellationToken)
            .ConfigureAwait(false);
    }
}

/// <summary>The TLS posture, for the dashboard.</summary>
public sealed record GetCertificateHealthQuery : IQuery<CertificateHealthDto>, IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetCertificateHealthQueryHandler(
    ICertificateRepository repository,
    ITlsCertificateProvider tlsProvider,
    IClock clock)
    : IRequestHandler<GetCertificateHealthQuery, CertificateHealthDto>
{
    private static readonly CertificateRenewalPolicy Policy = new();

    public async Task<CertificateHealthDto> Handle(
        GetCertificateHealthQuery request,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<Certificate> certificates = await repository
            .GetAllAsync(cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyList<CertificateBinding> bindings = await repository
            .GetBindingsAsync(cancellationToken)
            .ConfigureAwait(false);

        DateTimeOffset now = clock.UtcNow;

        int selfSigned = 0;
        int expiringSoon = 0;
        int expired = 0;
        int? soonestDays = null;
        string? soonestHostname = null;

        foreach (Certificate certificate in certificates)
        {
            if (certificate.IsSelfSigned)
            {
                selfSigned++;
            }

            int daysRemaining = certificate.DaysRemaining(now);

            if (daysRemaining < 0)
            {
                expired++;
            }
            else if (daysRemaining <= Policy.RenewalWindowDays)
            {
                expiringSoon++;
            }

            // Expired certificates are included in "soonest", deliberately: the most urgent
            // thing on this server is the one that has already stopped working, and hiding it
            // from the headline number would make the dashboard look calmer than it is.
            if (soonestDays is null || daysRemaining < soonestDays)
            {
                soonestDays = daysRemaining;

                soonestHostname = bindings
                    .FirstOrDefault(b => b.CertificateId == certificate.Id)
                    ?.Hostname.Value
                    ?? certificate.SubjectAlternativeNames.FirstOrDefault()?.Value;
            }
        }

        return new CertificateHealthDto
        {
            TotalCertificates = certificates.Count,
            SelfSignedCount = selfSigned,
            ExpiringSoonCount = expiringSoon,
            ExpiredCount = expired,
            SoonestExpiryDays = soonestDays,
            SoonestExpiryHostname = soonestHostname,
            HasDefaultBinding = bindings.Any(static b => b.IsDefault),
            TlsIsReady = tlsProvider.IsReady,
            SelfSignedWarning = selfSigned > 0
                ? CertificateRenewalPolicy.SelfSignedWarning
                : null,
        };
    }
}

/// <summary>Certificates in the Windows store that could be adopted.</summary>
public sealed record GetAvailableStoreCertificatesQuery
    : IQuery<IReadOnlyList<AvailableStoreCertificateDto>>, IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;
}

/// <remarks>
/// Returns an empty list rather than throwing on a non-Windows host. The admin application
/// asks this to decide whether to offer the "adopt from store" option at all, and a query that
/// throws on a supported platform configuration would make that a special case in the view.
/// </remarks>
internal sealed class GetAvailableStoreCertificatesQueryHandler(
    ICertificateRepository repository)
    : IRequestHandler<GetAvailableStoreCertificatesQuery, IReadOnlyList<AvailableStoreCertificateDto>>
{
    public async Task<IReadOnlyList<AvailableStoreCertificateDto>> Handle(
        GetAvailableStoreCertificatesQuery request,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        IReadOnlyList<Certificate> adopted = await repository
            .GetAllAsync(cancellationToken)
            .ConfigureAwait(false);

        HashSet<string> adoptedThumbprints = [.. adopted.Select(static c => c.Thumbprint.Value)];

        return Read(adoptedThumbprints);
    }

    [SupportedOSPlatform("windows")]
    private static List<AvailableStoreCertificateDto> Read(HashSet<string> adoptedThumbprints)
    {
        using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        List<AvailableStoreCertificateDto> available = [];

        foreach (X509Certificate2 certificate in store.Certificates)
        {
            using (certificate)
            {
                List<string> sans = [];

                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (extension is X509SubjectAlternativeNameExtension san)
                    {
                        sans.AddRange(san.EnumerateDnsNames());
                    }
                }

                available.Add(new AvailableStoreCertificateDto
                {
                    Thumbprint = certificate.Thumbprint,
                    Subject = certificate.Subject,
                    Issuer = certificate.Issuer,
                    SubjectAlternativeNames = sans,
                    NotAfterUtc = certificate.NotAfter,

                    // Surfaced rather than filtered out. A certificate whose key this service
                    // cannot read looks identical in the store, and an operator choosing from
                    // a list needs to see why the one they expected is not selectable.
                    HasPrivateKey = certificate.HasPrivateKey,
                    AlreadyAdopted = adoptedThumbprints.Contains(certificate.Thumbprint),
                });
            }
        }

        return available;
    }
}
