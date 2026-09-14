using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Certificates.Dtos;
using MailServer.Application.Certificates.Queries;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Certificates.Commands;

// =========================================================================================
// Generate a self-signed certificate
// =========================================================================================

/// <summary>
/// Generates a self-signed certificate covering the given hostnames.
/// </summary>
/// <remarks>
/// The result is not publicly trusted. Callers must display
/// <see cref="CertificateRenewalPolicy.SelfSignedWarning"/> verbatim; the returned DTO carries
/// <c>IsSelfSigned</c> precisely so no surface has to infer it.
/// </remarks>
public sealed record GenerateSelfSignedCertificateCommand : ICommand<CertificateDto>,
                                                            IAuditableRequest,
                                                            IAuthorizedRequest
{
    /// <summary>Every hostname the certificate must cover. The first becomes the subject.</summary>
    public required IReadOnlyList<string> Hostnames { get; init; }

    public int KeySizeBits { get; init; } = 3072;

    public int ValidityYears { get; init; } = 1;

    /// <summary>Bind the new certificate to its first hostname immediately.</summary>
    public bool BindImmediately { get; init; } = true;

    /// <summary>Make that binding the default presented when a client offers no SNI.</summary>
    public bool MakeDefault { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;

    public AuditDescriptor DescribeForAudit() =>
        new("Certificate.GenerateSelfSigned",
            nameof(Certificate),
            Hostnames.Count > 0 ? Hostnames[0] : "(none)",
            $"RSA {KeySizeBits}, {ValidityYears} year(s), {Hostnames.Count} hostname(s). " +
            "NOT PUBLICLY TRUSTED.");
}

/// <remarks>
/// Deliberately <b>not</b> <see cref="ITransactionalRequest"/>. Generating a certificate writes
/// a file and a secret before the database row, and holding a write transaction open across
/// key generation and file I/O would keep SQLite's single writer locked for the duration of an
/// RSA-3072 keygen. The failure mode without a transaction is an orphaned file, which the next
/// write of the same thumbprint replaces; the failure mode with one is a stalled server.
/// </remarks>
internal sealed class GenerateSelfSignedCertificateCommandHandler(
    ICertificateManager manager,
    ICertificateRepository repository,
    ITlsReloadCoordinator tlsReload,
    IClock clock,
    ILogger<GenerateSelfSignedCertificateCommandHandler> logger)
    : IRequestHandler<GenerateSelfSignedCertificateCommand, CertificateDto>
{
    public async Task<CertificateDto> Handle(
        GenerateSelfSignedCertificateCommand request,
        CancellationToken cancellationToken)
    {
        List<DomainName> hostnames = [];

        foreach (string hostname in request.Hostnames)
        {
            hostnames.Add(DomainName.Parse(hostname));
        }

        Certificate certificate = await manager.GenerateSelfSignedAsync(
            new SelfSignedCertificateRequest(hostnames, request.KeySizeBits, request.ValidityYears),
            cancellationToken).ConfigureAwait(false);

        if (request.BindImmediately)
        {
            await BindAsync(
                repository,
                certificate,
                hostnames[0],
                CertificatePurpose.All,
                request.MakeDefault,
                clock.UtcNow,
                cancellationToken).ConfigureAwait(false);
        }

        // The swap that makes this take effect without a restart. Reloaded after the binding
        // is written, so the new snapshot is built from committed state.
        tlsReload.RequestReload();

        logger.LogWarning(
            "A self-signed certificate was generated for {HostnameCount} hostname(s). {Warning}",
            hostnames.Count,
            CertificateRenewalPolicy.SelfSignedWarning.Replace('\n', ' '));

        return await CertificateMapper
            .ToDtoAsync(certificate, repository, clock.UtcNow, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Creates or repoints the binding for a hostname.</summary>
    /// <remarks>
    /// <para>
    /// Shared by every command that installs a certificate. Repointing an existing binding
    /// rather than failing on the unique hostname index is what makes "generate a new
    /// certificate for this name" work the second time.
    /// </para>
    /// <para>
    /// <b>The default flag is cleared from the other rows BEFORE this row claims it.</b> A
    /// unique filtered index enforces "at most one default", so writing the new default first
    /// violates the constraint and the whole operation fails — which is what happens the moment
    /// a second certificate is made the default, not on the first one. Clearing first means
    /// there is never an instant with two defaults; there is briefly none, which is safe
    /// because the transaction has not committed and no handshake can observe it.
    /// </para>
    /// </remarks>
    internal static async Task BindAsync(
        ICertificateRepository repository,
        Certificate certificate,
        DomainName hostname,
        CertificatePurpose purpose,
        bool makeDefault,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        CertificateBinding? existing = await repository
            .GetBindingByHostnameAsync(hostname, cancellationToken)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            if (makeDefault)
            {
                await repository
                    .ClearOtherDefaultsAsync(existing.Id, cancellationToken)
                    .ConfigureAwait(false);

                existing.SetDefault(true, now);
            }

            existing.PointAt(certificate.Id, now);
            existing.SetPurpose(purpose, now);

            await repository.UpdateBindingAsync(existing, cancellationToken).ConfigureAwait(false);

            return;
        }

        // The first binding is always the default, whatever the caller asked for. A server
        // whose only certificate is not its default would fail every handshake that arrives
        // without SNI, which is not a state an operator would ever intend.
        bool isFirst = (await repository.GetBindingsAsync(cancellationToken)
            .ConfigureAwait(false)).Count == 0;

        CertificateBinding binding = CertificateBinding.Create(
            hostname,
            certificate.Id,
            purpose,
            makeDefault || isFirst,
            now);

        if (binding.IsDefault)
        {
            // The id exists before the insert, so the row being created can be named as the
            // one to keep even though it is not there yet.
            await repository
                .ClearOtherDefaultsAsync(binding.Id, cancellationToken)
                .ConfigureAwait(false);
        }

        await repository.AddBindingAsync(binding, cancellationToken).ConfigureAwait(false);
    }
}

// =========================================================================================
// Import a PFX
// =========================================================================================

/// <summary>Imports an operator-supplied PKCS#12 certificate.</summary>
public sealed record ImportCertificateCommand : ICommand<CertificateDto>,
                                                IAuditableRequest,
                                                IAuthorizedRequest
{
    /// <summary>The PKCS#12 blob. Cleared by the infrastructure layer once consumed.</summary>
    public required byte[] PfxBytes { get; init; }

    /// <summary>
    /// The file's passphrase.
    /// </summary>
    /// <remarks>
    /// Never logged, never audited, and never persisted as supplied — the import re-wraps the
    /// certificate under a server-generated 256-bit passphrase and discards this one.
    /// </remarks>
    public string? Passphrase { get; init; }

    /// <summary>Hostname to bind the imported certificate to. Optional.</summary>
    public string? BindToHostname { get; init; }

    public bool MakeDefault { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;

    /// <remarks>
    /// The audit record names the target hostname and the payload size, never the passphrase
    /// and never the bytes. Rule 97: secret values are not audited.
    /// </remarks>
    public AuditDescriptor DescribeForAudit() =>
        new("Certificate.Import",
            nameof(Certificate),
            BindToHostname ?? "(unbound)",
            $"PKCS#12 import, {PfxBytes.Length} bytes.");
}

internal sealed class ImportCertificateCommandHandler(
    ICertificateManager manager,
    ICertificateRepository repository,
    ITlsReloadCoordinator tlsReload,
    IClock clock,
    ILogger<ImportCertificateCommandHandler> logger)
    : IRequestHandler<ImportCertificateCommand, CertificateDto>
{
    public async Task<CertificateDto> Handle(
        ImportCertificateCommand request,
        CancellationToken cancellationToken)
    {
        Certificate certificate = await manager
            .ImportPfxAsync(request.PfxBytes, request.Passphrase, cancellationToken)
            .ConfigureAwait(false);

        if (request.BindToHostname is not null)
        {
            DomainName hostname = DomainName.Parse(request.BindToHostname);

            if (!certificate.Covers(hostname))
            {
                // Refused rather than warned about. A binding whose certificate does not cover
                // its hostname produces a name-mismatch warning in every connecting client,
                // and the operator would discover it from user reports rather than from here.
                throw new DomainRuleViolationException(
                    "certificate.binding.hostname_not_covered",
                    $"The imported certificate does not cover '{hostname}'. Its subjectAltName " +
                    "entries are: " +
                    string.Join(", ", certificate.SubjectAlternativeNames.Select(n => n.Value)) +
                    ".");
            }

            await GenerateSelfSignedCertificateCommandHandler.BindAsync(
                repository,
                certificate,
                hostname,
                CertificatePurpose.All,
                request.MakeDefault,
                clock.UtcNow,
                cancellationToken).ConfigureAwait(false);
        }

        tlsReload.RequestReload();

        logger.LogInformation(
            "Imported certificate {Thumbprint} issued by {Issuer}.",
            certificate.Thumbprint,
            certificate.Issuer);

        return await CertificateMapper
            .ToDtoAsync(certificate, repository, clock.UtcNow, cancellationToken)
            .ConfigureAwait(false);
    }
}

// =========================================================================================
// Adopt from the Windows certificate store
// =========================================================================================

/// <summary>Adopts a certificate already present in <c>LocalMachine\My</c>.</summary>
public sealed record AdoptStoreCertificateCommand : ICommand<CertificateDto>,
                                                    IAuditableRequest,
                                                    IAuthorizedRequest
{
    public required string Thumbprint { get; init; }

    public string? BindToHostname { get; init; }

    public bool MakeDefault { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;

    public AuditDescriptor DescribeForAudit() =>
        new("Certificate.AdoptFromStore",
            nameof(Certificate),
            Thumbprint,
            "Adopted from LocalMachine\\My; the private key is not exported.");
}

internal sealed class AdoptStoreCertificateCommandHandler(
    ICertificateManager manager,
    ICertificateRepository repository,
    ITlsReloadCoordinator tlsReload,
    IClock clock)
    : IRequestHandler<AdoptStoreCertificateCommand, CertificateDto>
{
    public async Task<CertificateDto> Handle(
        AdoptStoreCertificateCommand request,
        CancellationToken cancellationToken)
    {
        CertificateThumbprint thumbprint = CertificateThumbprint.Parse(request.Thumbprint);

        Certificate? existing = await repository
            .GetByThumbprintAsync(thumbprint, cancellationToken)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            throw new DuplicateEntityException(nameof(Certificate), thumbprint.Value);
        }

        Certificate certificate = await manager
            .AdoptFromWindowsStoreAsync(thumbprint, cancellationToken)
            .ConfigureAwait(false);

        if (request.BindToHostname is not null)
        {
            DomainName hostname = DomainName.Parse(request.BindToHostname);

            if (!certificate.Covers(hostname))
            {
                throw new DomainRuleViolationException(
                    "certificate.binding.hostname_not_covered",
                    $"Certificate {thumbprint} does not cover '{hostname}'.");
            }

            await GenerateSelfSignedCertificateCommandHandler.BindAsync(
                repository,
                certificate,
                hostname,
                CertificatePurpose.All,
                request.MakeDefault,
                clock.UtcNow,
                cancellationToken).ConfigureAwait(false);
        }

        tlsReload.RequestReload();

        return await CertificateMapper
            .ToDtoAsync(certificate, repository, clock.UtcNow, cancellationToken)
            .ConfigureAwait(false);
    }
}
