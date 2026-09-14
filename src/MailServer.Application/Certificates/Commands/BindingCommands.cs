using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Certificates.Commands;

/// <summary>Points a hostname at a certificate.</summary>
public sealed record BindCertificateCommand : ICommand<Unit>,
                                              ITransactionalRequest,
                                              IAuditableRequest,
                                              IAuthorizedRequest
{
    public required Guid CertificateId { get; init; }

    public required string Hostname { get; init; }

    public CertificatePurpose Purpose { get; init; } = CertificatePurpose.All;

    public bool MakeDefault { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;

    public AuditDescriptor DescribeForAudit() =>
        new("Certificate.Bind",
            nameof(CertificateBinding),
            Hostname,
            $"Certificate {CertificateId}, purpose {Purpose}" +
            (MakeDefault ? ", as the default." : "."));
}

/// <remarks>
/// Transactional, unlike the issuance commands: this touches only database rows — the binding
/// and possibly the default flag on others — and those must move together or not at all. The
/// TLS reload happens after the transaction commits, so the provider never builds a snapshot
/// from uncommitted state.
/// </remarks>
internal sealed class BindCertificateCommandHandler(
    ICertificateRepository repository,
    ITlsReloadCoordinator tlsReload,
    IClock clock,
    ILogger<BindCertificateCommandHandler> logger)
    : IRequestHandler<BindCertificateCommand, Unit>
{
    public async Task<Unit> Handle(
        BindCertificateCommand request,
        CancellationToken cancellationToken)
    {
        CertificateId certificateId = new(request.CertificateId);
        DomainName hostname = DomainName.Parse(request.Hostname);

        Certificate certificate =
            await repository.GetAsync(certificateId, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(Certificate), request.CertificateId.ToString());

        if (!certificate.Covers(hostname))
        {
            // The whole point of the binding is that a client connecting for this hostname is
            // handed a certificate it will accept. Allowing a mismatch would move the failure
            // from here — where it is one clear message — to every client's warning dialog.
            throw new DomainRuleViolationException(
                "certificate.binding.hostname_not_covered",
                $"Certificate {certificate.Thumbprint} does not cover '{hostname}'. Its " +
                "subjectAltName entries are: " +
                string.Join(", ", certificate.SubjectAlternativeNames.Select(n => n.Value)) +
                ".");
        }

        await GenerateSelfSignedCertificateCommandHandler.BindAsync(
            repository,
            certificate,
            hostname,
            request.Purpose,
            request.MakeDefault,
            clock.UtcNow,
            cancellationToken).ConfigureAwait(false);

        // Signalled, not performed: this handler runs inside the transaction, and a snapshot
        // rebuilt now would read the rows as they were before this change.
        tlsReload.RequestReload();

        logger.LogInformation(
            "Bound {Hostname} to certificate {Thumbprint} for {Purpose}.",
            hostname,
            certificate.Thumbprint,
            request.Purpose);

        return Unit.Value;
    }
}

/// <summary>Removes a hostname binding.</summary>
public sealed record UnbindCertificateCommand : ICommand<Unit>,
                                                ITransactionalRequest,
                                                IAuditableRequest,
                                                IAuthorizedRequest
{
    public required Guid BindingId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;

    public AuditDescriptor DescribeForAudit() =>
        new("Certificate.Unbind", nameof(CertificateBinding), BindingId.ToString(), null);
}

internal sealed class UnbindCertificateCommandHandler(
    ICertificateRepository repository,
    ITlsReloadCoordinator tlsReload,
    ILogger<UnbindCertificateCommandHandler> logger)
    : IRequestHandler<UnbindCertificateCommand, Unit>
{
    public async Task<Unit> Handle(
        UnbindCertificateCommand request,
        CancellationToken cancellationToken)
    {
        CertificateBindingId id = new(request.BindingId);

        CertificateBinding binding =
            await repository.GetBindingAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(
                nameof(CertificateBinding),
                request.BindingId.ToString());

        if (binding.IsDefault)
        {
            IReadOnlyList<CertificateBinding> all = await repository
                .GetBindingsAsync(cancellationToken)
                .ConfigureAwait(false);

            // Removing the last default would leave a handshake without SNI — which older
            // MTAs still send, and which carries real inbound mail — with no certificate to be
            // answered with. That failure surfaces as remote servers reporting TLS errors, not
            // as anything visible here, so it is refused at the point of the change.
            if (all.Count > 1)
            {
                throw new DomainRuleViolationException(
                    "certificate.binding.default_required",
                    "This is the default certificate binding. Make another binding the default " +
                    "before removing it, or a TLS handshake that offers no SNI hostname will " +
                    "have no certificate to present.");
            }
        }

        await repository.RemoveBindingAsync(id, cancellationToken).ConfigureAwait(false);

        tlsReload.RequestReload();

        logger.LogInformation("Removed the certificate binding for {Hostname}.", binding.Hostname);

        return Unit.Value;
    }
}

/// <summary>Makes one binding the default presented when a client offers no SNI hostname.</summary>
public sealed record SetDefaultBindingCommand : ICommand<Unit>,
                                                ITransactionalRequest,
                                                IAuditableRequest,
                                                IAuthorizedRequest
{
    public required Guid BindingId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;

    public AuditDescriptor DescribeForAudit() =>
        new("Certificate.SetDefaultBinding",
            nameof(CertificateBinding),
            BindingId.ToString(),
            "Presented when a client offers no SNI hostname.");
}

internal sealed class SetDefaultBindingCommandHandler(
    ICertificateRepository repository,
    ITlsReloadCoordinator tlsReload,
    IClock clock)
    : IRequestHandler<SetDefaultBindingCommand, Unit>
{
    public async Task<Unit> Handle(
        SetDefaultBindingCommand request,
        CancellationToken cancellationToken)
    {
        CertificateBindingId id = new(request.BindingId);

        CertificateBinding binding =
            await repository.GetBindingAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(
                nameof(CertificateBinding),
                request.BindingId.ToString());

        // Clear first, then set. The reverse order would transiently have two rows flagged,
        // which the unique filtered index rejects — the statement would fail rather than the
        // invariant being violated, but it would fail for a reason that looks like a bug.
        await repository.ClearOtherDefaultsAsync(id, cancellationToken).ConfigureAwait(false);

        binding.SetDefault(true, clock.UtcNow);

        await repository.UpdateBindingAsync(binding, cancellationToken).ConfigureAwait(false);

        tlsReload.RequestReload();

        return Unit.Value;
    }
}

/// <summary>Removes a certificate this server installed.</summary>
public sealed record DeleteCertificateCommand : ICommand<Unit>,
                                                IAuditableRequest,
                                                IAuthorizedRequest
{
    public required Guid CertificateId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageCertificates;

    public AuditDescriptor DescribeForAudit() =>
        new("Certificate.Delete", nameof(Certificate), CertificateId.ToString(), null);
}

/// <remarks>
/// Not transactional: it deletes a file and a secret as well as a row, and a database
/// transaction cannot roll back a deleted file. The order is row-then-file, so a crash between
/// them leaves an orphaned file rather than a row pointing at a certificate that is gone.
/// </remarks>
internal sealed class DeleteCertificateCommandHandler(
    ICertificateRepository repository,
    ICertificateManager manager,
    ITlsReloadCoordinator tlsReload,
    ILogger<DeleteCertificateCommandHandler> logger)
    : IRequestHandler<DeleteCertificateCommand, Unit>
{
    public async Task<Unit> Handle(
        DeleteCertificateCommand request,
        CancellationToken cancellationToken)
    {
        CertificateId id = new(request.CertificateId);

        Certificate certificate =
            await repository.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(Certificate), request.CertificateId.ToString());

        IReadOnlyList<CertificateBinding> bindings = await repository
            .GetBindingsForCertificateAsync(id, cancellationToken)
            .ConfigureAwait(false);

        if (bindings.Count > 0)
        {
            // Also enforced by the foreign key, but caught here so the operator gets the list
            // of affected hostnames instead of a constraint-violation message.
            throw new DomainRuleViolationException(
                "certificate.delete.still_bound",
                "This certificate is still bound to " +
                string.Join(", ", bindings.Select(b => b.Hostname.Value)) +
                ". Rebind those hostnames to another certificate before deleting it.");
        }

        await repository.RemoveAsync(id, cancellationToken).ConfigureAwait(false);
        await manager.RemoveAsync(certificate.KeyLocation, cancellationToken).ConfigureAwait(false);
        tlsReload.RequestReload();

        logger.LogInformation("Deleted certificate {Thumbprint}.", certificate.Thumbprint);

        return Unit.Value;
    }
}
