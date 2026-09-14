using FluentValidation;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Certificates.Commands;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Certificates.Validators;

/// <summary>
/// Shape checks for certificate requests.
/// </summary>
/// <remarks>
/// Shape only. Whether a certificate actually covers a hostname is a question about the
/// certificate, not about the request, so it lives in the handler where the certificate has
/// been loaded — a validator asserting it would have to load one too, and validation runs
/// before the transaction precisely so it does no I/O.
/// </remarks>
internal sealed class GenerateSelfSignedCertificateCommandValidator
    : AbstractValidator<GenerateSelfSignedCertificateCommand>
{
    /// <summary>
    /// Upper bound on hostnames in one certificate.
    /// </summary>
    /// <remarks>
    /// Public CAs impose limits of this order, and a certificate with hundreds of SANs is both
    /// slow to validate on every handshake and a privacy problem — every name in it is
    /// disclosed to every client that connects, and to certificate transparency logs.
    /// </remarks>
    private const int MaxHostnames = 100;

    public GenerateSelfSignedCertificateCommandValidator()
    {
        RuleFor(c => c.Hostnames)
            .NotEmpty()
            .WithMessage(
                "A certificate must cover at least one hostname. One with no subjectAltName " +
                "entries is not usable for TLS by any current client.")
            .Must(h => h.Count <= MaxHostnames)
            .WithMessage($"A certificate may cover at most {MaxHostnames} hostnames.");

        RuleForEach(c => c.Hostnames)
            .Must(static h => DomainName.TryParse(h, out _))
            .WithMessage("'{PropertyValue}' is not a valid hostname.");

        RuleFor(c => c.KeySizeBits)
            .Must(static k => SelfSignedCertificateRequest.SupportedKeySizes.Contains(k))
            .WithMessage(
                "Supported RSA key sizes are " +
                string.Join(", ", SelfSignedCertificateRequest.SupportedKeySizes) + ".");

        RuleFor(c => c.ValidityYears)
            .Must(static y => SelfSignedCertificateRequest.SupportedValidityYears.Contains(y))
            .WithMessage(
                "Supported validity periods are " +
                string.Join(", ", SelfSignedCertificateRequest.SupportedValidityYears) +
                " years.");
    }
}

internal sealed class ImportCertificateCommandValidator
    : AbstractValidator<ImportCertificateCommand>
{
    /// <summary>
    /// Ceiling on an uploaded PKCS#12 file.
    /// </summary>
    /// <remarks>
    /// A certificate chain with a private key is a few kilobytes; a megabyte is already
    /// generous. The bound exists because the blob arrives over IPC and is held in memory to be
    /// parsed, and rule 105 forbids unbounded reads — an unbounded one here is a trivial
    /// memory-exhaustion path against the service.
    /// </remarks>
    private const int MaxPfxBytes = 1024 * 1024;

    public ImportCertificateCommandValidator()
    {
        RuleFor(c => c.PfxBytes)
            .NotEmpty()
            .WithMessage("No certificate file was supplied.")
            .Must(b => b.Length <= MaxPfxBytes)
            .WithMessage(
                $"A PKCS#12 file larger than {MaxPfxBytes / 1024} KB is not a certificate.");

        RuleFor(c => c.BindToHostname!)
            .Must(static h => DomainName.TryParse(h, out _))
            .When(c => c.BindToHostname is not null)
            .WithMessage("'{PropertyValue}' is not a valid hostname.");

        // The passphrase is deliberately not validated for length or content. It is the
        // operator's existing file's passphrase; rejecting it for failing our policy would be
        // refusing a perfectly valid certificate on the basis of a rule we do not own.
    }
}

internal sealed class AdoptStoreCertificateCommandValidator
    : AbstractValidator<AdoptStoreCertificateCommand>
{
    public AdoptStoreCertificateCommandValidator()
    {
        RuleFor(c => c.Thumbprint)
            .NotEmpty()
            .Must(static t => CertificateThumbprint.TryParse(t, out _))
            .WithMessage(
                "'{PropertyValue}' is not a certificate thumbprint. A thumbprint is 40 " +
                "hexadecimal characters for SHA-1, or 64 for SHA-256.");

        RuleFor(c => c.BindToHostname!)
            .Must(static h => DomainName.TryParse(h, out _))
            .When(c => c.BindToHostname is not null)
            .WithMessage("'{PropertyValue}' is not a valid hostname.");
    }
}

internal sealed class BindCertificateCommandValidator : AbstractValidator<BindCertificateCommand>
{
    public BindCertificateCommandValidator()
    {
        RuleFor(c => c.CertificateId).NotEmpty();

        RuleFor(c => c.Hostname)
            .NotEmpty()
            .Must(static h => DomainName.TryParse(h, out _))
            .WithMessage("'{PropertyValue}' is not a valid hostname.");

        RuleFor(c => c.Purpose)
            .NotEqual(Domain.Enums.CertificatePurpose.None)
            .WithMessage(
                "A binding must apply to at least one service, or it would never be consulted " +
                "during a handshake.");
    }
}

internal sealed class UnbindCertificateCommandValidator
    : AbstractValidator<UnbindCertificateCommand>
{
    public UnbindCertificateCommandValidator() => RuleFor(c => c.BindingId).NotEmpty();
}

internal sealed class SetDefaultBindingCommandValidator
    : AbstractValidator<SetDefaultBindingCommand>
{
    public SetDefaultBindingCommandValidator() => RuleFor(c => c.BindingId).NotEmpty();
}

internal sealed class DeleteCertificateCommandValidator
    : AbstractValidator<DeleteCertificateCommand>
{
    public DeleteCertificateCommandValidator() => RuleFor(c => c.CertificateId).NotEmpty();
}
