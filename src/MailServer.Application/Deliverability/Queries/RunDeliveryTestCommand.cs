using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Exceptions;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Deliverability.Queries;

/// <summary>
/// Sends one real message to a nominated address and reports the whole conversation.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="AdminPermission.ManageQueue"/>, not
/// <see cref="AdminPermission.ViewServerState"/>, and the difference is the point.</b> Every
/// other deliverability query reads: it resolves DNS, inspects a certificate, scores what it
/// found. This one <i>sends mail</i> — from this server's IP, into somebody's mailbox, over the
/// public Internet. An operator who may look at diagnostics is not thereby an operator who may
/// emit traffic that counts against this server's reputation, so it sits behind the write-level
/// permission that governs mail flow.
/// </para>
/// <para>
/// <b>The address is the operator's to choose and their responsibility to own.</b> There is no
/// list of permitted destinations, because a delivery test's whole value is testing against the
/// receiver that matters — usually Gmail or Microsoft 365, where the
/// <c>Authentication-Results</c> header they add is the verdict worth having. What stops this
/// being a mail-sending primitive is the permission above and the operator's own judgement, and
/// the audit trail records who ran it and where it went.
/// </para>
/// </remarks>
public sealed record RunDeliveryTestCommand : ICommand<DeliveryTestDto>, IAuthorizedRequest
{
    /// <summary>The address to send from. Must be one this server is authoritative for.</summary>
    public required string From { get; init; }

    /// <summary>The address to send to.</summary>
    public required string To { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageQueue;
}

internal sealed class RunDeliveryTestCommandHandler(IDeliveryTestService tests)
    : IRequestHandler<RunDeliveryTestCommand, DeliveryTestDto>
{
    public async Task<DeliveryTestDto> Handle(
        RunDeliveryTestCommand request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Dictionary<string, string[]> failures = [];

        if (!EmailAddress.TryParse(request.From, out EmailAddress? from))
        {
            failures[nameof(request.From)] = [$"'{request.From}' is not an email address."];
        }

        if (!EmailAddress.TryParse(request.To, out EmailAddress? to))
        {
            failures[nameof(request.To)] = [$"'{request.To}' is not an email address."];
        }

        if (failures.Count > 0)
        {
            throw new ValidationFailedException(failures);
        }

        DeliveryTestResult result = await tests
            .RunAsync(from!, to!, cancellationToken)
            .ConfigureAwait(false);

        return new DeliveryTestDto
        {
            Succeeded = result.Succeeded,
            Recipient = result.Recipient.Value,
            MessageId = result.MessageId,
            MxHost = result.MxHost,
            MxPreference = result.MxPreference,
            RemoteAddress = result.RemoteAddress?.Value,
            TlsProtocol = result.TlsProtocol,
            TlsCipher = result.TlsCipher,
            PeerCertificateSubject = result.PeerCertificateSubject,
            PeerCertificateIssuer = result.PeerCertificateIssuer,
            DkimSelector = result.DkimSelector,
            ReplyCode = result.ReplyCode,
            EnhancedStatus = result.EnhancedStatus,
            ReplyText = result.ReplyText,
            ErrorDetail = result.ErrorDetail,
            ElapsedMilliseconds = (long)result.Elapsed.TotalMilliseconds,
            Transcript = [.. result.Transcript],
        };
    }
}
