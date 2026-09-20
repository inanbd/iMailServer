using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Exceptions;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Enums;
using MailServer.Domain.Mail;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Deliverability.Queries;

/// <summary>
/// Reads a pasted header block and checks it against DNS.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AdminPermission.ViewServerState"/> and not <c>ReadMessageContent</c>: the headers
/// arrive in the request because the operator pasted them. Nothing here opens a stored message,
/// and the moment something did, this would need the stronger permission.
/// </para>
/// <para>
/// <b>The analysis never treats the pasted text as authority.</b> It is a message somebody
/// received, so everything in it was written by whoever sent it — including any header claiming
/// that an earlier hop authenticated it. See <see cref="IHeaderAnalysisService"/>.
/// </para>
/// </remarks>
public sealed record AnalyseHeadersQuery : IQuery<HeaderAnalysisDto>, IAuthorizedRequest
{
    /// <summary>The header block, as pasted.</summary>
    public required string Headers { get; init; }

    /// <summary>
    /// The address the message was received from, when the operator knows it.
    /// </summary>
    /// <remarks>
    /// Supplying it is what makes the SPF result trustworthy: without it the analyser falls back
    /// to an address out of the message's own trace, which whoever sent the message may have
    /// written.
    /// </remarks>
    public string? ClientAddress { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class AnalyseHeadersQueryHandler(IHeaderAnalysisService analyser)
    : IRequestHandler<AnalyseHeadersQuery, HeaderAnalysisDto>
{
    public async Task<HeaderAnalysisDto> Handle(
        AnalyseHeadersQuery request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        IpAddressValue? address = null;

        if (request.ClientAddress is { Length: > 0 } text &&
            !IpAddressValue.TryParse(text, out address))
        {
            throw new ValidationFailedException(new Dictionary<string, string[]>
            {
                [nameof(request.ClientAddress)] = [$"'{text}' is not an IP address."],
            });
        }

        AnalysedHeaders analysis = await analyser
            .AnalyseAsync(request.Headers, address, cancellationToken)
            .ConfigureAwait(false);

        return Map(analysis);
    }

    internal static HeaderAnalysisDto Map(AnalysedHeaders analysis)
    {
        HeaderAnalysis headers = analysis.Headers;
        HeaderAuthentication auth = analysis.Authentication;

        // Each signature is paired with what its own selector's lookup found, by selector and
        // domain. A positional join would mis-pair the moment a signature failed to parse and
        // so was never looked up.
        Dictionary<string, AnalysedKey> keys = auth.Keys
            .GroupBy(k => $"{k.Selector}\u0000{k.Domain}", StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        return new HeaderAnalysisDto
        {
            From = headers.From?.Raw,
            ReturnPath = headers.ReturnPath?.Raw,
            ReplyTo = headers.ReplyTo?.Raw,
            ListUnsubscribe = headers.ListUnsubscribe,
            OneClickUnsubscribe = headers.OneClickUnsubscribe,
            Trace = [.. headers.Chain.Hops.Select(Map)],
            TotalTransitSeconds = headers.Chain.TotalTransit?.TotalSeconds,
            Signatures = [.. headers.Signatures.Select(s => Map(s, keys))],
            Spf = auth.Spf?.ToString(),
            SpfDomain = auth.SpfDomain?.Value,
            SpfAddress = auth.SpfAddress?.Value,
            SpfAddressFromTrace = auth.SpfAddressFromTrace,
            SpfDiagnostic = auth.SpfDiagnostic,
            DmarcRecord = auth.DmarcRecordText,
            DmarcPolicy = auth.DmarcPolicy?.ToString(),
            SpfAligned = auth.SpfAligned,
            DkimCouldAlign = auth.DkimCouldAlign,
            Observations = [.. analysis.Observations.Select(o => new HeaderObservationDto
            {
                Id = o.Id,
                Text = o.Text,
            })],
        };
    }

    private static TraceHopDto Map(ReceivedHopTiming timing) => new()
    {
        GreetedName = timing.Hop.From?.GreetedName,
        ObservedName = timing.Hop.From?.ObservedName,
        ObservedAddress = timing.Hop.From?.ObservedAddress,
        By = timing.Hop.By,
        With = timing.Hop.With,
        For = timing.Hop.For,
        Timestamp = timing.Hop.Timestamp,
        DelaySeconds = timing.Delay?.TotalSeconds,
        Ambiguous = timing.Hop.AmbiguousClauses,
    };

    private static AnalysedSignatureDto Map(
        AnalysedSignature signature,
        Dictionary<string, AnalysedKey> keys)
    {
        AnalysedKey? key = signature.Selector is not null && signature.Domain is not null &&
                           keys.TryGetValue($"{signature.Selector}\u0000{signature.Domain}", out AnalysedKey? found)
            ? found
            : null;

        return new AnalysedSignatureDto
        {
            Selector = signature.Selector,
            Domain = signature.Domain,
            Algorithm = signature.Algorithm,
            SignedHeaders = signature.SignedHeaders,
            SignedAt = signature.SignedAt,
            Expires = signature.Expires,
            BodyLengthLimit = signature.BodyLengthLimit,
            KeyState = (key?.State ?? AnalysedKeyState.Unknown).ToString(),
            KeyBits = key?.KeyBits,

            // A signature that did not parse has no key lookup to explain it, so its own parse
            // error is the diagnostic worth showing.
            Diagnostic = signature.ParseError ?? key?.Diagnostic,
        };
    }
}
