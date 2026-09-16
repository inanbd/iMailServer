using System.Text;
using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Infrastructure.Dkim;

namespace MailServer.Infrastructure.Dmarc;

/// <summary>
/// Composes an RFC 8601 <c>Authentication-Results</c> header value from this server's own SPF,
/// DKIM and DMARC verdicts.
/// </summary>
/// <remarks>
/// <para>
/// Pure formatting: takes already-computed results and returns text, touching no I/O and no
/// stored message. Nothing here reads a header already on the message — see the remarks on
/// <see cref="DmarcEvaluator"/> and <c>docs/DMARC.md</c>'s "Inbound handling" section. Consuming
/// an existing <c>Authentication-Results</c> header as a trust input, from this server or the
/// composer that will one day call this method, is the one thing that must never happen; a
/// pre-existing header from an untrusted upstream is stripped or renamed before this server's
/// own value (built only from <see cref="SpfEvaluationOutcome"/>, <see cref="DkimVerifiedSignature"/>
/// and <see cref="DmarcEvaluationOutcome"/> — this server's own verification, never the wire) is
/// added.
/// </para>
/// <para>
/// Not yet wired into stored or served messages — the result is synthesized at the point of use,
/// never written into the archived original (the same discipline
/// <see cref="Domain.Entities.DkimVerificationRecord"/> and
/// <see cref="Domain.Entities.DmarcVerificationRecord"/> already follow), and the first point of
/// use (IMAP <c>FETCH</c>) is a later milestone.
/// </para>
/// </remarks>
public static class AuthenticationResultsComposer
{
    /// <summary>
    /// Composes the header's value — everything after <c>Authentication-Results:</c>, not
    /// including the field name or a trailing line break. Each result is folded onto its own
    /// line, indented, per RFC 5322 header folding.
    /// </summary>
    /// <param name="authServId">This server's identifier (RFC 8601 §2.2) — its own hostname.</param>
    public static string Compose(
        string authServId,
        SpfEvaluationOutcome? spfOutcome,
        IReadOnlyList<DkimVerifiedSignature> dkimResults,
        DmarcEvaluationOutcome dmarcOutcome)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authServId);
        ArgumentNullException.ThrowIfNull(dkimResults);
        ArgumentNullException.ThrowIfNull(dmarcOutcome);

        List<string> resInfo = [];

        foreach (DkimVerifiedSignature signature in dkimResults)
        {
            resInfo.Add(ComposeDkim(signature));
        }

        if (spfOutcome is not null)
        {
            resInfo.Add(ComposeSpf(spfOutcome));
        }

        resInfo.Add(ComposeDmarc(dmarcOutcome));

        StringBuilder builder = new();
        builder.Append(authServId);

        foreach (string entry in resInfo)
        {
            builder.Append(";\r\n    ").Append(entry);
        }

        return builder.ToString();
    }

    private static string ComposeDkim(DkimVerifiedSignature signature)
    {
        string result = signature.Result.ToString().ToLowerInvariant();

        return signature.SigningDomain is { } domain
            ? $"dkim={result} header.d={domain.Value}"
            : $"dkim={result}";
    }

    private static string ComposeSpf(SpfEvaluationOutcome outcome)
    {
        string result = outcome.Result.ToString().ToLowerInvariant();

        return outcome.CheckedDomain is { } domain
            ? $"spf={result} smtp.mailfrom={domain.Value}"
            : $"spf={result}";
    }

    private static string ComposeDmarc(DmarcEvaluationOutcome outcome)
    {
        string result = outcome.Result?.ToString().ToLowerInvariant() ?? "none";

        return outcome.FromDomain is { } domain
            ? $"dmarc={result} header.from={domain.Value}"
            : $"dmarc={result}";
    }
}
