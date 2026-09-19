using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Gathers the observations the authentication checks judge.
/// </summary>
/// <remarks>
/// <para>
/// The counterpart of <see cref="IdentityProbe"/>, and the same division: all I/O and no rules,
/// with every judgement in the pure <see cref="AuthenticationChecks"/>. Three names are asked
/// about — the domain itself, <c>_dmarc</c> beneath it, and one <c>_domainkey</c> name per
/// configured selector — and each answer is passed through with the distinction between "did not
/// answer" and "answered with nothing" intact.
/// </para>
/// <para>
/// <b>Every TXT record at a name is carried, not just the one that looks relevant.</b> RFC 7208
/// §4.5 makes two <c>v=spf1</c> records at one name a permanent error, so a probe that returned
/// only the first SPF record it recognised would make the most consequential SPF fault in the
/// category undetectable. Choosing among the records is a rule, and rules live in the Domain.
/// </para>
/// </remarks>
public sealed class AuthenticationProbe(IDnsDiagnosticsService dns)
{
    /// <summary>The label DKIM publishes keys under. RFC 6376 §3.6.2.1.</summary>
    public const string DomainKeyLabel = "_domainkey";

    /// <summary>The label DMARC publishes its policy under. RFC 7489 §6.1.</summary>
    public const string DmarcLabel = "_dmarc";

    /// <summary>Looks up everything the authentication checks need.</summary>
    /// <param name="domain">The domain being judged.</param>
    /// <param name="selectors">
    /// The selectors this server signs with. Empty is a meaningful answer rather than a missing
    /// one: a server that signs nothing is a finding, and
    /// <see cref="AuthenticationChecks.DkimPublishedId"/> reports it as such.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<AuthenticationFacts> GatherAsync(
        DomainName domain,
        IReadOnlyList<DkimSelector> selectors,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(selectors);

        IReadOnlyList<string>? domainTxt =
            await TextAsync(domain.Value, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<string>? dmarcTxt =
            await TextAsync($"{DmarcLabel}.{domain.Value}", cancellationToken).ConfigureAwait(false);

        List<DkimSelectorFacts> selectorFacts = [];

        foreach (DkimSelector selector in selectors)
        {
            string name = $"{selector.Value}.{DomainKeyLabel}.{domain.Value}";

            selectorFacts.Add(new DkimSelectorFacts(
                selector.Value,
                await TextAsync(name, cancellationToken).ConfigureAwait(false)));
        }

        return new AuthenticationFacts(domain, domainTxt, dmarcTxt, selectorFacts);
    }

    /// <summary>
    /// The TXT records at a name, or null when the lookup did not answer.
    /// </summary>
    /// <remarks>
    /// <see cref="DnsDiagnosticAnswer.Answered"/> is the whole distinction: a name that exists
    /// and has no TXT record answers with an empty list, and that empty list is what turns into
    /// "you have not published this". A resolver that timed out returns null instead, and the
    /// check goes unjudged rather than telling an operator to republish records that are
    /// already correct.
    /// </remarks>
    private async Task<IReadOnlyList<string>?> TextAsync(string name, CancellationToken cancellationToken)
    {
        DnsDiagnosticAnswer answer = await dns
            .LookupAsync(name, DnsDiagnosticRecordType.Txt, cancellationToken)
            .ConfigureAwait(false);

        return answer.Answered ? answer.Values : null;
    }
}
