using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Acme;

/// <summary>One pre-flight finding.</summary>
/// <param name="Identifier">The hostname checked.</param>
/// <param name="Passed">False when this would stop the CA validating.</param>
/// <param name="Summary">What was checked and what was found.</param>
/// <param name="IsBlocking">
/// True when issuance should be refused. A check that could not be <i>performed</i> — no
/// outbound DNS, say — reports a warning rather than a block, because refusing on the basis of
/// a check that did not run would make a local network fault look like a misconfigured domain.
/// </param>
public sealed record PreflightFinding(
    DomainName Identifier,
    bool Passed,
    string Summary,
    bool IsBlocking);

/// <summary>The combined result of the pre-flight checks.</summary>
public sealed record PreflightReport(IReadOnlyList<PreflightFinding> Findings)
{
    /// <summary>True when nothing blocking was found.</summary>
    public bool CanProceed => !Findings.Any(static f => f.IsBlocking && !f.Passed);

    /// <summary>Why issuance was refused, or null when it was not.</summary>
    public string? BlockingSummary
    {
        get
        {
            string[] blocking =
            [
                .. Findings
                    .Where(static f => f.IsBlocking && !f.Passed)
                    .Select(static f => f.Summary),
            ];

            return blocking.Length == 0 ? null : string.Join(" ", blocking);
        }
    }
}

/// <summary>
/// Checks locally what the CA is about to check remotely.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists to protect a rate-limit slot, not to be thorough.</b> A misconfiguration
/// caught here costs nothing; the same misconfiguration discovered at the CA costs one of five
/// failed validations per hostname per hour, and five of those lock an operator out for the
/// rest of the hour with no way to undo it.
/// </para>
/// <para>
/// The checks are therefore biased towards catching the two mistakes that account for nearly
/// every failed validation — DNS not pointing at this server, and inbound port 80 blocked
/// upstream — and towards <i>not</i> blocking on anything uncertain.
/// </para>
/// </remarks>
public interface IAcmePreflightCheck
{
    Task<PreflightReport> CheckAsync(
        IReadOnlyList<DomainName> identifiers,
        AcmeChallengeType challengeType,
        CancellationToken cancellationToken);
}
