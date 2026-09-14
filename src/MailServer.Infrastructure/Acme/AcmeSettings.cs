using System.Net;
using MailServer.Application.Abstractions.Acme;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Acme;

/// <summary>Resolves ACME configuration once, so no handler reads raw options.</summary>
internal sealed class AcmeSettings : IAcmeSettings
{
    /// <summary>Let's Encrypt's staging directory.</summary>
    public const string LetsEncryptStagingUrl =
        "https://acme-staging-v02.api.letsencrypt.org/directory";

    /// <summary>Let's Encrypt's production directory.</summary>
    public const string LetsEncryptProductionUrl =
        "https://acme-v02.api.letsencrypt.org/directory";

    private readonly AcmeOptions _options;

    public AcmeSettings(IOptions<MailServerOptions> options, ILogger<AcmeSettings> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value.Acme;

        List<IPAddress> resolvers = [];

        foreach (string candidate in _options.ChallengeCheckResolvers)
        {
            if (IPAddress.TryParse(candidate, out IPAddress? parsed))
            {
                resolvers.Add(parsed);
            }
            else
            {
                // Skipped rather than fatal: one malformed entry should not stop the service
                // starting, and the remaining resolvers still give a usable check.
                logger.LogWarning(
                    "'{Resolver}' in MailServer:Acme:ChallengeCheckResolvers is not an IP " +
                    "address and will not be queried.",
                    candidate);
            }
        }

        ChallengeCheckResolvers = resolvers;

        if (_options.Directory == AcmeDirectory.LetsEncryptProduction)
        {
            // Worth a line in the log. Production issuance is rate-limited in ways that bite,
            // and an operator reading a startup log should be able to see which directory this
            // installation is pointed at without opening configuration.
            logger.LogInformation(
                "ACME is configured against the Let's Encrypt PRODUCTION directory. Rate " +
                "limits apply: 50 certificates per registered domain per week, 5 duplicates " +
                "per week, 5 failed validations per hostname per hour.");
        }
        else
        {
            logger.LogInformation(
                "ACME is configured against {Directory}. Certificates issued from staging are " +
                "NOT publicly trusted; they exist to prove the flow works without spending " +
                "production quota.",
                _options.Directory);
        }
    }

    public AcmeDirectory DefaultDirectory => _options.Directory;

    public string? ContactEmail => _options.ContactEmail;

    public bool TermsOfServiceAccepted => _options.AcceptTermsOfService;

    public AcmeChallengeType DefaultChallengeType => _options.ChallengeType;

    public IReadOnlyList<IPAddress> ChallengeCheckResolvers { get; }

    public int HttpChallengePort => _options.HttpChallengePort;

    public bool EnableHttpChallengeListener => _options.EnableHttpChallengeListener;

    public int CertificateKeySizeBits => _options.CertificateKeySizeBits;

    /// <remarks>
    /// The published production figures. Staging's limits are far looser, but the same policy
    /// is applied to both: being conservative on staging costs nothing, and a separate set of
    /// numbers per directory would be one more thing that could be wrong in the direction that
    /// matters.
    /// </remarks>
    public AcmeRateLimitPolicy RateLimitPolicy { get; } = new();

    public string GetDirectoryUrl(AcmeDirectory directory) => directory switch
    {
        AcmeDirectory.LetsEncryptStaging => LetsEncryptStagingUrl,
        AcmeDirectory.LetsEncryptProduction => LetsEncryptProductionUrl,
        AcmeDirectory.Custom => _options.CustomDirectoryUrl
            ?? throw new InvalidOperationException(
                "MailServer:Acme:Directory is 'Custom' but no CustomDirectoryUrl is set."),
        _ => throw new ArgumentOutOfRangeException(nameof(directory), directory, null),
    };
}
