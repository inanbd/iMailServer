using Certes;
using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Enums;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Acme;

/// <summary>Builds a Certes-backed client for one issuance.</summary>
/// <remarks>
/// A factory rather than a registered client, because <see cref="IAcmeClient"/> is stateful for
/// the length of an issuance and because the account key it needs is fetched from the protected
/// secret store at the moment of use rather than held.
/// </remarks>
internal sealed class AcmeClientFactory(
    IClock clock,
    ILoggerFactory loggerFactory) : IAcmeClientFactory
{
    public Task<IAcmeClient> CreateAsync(
        string directoryUrl,
        string accountKeyPem,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountKeyPem);

        IKey key = KeyFactory.FromPem(accountKeyPem);

        AcmeContext context = new(new Uri(directoryUrl), key);

        return Task.FromResult<IAcmeClient>(new CertesAcmeClient(
            context,
            clock,
            loggerFactory.CreateLogger<CertesAcmeClient>()));
    }
}

/// <summary>
/// Creates and retrieves ACME account keys, which live in the protected secret store.
/// </summary>
/// <remarks>
/// <para>
/// <b>The account key is the most consequential secret this subsystem holds.</b> It is not just
/// a credential for issuing: it is the only thing that can later <i>revoke</i> a certificate
/// issued through the account. Losing it means losing the ability to revoke, which is exactly
/// the ability most needed after a key compromise.
/// </para>
/// <para>
/// It is therefore stored, never regenerated on a miss. A missing key is reported as an error
/// an operator must resolve — usually by re-registering — rather than papered over by quietly
/// creating a new one, which would orphan every certificate the old account issued.
/// </para>
/// <para>
/// ES256 rather than RSA: the key is used only for JWS signing, elliptic-curve signatures are
/// faster and smaller, and every ACME CA supports it. The <i>certificate</i> key is a separate
/// decision made at finalisation.
/// </para>
/// </remarks>
internal sealed class AcmeAccountKeyStore(
    ISecretStore secrets,
    ILogger<AcmeAccountKeyStore> logger)
{
    /// <summary>Prefix for the secret holding an account key.</summary>
    private const string KeySecretPrefix = "Acme.AccountKey.";

    /// <summary>The secret name for a directory's account key.</summary>
    /// <remarks>
    /// Per directory, because staging and production are separate accounts with separate keys.
    /// One shared name would mean registering against production destroyed the staging key and
    /// with it the ability to revoke anything staging had issued.
    /// </remarks>
    public static string SecretNameFor(AcmeDirectory directory) =>
        KeySecretPrefix + directory;

    /// <summary>Creates and stores a key, or returns the existing one.</summary>
    public async Task<string> EnsureKeyAsync(
        AcmeDirectory directory,
        CancellationToken cancellationToken)
    {
        string name = SecretNameFor(directory);

        string? existing = await secrets.GetAsync(name, cancellationToken).ConfigureAwait(false);

        if (existing is not null)
        {
            return existing;
        }

        string pem = KeyFactory.NewKey(KeyAlgorithm.ES256).ToPem();

        await secrets.SetAsync(
            name,
            pem,
            $"ACME account key for {directory}. Losing this key means losing the ability to " +
            "revoke certificates issued through this account.",
            cancellationToken).ConfigureAwait(false);

        // The algorithm and the directory, never the key. Rule 77 lists ACME private keys among
        // the things that must never reach a log.
        logger.LogInformation(
            "Generated a new ES256 ACME account key for {Directory}.",
            directory);

        return pem;
    }

    /// <summary>Retrieves an existing key, or null when it is gone.</summary>
    public async Task<string?> GetKeyAsync(
        string secretName,
        CancellationToken cancellationToken)
    {
        string? pem = await secrets.GetAsync(secretName, cancellationToken).ConfigureAwait(false);

        if (pem is null)
        {
            logger.LogError(
                "The ACME account key secret '{SecretName}' could not be read. Certificates " +
                "cannot be issued or revoked through this account until it is restored. If " +
                "this database was moved to a different machine, DPAPI-protected secrets do " +
                "not travel with it and the account must be re-registered.",
                secretName);
        }

        return pem;
    }
}
