using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dkim;

/// <summary>A freshly generated RSA key pair, ready to hand to the repository and to DNS.</summary>
/// <param name="Pkcs8PrivateKey">Plaintext PKCS#8. Never logged; the caller protects and stores it immediately.</param>
/// <param name="PublicKeyBase64">
/// Base64 of the SubjectPublicKeyInfo DER encoding — the exact value a <c>p=</c> DNS tag
/// publishes.
/// </param>
/// <param name="KeyLengthBits">The RSA modulus size actually generated.</param>
public sealed record GeneratedDkimKeyPair(byte[] Pkcs8PrivateKey, string PublicKeyBase64, int KeyLengthBits);

/// <summary>
/// Generates RSA key pairs for DKIM signing, using <see cref="RSA"/> from the BCL.
/// </summary>
/// <remarks>
/// Mirrors <c>SelfSignedCertificateGenerator</c>'s own reasoning for not taking a third-party
/// dependency here: RSA key generation is well covered by the framework, and a supply-chain
/// dependency in the one component that produces private keys is a cost with no offsetting
/// benefit.
/// </remarks>
internal sealed class DkimKeyGenerator(ILogger<DkimKeyGenerator> logger)
{
    public static IReadOnlyList<int> SupportedKeySizes { get; } = [2048, 3072, 4096];

    public GeneratedDkimKeyPair Generate(int keySizeBits)
    {
        if (!SupportedKeySizes.Contains(keySizeBits))
        {
            throw new ArgumentOutOfRangeException(
                nameof(keySizeBits),
                keySizeBits,
                "Supported RSA key sizes are " + string.Join(", ", SupportedKeySizes) + ".");
        }

        using RSA key = RSA.Create(keySizeBits);

        byte[] pkcs8PrivateKey = key.ExportPkcs8PrivateKey();
        string publicKeyBase64 = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        // Key size only. Nothing about the key itself is ever safe to log.
        logger.LogInformation("Generated a new DKIM RSA {KeySize}-bit key pair.", keySizeBits);

        return new GeneratedDkimKeyPair(pkcs8PrivateKey, publicKeyBase64, keySizeBits);
    }
}
