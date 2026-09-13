using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Security;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// A development-only secret protector backed by a key file, for machines where DPAPI is
/// unavailable.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is not a fallback.</b> Brief rule 105 forbids insecure fallbacks, and this class
/// is not one: it is never selected automatically. It requires
/// <c>Security:SecretProtection = Development</c> in configuration, the options validator
/// refuses that value when the environment is Production, it reports
/// <see cref="IsProductionGrade"/> as false, and it logs a Critical warning on every single
/// start so its use can never be accidental or quiet.
/// </para>
/// <para>
/// It exists so the server can be developed, built and integration-tested on a non-Windows
/// machine. The key sits next to the data it protects, which is precisely why it is unfit
/// for production.
/// </para>
/// <para>
/// AES-GCM is used rather than AES-CBC: it is authenticated, so tampering with a stored
/// secret is detected on decryption instead of producing plausible-looking garbage.
/// </para>
/// </remarks>
public sealed class DevelopmentSecretProtector : ISecretProtector
{
    private const string KeyFileName = "development-secret.key";
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    private readonly byte[] _key;

    public DevelopmentSecretProtector(IServerPaths paths, ILogger<DevelopmentSecretProtector> logger)
    {
        ArgumentNullException.ThrowIfNull(paths);

        _key = LoadOrCreateKey(paths.CertificatesRoot);

        logger.LogCritical(
            "SECRET PROTECTION IS IN DEVELOPMENT MODE. Secrets are encrypted with a key " +
            "stored on disk beside the data it protects. This is NOT suitable for production. " +
            "Set MailServer:Security:SecretProtection to 'Dpapi' on Windows Server.");
    }

    public string SchemeName => "Development/AesGcm";

    public bool IsProductionGrade => false;

    public byte[] Protect(ReadOnlySpan<byte> plaintext)
    {
        // Layout: nonce || ciphertext || tag
        byte[] result = new byte[NonceBytes + plaintext.Length + TagBytes];

        Span<byte> nonce = result.AsSpan(0, NonceBytes);
        Span<byte> ciphertext = result.AsSpan(NonceBytes, plaintext.Length);
        Span<byte> tag = result.AsSpan(NonceBytes + plaintext.Length, TagBytes);

        RandomNumberGenerator.Fill(nonce);

        using AesGcm aes = new(_key, TagBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return result;
    }

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData)
    {
        if (protectedData.Length < NonceBytes + TagBytes)
        {
            throw new CryptographicException("The protected payload is too short to be valid.");
        }

        ReadOnlySpan<byte> nonce = protectedData[..NonceBytes];
        ReadOnlySpan<byte> ciphertext = protectedData[NonceBytes..^TagBytes];
        ReadOnlySpan<byte> tag = protectedData[^TagBytes..];

        byte[] plaintext = new byte[ciphertext.Length];

        using AesGcm aes = new(_key, TagBytes);

        // Throws CryptographicException if the tag does not verify, i.e. if the stored
        // secret has been tampered with. That is the point of using an AEAD here.
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }

    public string ProtectString(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Convert.ToBase64String(Protect(Encoding.UTF8.GetBytes(plaintext)));
    }

    public string UnprotectString(string protectedBase64)
    {
        ArgumentNullException.ThrowIfNull(protectedBase64);
        return Encoding.UTF8.GetString(Unprotect(Convert.FromBase64String(protectedBase64)));
    }

    private static byte[] LoadOrCreateKey(string directory)
    {
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, KeyFileName);

        if (File.Exists(path))
        {
            byte[] existing = File.ReadAllBytes(path);

            if (existing.Length != KeyBytes)
            {
                throw new InvalidOperationException(
                    $"The development key file at '{path}' is {existing.Length} bytes; " +
                    $"{KeyBytes} were expected.");
            }

            return existing;
        }

        byte[] key = RandomNumberGenerator.GetBytes(KeyBytes);

        using (FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.Write(key);
            stream.Flush(flushToDisk: true);
        }

        return key;
    }
}
