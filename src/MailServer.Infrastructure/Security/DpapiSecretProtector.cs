using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Platform;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// Protects secrets using Windows DPAPI at machine scope, with additional entropy.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why machine scope.</b> The Windows Service runs under a dedicated service account and
/// must be able to read DKIM keys and ACME account keys at boot with nobody logged in. User
/// scope would tie the secrets to an interactive profile that is not loaded at that point.
/// </para>
/// <para>
/// <b>Why additional entropy.</b> Machine-scope DPAPI alone means any process on the machine
/// can unprotect the data. The entropy file adds a second factor held under an ACL that
/// grants only the service account and administrators, so copying the database off the
/// machine - or reading it as a low-privileged local process - is not sufficient to recover
/// DKIM private keys.
/// </para>
/// <para>
/// <b>Consequence for backups.</b> DPAPI is machine-scoped, so a backup restored onto a new
/// machine cannot decrypt these secrets. Backups therefore re-wrap secrets under a
/// passphrase-derived key at export time - see <c>docs/BackupRestore.md</c>. This is a
/// documented, exercised procedure rather than a surprise discovered during a disaster.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    private const string EntropyFileName = "secret-entropy.bin";
    private const int EntropyBytes = 32;

    private readonly byte[] _entropy;

    public DpapiSecretProtector(IServerPaths paths, ILogger<DpapiSecretProtector> logger)
    {
        ArgumentNullException.ThrowIfNull(paths);

        _entropy = LoadOrCreateEntropy(paths.CertificatesRoot, logger);
        logger.LogInformation("Secret protection: Windows DPAPI (LocalMachine) with additional entropy.");
    }

    public string SchemeName => "Dpapi/LocalMachine";

    public bool IsProductionGrade => true;

    public byte[] Protect(ReadOnlySpan<byte> plaintext) =>
        ProtectedData.Protect(plaintext.ToArray(), _entropy, DataProtectionScope.LocalMachine);

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData) =>
        ProtectedData.Unprotect(protectedData.ToArray(), _entropy, DataProtectionScope.LocalMachine);

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

    private static byte[] LoadOrCreateEntropy(string directory, ILogger logger)
    {
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, EntropyFileName);

        if (File.Exists(path))
        {
            byte[] existing = File.ReadAllBytes(path);

            if (existing.Length == EntropyBytes)
            {
                return existing;
            }

            // Regenerating would render every existing protected secret unrecoverable:
            // DKIM keys, the ACME account key, certificate passphrases. Refusing to start is
            // the only responsible response.
            throw new InvalidOperationException(
                $"The secret entropy file at '{path}' is {existing.Length} bytes; " +
                $"{EntropyBytes} were expected. It appears to be corrupt. Every protected " +
                "secret was encrypted with this value and cannot be recovered without it. " +
                "Restore it from backup rather than deleting it.");
        }

        byte[] entropy = RandomNumberGenerator.GetBytes(EntropyBytes);

        // Create exclusively: two service instances starting at once must not both write a
        // file, because the loser's secrets would then be unreadable.
        using (FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.Write(entropy);
            stream.Flush(flushToDisk: true);
        }

        logger.LogWarning(
            "Generated a new secret entropy file at {Path}. BACK THIS FILE UP: without it, " +
            "protected secrets such as DKIM private keys and the ACME account key cannot be " +
            "recovered.",
            path);

        return entropy;
    }
}
