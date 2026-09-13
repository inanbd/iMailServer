using System.Security.Cryptography;
using System.Text;
using MailServer.Application.Abstractions.Platform;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Platform;
using MailServer.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Tests;

/// <summary>
/// Exercises the development secret protector.
/// </summary>
/// <remarks>
/// DPAPI cannot be tested off Windows, so these tests cover the development implementation.
/// Both implement the same interface and the same round-trip contract; what differs is where
/// the key lives, which is exactly why the development one reports
/// <see cref="MailServer.Application.Abstractions.Security.ISecretProtector.IsProductionGrade"/>
/// as false and logs a Critical warning on every start.
/// </remarks>
public sealed class DevelopmentSecretProtectorTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "aethermail-secret-tests",
        Guid.NewGuid().ToString("N"));

    private readonly DevelopmentSecretProtector _protector;
    private readonly IServerPaths _paths;

    public DevelopmentSecretProtectorTests()
    {
        MailServerOptions options = new() { Storage = new StorageOptions { DataRoot = _root } };

        _paths = new ServerPaths(Options.Create(options), NullLogger<ServerPaths>.Instance);
        _paths.EnsureCreated();

        _protector = new DevelopmentSecretProtector(
            _paths,
            NullLogger<DevelopmentSecretProtector>.Instance);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void A_secret_round_trips()
    {
        byte[] secret = "a DKIM private key, notionally"u8.ToArray();

        byte[] protectedBytes = _protector.Protect(secret);
        byte[] recovered = _protector.Unprotect(protectedBytes);

        recovered.ShouldBe(secret);
    }

    [Fact]
    public void A_string_secret_round_trips()
    {
        const string Secret = "Server=db;Database=mail;User Id=sa;Password=hunter2";

        string protectedValue = _protector.ProtectString(Secret);

        protectedValue.ShouldNotBe(Secret);
        _protector.UnprotectString(protectedValue).ShouldBe(Secret);
    }

    [Fact]
    public void The_protected_form_does_not_contain_the_plaintext()
    {
        const string Secret = "SUPER-SECRET-VALUE";

        string protectedValue = _protector.ProtectString(Secret);

        Encoding.UTF8.GetString(Convert.FromBase64String(protectedValue))
            .ShouldNotContain(Secret);
    }

    [Fact]
    public void Protecting_the_same_value_twice_yields_different_ciphertext()
    {
        // A fresh nonce per encryption. Deterministic ciphertext would let an observer tell
        // that two mailboxes share a value without decrypting either.
        const string Secret = "same value";

        _protector.ProtectString(Secret).ShouldNotBe(_protector.ProtectString(Secret));
    }

    [Fact]
    public void Tampering_with_the_protected_data_is_detected()
    {
        // AES-GCM is authenticated, so a modified secret fails to decrypt rather than
        // producing plausible-looking garbage that the server would then act on.
        byte[] protectedBytes = _protector.Protect("original"u8);

        protectedBytes[^1] ^= 0xFF;

        Should.Throw<CryptographicException>(() => _protector.Unprotect(protectedBytes));
    }

    [Fact]
    public void A_truncated_payload_is_rejected() =>
        Should.Throw<CryptographicException>(() => _protector.Unprotect(new byte[4]));

    [Fact]
    public void It_reports_itself_as_not_production_grade()
    {
        // The flag the setup wizard and the deliverability report read. Silently behaving
        // like a production protector would be the worst possible outcome for this class.
        _protector.IsProductionGrade.ShouldBeFalse();
        _protector.SchemeName.ShouldBe("Development/AesGcm");
    }

    [Fact]
    public void A_second_instance_reuses_the_existing_key()
    {
        // Otherwise every service restart would render previously protected secrets -
        // DKIM keys, the ACME account key - permanently unrecoverable.
        string protectedValue = _protector.ProtectString("persisted");

        DevelopmentSecretProtector second = new(
            _paths,
            NullLogger<DevelopmentSecretProtector>.Instance);

        second.UnprotectString(protectedValue).ShouldBe("persisted");
    }

    [Fact]
    public void An_empty_secret_round_trips()
    {
        _protector.UnprotectString(_protector.ProtectString(string.Empty))
            .ShouldBe(string.Empty);
    }
}
