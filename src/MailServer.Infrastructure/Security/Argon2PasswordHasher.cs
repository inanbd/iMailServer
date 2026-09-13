using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using MailServer.Application.Abstractions.Security;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// Argon2id password hashing.
/// </summary>
/// <remarks>
/// <para>
/// <b>Argon2id specifically.</b> Argon2d resists GPU cracking but is vulnerable to
/// side-channel attack; Argon2i resists side channels but is weaker against GPUs. Argon2id
/// runs the first half in the i mode and the rest in d, which is the variant RFC 9106
/// recommends for password hashing and the one every current guideline names.
/// </para>
/// <para>
/// <b>Why not PBKDF2</b>, which the BCL does provide: PBKDF2 has no memory cost, so a GPU or
/// ASIC can evaluate it thousands of times in parallel at negligible cost per attempt. Argon2's
/// memory hardness is what makes parallel cracking expensive rather than merely slow.
/// </para>
/// <para>
/// Default parameters (64 MiB, 3 passes, 2 lanes) follow the RFC 9106 second recommended
/// option. They put a single verification in the region of 100 ms on server hardware — slow
/// enough to make an offline run against a stolen database expensive, fast enough that a
/// sign-in feels immediate.
/// </para>
/// </remarks>
public sealed class Argon2PasswordHasher : IPasswordHasher
{
    /// <summary>Salt length. 16 bytes is the RFC 9106 recommendation.</summary>
    public const int SaltBytes = 16;

    /// <summary>
    /// Stand-in used when the candidate is empty, so the rejection still costs a full
    /// derivation. Its value is irrelevant; only that it is non-empty and constant.
    /// </summary>
    private const string EmptyCandidatePlaceholder = "\u0000empty-candidate-placeholder";

    /// <summary>Digest length. 32 bytes matches the strength of the rest of the system.</summary>
    public const int HashBytes = 32;

    private readonly int _memoryKib;
    private readonly int _iterations;
    private readonly int _parallelism;
    private readonly PasswordHash _dummyHash;

    public Argon2PasswordHasher(
        IOptions<MailServerOptions> options,
        ILogger<Argon2PasswordHasher> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        SecurityOptions security = options.Value.Security;

        _memoryKib = Math.Clamp(security.Argon2MemoryKib, 8 * 1024, 1024 * 1024);
        _iterations = Math.Clamp(security.Argon2Iterations, 1, 20);
        _parallelism = Math.Clamp(security.Argon2Parallelism, 1, 16);

        // Computed once at startup so that VerifyAgainstDummy pays the same cost as a real
        // verification without also paying for hashing a throwaway password every time.
        _dummyHash = Hash("dummy-password-for-constant-time-comparison");

        logger.LogInformation(
            "Password hashing: Argon2id with m={MemoryKib} KiB, t={Iterations}, p={Parallelism}.",
            _memoryKib,
            _iterations,
            _parallelism);
    }

    public string Describe() =>
        $"argon2id (m={_memoryKib} KiB, t={_iterations}, p={_parallelism})";

    public PasswordHash Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length == 0)
        {
            // The password policy already refuses this. Failing here too, with a clear
            // message, means a future caller that bypasses the policy gets an explicable
            // error rather than an obscure one from inside the Argon2 library.
            throw new ArgumentException("A password cannot be empty.", nameof(password));
        }

        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        byte[] digest = Derive(password, salt, _memoryKib, _iterations, _parallelism);

        return PasswordHash.Create(
            PasswordHash.Argon2idAlgorithm,
            PasswordHash.Argon2Version,
            _memoryKib,
            _iterations,
            _parallelism,
            salt,
            digest);
    }

    public PasswordVerificationResult Verify(string candidate, PasswordHash stored)
    {
        ArgumentNullException.ThrowIfNull(stored);

        // An empty or missing candidate can never match a real verifier, but it must still
        // cost the same to reject. The underlying Argon2 implementation throws on empty
        // input, and an exception has a different shape AND a different duration from an
        // ordinary failure - either of which is an oracle. So the work is done against a
        // fixed placeholder and the answer is false regardless.
        if (string.IsNullOrEmpty(candidate))
        {
            Derive(
                EmptyCandidatePlaceholder,
                stored.Salt,
                stored.MemoryKib,
                stored.Iterations,
                stored.Parallelism);

            return new PasswordVerificationResult(false, false);
        }

        // Derived with the STORED parameters, not the current ones. Raising the work factors
        // must not invalidate every existing password; the rehash flag below handles the
        // upgrade at the one moment the plaintext is available.
        byte[] computed = Derive(
            candidate,
            stored.Salt,
            stored.MemoryKib,
            stored.Iterations,
            stored.Parallelism);

        // Constant time. A comparison that returns on the first differing byte leaks the
        // length of the correct prefix, and over enough attempts that recovers the digest.
        bool valid = CryptographicOperations.FixedTimeEquals(computed, stored.Hash);

        CryptographicOperations.ZeroMemory(computed);

        return new PasswordVerificationResult(
            valid,
            valid && stored.NeedsRehash(_memoryKib, _iterations, _parallelism));
    }

    /// <summary>
    /// Spends a verification's worth of work and returns false.
    /// </summary>
    /// <remarks>
    /// Called when no account exists. Without it, a sign-in attempt against an unconfigured
    /// server would return in microseconds while a real one took ~100 ms — a difference any
    /// client can measure, revealing whether the server has been set up and, in a
    /// multi-account future, which accounts exist.
    /// </remarks>
    public bool VerifyAgainstDummy(string candidate)
    {
        Verify(candidate ?? string.Empty, _dummyHash);
        return false;
    }

    private static byte[] Derive(
        string password,
        byte[] salt,
        int memoryKib,
        int iterations,
        int parallelism)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            using Argon2id argon2 = new(passwordBytes)
            {
                Salt = salt,
                MemorySize = memoryKib,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };

            return argon2.GetBytes(HashBytes);
        }
        finally
        {
            // The plaintext lives in a byte array the GC may copy or leave behind. Zeroing is
            // best-effort - the immutable string it came from cannot be cleared - but it
            // shortens the window in which a memory dump yields the password.
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}

/// <summary>
/// Generates recovery keys.
/// </summary>
/// <remarks>
/// <para>
/// 25 characters from a 32-symbol alphabet gives 125 bits of entropy — beyond any feasible
/// guessing attack, which is what lets the recovery flow bypass lockout safely.
/// </para>
/// <para>
/// <b>Crockford base32.</b> The alphabet omits I, L, O and U: the first three because they are
/// indistinguishable from 1 and 0 in most fonts, and U because dropping it avoids accidentally
/// generating a recognisable obscenity. This key is read off a screen and copied onto paper
/// exactly once, and a transcription error is discovered only in the emergency it was written
/// for.
/// </para>
/// </remarks>
public sealed class RecoveryKeyGenerator : IRecoveryKeyGenerator
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>Length in characters, giving 125 bits of entropy.</summary>
    public const int KeyLength = 25;

    public string Generate()
    {
        Span<char> buffer = stackalloc char[KeyLength];

        for (int i = 0; i < KeyLength; i++)
        {
            // RandomNumberGenerator.GetInt32 is unbiased and cryptographically secure.
            // Random.Shared is neither, and a predictable recovery key is a permanent backdoor.
            buffer[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        }

        return new string(buffer);
    }
}
