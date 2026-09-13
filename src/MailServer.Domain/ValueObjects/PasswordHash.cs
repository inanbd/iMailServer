using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using MailServer.Domain.Exceptions;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// A stored password verifier: the algorithm, its work factors, the salt and the digest.
/// </summary>
/// <remarks>
/// <para>
/// Encoded in the PHC string format used by the reference Argon2 implementation:
/// </para>
/// <code>$argon2id$v=19$m=65536,t=3,p=2$&lt;salt-b64&gt;$&lt;hash-b64&gt;</code>
/// <para>
/// <b>Self-describing on purpose.</b> The work factors travel with the hash rather than
/// living in configuration, so raising them later does not invalidate every existing
/// password. An old hash still verifies against its own parameters, and
/// <see cref="NeedsRehash"/> reports that it should be upgraded the next time the plaintext
/// is available - which is at the moment of a successful sign-in.
/// </para>
/// <para>
/// A hash whose parameters lived only in configuration would be unverifiable the moment an
/// administrator edited that configuration, locking everyone out.
/// </para>
/// </remarks>
public sealed class PasswordHash : IEquatable<PasswordHash>
{
    /// <summary>The only algorithm this product writes. Others may be readable for migration.</summary>
    public const string Argon2idAlgorithm = "argon2id";

    /// <summary>Argon2 version 1.3, the current revision.</summary>
    public const int Argon2Version = 19;

    /// <summary>Bound on the encoded length, so a malformed row cannot drive a huge allocation.</summary>
    public const int MaxEncodedLength = 1024;

    private PasswordHash(
        string algorithm,
        int version,
        int memoryKib,
        int iterations,
        int parallelism,
        byte[] salt,
        byte[] hash,
        string encoded)
    {
        Algorithm = algorithm;
        Version = version;
        MemoryKib = memoryKib;
        Iterations = iterations;
        Parallelism = parallelism;
        Salt = salt;
        Hash = hash;
        Encoded = encoded;
    }

    /// <summary>Algorithm identifier, e.g. <c>argon2id</c>.</summary>
    public string Algorithm { get; }

    /// <summary>Algorithm version number.</summary>
    public int Version { get; }

    /// <summary>Memory cost in kibibytes.</summary>
    public int MemoryKib { get; }

    /// <summary>Time cost: number of passes.</summary>
    public int Iterations { get; }

    /// <summary>Degree of parallelism (lanes).</summary>
    public int Parallelism { get; }

    /// <summary>The per-password salt.</summary>
    public byte[] Salt { get; }

    /// <summary>The derived digest.</summary>
    public byte[] Hash { get; }

    /// <summary>The PHC-format encoding. This is what goes in the database column.</summary>
    public string Encoded { get; }

    /// <summary>Builds a hash record from freshly computed material.</summary>
    public static PasswordHash Create(
        string algorithm,
        int version,
        int memoryKib,
        int iterations,
        int parallelism,
        byte[] salt,
        byte[] hash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentNullException.ThrowIfNull(hash);

        if (salt.Length == 0 || hash.Length == 0)
        {
            throw new InvalidValueObjectException(
                nameof(PasswordHash),
                "the salt and the digest must both be non-empty.");
        }

        string encoded = string.Create(
            CultureInfo.InvariantCulture,
            $"${algorithm}$v={version}$m={memoryKib},t={iterations},p={parallelism}$" +
            $"{Convert.ToBase64String(salt).TrimEnd('=')}$" +
            $"{Convert.ToBase64String(hash).TrimEnd('=')}");

        return new PasswordHash(
            algorithm, version, memoryKib, iterations, parallelism, salt, hash, encoded);
    }

    /// <summary>Parses a stored PHC string.</summary>
    /// <exception cref="InvalidValueObjectException">The value is not a valid encoding.</exception>
    public static PasswordHash Parse(string? encoded)
    {
        if (!TryParse(encoded, out PasswordHash? result, out string? error))
        {
            throw new InvalidValueObjectException(nameof(PasswordHash), error);
        }

        return result;
    }

    /// <summary>
    /// Attempts to parse a stored PHC string.
    /// </summary>
    /// <remarks>
    /// Used on the authentication path, where a malformed stored value must produce a clean
    /// authentication failure rather than an exception that could be distinguished by timing
    /// or by an error message.
    /// </remarks>
    public static bool TryParse(string? encoded, [NotNullWhen(true)] out PasswordHash? result) =>
        TryParse(encoded, out result, out _);

    /// <summary>Attempts to parse a stored PHC string, reporting why it failed.</summary>
    public static bool TryParse(
        string? encoded,
        [NotNullWhen(true)] out PasswordHash? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;
        error = null;

        if (string.IsNullOrWhiteSpace(encoded))
        {
            error = "the value is empty.";
            return false;
        }

        if (encoded.Length > MaxEncodedLength)
        {
            error = $"the encoding exceeds {MaxEncodedLength} characters.";
            return false;
        }

        // $algorithm$v=N$m=N,t=N,p=N$salt$hash  ->  ["", algo, v=N, params, salt, hash]
        string[] parts = encoded.Split('$');

        if (parts.Length != 6 || parts[0].Length != 0)
        {
            error = "the value is not in PHC string format.";
            return false;
        }

        string algorithm = parts[1];

        if (!parts[2].StartsWith("v=", StringComparison.Ordinal) ||
            !int.TryParse(parts[2][2..], CultureInfo.InvariantCulture, out int version))
        {
            error = "the version segment is malformed.";
            return false;
        }

        if (!TryParseParameters(parts[3], out int memoryKib, out int iterations, out int parallelism))
        {
            error = "the parameter segment is malformed.";
            return false;
        }

        if (!TryDecodeBase64(parts[4], out byte[]? salt) ||
            !TryDecodeBase64(parts[5], out byte[]? hash))
        {
            error = "the salt or digest is not valid base64.";
            return false;
        }

        if (salt.Length == 0 || hash.Length == 0)
        {
            error = "the salt and the digest must both be non-empty.";
            return false;
        }

        result = new PasswordHash(
            algorithm, version, memoryKib, iterations, parallelism, salt, hash, encoded);

        return true;
    }

    /// <summary>
    /// True when this hash was produced with weaker parameters than the current policy, and
    /// should be recomputed.
    /// </summary>
    /// <remarks>
    /// Only checked after a <i>successful</i> verification, because that is the one moment the
    /// plaintext is available to rehash with. Hardware gets faster; a password hashed in 2026
    /// should not still be protected by 2026 work factors in 2031.
    /// </remarks>
    public bool NeedsRehash(int currentMemoryKib, int currentIterations, int currentParallelism) =>
        !string.Equals(Algorithm, Argon2idAlgorithm, StringComparison.Ordinal) ||
        Version != Argon2Version ||
        MemoryKib < currentMemoryKib ||
        Iterations < currentIterations ||
        Parallelism != currentParallelism;

    private static bool TryParseParameters(
        string segment,
        out int memoryKib,
        out int iterations,
        out int parallelism)
    {
        memoryKib = 0;
        iterations = 0;
        parallelism = 0;

        foreach (string pair in segment.Split(','))
        {
            int separator = pair.IndexOf('=', StringComparison.Ordinal);

            if (separator <= 0 ||
                !int.TryParse(pair[(separator + 1)..], CultureInfo.InvariantCulture, out int value) ||
                value <= 0)
            {
                return false;
            }

            switch (pair[..separator])
            {
                case "m": memoryKib = value; break;
                case "t": iterations = value; break;
                case "p": parallelism = value; break;
                default: return false;
            }
        }

        return memoryKib > 0 && iterations > 0 && parallelism > 0;
    }

    private static bool TryDecodeBase64(string value, [NotNullWhen(true)] out byte[]? decoded)
    {
        // PHC omits base64 padding; restore it before decoding.
        string padded = (value.Length % 4) switch
        {
            2 => value + "==",
            3 => value + "=",
            0 => value,
            _ => string.Empty,
        };

        if (padded.Length == 0)
        {
            decoded = null;
            return false;
        }

        byte[] buffer = new byte[padded.Length * 3 / 4];

        if (Convert.TryFromBase64String(padded, buffer, out int written))
        {
            decoded = buffer[..written];
            return true;
        }

        decoded = null;
        return false;
    }

    public bool Equals(PasswordHash? other) =>
        other is not null && string.Equals(Encoded, other.Encoded, StringComparison.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as PasswordHash);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Encoded);

    /// <summary>
    /// Deliberately does NOT return the encoded hash.
    /// </summary>
    /// <remarks>
    /// A password verifier interpolated into a log line or an exception message by an
    /// incidental <c>ToString()</c> is an offline-cracking gift. The encoded form is available
    /// through <see cref="Encoded"/>, which a developer has to name explicitly.
    /// </remarks>
    public override string ToString() => $"{Algorithm} (m={MemoryKib},t={Iterations},p={Parallelism})";
}
