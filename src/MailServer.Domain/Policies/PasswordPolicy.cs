using System.Text;

namespace MailServer.Domain.Policies;

/// <summary>The outcome of evaluating a candidate password.</summary>
/// <param name="IsAcceptable">True when the password may be used.</param>
/// <param name="Failures">Reasons it was rejected. Empty when acceptable.</param>
/// <param name="Warnings">Advice that does not block acceptance.</param>
public sealed record PasswordEvaluation(
    bool IsAcceptable,
    IReadOnlyList<string> Failures,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Decides whether a candidate password is acceptable.
/// </summary>
/// <remarks>
/// <para>
/// <b>Length is the requirement; composition rules are deliberately absent.</b> NIST SP
/// 800-63B explicitly recommends against "must contain an uppercase letter, a digit and a
/// symbol" rules, because they do not measurably increase entropy and they push people
/// toward predictable shapes — <c>Password1!</c>, <c>Summer2026!</c> — which are the first
/// things a cracking dictionary tries.
/// </para>
/// <para>
/// What this policy does instead: require real length, reject values that are trivially
/// guessable regardless of their character mix, and bound the input so a megabyte-long
/// "password" cannot be used to make the server do Argon2 work on an attacker's behalf.
/// </para>
/// <para>
/// A pure policy in the Domain layer: no I/O, no clock, no configuration object. That makes
/// it exhaustively testable, which matters because it is the gate on the most privileged
/// credential in the product.
/// </para>
/// </remarks>
public sealed class PasswordPolicy
{
    /// <summary>
    /// Minimum length for the master password.
    /// </summary>
    /// <remarks>
    /// Twelve rather than the more common eight. This single credential controls every
    /// domain, mailbox, certificate and DKIM key on the server; it is not a consumer login.
    /// </remarks>
    public const int MinimumMasterPasswordLength = 12;

    /// <summary>Minimum length for a mailbox password (Milestone 5).</summary>
    public const int MinimumMailboxPasswordLength = 10;

    /// <summary>
    /// Upper bound on the input, in UTF-16 characters.
    /// </summary>
    /// <remarks>
    /// A denial-of-service bound, not a security limit. Argon2 cost scales with input length,
    /// so an unbounded field lets an unauthenticated caller spend the server's memory and CPU
    /// at will. Long passphrases remain entirely usable.
    /// </remarks>
    public const int MaximumLength = 256;

    /// <summary>Length at which a password is considered strong regardless of composition.</summary>
    public const int PassphraseLength = 20;

    /// <summary>
    /// Substrings so common that a password containing one is guessable no matter what else
    /// it contains. Compared case-insensitively.
    /// </summary>
    /// <remarks>
    /// Deliberately short and mail-server specific. A serious deployment should check against
    /// a breached-password corpus (Have I Been Pwned's k-anonymity range API, or an offline
    /// list); that is a Milestone 12 item and is recorded in the docs rather than pretended at
    /// here. This list catches only the most embarrassing cases.
    /// </remarks>
    private static readonly string[] ForbiddenSubstrings =
    [
        "password", "passw0rd", "qwerty", "letmein", "welcome", "admin123",
        "123456", "abc123", "iloveyou", "monkey", "dragon", "aethermail",
        "mailserver", "postmaster", "changeme", "default",
    ];

    private readonly int _minimumLength;

    /// <param name="minimumLength">
    /// Minimum acceptable length. Defaults to <see cref="MinimumMasterPasswordLength"/>.
    /// </param>
    public PasswordPolicy(int minimumLength = MinimumMasterPasswordLength) =>
        _minimumLength = Math.Max(1, minimumLength);

    /// <summary>The minimum length this policy enforces, for display in the UI.</summary>
    public int MinimumLength => _minimumLength;

    /// <summary>Evaluates a candidate password.</summary>
    public PasswordEvaluation Evaluate(string? candidate)
    {
        List<string> failures = [];
        List<string> warnings = [];

        if (string.IsNullOrEmpty(candidate))
        {
            failures.Add("A password is required.");
            return new PasswordEvaluation(false, failures, warnings);
        }

        if (candidate.Length < _minimumLength)
        {
            failures.Add(
                $"The password must be at least {_minimumLength} characters. " +
                "A memorable passphrase of several words is both stronger and easier to type " +
                "than a short password with substitutions.");
        }

        if (candidate.Length > MaximumLength)
        {
            failures.Add($"The password must be no more than {MaximumLength} characters.");
        }

        if (candidate.Trim().Length == 0)
        {
            failures.Add("The password cannot consist only of whitespace.");
        }

        // Leading or trailing whitespace is accepted but warned about, because it is almost
        // always an accidental paste and produces a password nobody can retype.
        if (candidate.Length > 0 &&
            (char.IsWhiteSpace(candidate[0]) || char.IsWhiteSpace(candidate[^1])))
        {
            warnings.Add(
                "The password begins or ends with a space. It will be stored exactly as " +
                "entered, including that space.");
        }

        string lowered = candidate.ToLowerInvariant();

        foreach (string forbidden in ForbiddenSubstrings)
        {
            if (lowered.Contains(forbidden, StringComparison.Ordinal))
            {
                failures.Add(
                    $"The password contains '{forbidden}', which appears in every password " +
                    "cracking dictionary. Choose something unrelated to the product or to " +
                    "common words.");
                break;
            }
        }

        if (IsSingleRepeatedCharacter(candidate))
        {
            failures.Add("The password is a single repeated character.");
        }

        if (IsSequential(candidate))
        {
            failures.Add("The password is a simple ascending or descending sequence.");
        }

        if (failures.Count == 0 && candidate.Length < PassphraseLength && CountCharacterClasses(candidate) < 2)
        {
            warnings.Add(
                $"This password uses a single class of character. Either lengthen it to " +
                $"{PassphraseLength} characters or more, or mix in another kind of character.");
        }

        return new PasswordEvaluation(failures.Count == 0, failures, warnings);
    }

    /// <summary>
    /// A coarse 0-100 strength indicator for the UI meter.
    /// </summary>
    /// <remarks>
    /// Presented as guidance, never as a gate — acceptance is decided by
    /// <see cref="Evaluate"/> alone. A score is a rough, explainable heuristic; treating one
    /// as authoritative would let a long, weak, dictionary-based passphrase score well.
    /// </remarks>
    public static int EstimateStrength(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate))
        {
            return 0;
        }

        // Length dominates, which is the honest weighting.
        int score = Math.Min(60, candidate.Length * 3);

        score += CountCharacterClasses(candidate) switch
        {
            >= 4 => 25,
            3 => 18,
            2 => 10,
            _ => 0,
        };

        // Distinct characters, as a cheap proxy for repetition.
        int distinct = candidate.Distinct().Count();
        score += Math.Min(15, distinct * 15 / Math.Max(1, candidate.Length));

        string lowered = candidate.ToLowerInvariant();

        if (ForbiddenSubstrings.Any(f => lowered.Contains(f, StringComparison.Ordinal)))
        {
            score /= 4;
        }

        if (IsSingleRepeatedCharacter(candidate) || IsSequential(candidate))
        {
            score = Math.Min(score, 10);
        }

        return Math.Clamp(score, 0, 100);
    }

    private static int CountCharacterClasses(string value)
    {
        bool lower = false, upper = false, digit = false, other = false;

        foreach (char c in value)
        {
            if (char.IsLower(c))
            {
                lower = true;
            }
            else if (char.IsUpper(c))
            {
                upper = true;
            }
            else if (char.IsDigit(c))
            {
                digit = true;
            }
            else
            {
                other = true;
            }
        }

        return (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
    }

    private static bool IsSingleRepeatedCharacter(string value)
    {
        if (value.Length < 2)
        {
            return false;
        }

        for (int i = 1; i < value.Length; i++)
        {
            if (value[i] != value[0])
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSequential(string value)
    {
        if (value.Length < 4)
        {
            return false;
        }

        int direction = Math.Sign(value[1] - value[0]);

        if (direction == 0)
        {
            return false;
        }

        for (int i = 1; i < value.Length; i++)
        {
            if (value[i] - value[i - 1] != direction)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Formats a recovery key for display: groups of five, separated by hyphens.
    /// </summary>
    /// <remarks>
    /// Grouping matters because this is shown once and transcribed by hand onto paper or into
    /// a password manager. An unbroken 25-character string is materially more likely to be
    /// copied wrongly, and a wrongly copied recovery key is discovered only in the emergency
    /// it was meant to resolve.
    /// </remarks>
    public static string FormatRecoveryKey(string raw)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(raw);

        StringBuilder builder = new(raw.Length + (raw.Length / 5));

        for (int i = 0; i < raw.Length; i++)
        {
            if (i > 0 && i % 5 == 0)
            {
                builder.Append('-');
            }

            builder.Append(raw[i]);
        }

        return builder.ToString();
    }

    /// <summary>Removes display formatting so a key can be compared as entered.</summary>
    public static string NormalizeRecoveryKey(string? entered)
    {
        if (string.IsNullOrWhiteSpace(entered))
        {
            return string.Empty;
        }

        StringBuilder builder = new(entered.Length);

        foreach (char c in entered)
        {
            if (char.IsAsciiLetterOrDigit(c))
            {
                builder.Append(char.ToUpperInvariant(c));
            }
        }

        return builder.ToString();
    }
}
