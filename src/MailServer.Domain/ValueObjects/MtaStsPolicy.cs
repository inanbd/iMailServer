using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using MailServer.Domain.Enums;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// The policy file served at <c>https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</c>.
/// RFC 8461 §3.2.
/// </summary>
/// <remarks>
/// <para>
/// Parses the resource's <i>content</i>, never the fetch. Whether the media type was
/// <c>text/plain</c>, whether the certificate on the policy host was valid, and what an HTTP 404
/// means are Infrastructure concerns; this type only interprets text it is handed.
/// </para>
/// <para>
/// <b>Deliberately lenient about line endings.</b> §3.2 says the pairs are CRLF-separated, and
/// a policy file edited on a Unix host is LF-separated about half the time. A parser that
/// rejected those would report a working domain's policy as malformed, which is the opposite of
/// useful: the senders that matter accept it.
/// </para>
/// </remarks>
public sealed class MtaStsPolicy
{
    /// <summary>§3.2's <c>max_age</c> ceiling: "maximum value of 31557600".</summary>
    public const long MaxAgeCeiling = 31_557_600;

    private readonly List<string> _mxPatterns;

    private MtaStsPolicy(MtaStsMode mode, IEnumerable<string> mxPatterns, long maxAgeSeconds)
    {
        Mode = mode;
        _mxPatterns = [.. mxPatterns];
        MaxAgeSeconds = maxAgeSeconds;
    }

    /// <summary><c>mode</c> — what senders should do when validation fails.</summary>
    public MtaStsMode Mode { get; }

    /// <summary><c>mx</c> — the host patterns this domain's mail may be delivered to.</summary>
    public IReadOnlyList<string> MxPatterns => _mxPatterns;

    /// <summary><c>max_age</c> — how long senders may cache this policy, in seconds.</summary>
    public long MaxAgeSeconds { get; }

    /// <summary>
    /// Whether an MX host is one this policy permits.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §4.1: "Matching is identical to the rules given in [RFC6125], with the
    /// restriction that the wildcard character '*' may only be used to match the entire
    /// left-most label in the presented identifier. Thus, the mx pattern '*.example.com' matches
    /// 'mail.example.com' but not 'example.com' or 'foo.bar.example.com'."
    /// </remarks>
    public bool Covers(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        string candidate = host.TrimEnd('.');

        foreach (string pattern in _mxPatterns)
        {
            if (Matches(pattern, candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Matches(string pattern, string host)
    {
        if (!pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            return string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);
        }

        string suffix = pattern[1..];

        if (!host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // The wildcard stands for exactly one label, so what it replaced must be non-empty and
        // must contain no dot of its own: "*.example.com" does not match "foo.bar.example.com".
        string replaced = host[..^suffix.Length];

        return replaced.Length > 0 && !replaced.Contains('.', StringComparison.Ordinal);
    }

    /// <summary>
    /// Composes the policy this server publishes for its own domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The counterpart of <see cref="TryParse"/>, and validated to the same rules rather than to
    /// looser ones: a policy this server would refuse to read from somebody else is not one it
    /// should ask the Internet to read from it.
    /// </para>
    /// <para>
    /// <b><c>max_age</c> is capped rather than rejected at the ceiling.</b> RFC 8461 §3.2 gives
    /// 31557600 as the "maximum value", and a configuration that asked for more meant "as long
    /// as possible" — refusing to publish anything at all would take a working domain's policy
    /// off the air over a number nobody would notice was too large.
    /// </para>
    /// </remarks>
    /// <param name="mode">What senders should do when validation fails.</param>
    /// <param name="mxPatterns">The hosts this domain's mail may be delivered to.</param>
    /// <param name="maxAgeSeconds">How long senders may cache it, capped at <see cref="MaxAgeCeiling"/>.</param>
    public static MtaStsPolicy Create(MtaStsMode mode, IEnumerable<string> mxPatterns, long maxAgeSeconds)
    {
        ArgumentNullException.ThrowIfNull(mxPatterns);
        ArgumentOutOfRangeException.ThrowIfNegative(maxAgeSeconds);

        List<string> patterns = [.. mxPatterns
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.Trim().TrimEnd('.'))];

        // §5: only "none" describes a domain with no active policy, so it is the one mode that
        // needs nowhere to deliver. Every other mode without an mx would publish a policy that
        // forbids delivery to every host, which is an outage rather than a configuration.
        if (patterns.Count == 0 && mode != MtaStsMode.None)
        {
            throw new ArgumentException(
                "A policy in enforce or testing mode must list at least one mx pattern; " +
                "publishing one without would forbid delivery to every host.",
                nameof(mxPatterns));
        }

        return new MtaStsPolicy(mode, patterns, Math.Min(maxAgeSeconds, MaxAgeCeiling));
    }

    /// <summary>
    /// Renders the policy as the resource body senders fetch.
    /// </summary>
    /// <remarks>
    /// <b>CRLF, because §3.2's ABNF says so.</b> <see cref="TryParse"/> accepts bare LF from
    /// other people's servers, for the reason its own remarks give; that leniency is about what
    /// this server will read, and says nothing about what it should write. Emitting exactly what
    /// the grammar specifies costs nothing and keeps this server off the list of implementations
    /// that made the leniency necessary in the first place.
    /// </remarks>
    public string Format()
    {
        System.Text.StringBuilder builder = new();

        builder.Append("version: STSv1\r\n");
        builder.Append("mode: ").Append(NameOf(Mode)).Append("\r\n");

        foreach (string pattern in _mxPatterns)
        {
            builder.Append("mx: ").Append(pattern).Append("\r\n");
        }

        builder.Append("max_age: ")
            .Append(MaxAgeSeconds.ToString(CultureInfo.InvariantCulture))
            .Append("\r\n");

        return builder.ToString();
    }

    /// <summary>
    /// The <c>id</c> for the <c>_mta-sts</c> TXT record that advertises this policy.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Derived from the policy's own content, never from a clock or a counter.</b> RFC 8461
    /// §3.1 makes the id how a sender knows its cached copy is stale — it re-fetches when the id
    /// changes and not otherwise. A timestamp would change the id on every restart and make
    /// every sender on the Internet re-fetch an identical file; a counter would need storage
    /// that has to survive a reinstall, and getting that wrong is worse, because a policy that
    /// changed while the id did not is one senders keep enforcing the old version of until their
    /// cache expires.
    /// </para>
    /// <para>
    /// §3.1 constrains the id to 1–32 printable ASCII characters, so this is the hash in hex,
    /// truncated. Truncation is safe here because the id is a change detector rather than a
    /// security boundary: the policy it points at is fetched over HTTPS and validated on its own.
    /// </para>
    /// </remarks>
    public string PolicyId()
    {
        byte[] hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(Format()));

        return Convert.ToHexStringLower(hash)[..32];
    }

    private static string NameOf(MtaStsMode mode) => mode switch
    {
        MtaStsMode.Enforce => "enforce",
        MtaStsMode.Testing => "testing",
        _ => "none",
    };

    /// <summary>Reads a policy resource, or explains why it is not one.</summary>
    public static bool TryParse(
        string? text,
        [NotNullWhen(true)] out MtaStsPolicy? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;
        error = null;

        if (string.IsNullOrWhiteSpace(text))
        {
            error = "the policy is empty.";
            return false;
        }

        string? version = null;
        MtaStsMode? mode = null;
        long? maxAge = null;
        List<string> mx = [];

        foreach (string rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();

            if (line.Length == 0)
            {
                continue;
            }

            int colon = line.IndexOf(':', StringComparison.Ordinal);

            if (colon <= 0)
            {
                error = $"\"{line}\" is not a key/value pair.";
                return false;
            }

            string key = line[..colon].Trim();
            string value = line[(colon + 1)..].Trim();

            switch (key.ToLowerInvariant())
            {
                case "version":
                    version = value;
                    break;

                case "mode":
                    if (!TryReadMode(value, out MtaStsMode parsedMode))
                    {
                        error = $"\"{value}\" is not one of enforce, testing or none.";
                        return false;
                    }

                    mode = parsedMode;
                    break;

                case "max_age":
                    if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long parsedAge))
                    {
                        error = $"max_age \"{value}\" is not a non-negative integer.";
                        return false;
                    }

                    maxAge = parsedAge;
                    break;

                case "mx":
                    mx.Add(value);
                    break;

                // §3.2's ABNF has an sts-policy-extension production, and §3.2 itself says
                // nothing about rejecting unknown keys. Ignoring them is what lets a later
                // revision add one without every existing parser calling the policy malformed.
                default:
                    break;
            }
        }

        if (!string.Equals(version, "STSv1", StringComparison.Ordinal))
        {
            error = version is null
                ? "the policy has no version field."
                : $"\"{version}\" is not a supported version; only STSv1 is defined.";

            return false;
        }

        if (mode is not { } finalMode)
        {
            error = "the policy has no mode field.";
            return false;
        }

        if (maxAge is not { } finalAge)
        {
            error = "the policy has no max_age field.";
            return false;
        }

        // §5: only "none" describes a domain with no active policy, so it is the one mode that
        // does not need somewhere to deliver. Requiring an mx for it would reject the very file
        // a domain publishes to withdraw a policy senders have cached.
        if (mx.Count == 0 && finalMode != MtaStsMode.None)
        {
            error = "the policy lists no mx patterns.";
            return false;
        }

        result = new MtaStsPolicy(finalMode, mx, finalAge);
        return true;
    }

    private static bool TryReadMode(string value, out MtaStsMode mode)
    {
        switch (value.ToLowerInvariant())
        {
            case "enforce":
                mode = MtaStsMode.Enforce;
                return true;

            case "testing":
                mode = MtaStsMode.Testing;
                return true;

            case "none":
                mode = MtaStsMode.None;
                return true;

            default:
                mode = MtaStsMode.None;
                return false;
        }
    }
}
