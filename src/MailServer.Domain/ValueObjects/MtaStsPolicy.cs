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
