using System.Diagnostics.CodeAnalysis;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// The tag-value list published at a DKIM selector's DNS name. RFC 6376 §3.6.1.
/// </summary>
/// <remarks>
/// Parses the record's <i>content</i> — the concatenation of a TXT resource's one or more
/// character-strings — never the DNS lookup itself. Concatenating multi-string TXT answers and
/// deciding what an absent, NXDOMAIN, or SERVFAIL answer means for verification are Infrastructure
/// concerns; this type only interprets text it is handed.
/// </remarks>
public sealed class DkimPublicKeyRecord
{
    private DkimPublicKeyRecord(string? version, string keyType, string publicKeyBase64)
    {
        Version = version;
        KeyType = keyType;
        PublicKeyBase64 = publicKeyBase64;
    }

    /// <summary><c>v=</c>, if present. When present it must be exactly <c>DKIM1</c>.</summary>
    public string? Version { get; }

    /// <summary><c>k=</c> — the published key's type. Defaults to <c>rsa</c> when absent.</summary>
    public string KeyType { get; }

    /// <summary>
    /// <c>p=</c> — the base64 public key. Empty specifically means this key has been revoked
    /// (RFC 6376 §3.6.1) — the domain owner published the selector and then explicitly
    /// withdrew it, which is different from the selector not existing at all.
    /// </summary>
    public string PublicKeyBase64 { get; }

    /// <summary>True when the domain has explicitly revoked this selector's key.</summary>
    public bool IsRevoked => PublicKeyBase64.Length == 0;

    public static bool TryParse(
        string? recordText,
        [NotNullWhen(true)] out DkimPublicKeyRecord? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;
        error = null;

        if (string.IsNullOrWhiteSpace(recordText))
        {
            error = "the record is empty.";
            return false;
        }

        var tags = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (string rawSegment in recordText.Split(';'))
        {
            string segment = rawSegment.Trim();

            if (segment.Length == 0)
            {
                continue;
            }

            int eq = segment.IndexOf('=');

            if (eq <= 0)
            {
                error = $"the tag segment '{segment}' has no '=' separator.";
                return false;
            }

            string name = segment[..eq].Trim();
            string value = StripWhitespace(segment[(eq + 1)..]);

            if (!tags.TryAdd(name, value))
            {
                error = $"tag '{name}' appears more than once.";
                return false;
            }
        }

        if (tags.TryGetValue("v", out string? version) && version != "DKIM1")
        {
            error = $"the v= tag is '{version}', not 'DKIM1'.";
            return false;
        }

        if (!tags.TryGetValue("p", out string? publicKeyBase64))
        {
            error = "the record has no p= tag.";
            return false;
        }

        string keyType = tags.GetValueOrDefault("k", "rsa");

        result = new DkimPublicKeyRecord(version, keyType, publicKeyBase64);
        return true;
    }

    private static string StripWhitespace(string value)
    {
        Span<char> buffer = value.Length <= 256 ? stackalloc char[value.Length] : new char[value.Length];
        int o = 0;

        foreach (char c in value)
        {
            if (!char.IsWhiteSpace(c))
            {
                buffer[o++] = c;
            }
        }

        return new string(buffer[..o]);
    }
}
