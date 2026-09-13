using System.Diagnostics.CodeAnalysis;
using MailServer.Domain.Exceptions;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// A SHA-256 digest in lower-case hexadecimal.
/// </summary>
/// <remarks>
/// Recorded when a message is written to storage and when a migration script is applied.
/// In both cases the point is to detect content that has changed when it should not have:
/// silent message-store corruption, and an edited migration that has already been applied.
/// </remarks>
public readonly record struct Sha256Hash
{
    /// <summary>Length of a SHA-256 digest in hexadecimal characters.</summary>
    public const int HexLength = 64;

    private readonly string? _value;

    private Sha256Hash(string value) => _value = value;

    public string Value => _value ?? new string('0', HexLength);

    public static Sha256Hash FromBytes(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != 32)
        {
            throw new InvalidValueObjectException(
                nameof(Sha256Hash),
                $"a SHA-256 digest is 32 bytes; got {digest.Length}.");
        }

        return new Sha256Hash(Convert.ToHexStringLower(digest));
    }

    public static Sha256Hash Parse(string? input)
    {
        if (!TryParse(input, out Sha256Hash result))
        {
            throw new InvalidValueObjectException(
                nameof(Sha256Hash),
                "the value is not 64 hexadecimal characters.");
        }

        return result;
    }

    public static bool TryParse(string? input, out Sha256Hash result)
    {
        result = default;

        if (input is null || input.Length != HexLength)
        {
            return false;
        }

        foreach (char c in input)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }

        result = new Sha256Hash(input.ToLowerInvariant());
        return true;
    }

    public override string ToString() => Value;
}

/// <summary>
/// A certificate thumbprint (SHA-1 or SHA-256) in upper-case hexadecimal.
/// </summary>
/// <remarks>
/// Upper-case because that is the form the Windows certificate store and
/// <c>X509Certificate2.Thumbprint</c> produce, and matching that convention avoids a
/// case-conversion bug every time a certificate is looked up by thumbprint.
/// </remarks>
public readonly record struct CertificateThumbprint
{
    private readonly string? _value;

    private CertificateThumbprint(string value) => _value = value;

    public string Value => _value ?? string.Empty;

    public bool IsEmpty => string.IsNullOrEmpty(_value);

    public static CertificateThumbprint Parse(string? input)
    {
        if (!TryParse(input, out CertificateThumbprint result))
        {
            throw new InvalidValueObjectException(
                nameof(CertificateThumbprint),
                "the value is not a hexadecimal certificate thumbprint.");
        }

        return result;
    }

    public static bool TryParse(string? input, out CertificateThumbprint result)
    {
        result = default;

        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        // Tolerate the space- and colon-separated forms shown by certificate viewers.
        string cleaned = input
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace(":", string.Empty, StringComparison.Ordinal)
            .Trim();

        // SHA-1 is 40 hex characters, SHA-256 is 64.
        if (cleaned.Length is not (40 or 64))
        {
            return false;
        }

        foreach (char c in cleaned)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }

        result = new CertificateThumbprint(cleaned.ToUpperInvariant());
        return true;
    }

    public override string ToString() => Value;
}
