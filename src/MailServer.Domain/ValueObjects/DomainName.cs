using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using MailServer.Domain.Exceptions;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// A fully-qualified DNS domain name, normalised to lower-case ASCII (A-label / Punycode) form.
/// </summary>
/// <remarks>
/// <para>
/// Two representations are kept deliberately:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///     <see cref="Value"/> - the ASCII A-label form (<c>xn--bcher-kva.example</c>). This is
///     what goes on the wire, into DNS queries, into database unique keys and into SMTP
///     envelopes when the peer does not advertise SMTPUTF8.
///     </description>
///   </item>
///   <item>
///     <description>
///     <see cref="UnicodeValue"/> - the U-label form (<c>bücher.example</c>). This is what an
///     administrator sees and what goes on the wire when SMTPUTF8 is in play.
///     </description>
///   </item>
/// </list>
/// <para>
/// Keeping both, and comparing only on <see cref="Value"/>, is how the product satisfies
/// "Never silently corrupt addresses" (brief §29). A single-representation design forces a
/// lossy conversion somewhere, and that conversion is where international domains break.
/// </para>
/// </remarks>
public sealed class DomainName : IEquatable<DomainName>, IComparable<DomainName>
{
    /// <summary>Maximum length of a fully-qualified name in A-label form, excluding the root dot.</summary>
    public const int MaxLength = 253;

    /// <summary>Maximum length of a single DNS label.</summary>
    public const int MaxLabelLength = 63;

    /// <summary>
    /// Minimum number of labels. A mail domain must be a registrable FQDN: <c>example.com</c>,
    /// not <c>localhost</c>. Accepting single-label names would produce mail that no public
    /// receiver can reply to.
    /// </summary>
    public const int MinLabelCount = 2;

    private static readonly IdnMapping Idn = new()
    {
        // Reject malformed input loudly rather than silently producing a different name.
        UseStd3AsciiRules = true,
        AllowUnassigned = false,
    };

    private DomainName(string asciiValue, string unicodeValue)
    {
        Value = asciiValue;
        UnicodeValue = unicodeValue;
    }

    /// <summary>Lower-case ASCII (A-label / Punycode) form. The canonical value.</summary>
    public string Value { get; }

    /// <summary>Lower-case Unicode (U-label) form, for display and SMTPUTF8.</summary>
    public string UnicodeValue { get; }

    /// <summary>True when the ASCII and Unicode forms differ, i.e. this is an IDN.</summary>
    public bool IsInternationalized => !string.Equals(Value, UnicodeValue, StringComparison.Ordinal);

    /// <summary>The labels of the ASCII form, left to right.</summary>
    public string[] Labels => Value.Split('.');

    /// <summary>
    /// Parses a domain name, throwing when it is not valid.
    /// </summary>
    /// <exception cref="InvalidValueObjectException">The input is not a valid domain name.</exception>
    public static DomainName Parse(string? input)
    {
        if (!TryParse(input, out DomainName? result, out string? error))
        {
            throw new InvalidValueObjectException(nameof(DomainName), error);
        }

        return result;
    }

    /// <summary>
    /// Attempts to parse a domain name. Preferred over <see cref="Parse"/> anywhere input
    /// arrives from a network peer, because exceptions are far too costly on the SMTP path.
    /// </summary>
    public static bool TryParse(string? input, [NotNullWhen(true)] out DomainName? result) =>
        TryParse(input, out result, out _);

    /// <summary>
    /// Attempts to parse a domain name, reporting why it failed.
    /// </summary>
    public static bool TryParse(
        string? input,
        [NotNullWhen(true)] out DomainName? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;
        error = null;

        if (string.IsNullOrWhiteSpace(input))
        {
            error = "the value is empty.";
            return false;
        }

        string candidate = input.Trim();

        // A single trailing dot denotes the DNS root and is accepted, then dropped.
        if (candidate.EndsWith('.'))
        {
            candidate = candidate[..^1];
        }

        if (candidate.Length == 0)
        {
            error = "the value is empty.";
            return false;
        }

        // Reject a bracketed address literal such as [203.0.113.10]. These are legal in an
        // SMTP envelope but are NOT domain names, and conflating them here would let an
        // address literal through into DNS lookups and DKIM alignment.
        if (candidate.StartsWith('[') || candidate.EndsWith(']'))
        {
            error = "address literals are not domain names.";
            return false;
        }

        string ascii;
        string unicode;
        try
        {
            // GetAscii is the validating direction: it applies the IDNA and STD3 rules and
            // throws on anything malformed. Running it first means an already-ASCII name is
            // still validated, not merely passed through.
            ascii = Idn.GetAscii(candidate).ToLowerInvariant();
            unicode = Idn.GetUnicode(ascii).ToLowerInvariant();
        }
        catch (ArgumentException ex)
        {
            error = $"not a valid international domain name ({ex.Message.TrimEnd('.')}).";
            return false;
        }

        if (ascii.Length > MaxLength)
        {
            error = $"the name is {ascii.Length} characters; the maximum is {MaxLength}.";
            return false;
        }

        string[] labels = ascii.Split('.');

        if (labels.Length < MinLabelCount)
        {
            error = $"'{ascii}' is not fully qualified; a mail domain needs at least {MinLabelCount} labels.";
            return false;
        }

        foreach (string label in labels)
        {
            if (!IsValidLabel(label, out string? labelError))
            {
                error = $"label '{label}' is invalid: {labelError}";
                return false;
            }
        }

        // A final numeric label means this is an IPv4 address, not a domain name.
        if (labels[^1].All(char.IsAsciiDigit))
        {
            error = "the top-level label is numeric; this looks like an IP address.";
            return false;
        }

        result = new DomainName(ascii, unicode);
        return true;
    }

    private static bool IsValidLabel(string label, [NotNullWhen(false)] out string? error)
    {
        error = null;

        if (label.Length == 0)
        {
            error = "it is empty (consecutive dots are not allowed).";
            return false;
        }

        if (label.Length > MaxLabelLength)
        {
            error = $"it is {label.Length} characters; the maximum is {MaxLabelLength}.";
            return false;
        }

        if (label[0] == '-' || label[^1] == '-')
        {
            error = "it may not start or end with a hyphen.";
            return false;
        }

        foreach (char c in label)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-')
            {
                error = $"'{c}' is not permitted in a DNS label.";
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// True when <paramref name="other"/> is this domain or a subdomain of it.
    /// Used for relaxed DMARC/DKIM alignment and for catch-all routing.
    /// </summary>
    public bool IsSameOrSubdomainOf(DomainName other)
    {
        ArgumentNullException.ThrowIfNull(other);

        if (Equals(other))
        {
            return true;
        }

        // The leading dot matters: "notexample.com" must not match "example.com".
        return Value.EndsWith('.' + other.Value, StringComparison.Ordinal);
    }

    public bool Equals(DomainName? other) =>
        other is not null && string.Equals(Value, other.Value, StringComparison.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as DomainName);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    public int CompareTo(DomainName? other) =>
        other is null ? 1 : string.CompareOrdinal(Value, other.Value);

    public override string ToString() => Value;

    public static bool operator ==(DomainName? left, DomainName? right) =>
        left?.Equals(right) ?? right is null;

    public static bool operator !=(DomainName? left, DomainName? right) => !(left == right);
}
