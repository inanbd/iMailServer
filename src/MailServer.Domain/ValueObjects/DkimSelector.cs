using System.Diagnostics.CodeAnalysis;
using MailServer.Domain.Exceptions;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// A DKIM selector: the label that, with <c>_domainkey</c>, locates a public key in DNS.
/// </summary>
/// <remarks>
/// For selector <c>mail2026</c> and domain <c>example.com</c>, the public key is published at
/// <c>mail2026._domainkey.example.com</c>. Selectors let a domain publish several keys at
/// once, which is what makes zero-downtime rotation possible: publish the new key, wait for
/// propagation, switch signing over, and only then retire the old key.
/// </remarks>
public sealed class DkimSelector : IEquatable<DkimSelector>
{
    /// <summary>The fixed label DKIM inserts between the selector and the domain.</summary>
    public const string DomainKeySubdomain = "_domainkey";

    /// <summary>A selector is a single DNS label, so it inherits the 63-character limit.</summary>
    public const int MaxLength = 63;

    private DkimSelector(string value) => Value = value;

    public string Value { get; }

    public static DkimSelector Parse(string? input)
    {
        if (!TryParse(input, out DkimSelector? result, out string? error))
        {
            throw new InvalidValueObjectException(nameof(DkimSelector), error);
        }

        return result;
    }

    public static bool TryParse(string? input, [NotNullWhen(true)] out DkimSelector? result) =>
        TryParse(input, out result, out _);

    public static bool TryParse(
        string? input,
        [NotNullWhen(true)] out DkimSelector? result,
        [NotNullWhen(false)] out string? error)
    {
        result = null;
        error = null;

        if (string.IsNullOrWhiteSpace(input))
        {
            error = "the selector is empty.";
            return false;
        }

        string candidate = input.Trim().ToLowerInvariant();

        if (candidate.Length > MaxLength)
        {
            error = $"the selector is {candidate.Length} characters; the maximum is {MaxLength}.";
            return false;
        }

        if (candidate[0] == '-' || candidate[^1] == '-')
        {
            error = "the selector may not start or end with a hyphen.";
            return false;
        }

        foreach (char c in candidate)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-')
            {
                error = $"'{c}' is not permitted in a DNS label.";
                return false;
            }
        }

        result = new DkimSelector(candidate);
        return true;
    }

    /// <summary>
    /// Generates a date-based selector such as <c>mail202609</c>. Date-based selectors make
    /// key age obvious in a DNS zone, which is exactly what an operator needs when deciding
    /// whether a rotation is overdue.
    /// </summary>
    public static DkimSelector CreateDateBased(DateTimeOffset now, string prefix = "mail") =>
        Parse($"{prefix}{now.UtcDateTime:yyyyMM}");

    /// <summary>The fully-qualified DNS name at which this selector's key is published.</summary>
    public string ToDnsName(DomainName domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        return $"{Value}.{DomainKeySubdomain}.{domain.Value}";
    }

    public bool Equals(DkimSelector? other) =>
        other is not null && string.Equals(Value, other.Value, StringComparison.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as DkimSelector);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    public override string ToString() => Value;

    public static bool operator ==(DkimSelector? left, DkimSelector? right) =>
        left?.Equals(right) ?? right is null;

    public static bool operator !=(DkimSelector? left, DkimSelector? right) => !(left == right);
}
