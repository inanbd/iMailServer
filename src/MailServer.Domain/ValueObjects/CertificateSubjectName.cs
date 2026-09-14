using System.Diagnostics.CodeAnalysis;
using MailServer.Domain.Exceptions;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// One dNSName entry from a certificate's subjectAltName extension: either an exact hostname
/// or a single-level wildcard pattern.
/// </summary>
/// <remarks>
/// <para>
/// <b>Deliberately not a <see cref="DomainName"/>.</b> A SAN entry and a hostname are
/// different things: <c>*.example.com</c> is a legal, common SAN and is not a domain name at
/// all — no mail is ever addressed to it and no DNS lookup ever resolves it. Forcing it
/// through <see cref="DomainName"/> would mean either rejecting real certificates or loosening
/// the type that mail domains, MX hostnames and EHLO names all depend on, so that
/// <c>*.example.com</c> became an acceptable mail domain.
/// </para>
/// <para>
/// The direction of the relationship is the useful one: a subject name <i>matches</i> a
/// hostname. Hostnames stay strictly validated; patterns live here.
/// </para>
/// </remarks>
public sealed class CertificateSubjectName : IEquatable<CertificateSubjectName>
{
    private const string WildcardPrefix = "*.";

    private CertificateSubjectName(string value, bool isWildcard, DomainName baseName)
    {
        Value = value;
        IsWildcard = isWildcard;
        BaseName = baseName;
    }

    /// <summary>The entry as it appears in the certificate, in ASCII A-label form.</summary>
    public string Value { get; }

    /// <summary>True when this entry is a <c>*.</c> pattern rather than an exact name.</summary>
    public bool IsWildcard { get; }

    /// <summary>
    /// The name with any wildcard label removed: the parent domain for a wildcard, or the name
    /// itself for an exact entry.
    /// </summary>
    public DomainName BaseName { get; }

    /// <exception cref="InvalidValueObjectException">The entry is not a usable dNSName.</exception>
    public static CertificateSubjectName Parse(string? input)
    {
        if (!TryParse(input, out CertificateSubjectName? result))
        {
            throw new InvalidValueObjectException(
                nameof(CertificateSubjectName),
                "the value is not a hostname or a single-level wildcard pattern such as " +
                "'*.example.com'.");
        }

        return result;
    }

    public static bool TryParse(string? input, [NotNullWhen(true)] out CertificateSubjectName? result)
    {
        result = null;

        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        string trimmed = input.Trim();

        if (!trimmed.StartsWith(WildcardPrefix, StringComparison.Ordinal))
        {
            // A partial-label wildcard such as 'm*.example.com' is rejected rather than
            // silently treated as a literal name. Support for it is inconsistent across
            // clients, so a certificate relying on one does not reliably cover anything, and
            // accepting it here would let the server report coverage that clients refuse.
            if (trimmed.Contains('*', StringComparison.Ordinal))
            {
                return false;
            }

            if (!DomainName.TryParse(trimmed, out DomainName? exact))
            {
                return false;
            }

            result = new CertificateSubjectName(exact.Value, isWildcard: false, exact);
            return true;
        }

        string remainder = trimmed[WildcardPrefix.Length..];

        // '*.com' is syntactically valid but no public CA will issue it, and honouring one
        // would mean a single certificate claimed every host under a TLD. A wildcard needs a
        // parent of at least two labels.
        if (!DomainName.TryParse(remainder, out DomainName? parent) || parent.Labels.Length < 2)
        {
            return false;
        }

        result = new CertificateSubjectName(
            WildcardPrefix + parent.Value,
            isWildcard: true,
            parent);

        return true;
    }

    /// <summary>
    /// True when this entry covers <paramref name="hostname"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Wildcard matching follows RFC 6125 §6.4.3 and is strict: <c>*.example.com</c> matches
    /// <c>mail.example.com</c>, but not <c>example.com</c> itself and not
    /// <c>a.b.example.com</c>. A wildcard replaces exactly one label.
    /// </para>
    /// <para>
    /// Erring permissive here would be the harmful direction — the server would report a
    /// hostname as covered while every connecting client showed a name-mismatch warning.
    /// </para>
    /// </remarks>
    public bool Matches(DomainName hostname)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        if (!IsWildcard)
        {
            return BaseName == hostname;
        }

        string[] candidate = hostname.Labels;
        string[] parent = BaseName.Labels;

        if (candidate.Length != parent.Length + 1)
        {
            return false;
        }

        for (int i = 0; i < parent.Length; i++)
        {
            if (!string.Equals(candidate[i + 1], parent[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Builds an exact entry from an already-validated hostname.</summary>
    public static CertificateSubjectName FromHostname(DomainName hostname)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        return new CertificateSubjectName(hostname.Value, isWildcard: false, hostname);
    }

    public bool Equals(CertificateSubjectName? other) =>
        other is not null && string.Equals(Value, other.Value, StringComparison.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as CertificateSubjectName);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    public override string ToString() => Value;

    public static bool operator ==(CertificateSubjectName? left, CertificateSubjectName? right) =>
        left is null ? right is null : left.Equals(right);

    public static bool operator !=(CertificateSubjectName? left, CertificateSubjectName? right) =>
        !(left == right);
}
