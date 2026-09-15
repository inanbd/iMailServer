namespace MailServer.Domain.ValueObjects;

/// <summary>One candidate destination host for a domain, as published in DNS.</summary>
/// <param name="Hostname">The MX target, or the domain itself for an implicit-MX fallback.</param>
/// <param name="Preference">
/// RFC 5321 preference (lower tried first). Zero for an implicit-MX fallback, which has no
/// preference of its own.
/// </param>
public readonly record struct MxHost(string Hostname, int Preference);
