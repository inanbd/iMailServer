using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using MailServer.Domain.Exceptions;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// A normalised IP address, suitable for storage, comparison and logging.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IPAddress"/> itself is not used as a domain value because two instances that
/// mean the same address can differ: an IPv4-mapped IPv6 address (<c>::ffff:203.0.113.10</c>)
/// and the plain IPv4 address are the same peer, but compare unequal and hash differently.
/// A dual-stack listener produces the mapped form, so an IP block list keyed on the raw
/// object would silently fail to match - a security bug, not a cosmetic one.
/// </para>
/// <para>
/// This type unmaps on construction, so the block list matches.
/// </para>
/// </remarks>
public sealed class IpAddressValue : IEquatable<IpAddressValue>
{
    private readonly IPAddress _address;

    private IpAddressValue(IPAddress address)
    {
        _address = address;
        Value = address.ToString();
    }

    /// <summary>The canonical textual form.</summary>
    public string Value { get; }

    public bool IsIpV4 => _address.AddressFamily == AddressFamily.InterNetwork;

    public bool IsIpV6 => _address.AddressFamily == AddressFamily.InterNetworkV6;

    /// <summary>True for loopback, link-local, or RFC 1918 / RFC 4193 private space.</summary>
    public bool IsPrivate => IsPrivateAddress(_address);

    /// <summary>Returns a copy of the underlying address.</summary>
    public IPAddress ToIpAddress() => _address;

    /// <summary>
    /// True when this address falls within <paramref name="network"/>/<paramref name="prefixLength"/>.
    /// </summary>
    /// <remarks>
    /// Used by SPF's <c>ip4</c>/<c>ip6</c> mechanisms and by matching a resolved <c>a</c>/<c>mx</c>
    /// address against the connecting client. Cross-family comparisons (an IPv4 candidate against
    /// an IPv6 network or vice versa) are never a match — SPF's own grammar keeps <c>ip4</c> and
    /// <c>ip6</c> mechanisms address-family-specific, so silently coercing one into the other
    /// would be inventing a match the record never asked for.
    /// </remarks>
    public bool IsInSubnet(IpAddressValue network, int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(network);

        if (_address.AddressFamily != network._address.AddressFamily)
        {
            return false;
        }

        byte[] candidateBytes = _address.GetAddressBytes();
        byte[] networkBytes = network._address.GetAddressBytes();

        ArgumentOutOfRangeException.ThrowIfNegative(prefixLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(prefixLength, candidateBytes.Length * 8);

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (candidateBytes[i] != networkBytes[i])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        int mask = 0xFF << (8 - remainingBits) & 0xFF;

        return (candidateBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }

    public static IpAddressValue From(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return new IpAddressValue(Normalize(address));
    }

    public static IpAddressValue Parse(string? input)
    {
        if (!TryParse(input, out IpAddressValue? result, out string? error))
        {
            throw new InvalidValueObjectException(nameof(IpAddressValue), error);
        }

        return result;
    }

    public static bool TryParse(string? input, [NotNullWhen(true)] out IpAddressValue? result) =>
        TryParse(input, out result, out _);

    public static bool TryParse(
        string? input,
        [NotNullWhen(true)] out IpAddressValue? result,
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

        // Accept the SMTP address-literal forms: [203.0.113.10] and [IPv6:2001:db8::1].
        if (candidate.StartsWith('[') && candidate.EndsWith(']'))
        {
            candidate = candidate[1..^1];
            if (candidate.StartsWith("IPv6:", StringComparison.OrdinalIgnoreCase))
            {
                candidate = candidate[5..];
            }
        }

        if (!IPAddress.TryParse(candidate, out IPAddress? parsed))
        {
            error = $"'{candidate}' is not a valid IP address.";
            return false;
        }

        result = new IpAddressValue(Normalize(parsed));
        return true;
    }

    private static IPAddress Normalize(IPAddress address)
    {
        // Collapse ::ffff:a.b.c.d to a.b.c.d so that a dual-stack listener and an
        // administrator typing an IPv4 address produce the same value.
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        // Drop the scope id: fe80::1%17 and fe80::1%3 are the same address seen through
        // different interfaces, and the scope is a local artefact with no meaning in storage.
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
        {
            return new IPAddress(address.GetAddressBytes());
        }

        return address;
    }

    private static bool IsPrivateAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] octets = address.GetAddressBytes();
            return octets[0] switch
            {
                10 => true,                                        // 10.0.0.0/8
                127 => true,                                       // 127.0.0.0/8
                169 => octets[1] == 254,                           // 169.254.0.0/16 link-local
                172 => octets[1] >= 16 && octets[1] <= 31,         // 172.16.0.0/12
                192 => octets[1] == 168,                           // 192.168.0.0/16
                _ => false,
            };
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal)
            {
                return true;
            }

            // fc00::/7 unique local addresses.
            byte[] octets = address.GetAddressBytes();
            return (octets[0] & 0xFE) == 0xFC;
        }

        return false;
    }

    /// <summary>
    /// The reverse-DNS name for this address, e.g. <c>10.113.0.203.in-addr.arpa</c>.
    /// Used by the PTR and FCrDNS checks.
    /// </summary>
    public string ToReverseDnsName()
    {
        byte[] octets = _address.GetAddressBytes();

        if (IsIpV4)
        {
            return $"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa";
        }

        // IPv6 reverse names are nibble-reversed, one nibble per label.
        char[] nibbles = new char[octets.Length * 4];
        int index = 0;
        for (int i = octets.Length - 1; i >= 0; i--)
        {
            nibbles[index++] = GetHexDigit(octets[i] & 0x0F);
            nibbles[index++] = '.';
            nibbles[index++] = GetHexDigit((octets[i] >> 4) & 0x0F);
            nibbles[index++] = '.';
        }

        return new string(nibbles) + "ip6.arpa";

        static char GetHexDigit(int value) => (char)(value < 10 ? '0' + value : 'a' + (value - 10));
    }

    public bool Equals(IpAddressValue? other) =>
        other is not null && _address.Equals(other._address);

    public override bool Equals(object? obj) => Equals(obj as IpAddressValue);

    public override int GetHashCode() => _address.GetHashCode();

    public override string ToString() => Value;

    public static bool operator ==(IpAddressValue? left, IpAddressValue? right) =>
        left?.Equals(right) ?? right is null;

    public static bool operator !=(IpAddressValue? left, IpAddressValue? right) => !(left == right);
}
