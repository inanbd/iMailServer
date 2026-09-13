namespace MailServer.Application.Abstractions.Platform;

/// <summary>
/// The server's own mail identity.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Hostname"/> is the single most consequential setting in the product. It is the
/// name announced in EHLO, the name a remote server's reverse-DNS lookup must return, the
/// name that must appear in the TLS certificate's SAN list, and the name the MX record
/// points at. If those four disagree, mail is rejected or spam-foldered by every major
/// receiver, and no amount of correct SPF or DKIM compensates.
/// </para>
/// <para>
/// It is therefore read from validated configuration through this interface rather than from
/// <c>Environment.MachineName</c> or a DNS lookup at startup, both of which produce a
/// plausible-looking wrong answer.
/// </para>
/// </remarks>
public interface IServerIdentityProvider
{
    /// <summary>The server's fully-qualified mail hostname, e.g. <c>mail.example.com</c>.</summary>
    string Hostname { get; }

    /// <summary>The configured public IP address, if one has been set.</summary>
    string? PublicIpAddress { get; }

    /// <summary>Product name used in SMTP banners and generated headers.</summary>
    string ProductName { get; }
}
