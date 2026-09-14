using System.Security.Cryptography.X509Certificates;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Certificates;

/// <summary>
/// Answers "which certificate do I present" during a TLS handshake, and can be updated
/// without restarting anything.
/// </summary>
/// <remarks>
/// <para>
/// <b>Listeners must never capture an <see cref="X509Certificate2"/> at startup.</b> They pass
/// a selection callback to <c>SslStream</c> that calls <see cref="Select"/> on every
/// handshake. Renewal then becomes a single atomic swap here: new connections get the new
/// certificate, in-flight sessions finish on the one they started with, and no listener is
/// reconfigured.
/// </para>
/// <para>
/// The alternative — restarting SMTP and IMAP listeners to pick up a renewed certificate —
/// drops every live session every 60 days. On a mail server that means interrupted deliveries
/// and disconnected IMAP clients on a schedule, which is exactly the kind of self-inflicted
/// disruption that teaches operators to turn automation off.
/// </para>
/// <para>
/// <see cref="Select"/> is called on the TLS handshake path and must be allocation-light,
/// lock-free and non-blocking. It therefore reads an immutable snapshot; all the work of
/// building one happens in <see cref="ReloadAsync"/>.
/// </para>
/// </remarks>
public interface ITlsCertificateProvider
{
    /// <summary>
    /// Chooses the certificate for an incoming handshake.
    /// </summary>
    /// <param name="hostname">
    /// The SNI hostname the client offered, or null when it offered none. Null is normal:
    /// SNI is an extension and older MTAs still connect without it, so a null here must
    /// return the default certificate rather than nothing.
    /// </param>
    /// <param name="purpose">The service the connection arrived on.</param>
    /// <returns>
    /// The certificate to present, or null when none is configured — at which point the
    /// handshake cannot proceed and the caller logs it.
    /// </returns>
    X509Certificate2? Select(string? hostname, CertificatePurpose purpose);

    /// <summary>Rebuilds the snapshot from current bindings and swaps it in atomically.</summary>
    /// <remarks>
    /// Called after issuance, renewal, import, or a binding change. The swap is the only
    /// mutation; a caller mid-handshake keeps the snapshot it already read.
    /// </remarks>
    Task ReloadAsync(CancellationToken cancellationToken);

    /// <summary>The hostnames currently served, for diagnostics and health reporting.</summary>
    IReadOnlyCollection<DomainName> ConfiguredHostnames { get; }

    /// <summary>True once a snapshot has been loaded and at least one certificate is available.</summary>
    bool IsReady { get; }
}
