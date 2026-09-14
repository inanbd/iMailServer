using System.Globalization;
using MailServer.Domain.Enums;

namespace MailServer.Domain.Smtp;

/// <summary>What this connection may be told about.</summary>
/// <param name="Role">The listener the peer reached.</param>
/// <param name="IsTlsActive">Whether the connection is already encrypted.</param>
/// <param name="IsAuthenticationAvailable">
/// Whether SASL is implemented and enabled. False until Milestone 7 — see
/// <see cref="SmtpCapabilities"/>.
/// </param>
/// <param name="MaxMessageSizeBytes">The effective size limit for this connection.</param>
/// <param name="IsSmtpUtf8Available">Whether SMTPUTF8 is implemented and enabled.</param>
/// <param name="IsChunkingAvailable">Whether BDAT is implemented and enabled.</param>
public sealed record SmtpCapabilityContext(
    SmtpListenerRole Role,
    bool IsTlsActive,
    bool IsAuthenticationAvailable,
    long MaxMessageSizeBytes,
    bool IsSmtpUtf8Available = false,
    bool IsChunkingAvailable = false);

/// <summary>
/// Builds the EHLO capability list.
/// </summary>
/// <remarks>
/// <para>
/// <b>Advertising an extension that is not honoured is worse than not advertising it.</b> Peers
/// make delivery decisions from this list: a sender that sees <c>SIZE</c> refuses locally
/// instead of trying, one that sees <c>STARTTLS</c> may have a policy requiring it, and one
/// that sees <c>SMTPUTF8</c> will send addresses this server would then have to mangle. So the
/// list is derived from what is implemented and currently permitted, and each entry is behind a
/// flag that is only turned on when the feature has passing tests.
/// </para>
/// <para>
/// <b>AUTH is the one that matters.</b> It is never advertised on port 25 and never before TLS.
/// That is how rule 105's "no plaintext SMTP AUTH over Internet" is enforced: not by rejecting
/// an attempt, but by never telling the peer the mechanism exists. A client that is never
/// offered AUTH does not send credentials in the clear, so there is nothing to intercept.
/// </para>
/// </remarks>
public static class SmtpCapabilities
{
    /// <summary>The SASL mechanisms offered once authentication is available and TLS is up.</summary>
    /// <remarks>
    /// PLAIN and LOGIN send the password in a form equivalent to the clear, which is acceptable
    /// only inside TLS and is why the gate below is unconditional rather than configurable.
    /// </remarks>
    public static IReadOnlyList<string> SaslMechanisms { get; } = ["PLAIN", "LOGIN"];

    /// <summary>Builds the list, in the order it is sent.</summary>
    public static IReadOnlyList<string> For(SmtpCapabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(context.MaxMessageSizeBytes);

        List<string> capabilities =
        [
            "PIPELINING",
            string.Create(CultureInfo.InvariantCulture, $"SIZE {context.MaxMessageSizeBytes}"),
            "8BITMIME",
            "ENHANCEDSTATUSCODES",
        ];

        if (context.IsSmtpUtf8Available)
        {
            capabilities.Add("SMTPUTF8");
        }

        if (context.IsChunkingAvailable)
        {
            capabilities.Add("CHUNKING");
        }

        if (MayOfferStartTls(context))
        {
            capabilities.Add("STARTTLS");
        }

        if (MayOfferAuthentication(context))
        {
            capabilities.Add($"AUTH {string.Join(' ', SaslMechanisms)}");
        }

        return capabilities;
    }

    /// <summary>Whether STARTTLS may be offered.</summary>
    /// <remarks>
    /// Not once TLS is active — offering it inside the tunnel invites a nested handshake and is
    /// forbidden by RFC 3207 §4.2 — and not on an implicit-TLS listener, where the connection
    /// was encrypted before the first octet.
    /// </remarks>
    public static bool MayOfferStartTls(SmtpCapabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return !context.IsTlsActive && context.Role != SmtpListenerRole.ImplicitTlsSubmission;
    }

    /// <summary>
    /// Whether AUTH may be offered.
    /// </summary>
    /// <remarks>
    /// Three conditions, all required. Dropping any one of them is an incident: without the
    /// role check, port 25 becomes an authenticating relay reachable from the Internet; without
    /// the TLS check, credentials cross the network in the clear; without the availability
    /// check, the server advertises a mechanism it cannot perform.
    /// </remarks>
    public static bool MayOfferAuthentication(SmtpCapabilityContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.IsAuthenticationAvailable)
        {
            return false;
        }

        if (context.Role is not (SmtpListenerRole.Submission or SmtpListenerRole.ImplicitTlsSubmission))
        {
            return false;
        }

        return context.IsTlsActive;
    }
}
