using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Smtp.Dtos;
using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Smtp;

/// <summary>
/// The SMTP configuration as the administration app sees it.
/// </summary>
/// <remarks>
/// <para>
/// Read-only. Configuration is changed by editing the service's settings and restarting it, not
/// by the administration app reaching in — which is the same rule as "no UI directly editing the
/// database", applied to the other kind of state.
/// </para>
/// <para>
/// The two capability flags are computed from <see cref="SmtpCapabilities"/> rather than
/// restated here. A status screen that described the rules in its own words would eventually
/// describe them wrongly, and an operator would believe it.
/// </para>
/// </remarks>
public sealed class SmtpConfigurationView(IOptionsMonitor<MailServerOptions> options) : ISmtpConfigurationView
{
    /// <inheritdoc />
    public bool IsAuthenticationAvailable => options.CurrentValue.Smtp.EnableAuthentication;

    /// <inheritdoc />
    public IReadOnlyList<string> AuthorizedRelayAddresses =>
        [.. options.CurrentValue.Smtp.AuthorizedRelayAddresses];

    /// <inheritdoc />
    public IReadOnlyList<SmtpListenerStatusDto> DescribeListeners()
    {
        SmtpOptions smtp = options.CurrentValue.Smtp;

        return
        [
            Describe(SmtpListenerRole.InboundMta, smtp.InboundMta, smtp),
            Describe(SmtpListenerRole.Submission, smtp.Submission, smtp),
            Describe(SmtpListenerRole.ImplicitTlsSubmission, smtp.ImplicitTlsSubmission, smtp),
        ];
    }

    private static SmtpListenerStatusDto Describe(
        SmtpListenerRole role,
        SmtpListenerOptions listener,
        SmtpOptions smtp)
    {
        // Asked at the listener's best case - TLS active - because the question the screen is
        // answering is "can this listener EVER offer AUTH", not "is it offering it right now on
        // some particular connection".
        SmtpCapabilityContext bestCase = new(
            role,
            IsTlsActive: true,
            smtp.EnableAuthentication,
            MaxMessageSizeBytes: 1,
            smtp.EnableSmtpUtf8,
            smtp.EnableChunking);

        bool offersAuthentication = SmtpCapabilities.MayOfferAuthentication(bestCase);

        return new SmtpListenerStatusDto
        {
            Role = role,
            Port = listener.Port,
            Enabled = listener.Enabled,
            BindAddresses = [.. listener.BindAddresses],
            OffersAuthentication = offersAuthentication,

            // Relaying for an authenticated sender requires the session to be able to
            // authenticate at all, which is exactly the AUTH question above. Port 25 answers
            // false whatever else is configured.
            CanRelayForAuthenticatedSenders = offersAuthentication,
        };
    }
}
