using MailServer.Application.Smtp.Dtos;

namespace MailServer.Application.Abstractions.Smtp;

/// <summary>
/// The SMTP configuration, as the administration app is allowed to see it.
/// </summary>
/// <remarks>
/// <para>
/// Read-only by construction. The WPF app never edits configuration or the database directly —
/// it asks the service, and the service decides. An interface with a setter here would be the
/// first crack in that rule.
/// </para>
/// <para>
/// It lives in the Application layer so the query handler does not have to reach into
/// Infrastructure's options types, which would make the read side depend on how configuration
/// happens to be bound.
/// </para>
/// </remarks>
public interface ISmtpConfigurationView
{
    /// <summary>Every configured listener, enabled or not.</summary>
    IReadOnlyList<SmtpListenerStatusDto> DescribeListeners();

    /// <summary>Whether SASL authentication is implemented and enabled.</summary>
    bool IsAuthenticationAvailable { get; }

    /// <summary>Addresses permitted to relay without authenticating.</summary>
    IReadOnlyList<string> AuthorizedRelayAddresses { get; }
}
