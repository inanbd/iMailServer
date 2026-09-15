using MailServer.Domain.Enums;

namespace MailServer.Application.Smtp.Dtos;

/// <summary>One message this server accepted, as the administration app shows it.</summary>
/// <remarks>
/// <b>The envelope, never the body.</b> The administration app displays who sent a message,
/// where it came from and where it went — the operational facts. It does not display content,
/// because reading customers' mail is not an administrative function and an interface that
/// offers it invites the use.
/// </remarks>
public sealed record ReceivedMessageDto
{
    public required Guid Id { get; init; }

    public required long SizeBytes { get; init; }

    /// <summary>SHA-256 of the stored content, for integrity checks.</summary>
    public required string ContentSha256 { get; init; }

    /// <summary>
    /// The envelope sender, or null for the null reverse path.
    /// </summary>
    /// <remarks>
    /// Null means <c>&lt;&gt;</c> — a bounce. The UI shows it as such rather than as "unknown",
    /// because it is a meaningful value and not a missing one.
    /// </remarks>
    public string? ReversePath { get; init; }

    /// <summary>The peer's address, from the transport. The one identifier that cannot be forged.</summary>
    public required string RemoteAddress { get; init; }

    /// <summary>What the peer claimed in EHLO. A claim, not a fact.</summary>
    public string? GreetedName { get; init; }

    public required SmtpListenerRole ListenerRole { get; init; }

    public required bool TlsActive { get; init; }

    public string? AuthenticatedAs { get; init; }

    public required DateTimeOffset ReceivedUtc { get; init; }

    /// <summary>Set once retention has removed the content. The record outlives it.</summary>
    public DateTimeOffset? ContentRemovedUtc { get; init; }

    /// <summary>The envelope recipients, as accepted.</summary>
    public required IReadOnlyList<ReceivedRecipientDto> Recipients { get; init; }

    /// <summary>How many mailboxes it ultimately reached, after aliases expanded.</summary>
    public required int DeliveryCount { get; init; }
}

/// <summary>One envelope recipient of a received message.</summary>
/// <param name="Address">The address the SENDER wrote, before alias expansion.</param>
/// <param name="Decision">Local delivery or onward relay.</param>
public sealed record ReceivedRecipientDto(string Address, RelayDecision Decision);

/// <summary>What the SMTP subsystem is doing right now.</summary>
public sealed record SmtpStatusDto
{
    /// <summary>One entry per configured listener, enabled or not.</summary>
    public required IReadOnlyList<SmtpListenerStatusDto> Listeners { get; init; }

    /// <summary>Messages accepted in the last 24 hours.</summary>
    public required long MessagesLastDay { get; init; }

    /// <summary>Messages accepted in the last hour.</summary>
    public required long MessagesLastHour { get; init; }

    /// <summary>Octets of message content currently stored.</summary>
    public required long StoredBytes { get; init; }

    /// <summary>
    /// Whether SASL authentication is available.
    /// </summary>
    /// <remarks>
    /// Shown because it explains why the submission listeners are off: a submission port with no
    /// way to authenticate refuses every sender, so it is disabled rather than advertised.
    /// </remarks>
    public required bool AuthenticationAvailable { get; init; }

    /// <summary>Addresses permitted to relay without authenticating.</summary>
    /// <remarks>
    /// Surfaced deliberately. An operator should be able to see this list without reading a JSON
    /// file, because it is the one setting that can widen who may send mail through this server.
    /// </remarks>
    public required IReadOnlyList<string> AuthorizedRelayAddresses { get; init; }
}

/// <summary>One listener's configuration and state.</summary>
public sealed record SmtpListenerStatusDto
{
    public required SmtpListenerRole Role { get; init; }

    public required int Port { get; init; }

    public required bool Enabled { get; init; }

    /// <summary>Addresses bound. Empty means every interface.</summary>
    public required IReadOnlyList<string> BindAddresses { get; init; }

    /// <summary>Whether this listener ever offers AUTH, given the role and the current configuration.</summary>
    public required bool OffersAuthentication { get; init; }

    /// <summary>Whether this listener can ever relay for an authenticated sender.</summary>
    public required bool CanRelayForAuthenticatedSenders { get; init; }
}
