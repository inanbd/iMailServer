namespace MailServer.Application.Filtering.Dtos;

/// <summary>One reason a message was held.</summary>
/// <remarks>
/// <b>Describes, never quotes.</b> A quarantine listing is read under <c>ViewServerState</c>
/// and the message itself needs <c>ReadMessageContent</c>, so a signal that carried a subject
/// line or a fragment of the body would be a way to read mail with the weaker of the two
/// permissions. <c>FilterSignal</c> is where that rule lives.
/// </remarks>
public sealed record FilterSignalDto
{
    /// <summary>The check's stable identifier, e.g. <c>BLOCKED_ATTACHMENT</c>.</summary>
    public required string Name { get; init; }

    /// <summary>What it contributed. Negative means it counted in the message's favour.</summary>
    public required double Score { get; init; }

    /// <summary>What was observed.</summary>
    public required string Detail { get; init; }
}

/// <summary>One message the filter held.</summary>
public sealed record QuarantinedMessageDto
{
    public required Guid Id { get; init; }

    /// <summary>The stored message, for a caller that goes on to read its content.</summary>
    public required Guid MessageId { get; init; }

    /// <summary>The envelope sender, or null for the null reverse path a bounce carries.</summary>
    public string? Sender { get; init; }

    /// <summary>The host that delivered it.</summary>
    public required string RemoteAddress { get; init; }

    public required double Score { get; init; }

    /// <summary>The one-line verdict, as it read when the message was held.</summary>
    public required string Summary { get; init; }

    /// <summary><c>Held</c>, <c>Released</c> or <c>Discarded</c>.</summary>
    public required string Status { get; init; }

    public required DateTimeOffset QuarantinedUtc { get; init; }

    /// <summary>When a retention sweep may remove it, while it is still held.</summary>
    public required DateTimeOffset ExpiresUtc { get; init; }

    public DateTimeOffset? ResolvedUtc { get; init; }

    /// <summary>Which administrator released or discarded it.</summary>
    public string? ResolvedBy { get; init; }

    /// <summary>Why it was held, in the order the checks produced the reasons.</summary>
    public required IReadOnlyList<FilterSignalDto> Signals { get; init; }
}

/// <summary>What a release actually achieved.</summary>
/// <param name="Delivered">How many mailboxes the message reached.</param>
/// <param name="Recipients">How many envelope recipients it was delivered for.</param>
/// <param name="Diagnostic">
/// Why it fell short, when it did. A release can succeed at the quarantine and still reach
/// nobody — an alias that now points at nothing, a mailbox deleted since — and saying so is
/// the difference between an operator believing the mail arrived and knowing it did not.
/// </param>
public sealed record QuarantineReleaseDto(int Delivered, int Recipients, string? Diagnostic = null);
