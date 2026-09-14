using System.Globalization;
using System.Text;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Smtp;

/// <summary>What goes into the trace header for one hop.</summary>
/// <param name="RemoteAddress">The peer's address, from the transport.</param>
/// <param name="GreetedName">The name the client gave in EHLO. A claim, not a fact.</param>
/// <param name="ReverseDnsName">The peer's PTR name if one was resolved, else null.</param>
/// <param name="LocalHostname">This server's name.</param>
/// <param name="Recipient">The recipient this copy is being delivered to, if singular.</param>
/// <param name="Protocol">ESMTP, ESMTPS, SMTP — whichever actually happened.</param>
/// <param name="TlsDescription">Cipher summary when TLS was used, else null.</param>
/// <param name="MessageId">This server's own identifier for the message.</param>
/// <param name="ReceivedAt">When receipt completed.</param>
public sealed record ReceivedHeaderContext(
    IpAddressValue RemoteAddress,
    string? GreetedName,
    string? ReverseDnsName,
    string LocalHostname,
    EmailAddress? Recipient,
    string Protocol,
    string? TlsDescription,
    StoredMessageId MessageId,
    DateTimeOffset ReceivedAt);

/// <summary>
/// Builds the <c>Received:</c> trace header RFC 5321 §4.4 requires every hop to add.
/// </summary>
/// <remarks>
/// <para>
/// The header is how a postmaster reconstructs a message's path, and it is the only record of
/// what actually connected. It therefore says plainly which parts are facts and which are the
/// client's claims: the address in <c>[brackets]</c> came from the transport and cannot be
/// forged; the name before it came from EHLO and can be anything.
/// </para>
/// <para>
/// <b>Every field is sanitised.</b> The EHLO name is attacker-chosen text going into a header
/// block, so a CR or LF in it would end the header and begin another — header injection, the
/// same shape as response splitting but written into the stored message where it is read by
/// every downstream tool, spam filter and mail client. Control characters are removed, and the
/// result is bounded in length so a peer cannot make each message carry kilobytes of its
/// choosing.
/// </para>
/// </remarks>
public static class ReceivedHeader
{
    /// <summary>Longest any single client-supplied field may be in the header.</summary>
    /// <remarks>
    /// RFC 1035 caps a domain name at 255 octets, and nothing legitimate in these fields is
    /// longer. Without a cap, a peer that sends a 4000-octet EHLO name adds 4000 octets to every
    /// message it delivers, which it chooses and this server stores.
    /// </remarks>
    public const int MaxFieldLength = 255;

    /// <summary>Names the protocol actually spoken, for the <c>with</c> clause.</summary>
    /// <remarks>
    /// ESMTPS means "ESMTP inside TLS" and is what a postmaster looks for when checking whether
    /// a message arrived encrypted. Reporting it for a session that was never encrypted would
    /// make the header lie about the one property it is most often consulted for.
    /// </remarks>
    public static string DescribeProtocol(bool extendedGreeting, bool tlsActive, bool authenticated) =>
        (extendedGreeting, tlsActive, authenticated) switch
        {
            (false, _, _) => "SMTP",
            (true, false, _) => "ESMTP",
            (true, true, false) => "ESMTPS",
            (true, true, true) => "ESMTPSA",
        };

    /// <summary>Builds the header, including its trailing CRLF.</summary>
    public static string Build(ReceivedHeaderContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        StringBuilder builder = new();

        builder.Append("Received: from ");
        builder.Append(Sanitize(context.GreetedName) is { Length: > 0 } greeted ? greeted : "unknown");

        // The parenthesised part is what this server observed, as opposed to what the client
        // said. Keeping the two visually distinct is the whole value of the header.
        builder.Append(" (");

        if (Sanitize(context.ReverseDnsName) is { Length: > 0 } reverseDns)
        {
            builder.Append(reverseDns);
            builder.Append(' ');
        }

        builder.Append('[');
        builder.Append(Sanitize(context.RemoteAddress.Value));
        builder.Append("])");

        builder.Append("\r\n\tby ");
        builder.Append(Sanitize(context.LocalHostname));

        builder.Append(" with ");
        builder.Append(Sanitize(context.Protocol));

        if (Sanitize(context.TlsDescription) is { Length: > 0 } tls)
        {
            builder.Append(" (");
            builder.Append(tls);
            builder.Append(')');
        }

        builder.Append("\r\n\tid ");
        builder.Append(context.MessageId.Value.ToString("N", CultureInfo.InvariantCulture));

        if (context.Recipient is not null)
        {
            builder.Append("\r\n\tfor <");
            builder.Append(Sanitize(context.Recipient.ToString()));
            builder.Append('>');
        }

        builder.Append(";\r\n\t");

        // RFC 5322 §3.3 date-time, always with a numeric offset. A header timestamped in local
        // time without an offset is unusable for reconstructing a path across time zones.
        builder.Append(context.ReceivedAt.ToUniversalTime()
            .ToString("ddd, dd MMM yyyy HH:mm:ss +0000", CultureInfo.InvariantCulture));

        builder.Append("\r\n");

        return builder.ToString();
    }

    /// <summary>
    /// Strips control characters and bounds the length.
    /// </summary>
    /// <remarks>
    /// Removing rather than escaping. There is no escape sequence in RFC 5322 that would make a
    /// bare CR safe in an unstructured header field, so the only correct handling is for it not
    /// to be there.
    /// </remarks>
    public static string? Sanitize(string? value)
    {
        if (value is null)
        {
            return null;
        }

        StringBuilder builder = new(Math.Min(value.Length, MaxFieldLength));

        foreach (char c in value)
        {
            if (char.IsControl(c))
            {
                continue;
            }

            builder.Append(c);

            if (builder.Length == MaxFieldLength)
            {
                break;
            }
        }

        return builder.ToString();
    }
}
