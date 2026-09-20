using MailServer.Domain.Smtp;

namespace MailServer.Infrastructure.Smtp.Outbound;

/// <summary>
/// The command-and-reply record of one outbound SMTP conversation, for the delivery test.
/// </summary>
/// <remarks>
/// <para>
/// <b>Commands and replies only — never the message.</b> The whole value of a delivery test is
/// being able to read what the remote said at each step, and none of that needs a single octet
/// of content. <c>DATA</c>'s command and its two replies are recorded; what goes between them is
/// streamed straight from the message store by a different method and never passes through here.
/// A transcript that carried the body would turn a diagnostic an operator wants to paste into a
/// support ticket into a copy of somebody's mail.
/// </para>
/// <para>
/// <b>Nothing here is a credential.</b> This server does not authenticate to a remote MX — RFC
/// 5321 delivery is unauthenticated, and <see cref="OutboundSmtpClient"/> issues no <c>AUTH</c>
/// — so unlike an inbound submission conversation there is no password on this wire to redact.
/// If a smarthost with SASL is ever added, this class is where the redaction belongs, and the
/// test asserting so is in <c>DeliveryTestServiceTests</c>.
/// </para>
/// <para>
/// <b>Bounded, like every other buffer that grows from a peer's output.</b> A remote that
/// answered every command with a long multi-line reply would otherwise decide how much memory a
/// delivery test holds.
/// </para>
/// </remarks>
public sealed class SmtpTranscript
{
    /// <summary>The most lines one transcript keeps.</summary>
    /// <remarks>
    /// A conversation is a banner, an EHLO with its capabilities, STARTTLS, a second EHLO, MAIL,
    /// RCPT, DATA and QUIT — a few dozen lines when the remote is chatty. Two hundred is well
    /// past that and still bounded.
    /// </remarks>
    public const int MaxLines = 200;

    /// <summary>The longest single line kept, before it is truncated.</summary>
    public const int MaxLineLength = 1_000;

    private readonly List<string> _lines = [];

    /// <summary>The conversation so far, oldest first.</summary>
    public IReadOnlyList<string> Lines => _lines;

    /// <summary>Records something this server sent.</summary>
    public void Sent(string command) => Add($"> {command}");

    /// <summary>Records something the remote sent.</summary>
    public void Received(SmtpReply reply)
    {
        ArgumentNullException.ThrowIfNull(reply);

        Add($"< {reply.Code} {reply.Text}");
    }

    /// <summary>Records an observation that is not a wire line — a TLS result, a chosen host.</summary>
    public void Note(string text) => Add($"* {text}");

    private void Add(string line)
    {
        if (_lines.Count >= MaxLines)
        {
            return;
        }

        _lines.Add(line.Length > MaxLineLength
            ? string.Concat(line.AsSpan(0, MaxLineLength), "…")
            : line);

        // Said once, at the boundary, so a reader can tell a short conversation from a truncated
        // one. Silently stopping would make a transcript that ends mid-handshake look like a
        // connection that died there.
        if (_lines.Count == MaxLines)
        {
            _lines[^1] = "* Transcript truncated; the conversation continued.";
        }
    }
}
