using MailServer.Domain.Smtp;

namespace MailServer.Infrastructure.Smtp.Outbound;

/// <summary>
/// Parses wire-format SMTP replies from a remote server.
/// </summary>
/// <remarks>
/// The receiving half of <see cref="SmtpReply.Format"/>: that method renders this server's own
/// replies; this reads a peer's. Nothing in the inbound listener needed a parser - it only ever
/// sends replies - so this is new for the outbound client rather than reused.
/// </remarks>
internal static class SmtpReplyParser
{
    /// <summary>Reads one complete reply, following continuation lines until the final one.</summary>
    /// <exception cref="IOException">
    /// The connection closed, a line timed out, a line exceeded the reader's bound, or the
    /// reply was not well-formed SMTP (missing code, or the code changed between continuation
    /// lines). Every one of these means the same thing to a caller: this conversation cannot
    /// continue, so it is a single exception type rather than a result the caller must remember
    /// to check.
    /// </exception>
    public static async Task<SmtpReply> ReadAsync(
        SmtpLineReader reader,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        int? code = null;
        string firstText = string.Empty;
        string? enhancedStatus = null;
        List<string> continuationLines = [];

        while (true)
        {
            SmtpLineResult result = await reader.ReadLineAsync(timeout, cancellationToken).ConfigureAwait(false);

            if (!result.IsLine)
            {
                throw new IOException(
                    $"The remote closed the connection or did not reply in time while a reply " +
                    $"was expected ({result.Status}).");
            }

            string line = result.Text;

            if (line.Length < 4 ||
                !int.TryParse(line.AsSpan(0, 3), out int lineCode) ||
                (line[3] != '-' && line[3] != ' '))
            {
                throw new IOException($"Malformed SMTP reply line from the remote: '{line}'.");
            }

            bool isFinal = line[3] == ' ';
            string text = line.Length > 4 ? line[4..] : string.Empty;

            if (code is null)
            {
                code = lineCode;
                (enhancedStatus, firstText) = ExtractEnhancedStatus(text);
            }
            else if (lineCode != code)
            {
                throw new IOException(
                    $"The remote's reply code changed mid-response: {code} then {lineCode}.");
            }
            else
            {
                (_, string continuation) = ExtractEnhancedStatus(text);
                continuationLines.Add(continuation);
            }

            if (isFinal)
            {
                return new SmtpReply(code.Value, enhancedStatus, firstText)
                {
                    ContinuationLines = continuationLines,
                };
            }
        }
    }

    /// <summary>
    /// Splits an RFC 3463 enhanced status code (<c>2.1.5</c>, <c>4.7.0</c>, <c>5.1.1</c>) off the
    /// front of a reply line's text, when the remote sent one.
    /// </summary>
    /// <remarks>
    /// Not every server sends one, so absence is not malformed input - just a reply this method
    /// leaves untouched.
    /// </remarks>
    private static (string? EnhancedStatus, string Text) ExtractEnhancedStatus(string text)
    {
        int spaceIndex = text.IndexOf(' ');
        string candidate = spaceIndex < 0 ? text : text[..spaceIndex];

        if (!IsEnhancedStatusToken(candidate))
        {
            return (null, text);
        }

        string remainder = spaceIndex < 0 ? string.Empty : text[(spaceIndex + 1)..];
        return (candidate, remainder);
    }

    private static bool IsEnhancedStatusToken(string token)
    {
        string[] parts = token.Split('.');

        if (parts.Length != 3 || parts[0] is not ("2" or "4" or "5"))
        {
            return false;
        }

        foreach (string part in parts)
        {
            if (part.Length is 0 or > 3)
            {
                return false;
            }

            foreach (char c in part)
            {
                if (!char.IsAsciiDigit(c))
                {
                    return false;
                }
            }
        }

        return true;
    }
}
